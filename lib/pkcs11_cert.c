/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2018 Mastercard
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* some parts of this file are extracted from the openssl project */
/* original licensing terms follow */

/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pkcs11lib.h"

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

static bool x509_add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /*
     * Issuer and subject certs: both the target since it is self signed, no
     * request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) {
	P_ERR();
	return false;
    }

    if(!X509_add_ext(cert, ex, -1)) {
	P_ERR();
	return false;
    }
    
    X509_EXTENSION_free(ex);
    return true;
}


CK_VOID_PTR pkcs11_create_X509_CERT(pkcs11Context *p11Context,
				    char *dn,
				    bool reverse,
				    int days,
				    char *san[],
				    int sancnt,
				    bool ext_ski,
				    key_type_t key_type,
				    sig_alg_t sig_alg,
				    hash_alg_t hash_alg,
				    CK_OBJECT_HANDLE hprivkey,
				    pkcs11AttrList *attrlist) 
{
    X509 *crt = NULL, *retval = NULL;
    EVP_PKEY *pk = NULL;
    X509_NAME *name=NULL;
    BIGNUM *bn_sn = NULL;
    CK_BYTE sn[20];
    CK_ATTRIBUTE_PTR attr;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    /* step 1: do some verifications on input data */
    if( ext_ski && !pkcs11_attrlist_has_attribute(attrlist, CKA_ID)) {
	fprintf(stderr, "Error: SKI/AKI extension requested, but CKA_ID not provided");
	goto err;
    }
    
    /* step 2: do key-type specific business*/
    switch(key_type) {
    case rsa:
	/* get SPKI */
	if((pk = pkcs11_SPKI_from_RSA( attrlist )) == NULL ) {
	    fprintf(stderr, "Error: unable to build SPKI structure\n");
	    goto err;
	}
	/* hook our crypto to OpenSSL methods */
	pkcs11_rsa_method_setup();
	pkcs11_rsa_method_pkcs11_context(p11Context, hprivkey, false);

	/* default for RSA signature: set to pkcs1 for now*/
	if(sig_alg==s_default) {
	    sig_alg = s_rsa_pkcs1;
	}    
	break;
	
    case dsa:
	/* get SPKI */
	if((pk = pkcs11_SPKI_from_DSA( attrlist )) == NULL ) {
	    fprintf(stderr, "Error: unable to build SPKI structure\n");
	    goto err;
	}
	/* hook our crypto to OpenSSL methods */
	pkcs11_dsa_method_setup();
	pkcs11_dsa_method_pkcs11_context(p11Context, hprivkey, false);
	break;
	
    case ec:
	/* get SPKI */
	if((pk = pkcs11_SPKI_from_EC( attrlist )) == NULL ) {
	    fprintf(stderr, "Error: unable to build SPKI structure\n");
	    goto err;
	}
	/* hook our crypto to OpenSSL methods */
	pkcs11_ecdsa_method_setup();
	pkcs11_ecdsa_method_pkcs11_context(p11Context, hprivkey, false);
	break;

    case ed:
	/* get SPKI */
	if((pk = pkcs11_SPKI_from_ED( attrlist )) == NULL ) {
	    fprintf(stderr, "Error: unable to build SPKI structure\n");
	    goto err;
	}
	/* hook our crypto to OpenSSL methods */
	pkcs11_eddsa_method_setup();
	pkcs11_eddsa_method_pkcs11_context(p11Context, hprivkey, false);
	break;

    default:
	fprintf(stderr, "Error: unsupported signing algorithm\n");
	goto err;
    }

    /* step 3: create cert structure */
    if ((crt=X509_new()) == NULL) {
	P_ERR();
	goto err;
    }

    /* step 4: set version to Certificate */
    if(!X509_set_version(crt,2) ) {
	P_ERR();
	goto err;
    }

    /* step 5: assign public key to certificate */
    if(!X509_set_pubkey(crt,pk)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the pk */

    /* step 6: set serial number */
    if(pkcs11_getrandombytes(p11Context, sn, sizeof sn / sizeof(CK_BYTE))!=rc_ok) {
	goto err;
    }

    bn_sn = BN_bin2bn(sn, sizeof sn / sizeof(CK_BYTE), NULL);
    if(bn_sn==NULL) {
	P_ERR();
	goto err;
    }

    BN_to_ASN1_INTEGER(bn_sn, X509_get_serialNumber(crt));
    BN_free(bn_sn); bn_sn=NULL;

    /* step 7: adjust validity */
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), (long)60 * 60 * 24 * days);


    /* step 8: parse subject DN (which becomes issuer DN) */
    if((name = pkcs11_DN_new_from_string(dn, MBSTRING_UTF8, false, reverse))==NULL) {
	P_ERR();
	goto err;
    }

    if (!X509_set_subject_name(crt, name)) {
	P_ERR();
	goto err;
    }

    if (!X509_set_issuer_name(crt, name)) {
	P_ERR();
	goto err;
    }

    /* step 9: add mandatory extensions */
    
    /* Standard extensions */
    x509_add_ext(crt, NID_basic_constraints, "critical,CA:FALSE");
    x509_add_ext(crt, NID_key_usage, "critical,digitalSignature"); /* we want code-signing */

    /* step 10: add SAN if specified */
    if(sancnt>0)
    {
	int i;
	size_t size=0;
	char *sanfield=NULL;

	for(i=0; i<sancnt; i++) {
	    size += strlen(san[i]) + 1;	/* we add one for the ',' */
	}
	size++;		/* add a supplementary byte for allowing extra last ',' with strcat() */

	if((sanfield=OPENSSL_malloc(size))!=NULL) {
	    sanfield[0]=0;	/* clear first byte */
	    for(i=0;i<sancnt;i++) {
		strcat(sanfield,san[i]);
		strcat(sanfield,",");
	    }

	    sanfield[strlen(sanfield)-1] = '\0'; /* erase last comma */
	    x509_add_ext(crt, NID_subject_alt_name, sanfield);
	    OPENSSL_free(sanfield);
	}
    }

    /* step 11: add SKI/AKI if specified */
    if(ext_ski) {
	char *value=NULL;
	const char keyid_prefix[] = "keyid:";

	attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_ID);

	value=(char *) OPENSSL_zalloc( (attr->ulValueLen) * 2  + sizeof keyid_prefix + 1 );

	if(value) {
	    int i;

	    strcpy(value, keyid_prefix);
	    
	    for(i=0; i<attr->ulValueLen; i++) {
		sprintf(&value[sizeof keyid_prefix - 1 + i*2], "%2.2x", ((unsigned char *)attr->pValue)[i]);
	    }

	    x509_add_ext(crt, NID_subject_key_identifier, &value[sizeof keyid_prefix - 1]); /* for SKI, we skip the 'keyid:' prefix */
	    x509_add_ext(crt, NID_authority_key_identifier, &value[0]); /* if we self-sign, we need this guy also */
	    OPENSSL_free(value);
	}
    }

    /* step 12: sign certificate */
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
	P_ERR();
	goto err;
    }

    if (!EVP_DigestSignInit(mdctx, &pctx, pkcs11_get_EVP_MD(key_type, hash_alg), NULL, pk)) {
	P_ERR();
	goto err;
    }

    /* if signature is RSA pss, we need to set up the context */
    if (key_type==rsa && sig_alg==s_rsa_pss) {
	/* set the PSS parameters */
	if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) {
	    P_ERR();
	    goto err;
	}
	if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_MAX) <= 0) {
	    P_ERR();
	    goto err;
	}
	if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, pkcs11_get_EVP_MD(key_type, hash_alg)) <= 0) {
	    P_ERR();
	    goto err;
	}
    }

    if(!X509_sign_ctx(crt, mdctx)) {
	P_ERR();
	goto err;
    }
    

    retval = (CK_VOID_PTR)crt;
    crt = NULL;			/* transfer to retval and avoid freeing structure */

err:
    /* cleanup */
    if(mdctx) { EVP_MD_CTX_free(mdctx); mdctx=NULL; }
    if(name != NULL) { X509_NAME_free(name); name=NULL; }
    if(bn_sn != NULL) { BN_free(bn_sn); bn_sn=NULL; }
    if(crt!=NULL) { X509_free(crt); crt=NULL; }
    if(pk!=NULL) { EVP_PKEY_free(pk); pk=NULL; }
    /* memory management */

    return retval;
}


void pkcs11_free_X509_CERT(CK_VOID_PTR crt) {
    X509 *xcrt = (X509 *)crt;

    if(xcrt) {
	X509_free(xcrt);
    }	
}


void write_X509_CERT(CK_VOID_PTR crt, char *filename, bool verbose)
{

    X509 *xcrt = (X509 *)crt;
    BIO *bio_file = NULL;
    BIO *bio_stdout = NULL;

    bio_file = BIO_new( BIO_s_file() );
    bio_stdout = BIO_new( BIO_s_file() );

    if( bio_file==NULL || bio_stdout==NULL) {
	fprintf(stderr, "Error: Can't create BIO objects.\n");
	goto err;
    }

    BIO_set_fp(bio_stdout, stdout, BIO_NOCLOSE);

    if(filename==NULL) {	/* no file: we write to stdout */
	BIO_set_fp(bio_file, stdout, BIO_NOCLOSE);
    }
    else {			/* write to filename */
	BIO_write_filename(bio_file, filename);
    }

    if(verbose) {
	X509_print(bio_stdout,xcrt); /* human-readable print */
    }

    PEM_write_bio_X509(bio_file,xcrt); /* PEM */

err:
    if(bio_file) BIO_free(bio_file);
    if(bio_stdout) BIO_free(bio_stdout);
}

/* EOF */
