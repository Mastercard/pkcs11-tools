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

static bool req_add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex) {
        P_ERR();
        return false;
    }

    if(!sk_X509_EXTENSION_push(sk, ex)) {
        P_ERR();
        return false;
    }

    return true;
}


CK_VOID_PTR pkcs11_create_X509_REQ(pkcs11Context *p11Context,
                                   char *dn,
                                   bool reverse,
                                   bool fake,
                                   char *san[],
                                   int sancnt,
                                   bool ext_ski,
                                   key_type_t key_type,
                                   sig_alg_t sig_alg,
                                   hash_alg_t hash_alg,
                                   CK_OBJECT_HANDLE hprivkey,
                                   pkcs11AttrList *attrlist) 
{
    X509_REQ *req = NULL, *retval = NULL;
    EVP_PKEY *pk = NULL;
    X509_NAME *name=NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
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

	/* determination between pkcs1 or pss is made later */
	pkcs11_rsa_method_setup();
	pkcs11_rsa_method_pkcs11_context(p11Context, hprivkey, fake);

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
	pkcs11_dsa_method_pkcs11_context(p11Context, hprivkey, fake);
	break;
		
    case ec:
	/* get SPKI */
	if((pk = pkcs11_SPKI_from_EC( attrlist )) == NULL ) {
	    fprintf(stderr, "Error: unable to build SPKI structure\n");
	    goto err;
	}
	/* hook our crypto to OpenSSL methods */
	pkcs11_ecdsa_method_setup();
	pkcs11_ecdsa_method_pkcs11_context(p11Context, hprivkey, fake);
	break;

    case ed:
	/* get SPKI */
	if((pk = pkcs11_SPKI_from_ED( attrlist )) == NULL ) {
	    fprintf(stderr, "Error: unable to build SPKI structure\n");
	    goto err;
	}
	/* hook our crypto to OpenSSL methods */
	pkcs11_eddsa_method_setup();
	pkcs11_eddsa_method_pkcs11_context(p11Context, hprivkey, fake);
	break;

    default:
	fprintf(stderr, "Error: unsupported signing algorithm\n");
	goto err;
    }

    /* step 3: create PKCS#10 structure */
    if ((req=X509_REQ_new()) == NULL) {
	P_ERR();
	goto err;
    }

    /* step 4: set version */
    if(!X509_REQ_set_version(req,0) ) {
	P_ERR();
	goto err;
    }

    /* step 5: assign public key to certificate */
    if(!X509_REQ_set_pubkey(req,pk)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the pk */

    /* step 6: parse subject DN (which becomes issuer DN) */
    if((name = pkcs11_DN_new_from_string(dn, MBSTRING_UTF8, false, reverse))==NULL) {
	P_ERR();
	goto err;
    }

    if (!X509_REQ_set_subject_name(req, name)) {
	P_ERR();
	goto err;
    }

    /* next steps are optional, as we do not necessarily have extensions to add */
    if(sancnt>0 || ext_ski) {
	/* allocate extention structure */
	if(!(exts = sk_X509_EXTENSION_new_null())) {
	    P_ERR();
	    goto err;
	}
		
	/* step 7: add SAN if specified */
	/* TODO extract and error checking */
	if(sancnt>0)
	{
	    int i;
	    size_t size=0;
	    char *sanfield=NULL;

	    for(i=0; i<sancnt; i++) {
		size += strlen(san[i]) + 1;     /* we add one for the ',' */
	    }
	    size++;             /* add a supplementary byte for allowing extra last ',' with strcat() */

	    if((sanfield=OPENSSL_malloc(size))!=NULL) {
		sanfield[0]=0;  /* clear first byte */
		for(i=0;i<sancnt;i++) {
		    strcat(sanfield,san[i]);
		    strcat(sanfield,",");
		}

		sanfield[strlen(sanfield)-1] = '\0'; /* erase last comma */
		req_add_ext(exts, NID_subject_alt_name, sanfield);
		OPENSSL_free(sanfield);
	    }
	}

	/* step 8: add SKI if specified */
	if(ext_ski) {           /* TODO fix error checking and extract */
	    char *value=NULL;

	    attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_ID);

	    value=(char *) OPENSSL_zalloc( (attr->ulValueLen) * 2  + 1);

	    if(value) {
		int i;

		for(i=0; i<attr->ulValueLen; i++) {
		    sprintf(&value[i*2], "%2.2x", ((unsigned char *)attr->pValue)[i]);
		}

		req_add_ext(exts, NID_subject_key_identifier, &value[0]);
		OPENSSL_free(value);
	    }
	}

	/* step 9: add extensions to the PKCS#10 structure */
	if(!X509_REQ_add_extensions(req, exts)) {
	    P_ERR();
	    goto err;
	}
    }
	
    /* step 10: sign PKCS#10 */
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

    if (!X509_REQ_sign_ctx(req, mdctx)) {
	P_ERR();
	goto err;
    }

    retval = (CK_VOID_PTR)req;
    req = NULL;                         /* transfer to retval and avoid freeing structure */

err:
    /* cleanup */
    if(mdctx) { EVP_MD_CTX_free(mdctx); mdctx=NULL; }
    if(exts != NULL) { sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free); exts=NULL; }
    if(name != NULL) { X509_NAME_free(name); name=NULL; }
    if(req!=NULL) { X509_REQ_free(req); req=NULL; }
    if(pk!=NULL) { EVP_PKEY_free(pk); pk=NULL; }
    /* memory management */

    return retval;
}


void pkcs11_free_X509_REQ(CK_VOID_PTR req) {
    X509_REQ *xreq = (X509_REQ *)req;

    if(xreq) {
        X509_REQ_free(xreq);
    }   
}


void write_X509_REQ(CK_VOID_PTR req, char *filename, bool verbose)
{

    X509_REQ *xreq = (X509_REQ *)req;
    BIO *bio_file = NULL;
    BIO *bio_stdout = NULL;

    bio_file = BIO_new( BIO_s_file() );
    bio_stdout = BIO_new( BIO_s_file() );

    if( bio_file==NULL || bio_stdout==NULL) {
        fprintf(stderr, "Error: Can't create BIO objects.\n");
        goto err;
    }

    BIO_set_fp(bio_stdout, stdout, BIO_NOCLOSE);

    if(filename==NULL) {        /* no file: we write to stdout */
        BIO_set_fp(bio_file, stdout, BIO_NOCLOSE);
    }
    else {                      /* write to filename */
        BIO_write_filename(bio_file, filename);
    }

    if(verbose) {
        X509_REQ_print(bio_stdout,xreq); /* human-readable print */
    }

    PEM_write_bio_X509_REQ(bio_file,xreq); /* PEM */

err:
    if(bio_file) BIO_free(bio_file);
    if(bio_stdout) BIO_free(bio_stdout);
}

/* EOF */
