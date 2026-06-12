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
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pkcs11lib.h"
#include "pkcs11_provider.h"

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

/*
 * Add an Authority Key Identifier (AKI) extension to `cert`, using the raw
 * Subject Key Identifier bytes (`ski`, `ski_len`) as the keyIdentifier value.
 *
 * Used for self-signed certificates where the subject and issuer are the same
 * entity: per RFC 5280 §4.2.1.1, the AKI keyIdentifier MUST then match the
 * SKI of the same certificate. Caller is responsible for first emitting the
 * SKI extension with the same bytes.
 *
 * Builds an AUTHORITY_KEYID ASN.1 structure carrying only the keyIdentifier
 * field (no authorityCertIssuer / authorityCertSerialNumber), encodes it via
 * X509V3_EXT_i2d() and appends it to the certificate.
 *
 * Returns true on success, false on any allocation/encoding failure (in which
 * case nothing has been added to `cert`).
 */
static bool x509_add_aki_from_ski(X509 *cert, const unsigned char *ski, size_t ski_len)
{
	AUTHORITY_KEYID *akid = NULL;
	X509_EXTENSION *ex = NULL;

	/* allocate the AuthorityKeyIdentifier ASN.1 container */
	akid = AUTHORITY_KEYID_new();
	if(akid == NULL) {
	P_ERR();
	goto err;
	}

	/* allocate the keyIdentifier OCTET STRING field */
	akid->keyid = ASN1_OCTET_STRING_new();
	if(akid->keyid == NULL) {
	P_ERR();
	goto err;
	}

	/* copy the SKI bytes into the keyIdentifier; AKI.keyIdentifier and
	 * SKI MUST hold the exact same value for a self-signed certificate */
	if(ASN1_OCTET_STRING_set(akid->keyid, ski, (int)ski_len) == 0) {
	P_ERR();
	goto err;
	}

	/* DER-encode the AUTHORITY_KEYID into a non-critical X.509 extension */
	ex = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid);
	if(ex == NULL) {
	P_ERR();
	goto err;
	}

	/* append the freshly built extension to the certificate */
	if(!X509_add_ext(cert, ex, -1)) {
	P_ERR();
	goto err;
	}

	X509_EXTENSION_free(ex);
	AUTHORITY_KEYID_free(akid);
	return true;

err:
	if(ex) { X509_EXTENSION_free(ex); }
	if(akid) { AUTHORITY_KEYID_free(akid); }
	return false;
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
    EVP_PKEY *signing_pk = NULL;        /* provider-bound key for signing */
    OSSL_LIB_CTX *prov_libctx = NULL;   /* private libctx hosting pkcs11tools */
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

    /* step 2: install the pkcs11tools OpenSSL 3 provider once for all
     * supported key types - all signing paths go through it. */
    if(!pkcs11_provider_install(&prov_libctx)) {
	fprintf(stderr, "Error: failed to install pkcs11tools provider\n");
	goto err;
    }

    /* step 3: do key-type specific business*/
    switch(key_type) {
    case rsa:
	if((pk = pkcs11_SPKI_from_RSA( attrlist )) == NULL ) {
	    fprintf(stderr, "Error: unable to build SPKI structure\n");
	    goto err;
	}
	/* default for RSA signature: set to pkcs1 for now*/
	if(sig_alg==s_default) {
	    sig_alg = s_rsa_pkcs1;
	}
	break;

    case dsa:
	if((pk = pkcs11_SPKI_from_DSA( attrlist )) == NULL ) {
	    fprintf(stderr, "Error: unable to build SPKI structure\n");
	    goto err;
	}
	break;

    case ec:
	if((pk = pkcs11_SPKI_from_EC( attrlist )) == NULL ) {
	    fprintf(stderr, "Error: unable to build SPKI structure\n");
	    goto err;
	}
	break;

    case ed:
	if((pk = pkcs11_SPKI_from_ED( attrlist )) == NULL ) {
	    fprintf(stderr, "Error: unable to build SPKI structure\n");
	    goto err;
	}
	break;

    default:
	fprintf(stderr, "Error: unsupported signing algorithm\n");
	goto err;
    }

    /* step 4: bind the PKCS#11 private key handle into the provider. */
    signing_pk = pkcs11_provider_make_pkey(prov_libctx, key_type, pk, p11Context, hprivkey, false);
    if(signing_pk == NULL) {
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
	uint8_t *ski=NULL;
	size_t ski_len=0;

	attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_ID);

	ski_len = attr->ulValueLen;
	ski=(uint8_t *) OPENSSL_malloc(ski_len);
	if(ski == NULL) {
	    P_ERR();
	    goto err;
	}
	memcpy(ski, attr->pValue, ski_len);

	value=(char *) OPENSSL_zalloc( (ski_len) * 2  + sizeof keyid_prefix + 1 );

	if(value) {
	    int i;

	    strcpy(value, keyid_prefix);
	    
	    for(i=0; i<attr->ulValueLen; i++) {
		sprintf(&value[sizeof keyid_prefix - 1 + i*2], "%2.2x", ((unsigned char *)attr->pValue)[i]);
	    }

	    x509_add_ext(crt, NID_subject_key_identifier, &value[sizeof keyid_prefix - 1]); /* for SKI, we skip the 'keyid:' prefix */
	    x509_add_aki_from_ski(crt, ski, ski_len); /* AKI must match the SKI value exactly */
	    OPENSSL_free(value);
	}
	if(ski) { OPENSSL_free(ski); }
    }

    /* step 12: sign certificate */
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
	P_ERR();
	goto err;
    }

    switch(key_type) {
    case ed:
	/* EdDSA path: PureEdDSA via pkcs11tools provider. */
	if (!EVP_DigestSignInit_ex(mdctx, &pctx, NULL, prov_libctx, NULL, signing_pk, NULL)) {
	    P_ERR();
	    goto err;
	}
	break;
    case rsa: {
	/* RSA path: pass PSS params via OSSL_PARAMs at init time. */
	const EVP_MD *md = pkcs11_get_EVP_MD(key_type, hash_alg);
	const char *mdname = md ? EVP_MD_get0_name(md) : NULL;
	OSSL_PARAM rsa_params[6];
	OSSL_PARAM *rsa_p = rsa_params;
	int saltlen_max = -1;
	const char *pad_pkcs1 = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
	const char *pad_pss   = OSSL_PKEY_RSA_PAD_MODE_PSS;
	if(sig_alg == s_rsa_pss) {
	    *rsa_p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
							(char *)pad_pss, 0);
	    *rsa_p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST,
							(char *)mdname, 0);
	    *rsa_p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
						&saltlen_max);
	} else {
	    *rsa_p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
							(char *)pad_pkcs1, 0);
	}
	*rsa_p = OSSL_PARAM_construct_end();
	if (!EVP_DigestSignInit_ex(mdctx, &pctx, mdname, prov_libctx, NULL, signing_pk, rsa_params)) {
	    P_ERR();
	    goto err;
	}
	break;
    }
    case ec:
    case dsa: {
	const EVP_MD *md = pkcs11_get_EVP_MD(key_type, hash_alg);
	const char *mdname = md ? EVP_MD_get0_name(md) : NULL;
	if (!EVP_DigestSignInit_ex(mdctx, &pctx, mdname, prov_libctx, NULL, signing_pk, NULL)) {
	    P_ERR();
	    goto err;
	}
	break;
    }
    default:
	if (!EVP_DigestSignInit(mdctx, &pctx, pkcs11_get_EVP_MD(key_type, hash_alg), NULL, pk)) {
	    P_ERR();
	    goto err;
	}
	break;
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
    if(signing_pk!=NULL) { EVP_PKEY_free(signing_pk); signing_pk=NULL; }
    if(pk!=NULL) { EVP_PKEY_free(pk); pk=NULL; }
    if(prov_libctx!=NULL) { OSSL_LIB_CTX_free(prov_libctx); prov_libctx=NULL; }
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
