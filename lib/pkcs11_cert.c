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

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>

#include "pkcs11lib.h"


static X509_NAME *parse_name(char *subject, long chtype, int multirdn, int reverse);
static int add_ext(X509 *cert, int nid, char *value);



/*----------------------------------------------------------------------*/
/* grabbed from openssl/apps/apps.c                                     */

/*
 * subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */

/* TODO : fix support for multirdn */

static X509_NAME *parse_name(char *subject, long chtype, int multirdn, int reverse)
{
    size_t buflen = strlen(subject)+1; /* to copy the types and values into. due to escaping, the copy can only become shorter */
    char *buf = OPENSSL_malloc(buflen);
    size_t max_ne = buflen / 2 + 1; /* maximum number of name elements */
    char **ne_types = OPENSSL_malloc(max_ne * sizeof (char *));
    char **ne_values = OPENSSL_malloc(max_ne * sizeof (char *));
    int *mval = OPENSSL_malloc (max_ne * sizeof (int));

    char *sp = subject, *bp = buf;
    int i, ne_num = 0;

    int actual_entries = 0;	/* hack: we overcome limitation of openssl, in case there is no NID or no value. */

    X509_NAME *n = NULL;
    int nid;

    if (!buf || !ne_types || !ne_values || !mval)
    {
	printf("malloc error\n");
	goto error;
    }

    if (*subject != '/')
    {
	printf("Subject does not start with '/'.\n");
	goto error;
    }
    sp++; /* skip leading / */

    /* no multivalued RDN by default */
    mval[ne_num] = 0;

    while (*sp)
    {
	/* collect type */
	ne_types[ne_num] = bp;
	while (*sp)
	{
	    if (*sp == '\\') /* is there anything to escape in the type...? */
	    {
		if (*++sp)
		    *bp++ = *sp++;
		else
		{
		    printf("escape character at end of string\n");
		    goto error;
		}
	    }
	    else if (*sp == '=')
	    {
		sp++;
		*bp++ = '\0';
		break;
	    }
	    else
		*bp++ = *sp++;
	}
	if (!*sp)
	{
	    printf("end of string encountered while processing type of subject name element #%d\n", ne_num);
	    goto error;
	}
	ne_values[ne_num] = bp;
	while (*sp)
	{
	    if (*sp == '\\')
	    {
		if (*++sp)
		    *bp++ = *sp++;
		else
		{
		    printf("escape character at end of string\n");
		    goto error;
		}
	    }
	    else if (*sp == '/')
	    {
		sp++;
		/* no multivalued RDN by default */
		mval[ne_num+1] = 0;
		break;
	    }
	    else if (*sp == '+' && multirdn)
	    {
		/* a not escaped + signals a mutlivalued RDN */
		sp++;
		mval[ne_num+1] = -1;
		break;
	    }
	    else
		*bp++ = *sp++;
	}
	*bp++ = '\0';
	ne_num++;
    }

    if (!(n = X509_NAME_new())) {
	P_ERR();
	goto error;
    }

    if( reverse == 0 ) {
	/* we append at the beginning, as we expect the -d parameter being written by a human */
	/* as such order goes from more specifc 'CN=... OU=...'  */
	/* binary order is reversed: from less specific to more specific. */
	/* this is why we walk the tree in reverse order */

	for (i = ne_num-1; i >=0 ; i--)
	{
	    if ((nid=OBJ_txt2nid(ne_types[i])) == NID_undef)
	    {
		printf("Subject Attribute %s has no known NID, skipped\n", ne_types[i]);
		continue;
	    }

	    if (!*ne_values[i])
	    {
		printf("No value provided for Subject Attribute %s, skipped\n", ne_types[i]);
		continue;
	    }

	    /* Note: there must be a bug in X509_NAME_add_entry_by_NID, as using loc=0 turns the subject name */
	    /* into RDN, with improper formatting of the Subject. */
	    /* reason why we insert at the end (-1) and walk the list in reverse order */

	    if (!X509_NAME_add_entry_by_NID(n, nid, chtype, (unsigned char*)ne_values[i], -1, -1,mval[i])) {
		P_ERR();
		goto error;
	    }

	    ++actual_entries;
	}
    } else {
	/* if reverse is not null, then we lay out X509 exactly as specified by Subject DN field */
	/* this is buggy, but was default for versions prior to 0.25 */
	/* the option is set for compatibility reasons */

	for (i = 0; i < ne_num ; i++)
	{
	    if ((nid=OBJ_txt2nid(ne_types[i])) == NID_undef)
	    {
		printf("Subject Attribute %s has no known NID, skipped\n", ne_types[i]);
		continue;
	    }

	    if (!*ne_values[i])
	    {
		printf("No value provided for Subject Attribute %s, skipped\n", ne_types[i]);
		continue;
	    }

	    /* Note: there must be a bug in X509_NAME_add_entry_by_NID, as using loc=0 turns the subject name */
	    /* into RDN, with improper formatting of the Subject. */
	    /* reason why we insert at the end (-1) and walk the list in reverse order */

	    if (!X509_NAME_add_entry_by_NID(n, nid, chtype, (unsigned char*)ne_values[i], -1, -1,mval[i])) {
		P_ERR();
		goto error;
	    }

	    ++actual_entries;
	}

    }

    if(actual_entries==0) {
	printf("Subject has no valuable field.\n");
	goto error;
    }


    OPENSSL_free(ne_values);
    OPENSSL_free(ne_types);
    OPENSSL_free(buf);
    OPENSSL_free(mval);
    return n;

error:
    X509_NAME_free(n);
    if (ne_values)
	OPENSSL_free(ne_values);
    if (ne_types)
	OPENSSL_free(ne_types);
    if (mval)
	OPENSSL_free(mval);
    if (buf)
	OPENSSL_free(buf);
    return NULL;
}

/* end of grab */
/*------------------------------------------------------------------------*/


int pkcs11_X509_CERT_check_DN(char *subject)
{
    X509_NAME *check;

    if((check = parse_name(subject, MBSTRING_UTF8, 0, 0))==NULL) {
	return 0;
    }

    X509_NAME_free(check);
    return 1;
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

static int add_ext(X509 *cert, int nid, char *value)
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
    if (!ex)
	return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}


/* TODO move this primitive to a separate file (common) */

static const EVP_MD * pkcs11_get_EVP_MD(hash_alg_t hash_alg)
{
    const EVP_MD * rv;
    
    switch(hash_alg) {

    case sha1:
	rv = EVP_sha1();
	break;
	
    case sha224:
	rv = EVP_sha224();
	break;
	
    case sha256:
	rv = EVP_sha256();
	break;
	
    case sha384:
	rv = EVP_sha384();
	break;
	
    case sha512:
	rv = EVP_sha512();
	break;
	
    default:
	rv = NULL;
    }
    return rv;
}


CK_VOID_PTR pkcs11_create_X509_CERT_RSA(pkcs11Context *p11Context,
					char *dn,
					int reverse,
					int days,
					char *san[],
					int sancnt,
					hash_alg_t hash_alg,
					CK_OBJECT_HANDLE hprivkey,
					CK_ATTRIBUTE_PTR ski,
					CK_ATTRIBUTE_PTR modulus,
					CK_ATTRIBUTE_PTR exponent)
{
    X509 *crt = NULL, *retval = NULL;
    EVP_PKEY *pk = NULL;
    RSA *rsa = NULL;
    X509_NAME *name=NULL;
    BIGNUM *bn_modulus = NULL;
    BIGNUM *bn_exponent = NULL;
    BIGNUM *bn_sn = NULL;
    CK_BYTE sn[20];

    if( (rsa=RSA_new()) == NULL ) {
	P_ERR();
	goto err;
    }

    if ((pk=EVP_PKEY_new()) == NULL) {
	P_ERR();
	goto err;
    }

    if ((crt=X509_new()) == NULL) {
	P_ERR();
	goto err;
    }

    /* set version to Certificate */
    if(!X509_set_version(crt,2) ) {
	P_ERR();
	goto err;
    }


    /* 1. first we take care of the public key information */
    if ( (bn_modulus = BN_bin2bn(modulus->pValue, modulus->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }

    if ( (bn_exponent = BN_bin2bn(exponent->pValue, exponent->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }
    RSA_set0_key(rsa, bn_modulus, bn_exponent, NULL);
    bn_modulus = NULL;
    bn_exponent = NULL;

    if (!EVP_PKEY_assign_RSA(pk,rsa)) {
	P_ERR();
	goto err;
    }
    rsa=NULL;	/* forget it, moved to pk */

    if(!X509_set_pubkey(crt,pk)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the pk */

    /* set serial number */
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

    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), (long)60 * 60 * 24 * days);

    /* 2. then we parse subject info */
    if((name = parse_name(dn, MBSTRING_UTF8, 0, reverse))==NULL) {
	P_ERR();
	goto err;
    }

    /* assign to subject name */
    if (!X509_set_subject_name(crt, name)) {
	P_ERR();
	goto err;
    }

    if (!X509_set_issuer_name(crt, name)) {
	P_ERR();
	goto err;
    }

    /* Standard extensions */
    add_ext(crt, NID_basic_constraints, "critical,CA:FALSE");
    add_ext(crt, NID_key_usage, "critical,digitalSignature"); /* we want code-signing */

    /* This is a typical use for request extensions: requesting a value for
     * subject alternative name.
     */
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
	    add_ext(crt, NID_subject_alt_name, sanfield);
	    OPENSSL_free(sanfield);
	}
    }

    if(ski!=NULL) {
	char *value=NULL;

	value=(char *) OPENSSL_malloc( (ski->ulValueLen) * 2  + 1 );
	
	if(value) {
	    int i;

	    value[0]=0;

	    for(i=0; i<ski->ulValueLen; i++) {
		sprintf(&value[i*2], "%02.2x", ((unsigned char *)ski->pValue)[i]);
	    }

	    add_ext(crt, NID_subject_key_identifier, value);
	    add_ext(crt, NID_authority_key_identifier, value); /* if we self-sign, we need this guy also */
	    OPENSSL_free(value);
	}
    }

    pkcs11_rsa_method_setup();
    pkcs11_rsa_method_pkcs11_context(p11Context, hprivkey);

    if(!X509_sign(crt, pk, pkcs11_get_EVP_MD(hash_alg))) {
	P_ERR();
	goto err;
    }
    
    retval = (CK_VOID_PTR)crt;
    crt = NULL;			/* transfer to retval and avoid freeing structure */

err:
    /* cleanup */
    if(name != NULL) { X509_NAME_free(name); name=NULL; }
    if(bn_modulus != NULL) { BN_free(bn_modulus); bn_modulus=NULL; }
    if(bn_exponent != NULL) { BN_free(bn_exponent); bn_exponent=NULL; }
    if(bn_sn != NULL) { BN_free(bn_sn); bn_sn=NULL; }
    if(crt!=NULL) { X509_free(crt); crt=NULL; }
    if(pk!=NULL) { EVP_PKEY_free(pk); pk=NULL; }
    if(rsa!=NULL) { RSA_free(rsa); rsa=NULL; }
    /* memory management */

    return retval;
}


CK_VOID_PTR pkcs11_create_X509_CERT_DSA(pkcs11Context *p11Context,
					char *dn,
					int reverse,
					int days,
					char *san[],
					int sancnt,
					hash_alg_t hash_alg,					
					CK_OBJECT_HANDLE hprivkey,
					CK_ATTRIBUTE_PTR ski,
					CK_ATTRIBUTE_PTR prime,
					CK_ATTRIBUTE_PTR subprime,
					CK_ATTRIBUTE_PTR base,
					CK_ATTRIBUTE_PTR pubkey)
					
{
    X509 *crt = NULL, *retval = NULL;
    EVP_PKEY *pk = NULL;
    DSA *dsa = NULL;
    X509_NAME *name=NULL;
    BIGNUM *bn_prime = NULL;
    BIGNUM *bn_subprime = NULL;
    BIGNUM *bn_base = NULL;
    BIGNUM *bn_pubkey = NULL;
    BIGNUM *bn_sn = NULL;
    CK_BYTE sn[20];

    STACK_OF(X509_EXTENSION) *exts = NULL;


    if( (dsa=DSA_new()) == NULL ) {
	P_ERR();
	goto err;
    }

    if ((pk=EVP_PKEY_new()) == NULL) {
	P_ERR();
	goto err;
    }

    if ((crt=X509_new()) == NULL) {
	P_ERR();
	goto err;
    }

    /* set version to Certificate */
    if(!X509_set_version(crt,2) ) {
	P_ERR();
	goto err;
    }


    /* 1. first we take care of the public key information */
    if ( (bn_prime = BN_bin2bn(prime->pValue, prime->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }

    if ( (bn_subprime = BN_bin2bn(subprime->pValue, subprime->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }

    if ( (bn_base = BN_bin2bn(base->pValue, base->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }

    if ( (bn_pubkey = BN_bin2bn(pubkey->pValue, pubkey->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }

    DSA_set0_pqg(dsa, bn_prime, bn_subprime, bn_base);
    bn_prime = NULL;
    bn_subprime = NULL;
    bn_base = NULL;
    DSA_set0_key(dsa, bn_pubkey, NULL);
    bn_pubkey = NULL;

    if (!EVP_PKEY_assign_DSA(pk,dsa)) {
	P_ERR();
	goto err;
    }
    dsa=NULL;	/* forget it, moved to pk */

    if(!X509_set_pubkey(crt,pk)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the pk */

    /* set serial number */
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

    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), (long)60 * 60 * 24 * days);

    /* 2. then we parse subject info */
    if((name = parse_name(dn, MBSTRING_UTF8, 0, reverse))==NULL) {
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

    /* Standard extenions */
    add_ext(crt, NID_basic_constraints, "critical,CA:FALSE");
    add_ext(crt, NID_key_usage, "critical,digitalSignature"); /* we want code-signing */

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
	    add_ext(crt, NID_subject_alt_name, sanfield);
	    OPENSSL_free(sanfield);
	}

    }

    if(ski!=NULL) {
	char *value=NULL;

	value=(char *) OPENSSL_malloc( (ski->ulValueLen) * 2  + 1 );

	if(value) {
	    int i;

	    value[0]=0;

	    for(i=0; i<ski->ulValueLen; i++) {
		sprintf(&value[i*2], "%02.2x", ((unsigned char *)ski->pValue)[i]);
	    }

	    add_ext(crt, NID_subject_key_identifier, value);
	    add_ext(crt, NID_authority_key_identifier, value); /* if we self-sign, we need this guy also */
	    OPENSSL_free(value);
	}
    }

    pkcs11_dsa_method_setup();
    pkcs11_dsa_method_pkcs11_context(p11Context, hprivkey);

    if(!X509_sign(crt, pk, pkcs11_get_EVP_MD(hash_alg))) {
	P_ERR();
	goto err;
    }
    
    retval = (CK_VOID_PTR)crt;
    crt = NULL;			/* transfer to retval and avoid freeing structure */

err:
    /* cleanup */
    if(name != NULL) { X509_NAME_free(name); name=NULL; }
    if(bn_prime != NULL) { BN_free(bn_prime); bn_prime=NULL; }
    if(bn_subprime != NULL) { BN_free(bn_subprime); bn_subprime=NULL; }
    if(bn_base != NULL) { BN_free(bn_base); bn_base=NULL; }
    if(bn_pubkey != NULL) { BN_free(bn_pubkey); bn_pubkey=NULL; }
    if(bn_sn != NULL) { BN_free(bn_sn); bn_sn=NULL; }
    if(crt!=NULL) { X509_free(crt); crt=NULL; }
    if(pk!=NULL) { EVP_PKEY_free(pk); pk=NULL; }
    if(dsa!=NULL) { DSA_free(dsa); dsa=NULL; }
    /* memory management */

    return retval;
}


CK_VOID_PTR pkcs11_create_X509_CERT_EC(pkcs11Context *p11Context,
				       char *dn,
				       int reverse,
				       int days,
				       char *san[],
				       int sancnt,
				       hash_alg_t hash_alg,					
				       CK_OBJECT_HANDLE hprivkey,
				       CK_ATTRIBUTE_PTR ski,
				       CK_ATTRIBUTE_PTR p_ec_params,
				       CK_ATTRIBUTE_PTR p_ec_point) 
{
    X509 *crt = NULL, *retval = NULL;
    EVP_PKEY *pk = NULL;
    EC_KEY *ec = NULL;
    X509_NAME *name=NULL;
    ASN1_OCTET_STRING *ec_point_container = NULL;
    ECPARAMETERS *ec_parameters = NULL;
    EC_GROUP *ec_group = NULL;
    EC_POINT *ec_point = NULL;
    const unsigned char * pp;
    BIGNUM *bn_sn = NULL;
    CK_BYTE sn[20];
    

    /* create EC key object */
    if( (ec=EC_KEY_new()) == NULL ) {
	P_ERR();
	goto err;
    }

    /* create EC group from curve parameters */
    const unsigned char *ptr = p_ec_params->pValue;
    if( (ec_group = d2i_ECPKParameters(&ec_group, &ptr, p_ec_params->ulValueLen)) == NULL) {
	P_ERR();
	goto err;
    }

    /* create ec_point on the group */
    if( (ec_point=EC_POINT_new(ec_group)) == NULL ) {
	P_ERR();
	goto err;
    }

    if ((pk=EVP_PKEY_new()) == NULL) {
	P_ERR();
	goto err;
    }

    if ((crt=X509_new()) == NULL) {
	P_ERR();
	goto err;
    }

    /* set version to Certificate */
    if(!X509_set_version(crt,2) ) {
	P_ERR();
	goto err;
    }

    /* 1. first we take care of the public key information */

    /* assign group to key */
    if(EC_KEY_set_group(ec, ec_group) == 0) {
      P_ERR();
      goto err;
    }

    /* create point container (OCTET STRING) */
    if( (ec_point_container=ASN1_OCTET_STRING_new()) == NULL ) {
	P_ERR();
	goto err;
    }
    /* extract point value into ASN1_OCTET_STRING structure */
    /* openssl pattern: &pp will be incremented beyond size of DER struct */
    pp = p_ec_point->pValue; /* copy the pointer */
    if(d2i_ASN1_OCTET_STRING(&ec_point_container, &pp, p_ec_point->ulValueLen) == NULL ) {
	P_ERR();
	goto err;
    }

    /* extract point from PKCS#11 attribute */
    /* embedded into ec_point_container     */
    if(EC_POINT_oct2point(ec_group, ec_point, ec_point_container->data, ec_point_container->length, NULL) == 0 ) {
	P_ERR();
	goto err;
    }

    /* assign point to key */
    if( EC_KEY_set_public_key(ec, ec_point) == 0) {
	P_ERR();
	goto err;
    }
    /* TODO: check if ec_point must be freed (is the reference stolen?) */

    /* assign EC key to EVP */
    if (!EVP_PKEY_assign_EC_KEY(pk, ec)) {
      P_ERR();
      goto err;
    }
    ec=NULL;	/* forget it, moved to pk */

    if(!X509_set_pubkey(crt,pk)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the pk */

    /* set serial number */
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

    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), (long)60 * 60 * 24 * days);


    /* 2. then we parse subject info */
    if((name = parse_name(dn, MBSTRING_UTF8, 0, reverse))==NULL) {
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

    /* Standard extensions */
    add_ext(crt, NID_basic_constraints, "critical,CA:FALSE");
    add_ext(crt, NID_key_usage, "critical,digitalSignature"); /* we want code-signing */

    /* This is a typical use for request extensions: requesting a value for
     * subject alternative name.
     */
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
	    add_ext(crt, NID_subject_alt_name, sanfield);
	    OPENSSL_free(sanfield);
	}
    }

    /* on a self-signed cert, AKI and SKI go along. */
    /* that is why we are setting them both.        */
    if(ski!=NULL) {
	char *value=NULL;
	const char keyid_prefix[] = "keyid:";

	value=(char *) OPENSSL_zalloc( (ski->ulValueLen) * 2  + sizeof keyid_prefix + 1 );

	if(value) {
	    int i;

	    strcpy(value, keyid_prefix);
	    
	    for(i=0; i<ski->ulValueLen; i++) {
		sprintf(&value[sizeof keyid_prefix - 1 + i*2], "%02.2x", ((unsigned char *)ski->pValue)[i]);
	    }

	    add_ext(crt, NID_subject_key_identifier, &value[sizeof keyid_prefix - 1]); /* for SKI, we skip the 'keyid:' prefix */
	    add_ext(crt, NID_authority_key_identifier, &value[0]); /* if we self-sign, we need this guy also */
	    OPENSSL_free(value);
	}
    }

    pkcs11_ecdsa_method_setup();
    pkcs11_ecdsa_method_pkcs11_context(p11Context, hprivkey);

    if(!X509_sign(crt, pk, pkcs11_get_EVP_MD(hash_alg))) {
	P_ERR();
	goto err;
    }
    

    retval = (CK_VOID_PTR)crt;
    crt = NULL;			/* transfer to retval and avoid freeing structure */

err:
    /* cleanup */
    if(name != NULL) { X509_NAME_free(name); name=NULL; }
    /* TODO CLEANUP */
    if(ec_parameters!=NULL) { ECPARAMETERS_free(ec_parameters); ec_parameters=NULL; }
    if(ec_point!=NULL) { EC_POINT_free(ec_point); ec_point=NULL; }
    if(ec_group!=NULL) { EC_GROUP_free(ec_group); ec_group=NULL; }
    if(bn_sn != NULL) { BN_free(bn_sn); bn_sn=NULL; }
    if(crt!=NULL) { X509_free(crt); crt=NULL; }
    if(pk!=NULL) { EVP_PKEY_free(pk); pk=NULL; }
    if(ec!=NULL) { EC_KEY_free(ec); ec=NULL; }
    /* memory management */

    return retval;
}


void write_X509_CERT(CK_VOID_PTR crt, char *filename, int verbose)
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
