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
static int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value);


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


int pkcs11_X509_REQ_check_DN(char *subject)
{
    X509_NAME *check;

    if((check = parse_name(subject, MBSTRING_UTF8, 0, 0))==NULL) {
	return 0;
    }

    X509_NAME_free(check);
    return 1;
}

/* end of grab */
/*------------------------------------------------------------------------*/


CK_VOID_PTR pkcs11_create_unsigned_X509_REQ(char *dn, int reverse, char *san[], int sancnt, CK_ATTRIBUTE_PTR ski, CK_ATTRIBUTE_PTR modulus, CK_ATTRIBUTE_PTR exponent)
{
    X509_REQ *req = NULL, *retval = NULL;
    EVP_PKEY *pk = NULL;
    RSA *rsa = NULL;
    X509_NAME *name=NULL;
    BIGNUM *bn_modulus = NULL;
    BIGNUM *bn_exponent = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;


    if( (rsa=RSA_new()) == NULL ) {
	P_ERR();
	goto err;
    }

    if ((pk=EVP_PKEY_new()) == NULL) {
	P_ERR();
	goto err;
    }

    if ((req=X509_REQ_new()) == NULL) {
	P_ERR();
	goto err;
    }

    /* set version to PKCS#10 */
    if(!X509_REQ_set_version(req,0) ) {
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

    if(!X509_REQ_set_pubkey(req,pk)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the pk */

    /* 2. then we parse subject info */
    if((name = parse_name(dn, MBSTRING_UTF8, 0, reverse))==NULL) {
	P_ERR();
	goto err;
    }

    if (!X509_REQ_set_subject_name(req, name)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the name */


    if(sancnt>0 || ski!=NULL) {
	/* 3. and then we fill in extensions */

	/* Certificate requests can contain extensions, which can be used
	 * to indicate the extensions the requestor would like added to
	 * their certificate. CAs might ignore them however or even choke
	 * if they are present.
	 */

	/* For request extensions they are all packed in a single attribute.
	 * We save them in a STACK and add them all at once later...
	 */

	exts = sk_X509_EXTENSION_new_null();

	/* Standard extenions */

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
		add_ext(exts, NID_subject_alt_name, sanfield);
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

		add_ext(exts, NID_subject_key_identifier, value);
		OPENSSL_free(value);
	    }
	}

/* Now we've created the extensions we add them to the request */

	X509_REQ_add_extensions(req, exts);
    }

    retval = (CK_VOID_PTR)req;
    req = NULL;			/* transfer to retval and avoid freeing structure */

err:
    /* cleanup */
    if(exts != NULL) { sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free); exts=NULL; }
    if(name != NULL) { X509_NAME_free(name); name=NULL; }
    if(bn_modulus != NULL) { BN_free(bn_modulus); bn_modulus=NULL; }
    if(bn_exponent != NULL) { BN_free(bn_exponent); bn_exponent=NULL; }
    if(req!=NULL) { X509_REQ_free(req); req=NULL; }
    if(pk!=NULL) { EVP_PKEY_free(pk); pk=NULL; }
    if(rsa!=NULL) { RSA_free(rsa); rsa=NULL; }
    /* memory management */

    return retval;
}


CK_VOID_PTR pkcs11_create_unsigned_X509_REQ_DSA(char *dn, int reverse, char *san[], int sancnt, CK_ATTRIBUTE_PTR ski,
						CK_ATTRIBUTE_PTR prime,
						CK_ATTRIBUTE_PTR subprime,
						CK_ATTRIBUTE_PTR base,
						CK_ATTRIBUTE_PTR pubkey )
{
    X509_REQ *req = NULL, *retval = NULL;
    EVP_PKEY *pk = NULL;
    DSA *dsa = NULL;
    X509_NAME *name=NULL;
    BIGNUM *bn_prime = NULL;
    BIGNUM *bn_subprime = NULL;
    BIGNUM *bn_base = NULL;
    BIGNUM *bn_pubkey = NULL;

    STACK_OF(X509_EXTENSION) *exts = NULL;


    if( (dsa=DSA_new()) == NULL ) {
	P_ERR();
	goto err;
    }

    if ((pk=EVP_PKEY_new()) == NULL) {
	P_ERR();
	goto err;
    }

    if ((req=X509_REQ_new()) == NULL) {
	P_ERR();
	goto err;
    }

    /* set version to PKCS#10 */
    if(!X509_REQ_set_version(req,0) ) {
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

    if(!X509_REQ_set_pubkey(req,pk)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the pk */

    /* 2. then we parse subject info */
    if((name = parse_name(dn, MBSTRING_UTF8, 0, reverse))==NULL) {
	P_ERR();
	goto err;
    }

    if (!X509_REQ_set_subject_name(req, name)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the name */


    if(sancnt>0 || ski!=NULL) {
	/* 3. and then we fill in extensions */

	/* Certificate requests can contain extensions, which can be used
	 * to indicate the extensions the requestor would like added to
	 * their certificate. CAs might ignore them however or even choke
	 * if they are present.
	 */

	/* For request extensions they are all packed in a single attribute.
	 * We save them in a STACK and add them all at once later...
	 */

	exts = sk_X509_EXTENSION_new_null();

	/* Standard extenions */

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
		add_ext(exts, NID_subject_alt_name, sanfield);
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

		add_ext(exts, NID_subject_key_identifier, value);
		OPENSSL_free(value);
	    }
	}

/* Now we've created the extensions we add them to the request */

	X509_REQ_add_extensions(req, exts);
    }

    retval = (CK_VOID_PTR)req;
    req = NULL;			/* transfer to retval and avoid freeing structure */

err:
    /* cleanup */
    if(exts != NULL) { sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free); exts=NULL; }
    if(name != NULL) { X509_NAME_free(name); name=NULL; }
    if(bn_prime != NULL) { BN_free(bn_prime); bn_prime=NULL; }
    if(bn_subprime != NULL) { BN_free(bn_subprime); bn_subprime=NULL; }
    if(bn_base != NULL) { BN_free(bn_base); bn_base=NULL; }
    if(bn_pubkey != NULL) { BN_free(bn_pubkey); bn_pubkey=NULL; }
    if(req!=NULL) { X509_REQ_free(req); req=NULL; }
    if(pk!=NULL) { EVP_PKEY_free(pk); pk=NULL; }
    if(dsa!=NULL) { DSA_free(dsa); dsa=NULL; }
    /* memory management */

    return retval;
}


CK_VOID_PTR pkcs11_create_unsigned_X509_REQ_EC(char *dn, int reverse, char *san[], int sancnt, CK_ATTRIBUTE_PTR ski, char *curvename, CK_ATTRIBUTE_PTR p_ec_point, int *degree)
{
    X509_REQ *req = NULL, *retval = NULL;
    EVP_PKEY *pk = NULL;
    EC_KEY *ec = NULL;
    X509_NAME *name=NULL;
    ASN1_OCTET_STRING *ec_point_container = NULL;
    EC_GROUP *ec_group = NULL;
    EC_POINT *ec_point = NULL;
    const unsigned char * pp;

    ERR_load_crypto_strings();

    STACK_OF(X509_EXTENSION) *exts = NULL;

    if( (ec=EC_KEY_new()) == NULL ) {
	P_ERR();
	goto err;
    }

    if( (ec_group=EC_GROUP_new_by_curve_name( OBJ_sn2nid(curvename)) ) == NULL ) {
	P_ERR();
	goto err;
    }

    /* we want to use OID shortcuts rather than the whole parameters */
    EC_GROUP_set_asn1_flag(ec_group,1);

    /* obtain group degree, aka bit length of public key */
    *degree = EC_GROUP_get_degree(ec_group);
    if(*degree == 0) {
	P_ERR();
	goto err;
    }

    if( (ec_point=EC_POINT_new(ec_group)) == NULL ) {
	P_ERR();
	goto err;
    }

    if ((pk=EVP_PKEY_new()) == NULL) {
	P_ERR();
	goto err;
    }

    if ((req=X509_REQ_new()) == NULL) {
	P_ERR();
	goto err;
    }

    /* set version to PKCS#10 */
    if(!X509_REQ_set_version(req,0) ) {
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

    if(!X509_REQ_set_pubkey(req,pk)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the pk */

    /* 2. then we parse subject info */
    if((name = parse_name(dn, MBSTRING_UTF8, 0, reverse))==NULL) {
	P_ERR();
	goto err;
    }

    if (!X509_REQ_set_subject_name(req, name)) {
	P_ERR();
	goto err;
    }
    /* caution, it does not steal the name */


    if(sancnt>0 || ski!=NULL) {
	/* 3. and then we fill in extensions */

	/* Certificate requests can contain extensions, which can be used
	 * to indicate the extensions the requestor would like added to
	 * their certificate. CAs might ignore them however or even choke
	 * if they are present.
	 */

	/* For request extensions they are all packed in a single attribute.
	 * We save them in a STACK and add them all at once later...
	 */

	exts = sk_X509_EXTENSION_new_null();

	/* Standard extenions */

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
		add_ext(exts, NID_subject_alt_name, sanfield);
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

		add_ext(exts, NID_subject_key_identifier, value);
		OPENSSL_free(value);
	    }
	}

/* Now we've created the extensions we add them to the request */

	X509_REQ_add_extensions(req, exts);
    }

    retval = (CK_VOID_PTR)req;
    req = NULL;			/* transfer to retval and avoid freeing structure */

err:

    /* cleanup */
    if(exts != NULL) { sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free); exts=NULL; }
    if(name != NULL) { X509_NAME_free(name); name=NULL; }
    /* TODO CLEANUP */

    if(req!=NULL) { X509_REQ_free(req); req=NULL; }
    if(pk!=NULL) { EVP_PKEY_free(pk); pk=NULL; }

    if(ec_point!=NULL) { EC_POINT_free(ec_point); ec_point=NULL; }
    if(ec_group!=NULL) { EC_GROUP_free(ec_group); ec_group=NULL; }
    if(ec!=NULL) { EC_KEY_free(ec); ec=NULL; }
    /* memory management */

    return retval;
}



int pkcs11_sign_X509_REQ(pkcs11Context * p11Context, CK_VOID_PTR req, int outputbytes, CK_OBJECT_HANDLE hPrivateKey, CK_MECHANISM_TYPE p_mechtype, int fake)
{
    int retval=0;
    int prehash=0;
    CK_MECHANISM_TYPE prehash_type=0;
    CK_MECHANISM_TYPE mechtype = p_mechtype;

    unsigned char *inbuf = NULL;
    CK_ULONG inlen=0;

    unsigned char *outbuf = NULL;
    CK_ULONG outlen=0;

    unsigned char *hashbuf = NULL;
    CK_ULONG hashlen=0;

    EVP_MD *type;
    int openssl_pkey_type = 0;

    switch( p_mechtype ) {
    case CKM_SHA1_RSA_PKCS:
	type = (EVP_MD *) EVP_sha1();
	break;

    case CKM_SHA224_RSA_PKCS:
	type = (EVP_MD*) EVP_sha224();
	break;

    case CKM_SHA256_RSA_PKCS:
	type = (EVP_MD*) EVP_sha256();
	break;

    case CKM_SHA384_RSA_PKCS:
	type = (EVP_MD*) EVP_sha384();
	break;

    case CKM_SHA512_RSA_PKCS:
	type = (EVP_MD*) EVP_sha512();
	break;


    case CKM_DSA_SHA1:
	type = (EVP_MD*) EVP_sha1();
	openssl_pkey_type = NID_dsaWithSHA1;
	break;

    case CKM_ECDSA_SHA1:
	type = (EVP_MD*) EVP_sha1();
	openssl_pkey_type = NID_ecdsa_with_SHA1;
	break;

    case CKM_ECDSA_SHA224:
	type = (EVP_MD*) EVP_sha224();

	if(pkcs11_is_mech_supported(p11Context, p_mechtype)==CK_FALSE) {
	    mechtype = CKM_ECDSA;
	    prehash  = 1;
	    prehash_type = CKM_SHA224;
	    openssl_pkey_type = NID_ecdsa_with_SHA224;
	}
	break;

    case CKM_ECDSA_SHA256:
	type = (EVP_MD*) EVP_sha256();
	if(pkcs11_is_mech_supported(p11Context, p_mechtype)==CK_FALSE) {
	    mechtype = CKM_ECDSA;
	    prehash  = 1;
	    prehash_type = CKM_SHA256;
	    openssl_pkey_type = NID_ecdsa_with_SHA256;
	}
	break;

    case CKM_ECDSA_SHA384:
	type = (EVP_MD*) EVP_sha384();
	if(pkcs11_is_mech_supported(p11Context, p_mechtype)==CK_FALSE) {
	    mechtype = CKM_ECDSA;
	    prehash  = 1;
	    prehash_type = CKM_SHA384;
	    openssl_pkey_type = NID_ecdsa_with_SHA384;
	}
	break;

    case CKM_ECDSA_SHA512:
	type = (EVP_MD*) EVP_sha512();
	if(pkcs11_is_mech_supported(p11Context, p_mechtype)==CK_FALSE) {
	    mechtype = CKM_ECDSA;
	    prehash  = 1;
	    prehash_type = CKM_SHA512;
	    openssl_pkey_type = NID_ecdsa_with_SHA512;
	}
	break;

    default:
	fprintf(stderr, "Unsupported mechanism for signing, or unsuitable hash algo for signing algorithm.\n");
	goto err;
    }


    X509_ALGOR *a;
    ASN1_BIT_STRING *signature;
    X509_REQ_get0_signature(req, (const ASN1_BIT_STRING **)&signature, (const X509_ALGOR **)&a);

    /* first of all extract stuff to be signed */
    if((inlen = i2d_re_X509_REQ_tbs((X509_REQ*)req, &inbuf))==0) {
	P_ERR();
	goto err;
    }

    /* full signature alg not supported, we need to prehash value */
    if(prehash==1) {
	CK_C_DigestInit pC_DigestInit = p11Context->FunctionList.C_DigestInit;
	CK_C_Digest pC_Digest = p11Context->FunctionList.C_Digest;

	CK_MECHANISM mechanism = { prehash_type, NULL_PTR, 0 };
	CK_RV rv;

	if(fake!=1) {
	    rv = pC_DigestInit(p11Context->Session, &mechanism);
	    if(rv!= CKR_OK) {
		pkcs11_error(rv,"C_DigestInit");
		goto err;
	    }

	    rv = pC_Digest(p11Context->Session, inbuf, inlen, NULL, &hashlen);
	    if(rv!= CKR_OK) {
		pkcs11_error(rv,"C_Digest");
		goto err;
	    }
	}

	hashbuf=(unsigned char *)OPENSSL_malloc((unsigned int)hashlen);
	if(hashbuf==NULL) {
	    P_ERR();
	    goto err;
	}

	if(fake!=1) {
	    rv = pC_Digest(p11Context->Session, inbuf, inlen, hashbuf, &hashlen);
	    if(rv!= CKR_OK) {
		pkcs11_error(rv,"C_Digest");
		goto err;
	    }
	}
    }

    /* then allocate memory for output */

    outlen= outputbytes;
    outbuf=(unsigned char *)OPENSSL_malloc((unsigned int)outlen);

    /* at this point, inbuf contains the stuff to sign. */

    if (fake==1) {
	/* pretend we sign */
	int i;
	unsigned char repeat[] = { '(', 0xc4, 0xbe }; /* this char sequence will print 'KMS' */
						      /* once encoded in base64              */

	for(i=0; i<outlen; i++) {
	    outbuf[i]=repeat[i%sizeof repeat];
	}

    } else {
	/* really sign */
	CK_C_SignInit pC_SignInit = p11Context->FunctionList.C_SignInit;
	CK_C_Sign pC_Sign = p11Context->FunctionList.C_Sign;

	CK_MECHANISM mechanism = { mechtype, NULL_PTR, 0 };
	CK_RV rv;

	rv = pC_SignInit(p11Context->Session, &mechanism, hPrivateKey);

	if (rv == CKR_OK) {
	    rv = pC_Sign(p11Context->Session,
			 prehash==1? hashbuf : inbuf,
			 prehash==1? hashlen : inlen,
			 outbuf,
			 &outlen);

	    if(rv!= CKR_OK) {
		pkcs11_error(rv,"C_Sign");
		goto err;
	    }
	} else {
	    pkcs11_error(rv,"C_SignInit");
	    goto err;
	}
    }

    /* carry-over, modified, from openssl  */

    /* fix req->sig_alg to make it match */
    /* borrowed/inspired by openssl/crypto/asn1/a_sign.c */
    if (EVP_MD_pkey_type(type) == NID_dsaWithSHA1 ||
      openssl_pkey_type == NID_ecdsa_with_SHA1 ||
      openssl_pkey_type == NID_ecdsa_with_SHA224 ||
      openssl_pkey_type == NID_ecdsa_with_SHA256 ||
      openssl_pkey_type == NID_ecdsa_with_SHA384 ||
      openssl_pkey_type == NID_ecdsa_with_SHA512) {
      /* special case: RFC 3279 tells us to omit 'parameters'
       * with id-dsa-with-sha1 and ecdsa-with-SHA1 */
      ASN1_TYPE_free(a->parameter);
      a->parameter = NULL;
    }  else if ((a->parameter == NULL) ||
                (a->parameter->type != V_ASN1_NULL)) {
      ASN1_TYPE_free(a->parameter);
      if ((a->parameter=ASN1_TYPE_new()) == NULL) {
        P_ERR();
        goto err;
      }
      a->parameter->type=V_ASN1_NULL;
    }
    ASN1_OBJECT_free(a->algorithm);
    a->algorithm=OBJ_nid2obj(openssl_pkey_type ? openssl_pkey_type : EVP_MD_pkey_type(type)); /* under openssl, was type->pkey_type */
    if (a->algorithm == NULL)  {
      ASN1err(ASN1_F_ASN1_ITEM_SIGN,ASN1_R_UNKNOWN_OBJECT_TYPE);
	    P_ERR();
      goto err;
    }
    if (OBJ_length(a->algorithm) == 0)  {
      ASN1err(ASN1_F_ASN1_ITEM_SIGN,ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
	    P_ERR();
      goto err;
    }
    /* end of borrow */

    /* free signature->data in case it is already busy */
    if (signature->data != NULL) OPENSSL_free(signature->data);

    switch(p_mechtype)
    {

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:

	/* fix req->signature to contain our stuff  */
	signature->data=outbuf;
	outbuf=NULL;
	signature->length=outlen;
	break;

    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:

	/* excerpt from PKCS11 v2.20 */
/* 12.3.1 EC Signatures */
/* For the purposes of these mechanisms, an ECDSA signature is an octet string of even */
/* length which is at most two times nLen octets, where nLen is the length in octets of the */
/* base point order n. The signature octets correspond to the concatenation of the ECDSA */
/* values r and s, both represented as an octet string of equal length of at most nLen with the */
/* most significant byte first. If r and s have different octet length, the shorter of both must */
/* be padded with leading zero octets such that both have the same octet length. Loosely */
/* spoken, the first half of the signature is r and the second half is s. For signatures created */
/* by a token, the resulting signature is always of length 2nLen. For signatures passed to a */
/* token for verification, the signature may have a shorter length but must be composed as */
/* specified before. */
/* If the length of the hash value is larger than the bit length of n, only the leftmost bits of */
/* the hash up to the length of n will be used. */

/* Note: For applications, it is recommended to encode the signature as an octet string of */
/* length two times nLen if possible. This ensures that the application works with PKCS#11 */
/* modules which have been implemented based on an older version of this document. */
/* Older versions required all signatures to have length two times nLen. It may be */
/* impossible to encode the signature with the maximum length of two times nLen if the */
/* application just gets the integer values of r and s (i.e. without leading zeros), but does not */
/* know the base point order n, because r and s can have any value between zero and the */
/* base point order n. */


	/* first we need to make two bignums */
    {

	ECDSA_SIG *ecsig = ECDSA_SIG_new();
	BIGNUM *sig_r;
	BIGNUM *sig_s;

	int siglen;
	unsigned char *sigder = NULL;

	if(ecsig==NULL) {
	    goto err;
	}
	if((sig_r = BN_new()) == NULL) {
	    goto err;
	}
	if((sig_s = BN_new()) == NULL) {
      goto err;
  }

	if( BN_bin2bn( &outbuf[0], outlen/2, sig_r) == NULL) {
	    P_ERR();
	    goto err;
	}

	if( BN_bin2bn( &outbuf[outlen/2], outlen/2, sig_s) == NULL ) {
	    P_ERR();
	    goto err;
	}
	ECDSA_SIG_set0(ecsig, sig_r, sig_s);


      siglen = i2d_ECDSA_SIG(ecsig, &sigder);
	if(siglen==0) {
	    P_ERR();
	    goto err;
	}

	signature->data=sigder;
	signature->length=siglen;
    }
    break;


    /* DSA_SHA1: same stuff as ECDSA_SHA1 */
    case CKM_DSA_SHA1:
    {

	DSA_SIG *sig = DSA_SIG_new();
	BIGNUM *sig_r;
	BIGNUM *sig_s;

	/*

	   DSA_SIG_new() does not generate r & s bignums
	   as it would with ECDSA_SIG_new().

	   because of this inconsistency, we need to capture bignums
	   as they come from the output of BN_bin2bn.

	 */

	int siglen;
	unsigned char *sigder = NULL;

	if(sig==NULL) {
	    goto err;
	}

	if((sig_r = BN_new()) == NULL) {
      goto err;
  }
  if((sig_s = BN_new()) == NULL) {
      goto err;
  }

	if( BN_bin2bn( &outbuf[0], outlen/2, sig_r) == NULL) {
	    P_ERR();
	    goto err;
	}

	if( BN_bin2bn( &outbuf[outlen/2], outlen/2, sig_s) == NULL ) {
	    P_ERR();
	    goto err;
	}
	DSA_SIG_set0(sig, sig_r, sig_s);

	siglen = i2d_DSA_SIG(sig, &sigder);
	if(siglen==0) {
	    P_ERR();
	    goto err;
	}

	signature->data=sigder;
	signature->length=siglen;
    }
    break;

    }


    /* In the interests of compatibility, I'll make sure that
     * the bit string has a 'not-used bits' value of 0
     */
    signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
    signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;

    retval = 1;

  err:
  /* TODO - proper cleanup */

  if(outbuf) { OPENSSL_free(outbuf); outbuf=NULL; }
  if(inbuf) { OPENSSL_free(inbuf); inbuf=NULL; }
  if(hashbuf) { OPENSSL_free(hashbuf); hashbuf=NULL; }
  return retval;

}



void write_X509_REQ(CK_VOID_PTR req, char *filename, int verbose)
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

    if(filename==NULL) {	/* no file: we write to stdout */
      BIO_set_fp(bio_file, stdout, BIO_NOCLOSE);
    }
    else {			/* write to filename */
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



/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

static int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex)
	return 0;
    sk_X509_EXTENSION_push(sk, ex);

    return 1;
}
