/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2020 Mastercard
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
#include <stdbool.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pkcs11lib.h"

static X509_NAME *parse_name(char *subject, long chtype, bool multirdn, bool reverse);


/*----------------------------------------------------------------------*/
/* grabbed from openssl/apps/apps.c, v1.0.2 and modified                */

/*
 * subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */

/* TODO : fix support for multirdn */

static X509_NAME *parse_name(char *subject, long chtype, bool multirdn, bool reverse)
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

    if( reverse == false ) {
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

inline X509_NAME *pkcs11_DN_new_from_string(char *subject, long chtype, bool multirdn, bool reverse)
{
    return parse_name(subject, chtype, multirdn, reverse);
}

bool pkcs11_X509_check_DN(char *subject)
{
    X509_NAME *check;

    if((check = parse_name(subject, MBSTRING_UTF8, 0, 0))==NULL) {
	return false;
    }

    X509_NAME_free(check);
    return true;
}

const EVP_MD *pkcs11_get_EVP_MD(key_type_t key_type, hash_alg_t hash_alg)
{
    const EVP_MD *rv;

    if(key_type == ed ) {	
	rv = EVP_md_null(); /* PureEdDSA has no pre-hash */
    } else {
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
    }
    return rv;
}

/* create an EVP_PKEY from DER-encoded key information */
/* from an RSA key                                     */
EVP_PKEY *pkcs11_SPKI_from_RSA(pkcs11AttrList *attrlist )
{
    EVP_PKEY *pk = NULL;
    RSA *rsa = NULL;
    BIGNUM *bn_modulus = NULL;
    BIGNUM *bn_exponent = NULL;
    CK_ATTRIBUTE_PTR attr;

    /* do we have everything we need? */
    if( !pkcs11_attrlist_has_attribute(attrlist, CKA_MODULUS) ||
	!pkcs11_attrlist_has_attribute(attrlist, CKA_PUBLIC_EXPONENT)) {
	fprintf(stderr, "Error: missing attributes to create Subject Public Key Information\n");
	goto err;
    }
    
    /* create RSA key object */
    if( (rsa=RSA_new()) == NULL ) {
	P_ERR();
	goto err;
    }

    if ((pk=EVP_PKEY_new()) == NULL) {
	P_ERR();
	goto err;
    }

    attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_MODULUS);
    if(attr == NULL) {
	fprintf(stderr, "Error: missing CKA_MODULUS attribute in key\n");
	goto err;
    }
    
    if ( (bn_modulus = BN_bin2bn(attr->pValue, attr->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }

    attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_PUBLIC_EXPONENT);
    if(attr == NULL) {
	fprintf(stderr, "Error: missing CKA_PUBLIC_EXPONENT attribute in key\n");
	goto err;
    }

    if ( (bn_exponent = BN_bin2bn(attr->pValue, attr->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }

    if(!RSA_set0_key(rsa, bn_modulus, bn_exponent, NULL)) {
	P_ERR();
	goto err;
    }
    bn_modulus = bn_exponent = NULL;

    if (!EVP_PKEY_assign_RSA(pk,rsa)) {
	P_ERR();
	goto err;
    }
    rsa=NULL;	/* forget it, moved to pk */

err:
    if(bn_modulus != NULL) { BN_free(bn_modulus); bn_modulus=NULL; }
    if(bn_exponent != NULL) { BN_free(bn_exponent); bn_exponent=NULL; }
    if(rsa!=NULL) { RSA_free(rsa); rsa=NULL; }
    
    return pk;
}

/* create an EVP_PKEY from DER-encoded key information */
/* from a DSA key                                      */
EVP_PKEY *pkcs11_SPKI_from_DSA(pkcs11AttrList *attrlist )
{
    EVP_PKEY *pk = NULL;
    DSA *dsa = NULL;
    BIGNUM *bn_prime = NULL;
    BIGNUM *bn_subprime = NULL;
    BIGNUM *bn_base = NULL;
    BIGNUM *bn_pubkey = NULL;
    CK_ATTRIBUTE_PTR attr;

    /* do we have everything we need? */
    if( !pkcs11_attrlist_has_attribute(attrlist, CKA_PRIME) ||
	!pkcs11_attrlist_has_attribute(attrlist, CKA_SUBPRIME) ||
	!pkcs11_attrlist_has_attribute(attrlist, CKA_BASE) ||
	!pkcs11_attrlist_has_attribute(attrlist, CKA_VALUE)) {
	fprintf(stderr, "Error: missing attributes to create Subject Public Key Information\n");
	goto err;
    }
    
    /* create DSA key object */
    if( (dsa=DSA_new()) == NULL ) {
	P_ERR();
	goto err;
    }

    if ((pk=EVP_PKEY_new()) == NULL) {
	P_ERR();
	goto err;
    }

    attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_PRIME);
    if(attr == NULL) {
	fprintf(stderr, "Error: missing CKA_PRIME attribute in key\n");
	goto err;
    }

    if ( (bn_prime = BN_bin2bn(attr->pValue, attr->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }

    attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_SUBPRIME);
    if(attr == NULL) {
	fprintf(stderr, "Error: missing CKA_SUBPRIME attribute in key\n");
	goto err;
    }

    if ( (bn_subprime = BN_bin2bn(attr->pValue, attr->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }

    attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_BASE);
    if(attr == NULL) {
	fprintf(stderr, "Error: missing CKA_BASE attribute in key\n");
	goto err;
    }

    if ( (bn_base = BN_bin2bn(attr->pValue, attr->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }
    
    attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_VALUE);
    if(attr == NULL) {
	fprintf(stderr, "Error: missing CKA_VALUE attribute in key\n");
	goto err;
    }

    if ( (bn_pubkey = BN_bin2bn(attr->pValue, attr->ulValueLen, NULL)) == NULL ) {
	P_ERR();
	goto err;
    }

    if(!DSA_set0_pqg(dsa, bn_prime, bn_subprime, bn_base)) {
	P_ERR();
	goto err;
    }
    bn_prime = bn_subprime = bn_base = NULL;

    if(!DSA_set0_key(dsa, bn_pubkey, NULL)) {
	P_ERR();
	goto err;
    }
    bn_pubkey = NULL;

    if (!EVP_PKEY_assign_DSA(pk,dsa)) {
	P_ERR();
	goto err;
    }
    dsa=NULL;	/* forget it, moved to pk */

err:
    if(bn_prime != NULL) { BN_free(bn_prime); bn_prime=NULL; }
    if(bn_subprime != NULL) { BN_free(bn_subprime); bn_subprime=NULL; }
    if(bn_base != NULL) { BN_free(bn_base); bn_base=NULL; }
    if(bn_pubkey != NULL) { BN_free(bn_pubkey); bn_pubkey=NULL; }
    if(dsa!=NULL) { DSA_free(dsa); dsa=NULL; }
    
    return pk;
}

/* create an EVP_PKEY from DER-encoded key information */
EVP_PKEY *pkcs11_SPKI_from_EC(pkcs11AttrList *attrlist )
{
    EVP_PKEY *pk = NULL;
    EC_KEY *ec = NULL;
    ASN1_OCTET_STRING *ec_point_container = NULL;
    ECPARAMETERS *ec_parameters = NULL;
    EC_GROUP *ec_group = NULL;
    EC_POINT *ec_point = NULL;
    CK_ATTRIBUTE_PTR attr;
    const unsigned char *ptr;

    /* do we have everything we need? */
    if( !pkcs11_attrlist_has_attribute(attrlist, CKA_EC_PARAMS) ||
	!pkcs11_attrlist_has_attribute(attrlist, CKA_EC_POINT)) {
	fprintf(stderr, "Error: missing attributes to create Subject Public Key Information\n");
	goto err;
    }
    
    /* create EC key object */
    if( (ec=EC_KEY_new()) == NULL ) {
	P_ERR();
	goto err;
    }

    /* create EC group from curve parameters */
    attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_EC_PARAMS);
    if(attr == NULL) {
	fprintf(stderr, "Error: missing CKA_EC_PARAMS attribute in key\n");
	goto err;
    }
    ptr = attr->pValue;
    
    if( (ec_group = d2i_ECPKParameters(&ec_group, &ptr, attr->ulValueLen)) == NULL) {
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

    /* 1. first we take care of the public key information */

    /* assign group to key */
    if(EC_KEY_set_group(ec, ec_group) == 0) {
      P_ERR();
      goto err;
    }

    /* extract point value into ASN1_OCTET_STRING structure */
    attr = pkcs11_get_attr_in_attrlist(attrlist, CKA_EC_POINT);
    if(attr == NULL) {
	fprintf(stderr, "Error: missing CKA_EC_POINT attribute in key\n");
	goto err;
    }
    ptr = attr->pValue; /* copy the pointer, check OpenSSL d2i & i2d API doc for details */
    
    if(d2i_ASN1_OCTET_STRING(&ec_point_container, &ptr, attr->ulValueLen) == NULL ) {
	/* P_ERR(); */
	fprintf(stderr, "Warning: CKA_EC_POINT format likely not compliant, trying alternate way to decode public key\n");
	/* d2i_TYPE() will NULLify the destination pointer in case of error (??!) */
	/* we need to reset the value */
	if( (ec_point_container=ASN1_OCTET_STRING_new()) == NULL ) {
	    P_ERR();
	    goto err;
	}

	if(ASN1_OCTET_STRING_set(ec_point_container, attr->pValue, attr->ulValueLen) == 0) {
	    P_ERR();
	    goto err;
	}
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

err:
    if(ec) { EC_KEY_free(ec); ec = NULL; }
    if(ec_point_container) { ASN1_OCTET_STRING_free(ec_point_container); ec_point_container = NULL; }
    if(ec_parameters) { ECPARAMETERS_free(ec_parameters); ec_parameters = NULL; }
    if(ec_group) { EC_GROUP_free(ec_group); ec_group = NULL; }
    if(ec_point) { EC_POINT_free(ec_point); ec_point = NULL; }
    
    return pk;
}


/* create an EVP_PKEY from DER-encoded key information */
EVP_PKEY *pkcs11_SPKI_from_ED(pkcs11AttrList *attrlist )
{

    /* Edwards curve are not defined in OpenSSL like any other EC alg  */
    /* More specifically, there is no EC_GROUP() associated            */
    /* therefore these cannot be constructed as regular EC keys        */
    /* The trick is to create an X509_PUBKEY object, then DER-encode   */
    /* and DER-decode into an EVP_PKEY object.                         */
    /* Ugly but works. If anyone has a better idea, please share!      */
		    
    ASN1_OCTET_STRING *ed_point = NULL;
    ASN1_OBJECT * ed_oid = NULL;
    X509_PUBKEY *x509pk = NULL;
    EVP_PKEY *pk = NULL;
    CK_ATTRIBUTE_PTR oecparams = NULL;
    CK_ATTRIBUTE_PTR oecpoint  = NULL;
    uint8_t *output = NULL;
    size_t outputlen = 0;
    const uint8_t * pp ;
		    
    oecparams = pkcs11_get_attr_in_attrlist(attrlist, CKA_EC_PARAMS);
    oecpoint  = pkcs11_get_attr_in_attrlist(attrlist, CKA_EC_POINT);

    if(oecparams==NULL || oecpoint==NULL) {
	fprintf(stderr, "Error: object missing attribute(s) CKA_EC_PARAMS and/or CKA_EC_POINT\n");
	goto key_ed_error;
    }
		    
    /* extract point into octet string */
    pp = oecpoint->pValue;
    if( (ed_point = d2i_ASN1_OCTET_STRING(NULL, &pp, oecpoint->ulValueLen)) == NULL ) {
	P_ERR();
	goto key_ed_error;
    }

    /* extract param into OID */
    /* for Edwards curve, it may come it two flavours: 
     * - as an OID, in which case it will be parsed by d2i_ASN1_OBJECT
     * - as a PrintableString 'edwards25519' or 'edwards448'
     * the later case cannot be converted directly to an OID
     * and is therefore detected upfront.
     */
    pp = oecparams->pValue;
    if(pkcs11_is_ed_param_named_25519(pp, oecparams->ulValueLen)) {
	ed_oid = OBJ_nid2obj(NID_ED25519);
    } else if(pkcs11_is_ed_param_named_448(pp, oecparams->ulValueLen)) {
	ed_oid = OBJ_nid2obj(NID_ED448);
    } else {
	ed_oid = d2i_ASN1_OBJECT(NULL, &pp, oecparams->ulValueLen);
    }
    if( ed_oid == NULL ) {
	P_ERR();
	goto key_ed_error;
    }

    /* create new X509_PUBKEY object and assign point and params */
    if( (x509pk = X509_PUBKEY_new()) ==NULL ) {
	P_ERR();
	goto key_ed_error;
    }

    if(!X509_PUBKEY_set0_param(x509pk, ed_oid, V_ASN1_UNDEF, NULL, ed_point->data, ed_point->length)) {
	P_ERR();
	goto key_ed_error;
    }
    ed_oid = NULL; ed_point = NULL; /* ownership transferred to x509pk */

    /* convert to DER */
    if( (outputlen = i2d_X509_PUBKEY(x509pk, &output)) == 0 ) {
	P_ERR();
	goto key_ed_error;
    }

    /* now the magic: convert that back to an EVP_PKEY object */
    pp = output;
    if( (pk = d2i_PUBKEY(NULL, &pp, outputlen)) == NULL ) {
	P_ERR();
	goto key_ed_error;
    }

key_ed_error:
    if(ed_point) { ASN1_OCTET_STRING_free(ed_point); }
    if(ed_oid) { ASN1_OBJECT_free(ed_oid); }
    if(x509pk) { X509_PUBKEY_free(x509pk); }
    if(output) { OPENSSL_free(output); }
    /* free stuff */

    return pk;
}

/* EOF */
