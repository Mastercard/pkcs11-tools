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

/* pkcs11_pubk.c: module to implement p11importpubk */
/* import of a public key onto a PKCS#11 token      */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <assert.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>

#include "pkcs11lib.h"

/* prototypes */

typedef enum e_pubk_source_type {
    source_file,
    source_buffer
} pubk_source_type;

static int compare_CKA( const void *a, const void *b);
static EVP_PKEY * new_pubk_from_file(char *filename);
static EVP_PKEY * new_pubk_from_buffer(unsigned char *buffer, size_t len);
static CK_ULONG get_RSA_modulus(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_RSA_public_exponent(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_DH_prime(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_DH_base(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_DH_pubkey(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_DSA_prime(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_DSA_subprime(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_DSA_base(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_DSA_pubkey(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_EC_point(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_EC_params(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_ED_point(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_ED_params(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_ULONG get_EVP_PKEY_sha1(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);
static CK_OBJECT_HANDLE _importpubk( pkcs11Context * p11Context,
				     char *filename,
				     unsigned char *buffer,
				     size_t len,
				     char *label,
				     CK_ATTRIBUTE attrs[],
				     CK_ULONG numattrs,
				     pubk_source_type source);


/* comparison function for attributes */
static int compare_CKA( const void *a, const void *b)
{
    return ((CK_ATTRIBUTE_PTR)a)->type == ((CK_ATTRIBUTE_PTR)b)->type ? 0 : -1;
}

/* when importing a key, we want to skip these parameters from template */
static inline bool is_attribute_skipped( const CK_ATTRIBUTE_TYPE attrib)
{
    return attrib==CKA_TOKEN || attrib==CKA_CLASS || attrib==CKA_KEY_TYPE;
}

static EVP_PKEY * new_pubk_from_file(char *filename)
{
    EVP_PKEY * rv = NULL;
    FILE *fp = NULL;

    fp = fopen(filename,"rb"); /* open in binary mode */

    if(fp) {
	EVP_PKEY *pubk;

	/* try DER first */
	pubk = d2i_PUBKEY_fp(fp, NULL);
	fclose(fp);

	if(pubk) {
	    puts("DER format detected");
	    rv = pubk;
	} else {
	    fp = fopen(filename,"r"); /* reopen in text mode */

	    if(fp) {
		pubk = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
		fclose(fp);

		if(pubk) {
		    puts("PEM format detected");
		    rv = pubk;
		}
	    } else {
		perror("Error opening file");
	    }
	}
    } else {
	perror("Error opening file");
    }

    return rv;
}

static EVP_PKEY * new_pubk_from_buffer(unsigned char *buffer, size_t len)
{
    EVP_PKEY * pubk = NULL;

    BIO *mem = BIO_new_mem_buf(buffer, len);

    pubk = d2i_PUBKEY_bio(mem, NULL);

    if(!pubk) {
	perror("Error when parsing public key");
    }

    BIO_free(mem);

    return pubk;
}

/* RSA / DSA / DH common helper: extract a BIGNUM-valued param from an
 * EVP_PKEY of the expected base_id and write its big-endian bytes into
 * a freshly OPENSSL_malloc'd buffer. */
static CK_ULONG bn_param_to_buf(EVP_PKEY *pubkey, const char *param,
				int expected_base_id, CK_BYTE_PTR *buf)
{
    BIGNUM *bn = NULL;
    CK_ULONG rv = 0;

    if (pubkey == NULL || buf == NULL) {
	return 0;
    }
    if (expected_base_id && EVP_PKEY_base_id(pubkey) != expected_base_id) {
	return 0;
    }
    if (pkcs11_pkey_get_bn(pubkey, param, &bn) != 1) {
	P_ERR();
	goto out;
    }
    *buf = OPENSSL_malloc(BN_num_bytes(bn));
    if (*buf == NULL) {
	P_ERR();
	goto out;
    }
    rv = (CK_ULONG)BN_bn2bin(bn, *buf);
    if (rv == 0) {
	P_ERR();
	OPENSSL_free(*buf);
	*buf = NULL;
    }
out:
    if (bn) BN_free(bn);
    return rv;
}


/* RSA */

static CK_ULONG get_RSA_modulus(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    return bn_param_to_buf(pubkey, OSSL_PKEY_PARAM_RSA_N, EVP_PKEY_RSA, buf);
}

static CK_ULONG get_RSA_public_exponent(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    return bn_param_to_buf(pubkey, OSSL_PKEY_PARAM_RSA_E, EVP_PKEY_RSA, buf);
}




/* DH */

static CK_ULONG get_DH_prime(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    return bn_param_to_buf(pubkey, OSSL_PKEY_PARAM_FFC_P, EVP_PKEY_DH, buf);
}


static CK_ULONG get_DH_base(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    return bn_param_to_buf(pubkey, OSSL_PKEY_PARAM_FFC_G, EVP_PKEY_DH, buf);
}

static CK_ULONG get_DH_pubkey(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    return bn_param_to_buf(pubkey, OSSL_PKEY_PARAM_PUB_KEY, EVP_PKEY_DH, buf);
}

/* DSA */

static CK_ULONG get_DSA_prime(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    return bn_param_to_buf(pubkey, OSSL_PKEY_PARAM_FFC_P, EVP_PKEY_DSA, buf);
}

static CK_ULONG get_DSA_subprime(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    return bn_param_to_buf(pubkey, OSSL_PKEY_PARAM_FFC_Q, EVP_PKEY_DSA, buf);
}

static CK_ULONG get_DSA_base(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    return bn_param_to_buf(pubkey, OSSL_PKEY_PARAM_FFC_G, EVP_PKEY_DSA, buf);
}

static CK_ULONG get_DSA_pubkey(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    return bn_param_to_buf(pubkey, OSSL_PKEY_PARAM_PUB_KEY, EVP_PKEY_DSA, buf);
}


/* EC */

static CK_ULONG get_EC_point(EVP_PKEY *pubkey, CK_BYTE_PTR *buf)
{
    CK_ULONG rv = 0;
    unsigned char *raw_point = NULL;
    size_t raw_point_len = 0;
    ASN1_OCTET_STRING *wrapped = NULL;
    int i2dlen;

    if (pubkey == NULL || buf == NULL || EVP_PKEY_base_id(pubkey) != EVP_PKEY_EC) {
	return 0;
    }

    /* OSSL_PKEY_PARAM_PUB_KEY returns the EC public key point in its
       configured conversion form (default: UNCOMPRESSED). This matches
       what PKCS#11 expects inside the CKA_EC_POINT OCTET STRING. */
    if (pkcs11_pkey_get_octets(pubkey, OSSL_PKEY_PARAM_PUB_KEY,
			       &raw_point, &raw_point_len) != 1) {
	P_ERR();
	goto error;
    }

    /* wrap the raw point inside an ASN.1 OCTET STRING (CKA_EC_POINT format) */
    wrapped = ASN1_OCTET_STRING_new();
    if (wrapped == NULL) {
	P_ERR();
	goto error;
    }
    if (ASN1_STRING_set(wrapped, raw_point, raw_point_len) == 0) {
	P_ERR();
	goto error;
    }

    i2dlen = i2d_ASN1_OCTET_STRING(wrapped, NULL);
    if (i2dlen < 0) {
	P_ERR();
	goto error;
    }

    *buf = OPENSSL_malloc(i2dlen);
    if (*buf == NULL) {
	P_ERR();
	goto error;
    }
    {
	CK_BYTE_PTR p = *buf;
	i2dlen = i2d_ASN1_OCTET_STRING(wrapped, &p);
    }
    if (i2dlen < 0) {
	P_ERR();
	OPENSSL_free(*buf);
	*buf = NULL;
	goto error;
    }
    rv = (CK_ULONG)i2dlen;

error:
    if (raw_point) OPENSSL_free(raw_point);
    if (wrapped) ASN1_OCTET_STRING_free(wrapped);
    return rv;
}



static CK_ULONG get_EC_params(EVP_PKEY *pubkey, CK_BYTE_PTR *buf)
{
    unsigned char *der = NULL;
    size_t der_len = 0;
    CK_ULONG rv = 0;

    if (pubkey == NULL || buf == NULL || EVP_PKEY_base_id(pubkey) != EVP_PKEY_EC) {
	return 0;
    }

    if (pkcs11_pkey_write_params_der(pubkey, &der, &der_len) != 1) {
	P_ERR();
	return 0;
    }

    *buf = der;
    rv = (CK_ULONG)der_len;
    return rv;
}

/* get_ED_point is merely a hack                                               */
/* this is because EDWARDS curves are not well supported in OpenSSL            */
/* while there is an EVP interface, there is no low-level PKEY or EC interface */
/* we assume here that only two curves are supported: ED25519 and ED448        */
/* the hack consists of encoding the key, then extract the point based on a    */
/* hardcoded offset. Ugly but works. Any other suggestion welcome.             */
static CK_ULONG get_ED_point(EVP_PKEY *pubkey, CK_BYTE_PTR *buf)
{
    CK_ULONG rv=0;
    uint8_t *pkeybuf = NULL;
    X509_PUBKEY *x509_pk = NULL;
    ASN1_OCTET_STRING *point = NULL;
    const uint8_t *p;
    int len;

    len = i2d_PUBKEY(pubkey, &pkeybuf);
    if(len<0) {
	P_ERR();
	goto error;
    }

    /* trick: convert back to X509_PUBKEY */
    p = pkeybuf;
    x509_pk = d2i_X509_PUBKEY(NULL, &p, len);
    if(!x509_pk) {
	P_ERR();
	goto error;
    }

    const uint8_t *pk;
    int pklen;

    X509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL, x509_pk); /* nothing to test, always returns 1 */

    if( (point = ASN1_OCTET_STRING_new()) == NULL ) {
	P_ERR();
	goto error;
    }
    ASN1_OCTET_STRING_set(point, pk, pklen); /* assign */

    len = i2d_ASN1_OCTET_STRING(point, buf);
    if(len<0) {
	P_ERR();
	goto error;
    }

    rv = len;

error:
    if(point) { ASN1_OCTET_STRING_free(point); }
    if(x509_pk) { X509_PUBKEY_free(x509_pk); }
    if(pkeybuf) { OPENSSL_free(pkeybuf); }
    return rv;
}

static CK_ULONG get_ED_params(EVP_PKEY *pubkey, CK_BYTE_PTR *buf)
{
    CK_ULONG rv = 0;
    ASN1_OBJECT *obj = NULL;

    obj = OBJ_nid2obj(EVP_PKEY_base_id(pubkey));
    if(!obj) {
	P_ERR();
	goto error;
    }

    assert( *buf == NULL );		/* make sure we point to nowhere */
    int len = i2d_ASN1_OBJECT(obj, buf);
    if(len<0) {
	P_ERR();
	goto error;
    }

    rv = len;

error:
    if(obj) { ASN1_OBJECT_free(obj); }
    return rv;
}


/*  get_EVP_PKEY_sha1: will retrieve RSA public key and compute SHA-1 digest
    on modulus, represented as big-endian binary digit,
    with no leading 0x00.
    This is what IBM JCE provider for PKCS#11 uses for setting CKA_ID.

    for DSA and DH, SHA-1 digest of CKA_PUBKEY is used instead.
    for EC, SHA-1 digest of CKA_EC_POINT is used instead (uncompressed form).

*/


/* small helper: SHA-1 of an arbitrary byte buffer into a freshly allocated
   SHA_DIGEST_LENGTH buffer assigned to *buf. Returns SHA_DIGEST_LENGTH on
   success, 0 on failure. Thin wrapper around pkcs11_pkey_sha1_to_buf to
   match the historical CK_ULONG/CK_BYTE_PTR signature used in this file. */
static CK_ULONG sha1_bytes_to_buf(const unsigned char *data, size_t data_len,
				  CK_BYTE_PTR *buf)
{
    unsigned char *out = NULL;
    size_t n;

    if (buf == NULL) {
	return 0;
    }
    n = pkcs11_pkey_sha1_to_buf(data, data_len, &out);
    if (n == 0) {
	P_ERR();
	*buf = NULL;
	return 0;
    }
    *buf = (CK_BYTE_PTR)out;
    return (CK_ULONG)n;
}

static CK_ULONG get_EVP_PKEY_sha1(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {

    CK_ULONG rv = 0;
    if (!pubkey || !buf) {
	return 0;
    }

    switch (EVP_PKEY_base_id(pubkey)) {

    case EVP_PKEY_RSA: {
	/* SHA-1 of the modulus (big-endian, no leading 0x00). */
	BIGNUM *n = NULL;
	unsigned char *bn_buf = NULL;
	int bn_buf_len;

	if (pkcs11_pkey_get_bn(pubkey, OSSL_PKEY_PARAM_RSA_N, &n) != 1) {
	    P_ERR();
	    break;
	}
	bn_buf = OPENSSL_malloc(BN_num_bytes(n));
	if (bn_buf) {
	    bn_buf_len = BN_bn2bin(n, bn_buf);
	    if (bn_buf_len > 0) {
		rv = sha1_bytes_to_buf(bn_buf, (size_t)bn_buf_len, buf);
	    }
	    OPENSSL_free(bn_buf);
	}
	BN_free(n);
    }
	break;

    case EVP_PKEY_DSA: {
	/* SHA-1 of the public value. */
	BIGNUM *pub = NULL;
	unsigned char *bn_buf = NULL;
	int bn_buf_len;

	if (pkcs11_pkey_get_bn(pubkey, OSSL_PKEY_PARAM_PUB_KEY, &pub) != 1) {
	    P_ERR();
	    break;
	}
	bn_buf = OPENSSL_malloc(BN_num_bytes(pub));
	if (bn_buf) {
	    bn_buf_len = BN_bn2bin(pub, bn_buf);
	    if (bn_buf_len > 0) {
		rv = sha1_bytes_to_buf(bn_buf, (size_t)bn_buf_len, buf);
	    }
	    OPENSSL_free(bn_buf);
	}
	BN_free(pub);
    }
	break;

    /* For EC, the SHA-1 input is the OCTET-STRING-wrapped uncompressed point,
       i.e. exactly the byte sequence stored under CKA_EC_POINT. */
    case EVP_PKEY_EC: {
	unsigned char *raw_point = NULL;
	size_t raw_point_len = 0;
	ASN1_OCTET_STRING *wrapped = NULL;
	unsigned char *wrapbuf = NULL;
	int i2dlen;

	if (pkcs11_pkey_get_octets(pubkey, OSSL_PKEY_PARAM_PUB_KEY,
				   &raw_point, &raw_point_len) != 1) {
	    P_ERR();
	    break;
	}

	wrapped = ASN1_OCTET_STRING_new();
	if (wrapped == NULL ||
	    ASN1_STRING_set(wrapped, raw_point, raw_point_len) == 0) {
	    P_ERR();
	    goto ec_cleanup;
	}

	i2dlen = i2d_ASN1_OCTET_STRING(wrapped, NULL);
	if (i2dlen < 0) {
	    P_ERR();
	    goto ec_cleanup;
	}
	wrapbuf = OPENSSL_malloc(i2dlen);
	if (wrapbuf == NULL) {
	    P_ERR();
	    goto ec_cleanup;
	}
	{
	    unsigned char *p = wrapbuf;
	    i2dlen = i2d_ASN1_OCTET_STRING(wrapped, &p);
	}
	if (i2dlen < 0) {
	    P_ERR();
	    goto ec_cleanup;
	}

	rv = sha1_bytes_to_buf(wrapbuf, (size_t)i2dlen, buf);

    ec_cleanup:
	if (wrapbuf) OPENSSL_free(wrapbuf);
	if (wrapped) ASN1_OCTET_STRING_free(wrapped);
	if (raw_point) OPENSSL_free(raw_point);
    }
	break;

    case EVP_PKEY_ED25519:
    case EVP_PKEY_ED448: {
	CK_BYTE_PTR point = NULL;
	CK_ULONG point_len = get_ED_point(pubkey, &point);
	if (point_len > 0) {
	    rv = sha1_bytes_to_buf(point, (size_t)point_len, buf);
	    OPENSSL_free(point);
	}
    }
	break;

    case EVP_PKEY_DH: {
	BIGNUM *pub = NULL;
	unsigned char *bn_buf = NULL;
	int bn_buf_len;

	if (pkcs11_pkey_get_bn(pubkey, OSSL_PKEY_PARAM_PUB_KEY, &pub) != 1) {
	    P_ERR();
	    break;
	}
	bn_buf = OPENSSL_malloc(BN_num_bytes(pub));
	if (bn_buf) {
	    bn_buf_len = BN_bn2bin(pub, bn_buf);
	    if (bn_buf_len > 0) {
		rv = sha1_bytes_to_buf(bn_buf, (size_t)bn_buf_len, buf);
	    }
	    OPENSSL_free(bn_buf);
	}
	BN_free(pub);
    }
	break;

    default:
	break;
    }
    return rv;
}

static CK_OBJECT_HANDLE _importpubk( pkcs11Context * p11Context,
				     char *filename,
				     unsigned char *buffer,
				     size_t len,
				     char *label,
				     CK_ATTRIBUTE attrs[],
				     CK_ULONG numattrs,
				     pubk_source_type source
    )
{

    CK_OBJECT_HANDLE pubkhandle = NULL_PTR;

    CK_RV retCode;
    CK_OBJECT_CLASS pubkClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE pubkType;

    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;

    EVP_PKEY *pubk = NULL;
    size_t i;

    /* When importing a public key, two cases are supported:
     * - importing a public key from `p11importpubk`
     *   in this case, there is a 'default' template that creates useful public keys
     *   that template is then adjusted using attributes given at the command line
     *
     * - importing a public key from `p11unwrap`
     *   in this case, the default template is "pristine", and is adjusted using
     *   what is provided from the wrap file. This is to ensure that no attibute
     *   is enabled by mistake.
     *
     */

    switch(source) {
    case source_file:
	if(!filename) {
	    fprintf(stderr, "***Filename not specified for public key\n");
	    break;
	}
	pubk = new_pubk_from_file(filename);
	break;

    case source_buffer:
	if(!buffer) {
	    fprintf(stderr, "***no buffer provided for public key\n");
	    break;
	}
	pubk = new_pubk_from_buffer(buffer, len);
	break;

    default:
	fprintf(stderr, "***internal error\n");
    };

    if(pubk) {

	switch( EVP_PKEY_base_id(pubk) ) {

	case EVP_PKEY_RSA: {
	    CK_BYTE_PTR pubkey_hash = NULL;
	    CK_ULONG pubkey_hash_len = 0;

	    CK_BYTE_PTR rsa_modulus = NULL;
	    CK_ULONG rsa_modulus_len = 0;

	    CK_BYTE_PTR rsa_public_exponent = NULL;
	    CK_ULONG rsa_public_exponent_len =0;

	    CK_ATTRIBUTE pubktemplate[] = {
		{CKA_CLASS, &pubkClass, sizeof pubkClass},       /* 0  */
		{CKA_KEY_TYPE, &pubkType, sizeof pubkType},      /* 1  */
		{CKA_ID, NULL, 0},				 /* 2  */
		{CKA_LABEL, label, label ? strlen(label) : 0 },	 /* 3  */
		{CKA_ENCRYPT, source == source_file ? &ck_true : &ck_false, sizeof ck_false },	 /* 4  */
		{CKA_WRAP,    source == source_file ? &ck_true : &ck_false, sizeof ck_false },	 /* 5  */
		{CKA_VERIFY,  source == source_file ? &ck_true : &ck_false, sizeof ck_false },	 /* 6  */
		{CKA_TOKEN, &ck_true, sizeof ck_true },		 /* 7  */
		{CKA_MODULUS, NULL, 0 },                         /* 8  */
		{CKA_PUBLIC_EXPONENT, NULL, 0 },                 /* 9 */
		/* leave room for up to 12 additional attributes */
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
	    };

	    size_t pubk_template_len_max = (sizeof(pubktemplate)/sizeof(CK_ATTRIBUTE));
	    size_t pubk_template_len_min = pubk_template_len_max - 12;
	    size_t pubk_num_elems = pubk_template_len_min;

	    pubkType = CKK_RSA;
	    pubkey_hash_len = get_EVP_PKEY_sha1( pubk, &pubkey_hash);

	    rsa_modulus_len = get_RSA_modulus( pubk, &rsa_modulus);
	    rsa_public_exponent_len = get_RSA_public_exponent( pubk, &rsa_public_exponent);

	    if(rsa_modulus_len>0 && rsa_public_exponent_len>0) {

		/* we have everything, let's fill in the template */

		pubktemplate[2].pValue = pubkey_hash; /* CKA_ID */
		pubktemplate[2].ulValueLen = pubkey_hash_len;

		pubktemplate[8].pValue = rsa_modulus;
		pubktemplate[8].ulValueLen = rsa_modulus_len;

		pubktemplate[9].pValue = rsa_public_exponent;
		pubktemplate[9].ulValueLen = rsa_public_exponent_len;

		for(i=0; i<numattrs && pubk_num_elems<pubk_template_len_max; i++)
		{
		    switch(attrs[i].type) {
		    case CKA_LABEL:
		    case CKA_ID:
		    case CKA_ENCRYPT:
		    case CKA_WRAP:
		    case CKA_VERIFY:
		    case CKA_VERIFY_RECOVER: /* not in template onwards */
		    case CKA_DERIVE:
		    case CKA_TRUSTED:
		    case CKA_PRIVATE:
		    case CKA_WRAP_TEMPLATE:
		    case CKA_COPYABLE:
		    case CKA_MODIFIABLE:
		    case CKA_DESTROYABLE:
		    case CKA_START_DATE:
		    case CKA_END_DATE:
		    case CKA_SUBJECT:
		    case CKA_PUBLIC_KEY_INFO:
		    {
			size_t next_pubk_num_elems = pubk_num_elems;

			CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
							  pubktemplate,
							  &next_pubk_num_elems,
							  sizeof(CK_ATTRIBUTE),
							  compare_CKA );

			/* if we have a match and the record was not created by lsearch */
			/* steal the pointer from attrs array. */
			/* It's OK as the template is sitting on the stack, no need */
			/* to dealloc when leaving scope  */
			if(match) {
			    if(next_pubk_num_elems==pubk_num_elems) {
				match->pValue = attrs[i].pValue;           /* copy pointer */
				match->ulValueLen = attrs[i].ulValueLen;   /* adjust length */
			    }
			    else {
				/* everything was copied by lsearch */
				/* just increment array length */
				pubk_num_elems = next_pubk_num_elems;
			    }
			} else {
			    fprintf(stderr, "***Error: can't update attribute array - skipping 0x%08lx\n", attrs[i].type);
			    /* TODO print attribute text */
			}
		    }
		    break;

		    default:
			if(!is_attribute_skipped(attrs[i].type)) {
			    fprintf(stderr, "***Warning: attribute 0x%08lx skipped\n", attrs[i].type);
			    /* pass */
			}
			break;
		    }
		}

		retCode = p11Context->FunctionList.C_CreateObject(p11Context->Session,
								  pubktemplate,
								  pubk_num_elems,
								  &pubkhandle);

		if(retCode!=CKR_OK) {
		    pkcs11_error( retCode, "CreateObject" );
		}

		/* if we are here, we have to free up memory anyway */
	    }

	    if(pubkey_hash) { OPENSSL_free(pubkey_hash); }
	    if(rsa_modulus) { OPENSSL_free(rsa_modulus); }
	    if(rsa_public_exponent) { OPENSSL_free(rsa_public_exponent); }
	}
	    break;

	case EVP_PKEY_DSA: {
	    CK_BYTE_PTR pubkey_hash = NULL;
	    CK_ULONG pubkey_hash_len = 0;

	    CK_BYTE_PTR dsa_prime = NULL;
	    CK_ULONG dsa_prime_len = 0;

	    CK_BYTE_PTR dsa_subprime = NULL;
	    CK_ULONG dsa_subprime_len = 0;

	    CK_BYTE_PTR dsa_base = NULL;
	    CK_ULONG dsa_base_len = 0;

	    CK_BYTE_PTR dsa_pubkey = NULL;
	    CK_ULONG dsa_pubkey_len = 0;


	    CK_ATTRIBUTE pubktemplate[] = {
		{CKA_CLASS, &pubkClass, sizeof pubkClass},           /* 0  */
		{CKA_KEY_TYPE, &pubkType, sizeof pubkType},	     /* 1  */
		{CKA_ID, NULL, 0},				     /* 2  */
		{CKA_LABEL, label, label ? strlen(label) : 0 },	     /* 3  */
		{CKA_VERIFY, source == source_file ? &ck_true : &ck_false, sizeof ck_false }, /* 4  */
		{CKA_TOKEN, &ck_true, sizeof ck_true},		     /* 5  */
		{CKA_PRIME, NULL, 0 },                               /* 6  */
		{CKA_SUBPRIME, NULL, 0 },                            /* 7  */
		{CKA_BASE, NULL, 0 },                                /* 8  */
		{CKA_VALUE, NULL, 0 },                               /* 9  */
		/* leave room for up to 12 additional attributes */
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
	    };

	    size_t pubk_template_len_max = (sizeof(pubktemplate)/sizeof(CK_ATTRIBUTE));
	    size_t pubk_template_len_min = pubk_template_len_max - 12;
	    size_t pubk_num_elems = pubk_template_len_min;

	    pubkType = CKK_DSA;
	    pubkey_hash_len = get_EVP_PKEY_sha1( pubk, &pubkey_hash);

	    dsa_prime_len = get_DSA_prime( pubk, &dsa_prime);          /* p */
	    dsa_subprime_len = get_DSA_subprime( pubk, &dsa_subprime); /* q */
	    dsa_base_len = get_DSA_base( pubk, &dsa_base);             /* g */
	    dsa_pubkey_len = get_DSA_pubkey( pubk, &dsa_pubkey);       /* public key */

	    if( dsa_prime_len > 0 &&
		dsa_subprime_len > 0 &&
		dsa_base_len > 0 &&
		dsa_pubkey_len > 0 ) {

		/* we have everything, let's fill in the template */

		pubktemplate[2].pValue = pubkey_hash; /* CKA_ID */
		pubktemplate[2].ulValueLen = pubkey_hash_len;

		pubktemplate[6].pValue = dsa_prime;
		pubktemplate[6].ulValueLen = dsa_prime_len;

		pubktemplate[7].pValue = dsa_subprime;
		pubktemplate[7].ulValueLen = dsa_subprime_len;

		pubktemplate[8].pValue = dsa_base;
		pubktemplate[8].ulValueLen = dsa_base_len;

		pubktemplate[9].pValue = dsa_pubkey;
		pubktemplate[9].ulValueLen = dsa_pubkey_len;

		for(i=0; i<numattrs && pubk_num_elems<pubk_template_len_max; i++)
		{
		    switch(attrs[i].type) {
		    case CKA_LABEL:
		    case CKA_ID:
		    case CKA_VERIFY:
		    case CKA_VERIFY_RECOVER: /* not in template onwards */
		    case CKA_DERIVE:
		    case CKA_TRUSTED:
		    case CKA_PRIVATE:
		    case CKA_COPYABLE:
		    case CKA_MODIFIABLE:
		    case CKA_DESTROYABLE:
		    case CKA_START_DATE:
		    case CKA_END_DATE:
		    case CKA_SUBJECT:
		    case CKA_PUBLIC_KEY_INFO:
		    {
			size_t next_pubk_num_elems = pubk_num_elems;

			CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
							  pubktemplate,
							  &next_pubk_num_elems,
							  sizeof(CK_ATTRIBUTE),
							  compare_CKA );

			/* if we have a match and the record was not created by lsearch */
			/* steal the pointer from attrs array. */
			/* It's OK as the template is sitting on the stack, no need */
			/* to dealloc when leaving scope  */
			if(match) {
			    if(next_pubk_num_elems==pubk_num_elems) {
				match->pValue = attrs[i].pValue;           /* copy pointer */
				match->ulValueLen = attrs[i].ulValueLen;   /* adjust length */
			    }
			    else {
				/* everything was copied by lsearch */
				/* just increment array length */
				pubk_num_elems = next_pubk_num_elems;
			    }
			} else {
			    fprintf(stderr, "***Error: can't update attribute array - skipping 0x%08lx\n", attrs[i].type);
			    /* TODO print attribute text */
			}
		    }
		    break;

		    default:
			if(!is_attribute_skipped(attrs[i].type)) {
			    fprintf(stderr, "***Warning: attribute 0x%08lx skipped\n", attrs[i].type);
			    /* pass */
			}
			break;
		    }
		}

		retCode = p11Context->FunctionList.C_CreateObject(p11Context->Session,
								  pubktemplate,
								  pubk_num_elems,
								  &pubkhandle);

		pkcs11_error( retCode, "CreateObject" );

		/* if we are here, we have to free up memory anyway */
	    }

	    if(pubkey_hash)  { OPENSSL_free(pubkey_hash); }
	    if(dsa_prime)    { OPENSSL_free(dsa_prime); }
	    if(dsa_subprime) { OPENSSL_free(dsa_subprime); }
	    if(dsa_base)     { OPENSSL_free(dsa_base); }
	    if(dsa_pubkey)   { OPENSSL_free(dsa_pubkey); }

	}
	    break;

	case EVP_PKEY_DH: {
	    CK_BYTE_PTR pubkey_hash = NULL;
	    CK_ULONG pubkey_hash_len = 0;

	    CK_BYTE_PTR dh_prime = NULL;
	    CK_ULONG dh_prime_len = 0;

	    CK_BYTE_PTR dh_base = NULL;
	    CK_ULONG dh_base_len = 0;

	    CK_BYTE_PTR dh_pubkey = NULL;
	    CK_ULONG dh_pubkey_len = 0;

	    CK_ATTRIBUTE pubktemplate[] = {
		{CKA_CLASS, &pubkClass, sizeof pubkClass},           /* 0  */
		{CKA_KEY_TYPE, &pubkType, sizeof pubkType},	     /* 1  */
		{CKA_ID, NULL, 0},				     /* 2  */
		{CKA_LABEL, label, label ? strlen(label) : 0 },	     /* 3  */
		{CKA_DERIVE, source == source_file ? &ck_true : &ck_false, sizeof ck_false }, /* 4  */
		{CKA_TOKEN, &ck_true, sizeof ck_true},		     /* 5  */
		{CKA_PRIME, NULL, 0 },                               /* 6  */
		{CKA_BASE, NULL, 0 },                                /* 7  */
		{CKA_VALUE, NULL, 0 },                               /* 8  */
		/* leave room for up to 12 additional attributes */
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
	    };

	    size_t pubk_template_len_max = (sizeof(pubktemplate)/sizeof(CK_ATTRIBUTE));
	    size_t pubk_template_len_min = pubk_template_len_max - 12;
	    size_t pubk_num_elems = pubk_template_len_min;

	    pubkType = CKK_DH;
	    pubkey_hash_len = get_EVP_PKEY_sha1( pubk, &pubkey_hash);

	    dh_prime_len = get_DH_prime( pubk, &dh_prime);          /* p */
	    dh_base_len = get_DH_base( pubk, &dh_base);             /* g */
	    dh_pubkey_len = get_DH_pubkey( pubk, &dh_pubkey);       /* public key */

	    if( dh_prime_len > 0 &&
		dh_base_len > 0 &&
		dh_pubkey_len > 0 ) {

		/* we have everything, let's fill in the template */

		pubktemplate[2].pValue = pubkey_hash; /* CKA_ID */
		pubktemplate[2].ulValueLen = pubkey_hash_len;

		pubktemplate[6].pValue = dh_prime;
		pubktemplate[6].ulValueLen = dh_prime_len;

		pubktemplate[7].pValue = dh_base;
		pubktemplate[7].ulValueLen = dh_base_len;

		pubktemplate[8].pValue = dh_pubkey;
		pubktemplate[8].ulValueLen = dh_pubkey_len;

		for(i=0; i<numattrs && pubk_num_elems<pubk_template_len_max; i++)
		{
		    switch(attrs[i].type) {
		    case CKA_LABEL:
		    case CKA_ID:
		    case CKA_DERIVE:
		    case CKA_TRUSTED: /* not in template onwards */
		    case CKA_PRIVATE:
		    case CKA_COPYABLE:
		    case CKA_MODIFIABLE:
		    case CKA_DESTROYABLE:
		    case CKA_START_DATE:
		    case CKA_END_DATE:
		    case CKA_SUBJECT:
		    case CKA_PUBLIC_KEY_INFO:
		    {
			size_t next_pubk_num_elems = pubk_num_elems;

			CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
							  pubktemplate,
							  &next_pubk_num_elems,
							  sizeof(CK_ATTRIBUTE),
							  compare_CKA );

			/* if we have a match and the record was not created by lsearch */
			/* steal the pointer from attrs array. */
			/* It's OK as the template is sitting on the stack, no need */
			/* to dealloc when leaving scope  */
			if(match) {
			    if(next_pubk_num_elems==pubk_num_elems) {
				match->pValue = attrs[i].pValue;           /* copy pointer */
				match->ulValueLen = attrs[i].ulValueLen;   /* adjust length */
			    }
			    else {
				/* everything was copied by lsearch */
				/* just increment array length */
				pubk_num_elems = next_pubk_num_elems;
			    }
			} else {
			    fprintf(stderr, "***Error: can't update attribute array - skipping 0x%08lx\n", attrs[i].type);
			    /* TODO print attribute text */
			}
		    }
		    break;

		    default:
			if(!is_attribute_skipped(attrs[i].type)) {
			    fprintf(stderr, "***Warning: attribute 0x%08lx skipped\n", attrs[i].type);
			    /* pass */
			}
			break;
		    }
		}

		retCode = p11Context->FunctionList.C_CreateObject(p11Context->Session,
								  pubktemplate,
								  pubk_num_elems,
								  &pubkhandle);

		pkcs11_error( retCode, "CreateObject" );

		/* if we are here, we have to free up memory anyway */
	    }

	    if(pubkey_hash)  { OPENSSL_free(pubkey_hash); }
	    if(dh_prime)    { OPENSSL_free(dh_prime); }
	    if(dh_base)     { OPENSSL_free(dh_base); }
	    if(dh_pubkey)   { OPENSSL_free(dh_pubkey); }
	}
	    break;

	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448: {
	    CK_BYTE_PTR pubkey_hash = NULL;
	    CK_ULONG pubkey_hash_len = 0;

	    CK_BYTE_PTR ec_params = NULL;
	    CK_ULONG ec_params_len = 0;

	    CK_BYTE_PTR ec_point = NULL;
	    CK_ULONG ec_point_len = 0;

	    CK_ATTRIBUTE pubktemplate[] = {
		{CKA_CLASS, &pubkClass, sizeof pubkClass },          /* 0  */
		{CKA_KEY_TYPE, &pubkType, sizeof pubkType},	     /* 1  */
		{CKA_ID, NULL, 0},				     /* 2  */
		{CKA_LABEL, label, label ? strlen(label) : 0 },	     /* 3  */
		{CKA_VERIFY, source == source_file ? &ck_true : &ck_false, sizeof ck_false }, /* 4  */
		{CKA_TOKEN, &ck_true, sizeof ck_true},		     /* 5  */
		{CKA_EC_PARAMS, NULL, 0 },                           /* 6  */
		{CKA_EC_POINT, NULL, 0 },                            /* 7  */
		/* leave room for up to 12 additional attributes */
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
	    };

	    size_t pubk_template_len_max = (sizeof(pubktemplate)/sizeof(CK_ATTRIBUTE));
	    size_t pubk_template_len_min = pubk_template_len_max - 12;
	    size_t pubk_num_elems = pubk_template_len_min;

	    pubkType = CKK_EC_EDWARDS;
	    pubkey_hash_len = get_EVP_PKEY_sha1( pubk, &pubkey_hash);

	    ec_params_len = get_ED_params( pubk, &ec_params);           /* curve parameters */
	    ec_point_len  = get_ED_point( pubk, &ec_point);             /* curve point */

	    if( ec_params_len > 0 && ec_point_len > 0 ) {

		/* we have everything, let's fill in the template */

		pubktemplate[2].pValue = pubkey_hash; /* CKA_ID */
		pubktemplate[2].ulValueLen = pubkey_hash_len;

		pubktemplate[6].pValue = ec_params;
		pubktemplate[6].ulValueLen = ec_params_len;

		pubktemplate[7].pValue = ec_point;
		pubktemplate[7].ulValueLen = ec_point_len;

		for(i=0; i<numattrs && pubk_num_elems<pubk_template_len_max; i++)
		{
		    switch(attrs[i].type) {
		    case CKA_LABEL:
		    case CKA_ID:
		    case CKA_VERIFY:
		    case CKA_VERIFY_RECOVER: /* not in template onwards */
		    case CKA_DERIVE:
		    case CKA_TRUSTED:
		    case CKA_PRIVATE:
		    case CKA_COPYABLE:
		    case CKA_MODIFIABLE:
		    case CKA_DESTROYABLE:
		    case CKA_START_DATE:
		    case CKA_END_DATE:
		    case CKA_SUBJECT:
		    case CKA_PUBLIC_KEY_INFO:
		    {
			size_t next_pubk_num_elems = pubk_num_elems;

			CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
							  pubktemplate,
							  &next_pubk_num_elems,
							  sizeof(CK_ATTRIBUTE),
							  compare_CKA );

			/* if we have a match and the record was not created by lsearch */
			/* steal the pointer from attrs array. */
			/* It's OK as the template is sitting on the stack, no need */
			/* to dealloc when leaving scope  */
			if(match) {
			    if(next_pubk_num_elems==pubk_num_elems) {
				match->pValue = attrs[i].pValue;           /* copy pointer */
				match->ulValueLen = attrs[i].ulValueLen;   /* adjust length */
			    }
			    else {
				/* everything was copied by lsearch */
				/* just increment array length */
				pubk_num_elems = next_pubk_num_elems;
			    }
			} else {
			    fprintf(stderr, "***Error: can't update attribute array - skipping 0x%08lx\n", attrs[i].type);
			    /* TODO print attribute text */
			}
		    }
		    break;

		    default:
			if(!is_attribute_skipped(attrs[i].type)) {
			    fprintf(stderr, "***Warning: attribute 0x%08lx skipped\n", attrs[i].type);
			    /* pass */
			}
			break;
		    }
		}

		retCode = p11Context->FunctionList.C_CreateObject(p11Context->Session,
								  pubktemplate,
								  pubk_num_elems,
								  &pubkhandle);

		if(retCode != CKR_OK) {
		    pkcs11_error( retCode, "CreateObject" );
		}

		/* if we are here, we have to free up memory anyway */
	    }

	    if(pubkey_hash)  { OPENSSL_free(pubkey_hash); }
	    if(ec_params)    { OPENSSL_free(ec_params); }
	    if(ec_point)     { OPENSSL_free(ec_point); }
	}
	    break;

	case EVP_PKEY_EC: {
	    CK_BYTE_PTR pubkey_hash = NULL;
	    CK_ULONG pubkey_hash_len = 0;

	    CK_BYTE_PTR ec_params = NULL;
	    CK_ULONG ec_params_len = 0;

	    CK_BYTE_PTR ec_point = NULL;
	    CK_ULONG ec_point_len = 0;

	    CK_ATTRIBUTE pubktemplate[] = {
		{CKA_CLASS, &pubkClass, sizeof pubkClass },          /* 0  */
		{CKA_KEY_TYPE, &pubkType, sizeof pubkType},	     /* 1  */
		{CKA_ID, NULL, 0},				     /* 2  */
		{CKA_LABEL, label, label ? strlen(label) : 0 },	     /* 3  */
		{CKA_VERIFY, source == source_file ? &ck_true : &ck_false, sizeof ck_false}, /* 4  */
		{CKA_TOKEN, &ck_true, sizeof ck_true},		     /* 5  */
		{CKA_EC_PARAMS, NULL, 0 },                           /* 6  */
		{CKA_EC_POINT, NULL, 0 },                            /* 7  */
		/* leave room for up to 12 additional attributes */
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
		{0L, NULL, 0L},
	    };

	    size_t pubk_template_len_max = (sizeof(pubktemplate)/sizeof(CK_ATTRIBUTE));
	    size_t pubk_template_len_min = pubk_template_len_max - 12;
	    size_t pubk_num_elems = pubk_template_len_min;

	    pubkType = CKK_EC;
	    pubkey_hash_len = get_EVP_PKEY_sha1( pubk, &pubkey_hash);

	    ec_params_len = get_EC_params( pubk, &ec_params);           /* curve parameters */
	    ec_point_len  = get_EC_point( pubk, &ec_point);             /* curve point */

	    if( ec_params_len > 0 &&
		ec_point_len > 0 ) {

		/* we have everything, let's fill in the template */

		pubktemplate[2].pValue = pubkey_hash; /* CKA_ID */
		pubktemplate[2].ulValueLen = pubkey_hash_len;

		pubktemplate[6].pValue = ec_params;
		pubktemplate[6].ulValueLen = ec_params_len;

		pubktemplate[7].pValue = ec_point;
		pubktemplate[7].ulValueLen = ec_point_len;

		for(i=0; i<numattrs && pubk_num_elems<pubk_template_len_max; i++)
		{
		    switch(attrs[i].type) {
		    case CKA_LABEL:
		    case CKA_ID:
		    case CKA_WRAP:
		    case CKA_VERIFY:
		    case CKA_VERIFY_RECOVER: /* not in template onwards */
		    case CKA_DERIVE:
		    case CKA_TRUSTED:
		    case CKA_PRIVATE:
		    case CKA_WRAP_TEMPLATE:
		    case CKA_COPYABLE:
		    case CKA_MODIFIABLE:
		    case CKA_DESTROYABLE:
		    case CKA_START_DATE:
		    case CKA_END_DATE:
		    case CKA_SUBJECT:
		    case CKA_PUBLIC_KEY_INFO:
		    {
			size_t next_pubk_num_elems = pubk_num_elems;

			CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
							  pubktemplate,
							  &next_pubk_num_elems,
							  sizeof(CK_ATTRIBUTE),
							  compare_CKA );

			/* if we have a match and the record was not created by lsearch */
			/* steal the pointer from attrs array. */
			/* It's OK as the template is sitting on the stack, no need */
			/* to dealloc when leaving scope  */
			if(match) {
			    if(next_pubk_num_elems==pubk_num_elems) {
				match->pValue = attrs[i].pValue;           /* copy pointer */
				match->ulValueLen = attrs[i].ulValueLen;   /* adjust length */
			    }
			    else {
				/* everything was copied by lsearch */
				/* just increment array length */
				pubk_num_elems = next_pubk_num_elems;
			    }
			} else {
			    fprintf(stderr, "***Error: can't update attribute array - skipping 0x%08lx\n", attrs[i].type);
			    /* TODO print attribute text */
			}
		    }
		    break;

		    default:
			if(!is_attribute_skipped(attrs[i].type)) {
			    fprintf(stderr, "***Warning: attribute 0x%08lx skipped\n", attrs[i].type);
			    /* pass */
			}
			break;
		    }
		}

		retCode = p11Context->FunctionList.C_CreateObject(p11Context->Session,
								  pubktemplate,
								  pubk_num_elems,
								  &pubkhandle);

		if(retCode != CKR_OK) {
		    pkcs11_error( retCode, "CreateObject" );
		}

		/* if we are here, we have to free up memory anyway */
	    }

	    if(pubkey_hash)  { OPENSSL_free(pubkey_hash); }
	    if(ec_params)    { OPENSSL_free(ec_params); }
	    if(ec_point)     { OPENSSL_free(ec_point); }
	}
	    break;

	default:
	    fprintf(stderr, "***ERROR - public key type not supported\n");
	    break;
	}

	EVP_PKEY_free(pubk);

    }
    return pubkhandle;
}

/* public interface */

inline CK_ULONG pkcs11_new_SKI_value_from_pubk(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    return get_EVP_PKEY_sha1(pubkey, buf);
}


inline CK_OBJECT_HANDLE pkcs11_importpubk( pkcs11Context * p11Context,
					   char *filename,
					   char *label,
					   CK_ATTRIBUTE attrs[],
					   CK_ULONG numattrs ) {
    return _importpubk(p11Context, filename, NULL, 0, label, attrs, numattrs, source_file);
}

inline CK_OBJECT_HANDLE pkcs11_importpubk_from_buffer( pkcs11Context * p11Context,
						       unsigned char *buffer,
						       size_t len,
						       char *label,
						       CK_ATTRIBUTE attrs[],
						       CK_ULONG numattrs ) {
    return _importpubk(p11Context, NULL, buffer, len, label, attrs, numattrs, source_buffer);
}
