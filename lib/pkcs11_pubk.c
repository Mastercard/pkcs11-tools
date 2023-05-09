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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>

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

/* RSA */

static CK_ULONG get_RSA_modulus(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    CK_ULONG rv = 0;

    if (pubkey && EVP_PKEY_base_id(pubkey) == EVP_PKEY_RSA) {
	RSA *rsa = EVP_PKEY_get0_RSA(pubkey);
	const BIGNUM *rsa_n;
	CK_BYTE_PTR p = NULL;

	if (rsa == NULL) {
	    P_ERR();
	    goto error;
	}
	RSA_get0_key(rsa, &rsa_n, NULL, NULL);
	p = *buf = OPENSSL_malloc(BN_num_bytes(rsa_n));

	if (*buf == NULL) {
	    P_ERR();
	    goto error;
	}

	rv = BN_bn2bin(rsa_n, p);

	/* if we fail here, we would free up requested memory */
	if (rv == 0) {
	    OPENSSL_free(*buf);
	    P_ERR();
	    goto error;
	}
    }
error:
    return rv;
}

static CK_ULONG get_RSA_public_exponent(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    CK_ULONG rv = 0;

    if (pubkey && EVP_PKEY_base_id(pubkey) == EVP_PKEY_RSA) {
	RSA *rsa = EVP_PKEY_get0_RSA(pubkey);
	const BIGNUM *rsa_e;
	CK_BYTE_PTR p = NULL;

	if (rsa == NULL) {
	    P_ERR();
	    goto error;
	}
	RSA_get0_key(rsa, NULL, &rsa_e, NULL);
	p = *buf = OPENSSL_malloc(BN_num_bytes(rsa_e));

	if (*buf == NULL) {
	    P_ERR();
	    goto error;
	}

	rv = BN_bn2bin(rsa_e, p);

	/* if we fail here, we would free up requested memory */
	if (rv == 0) {
	    OPENSSL_free(*buf);
	    P_ERR();
	    goto error;
	}
    }
error:
    return rv;
}




/* DH */

static CK_ULONG get_DH_prime(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    CK_ULONG rv = 0;

    if (pubkey && EVP_PKEY_base_id(pubkey) == EVP_PKEY_DH) {
	DH *dh = EVP_PKEY_get0_DH(pubkey);
	const BIGNUM *dh_p;
	CK_BYTE_PTR p = NULL;

	if (dh == NULL) {
	    P_ERR();
	    goto error;
	}
	DH_get0_pqg(dh, &dh_p, NULL, NULL);
	p = *buf = OPENSSL_malloc(BN_num_bytes(dh_p));

	if (*buf == NULL) {
	    P_ERR();
	    goto error;
	}

	rv = BN_bn2bin(dh_p, p);

	/* if we fail here, we would free up requested memory */
	if (rv == 0) {
	    OPENSSL_free(*buf);
	    P_ERR();
	    goto error;
	}
    }
error:
    return rv;
}


static CK_ULONG get_DH_base(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    CK_ULONG rv = 0;

    if (pubkey && EVP_PKEY_base_id(pubkey) == EVP_PKEY_DH) {
	DH *dh = EVP_PKEY_get0_DH(pubkey);
	const BIGNUM *dh_g;
	CK_BYTE_PTR p = NULL;

	if (dh == NULL) {
	    P_ERR();
	    goto error;
	}
	DH_get0_pqg(dh, NULL, NULL, &dh_g);
	p = *buf = OPENSSL_malloc(BN_num_bytes(dh_g));

	if (*buf == NULL) {
	    P_ERR();
	    goto error;
	}

	rv = BN_bn2bin(dh_g, p);

	/* if we fail here, we would free up requested memory */
	if (rv == 0) {
	    OPENSSL_free(*buf);
	    P_ERR();
	    goto error;
	}
    }
error:
    return rv;
}

static CK_ULONG get_DH_pubkey(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    CK_ULONG rv = 0;

    if (pubkey && EVP_PKEY_base_id(pubkey) == EVP_PKEY_DH) {
	DH *dh = EVP_PKEY_get0_DH(pubkey);
	const BIGNUM *dh_pub;
	CK_BYTE_PTR p = NULL;

	if (dh == NULL) {
	    P_ERR();
	    goto error;
	}
	DH_get0_key(dh, &dh_pub, NULL);
	p = *buf = OPENSSL_malloc(BN_num_bytes(dh_pub));

	if (*buf == NULL) {
	    P_ERR();
	    goto error;
	}

	rv = BN_bn2bin(dh_pub, p);

	/* if we fail here, we would free up requested memory */
	if (rv == 0) {
	    OPENSSL_free(*buf);
	    P_ERR();
	    goto error;
	}
    }
error:
    return rv;
}

/* DSA */

static CK_ULONG get_DSA_prime(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    CK_ULONG rv = 0;

    if (pubkey && EVP_PKEY_base_id(pubkey) == EVP_PKEY_DSA) {
	DSA *dsa = EVP_PKEY_get0_DSA(pubkey);
	const BIGNUM *dsa_p;
	CK_BYTE_PTR p = NULL;

	if (dsa == NULL) {
	    P_ERR();
	    goto error;
	}
	DSA_get0_pqg(dsa, &dsa_p, NULL, NULL);
	p = *buf = OPENSSL_malloc(BN_num_bytes(dsa_p));

	if (*buf == NULL) {
	    P_ERR();
	    goto error;
	}

	rv = BN_bn2bin(dsa_p, p);

	/* if we fail here, we would free up requested memory */
	if (rv == 0) {
	    OPENSSL_free(*buf);
	    P_ERR();
	    goto error;
	}
    }
error:
    return rv;
}

static CK_ULONG get_DSA_subprime(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    CK_ULONG rv = 0;

    if (pubkey && EVP_PKEY_base_id(pubkey) == EVP_PKEY_DSA) {
	DSA *dsa = EVP_PKEY_get0_DSA(pubkey);
	const BIGNUM *dsa_q;
	CK_BYTE_PTR p = NULL;

	if (dsa == NULL) {
	    P_ERR();
	    goto error;
	}
	DSA_get0_pqg(dsa, NULL, &dsa_q, NULL);
	p = *buf = OPENSSL_malloc(BN_num_bytes(dsa_q));

	if (*buf == NULL) {
	    P_ERR();
	    goto error;
	}

	rv = BN_bn2bin(dsa_q, p);

	/* if we fail here, we would free up requested memory */
	if (rv == 0) {
	    OPENSSL_free(*buf);
	    P_ERR();
	    goto error;
	}
    }
error:
    return rv;
}

static CK_ULONG get_DSA_base(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    CK_ULONG rv = 0;

    if (pubkey && EVP_PKEY_base_id(pubkey) == EVP_PKEY_DSA) {
	DSA *dsa = EVP_PKEY_get0_DSA(pubkey);
	const BIGNUM *dsa_g;
	CK_BYTE_PTR p = NULL;

	if (dsa == NULL) {
	    P_ERR();
	    goto error;
	}
	DSA_get0_pqg(dsa, NULL, NULL, &dsa_g);
	p = *buf = OPENSSL_malloc(BN_num_bytes(dsa_g));

	if (*buf == NULL) {
	    P_ERR();
	    goto error;
	}

	rv = BN_bn2bin(dsa_g, p);

	/* if we fail here, we would free up requested memory */
	if (rv == 0) {
	    OPENSSL_free(*buf);
	    P_ERR();
	    goto error;
	}
    }
error:
    return rv;
}

static CK_ULONG get_DSA_pubkey(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {
    CK_ULONG rv = 0;

    if (pubkey && EVP_PKEY_base_id(pubkey) == EVP_PKEY_DSA) {
	DSA *dsa = EVP_PKEY_get0_DSA(pubkey);
	const BIGNUM *dsa_pubkey;
	CK_BYTE_PTR p = NULL;

	if (dsa == NULL) {
	    P_ERR();
	    goto error;
	}
	DSA_get0_key(dsa, &dsa_pubkey, NULL);
	p = *buf = OPENSSL_malloc(BN_num_bytes(dsa_pubkey));

	if (*buf == NULL) {
	    P_ERR();
	    goto error;
	}

	rv = BN_bn2bin(dsa_pubkey, p);

	/* if we fail here, we would free up requested memory */
	if (rv == 0) {
	    OPENSSL_free(*buf);
	    P_ERR();
	    goto error;
	}
    }
error:
    return rv;
}


/* EC */

static CK_ULONG get_EC_point(EVP_PKEY *pubkey, CK_BYTE_PTR *buf)
{
    CK_ULONG rv=0;
    EC_KEY* ec=NULL;
    int i2dlen=0;
    unsigned char *octp = NULL, *octbuf = NULL;
    ASN1_OCTET_STRING *wrapped = NULL;

    if ( pubkey && EVP_PKEY_base_id(pubkey)==EVP_PKEY_EC  ) {

	ec = EVP_PKEY_get0_EC_KEY(pubkey);

	if(ec==NULL) {
	    P_ERR();
	    goto error;
	}

	const EC_POINT *ec_point = EC_KEY_get0_public_key(ec);
	/* get0 means no ref counter is incremented */

	if(ec_point==NULL) {
	    P_ERR();
	    goto error;
	}

	const EC_GROUP *ec_group = EC_KEY_get0_group(ec);
	/* get0 means no ref counter is incremented */

	if(ec_group==NULL) {
	    P_ERR();
	    goto error;
	}

	size_t octbuflen = EC_POINT_point2oct(ec_group, ec_point,
					      POINT_CONVERSION_UNCOMPRESSED,
					      NULL, 0, NULL);

	if(octbuflen==0) {
	    P_ERR();
	    goto error;
	}

	octp = octbuf = OPENSSL_malloc( octbuflen );

	if(octbuf==NULL) {
	    P_ERR();
	    goto error;
	}

	rv = (CK_ULONG) EC_POINT_point2oct(ec_group, ec_point,
					   POINT_CONVERSION_UNCOMPRESSED,
					   octp, octbuflen, NULL);

	if(rv==0) {
	    P_ERR();
	    OPENSSL_free(buf);
	    goto error;
	}

	/* DER-encoded of point in octbuf  */
	/* now wrap this into OCTET_STRING */

	wrapped = ASN1_OCTET_STRING_new();

	if(wrapped==NULL) {
	    P_ERR();
	    goto error;
	}

	if( ASN1_STRING_set(wrapped, octbuf, octbuflen) == 0 ) {
	    P_ERR();
	    goto error;
	}

	/* wrapped contains the data we need to set into buf */

	i2dlen = i2d_ASN1_OCTET_STRING(wrapped, NULL);

	if(i2dlen<0) {
	    P_ERR();
	    goto error;
	}

	CK_BYTE_PTR p = NULL;

	*buf = OPENSSL_malloc(i2dlen);

	if(*buf==NULL) {
	    P_ERR();
	    goto error;
	}

	p = *buf;

	i2dlen = i2d_ASN1_OCTET_STRING(wrapped, &p);

	if(i2dlen<0) {
	    P_ERR();
	    goto error;
	}

	rv = i2dlen;
    }
error:
    if(octbuf != NULL) { OPENSSL_free(octbuf); }
    if(wrapped != NULL) { ASN1_OCTET_STRING_free(wrapped); }

    return rv;
}



static CK_ULONG get_EC_params(EVP_PKEY *pubkey, CK_BYTE_PTR *buf)
{
    CK_LONG rv=0;
    EC_KEY* ec=NULL;

    if ( pubkey && EVP_PKEY_base_id(pubkey)==EVP_PKEY_EC  ) {

	ec = EVP_PKEY_get0_EC_KEY(pubkey);

	if(ec==NULL) {
	    P_ERR();
	    goto error;
	}

	const EC_GROUP *ec_group = EC_KEY_get0_group(ec);
	/* get0 means no ref counter is incremented */

	if(ec_group==NULL) {
	    P_ERR();
	    goto error;
	}

	*buf = NULL;		/* clearing it */

	rv = i2d_ECPKParameters(ec_group, buf);

	if(rv<0) {
	    P_ERR();
	    goto error;
	}

    }
error:
    return rv<0 ? 0 : rv ;
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


static CK_ULONG get_EVP_PKEY_sha1(EVP_PKEY *pubkey, CK_BYTE_PTR *buf) {

    CK_ULONG rv = 0;
    if (pubkey && buf) {
	switch (EVP_PKEY_base_id(pubkey)) {

	case EVP_PKEY_RSA: {
	    RSA *rsa;
	    const BIGNUM *rsa_n;

	    rsa = EVP_PKEY_get0_RSA(pubkey);
	    if (rsa) {
		RSA_get0_key(rsa, &rsa_n, NULL, NULL);
		CK_BYTE_PTR bn_buf = OPENSSL_malloc(BN_num_bytes(rsa_n)); /* we allocate before converting */
		if (bn_buf) {
		    int bn_buf_len = BN_bn2bin(rsa_n, bn_buf);
		    {
			/* SHA-1 block */
			EVP_MD_CTX *mdctx;
			const EVP_MD *md;
			unsigned int md_len;

			*buf = OPENSSL_malloc(SHA_DIGEST_LENGTH); /* we allocate the buffer, and return it. */

			if (*buf) {
			    md = EVP_sha1();
			    mdctx = EVP_MD_CTX_create();
			    EVP_DigestInit_ex(mdctx, md, NULL);
			    EVP_DigestUpdate(mdctx, bn_buf, bn_buf_len);
			    EVP_DigestFinal_ex(mdctx, *buf, &md_len);
			    EVP_MD_CTX_destroy(mdctx);
			    rv = md_len;
			}
		    }
		    OPENSSL_free(bn_buf);
		}
	    }
	}
	    break;


	case EVP_PKEY_DSA: {
	    DSA *dsa;
	    const BIGNUM *dsa_pub_key;

	    dsa = EVP_PKEY_get0_DSA(pubkey);
	    if (dsa) {
		DSA_get0_key(dsa, &dsa_pub_key, NULL);
		CK_BYTE_PTR bn_buf = OPENSSL_malloc(BN_num_bytes(dsa_pub_key)); /* we allocate before converting */
		if (bn_buf) {
		    int bn_buf_len = BN_bn2bin(dsa_pub_key, bn_buf);
		    {
			/* SHA-1 block */
			EVP_MD_CTX *mdctx;
			const EVP_MD *md;
			unsigned int md_len;

			*buf = OPENSSL_malloc(SHA_DIGEST_LENGTH); /* we allocate the buffer, and return it. */

			if (*buf) {
			    md = EVP_sha1();
			    mdctx = EVP_MD_CTX_create();
			    EVP_DigestInit_ex(mdctx, md, NULL);
			    EVP_DigestUpdate(mdctx, bn_buf, bn_buf_len);
			    EVP_DigestFinal_ex(mdctx, *buf, &md_len);
			    EVP_MD_CTX_destroy(mdctx);
			    rv = md_len;
			}
		    }
		    OPENSSL_free(bn_buf);
		}
	    }
	}
	    break;

	    /* for EC, we need to retrieve the points (uncompressed), then encapsulate into an OCTETSTRING */
	    /* which corresponds to the encoding on PKCS#11 */
	case EVP_PKEY_EC: {
	    EC_KEY *ec;

	    ec = EVP_PKEY_get0_EC_KEY(pubkey);
	    if (ec == NULL) {
		P_ERR();
	    } else {
		const EC_POINT *ec_point = EC_KEY_get0_public_key(ec);
		const EC_GROUP *ec_group = EC_KEY_get0_group(ec);


		if (ec_point == NULL) {
		    P_ERR();
		} else if (ec_group == NULL) {
		    P_ERR();
		} else {

		    /* first call to assess length of target buffer */
		    size_t ec_buflen = EC_POINT_point2oct(ec_group, ec_point,
							  POINT_CONVERSION_UNCOMPRESSED,
							  NULL, 0, NULL);

		    if (ec_buflen == 0) {
			P_ERR();
		    } else {

			unsigned char *p, *ec_buf;

			p = ec_buf = OPENSSL_malloc(ec_buflen);

			if (ec_buf == NULL) {
			    P_ERR();
			} else {
			    /* second call to obtain DER-encoded point */
			    rv = (CK_ULONG) EC_POINT_point2oct(ec_group, ec_point,
							       POINT_CONVERSION_UNCOMPRESSED,
							       p, ec_buflen, NULL);
			    if (rv == 0) {
				P_ERR();
			    } else {

				/* now start the wrapping to OCTET STRING business */

				ASN1_OCTET_STRING *wrapped = ASN1_OCTET_STRING_new();

				if (wrapped == NULL) {
				    P_ERR();
				} else {
				    if (ASN1_STRING_set(wrapped, ec_buf, ec_buflen) == 0) {
					P_ERR();
				    } else {
					/* wrapped contains the data we need to set into buf */

					/* determine length of buffer */
					int i2dlen = i2d_ASN1_OCTET_STRING(wrapped, NULL);

					if (i2dlen < 0) {
					    P_ERR();
					} else {

					    CK_BYTE_PTR p = NULL, wrapbuf = NULL;

					    wrapbuf = OPENSSL_malloc(i2dlen);

					    if (wrapbuf == NULL) {
						P_ERR();
					    } else {

						p = wrapbuf;

						i2dlen = i2d_ASN1_OCTET_STRING(wrapped, &p);

						if (i2dlen < 0) {
						    P_ERR();
						} else {

						    /* SHA-1 block */
						    EVP_MD_CTX *mdctx;
						    const EVP_MD *md;
						    unsigned int md_len;

						    *buf = OPENSSL_malloc(SHA_DIGEST_LENGTH); /* we allocate the buffer, and return it. */

						    if (*buf == NULL) {
							P_ERR();
						    } else {
							md = EVP_sha1();
							mdctx = EVP_MD_CTX_create();
							EVP_DigestInit_ex(mdctx, md, NULL);
							EVP_DigestUpdate(mdctx, wrapbuf, i2dlen);
							EVP_DigestFinal_ex(mdctx, *buf, &md_len);
							EVP_MD_CTX_destroy(mdctx);
							rv = md_len;
						    }
						}
					    }
					    OPENSSL_free(wrapbuf);
					}
				    }
				    ASN1_OCTET_STRING_free(wrapped);
				}

			    }
			    OPENSSL_free(ec_buf);
			}
		    }
		    /* get0 on ec_point & ec_group, we can safely forget */
		}
	    }
	}
	    break;

	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448: {
	    CK_BYTE_PTR point = NULL;
	    CK_ULONG point_len;

	    point_len = get_ED_point(pubkey, &point); /* get octet-string */
	    if(point_len>0) {
		/* SHA-1 block */
		EVP_MD_CTX *mdctx;
		const EVP_MD *md;
		unsigned int md_len;

		*buf = OPENSSL_malloc(SHA_DIGEST_LENGTH); /* we allocate the buffer, and return it. */

		if (*buf == NULL) {
		    P_ERR();
		} else {
		    md = EVP_sha1();
		    mdctx = EVP_MD_CTX_create();
		    EVP_DigestInit_ex(mdctx, md, NULL);
		    EVP_DigestUpdate(mdctx, point, point_len);
		    EVP_DigestFinal_ex(mdctx, *buf, &md_len);
		    EVP_MD_CTX_destroy(mdctx);
		    rv = md_len;
		}
		OPENSSL_free(point);
	    }
	}
	    break;


	case EVP_PKEY_DH: {
	    DH *dh;
	    const BIGNUM *dh_pub_key;

	    dh = EVP_PKEY_get0_DH(pubkey);
	    if (dh) {
		DH_get0_key(dh, &dh_pub_key, NULL);
		CK_BYTE_PTR bn_buf = OPENSSL_malloc(BN_num_bytes(dh_pub_key)); /* we allocate before converting */
		if (bn_buf) {
		    int bn_buf_len = BN_bn2bin(dh_pub_key, bn_buf);
		    {
			/* SHA-1 block */
			EVP_MD_CTX *mdctx;
			const EVP_MD *md;
			unsigned int md_len;

			*buf = OPENSSL_malloc(SHA_DIGEST_LENGTH); /* we allocate the buffer, and return it. */

			if (*buf) {
			    md = EVP_sha1();
			    mdctx = EVP_MD_CTX_create();
			    EVP_DigestInit_ex(mdctx, md, NULL);
			    EVP_DigestUpdate(mdctx, bn_buf, bn_buf_len);
			    EVP_DigestFinal_ex(mdctx, *buf, &md_len);
			    EVP_MD_CTX_destroy(mdctx);
			    rv = md_len;
			}
		    }
		    OPENSSL_free(bn_buf);
		}
	    }
	}
	    break;

	default:
	    break;

	}
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
