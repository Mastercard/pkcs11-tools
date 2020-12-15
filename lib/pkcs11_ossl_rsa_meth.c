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

#include <config.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "pkcs11lib.h"
#include "pkcs11_ossl.h"

typedef struct {
    pkcs11Context *p11Context;
    CK_OBJECT_HANDLE hPrivateKey;
    bool fake;			/* set when we don't really want to sign */
} local_rsa_method_st ;


static local_rsa_method_st static_st; /* TODO use CTRL API to make reentrant */


static int (*orig_rsasign) (EVP_PKEY_CTX *ctx,
			    unsigned char *sig, size_t *siglen,
			    const unsigned char *tbs, size_t tbslen) = NULL;



static int custom_rsasign( EVP_PKEY_CTX *ctx,
			   unsigned char *sig,
			   size_t *siglen,
			   const unsigned char *tbs,
			   size_t tbslen) {

    /* TODO: check if static_st is populated */

    CK_RV rv;
    const EVP_MD *md;
    char digestinfo[19+64];	/* the longest supported is SHA512 */

    /* TODO: change this to dynamic build of the object */
    static const char header_sha1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
    };

    static const char header_sha224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
	0x00, 0x04, 0x1c
    };
    
    static const char header_sha256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20
    };

    static const char header_sha384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
	0x00, 0x04, 0x30
    };

    static const char header_sha512[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
	0x00, 0x04, 0x30
    };

    typedef struct {
	const unsigned int nid;
	const char * header;
	const size_t len;
    } hash_header_map_st;

    static const hash_header_map_st hash_header_map[] = {
	{ NID_sha1, header_sha1, sizeof header_sha1 / sizeof(char) },
	{ NID_sha224, header_sha224, sizeof header_sha224 / sizeof(char) },
	{ NID_sha256, header_sha256, sizeof header_sha256 / sizeof(char) },
	{ NID_sha384, header_sha384, sizeof header_sha384 / sizeof(char) },
	{ NID_sha512, header_sha512, sizeof header_sha512 / sizeof(char) },
    };	
    
    CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };

    if(!static_st.fake) {
	rv = static_st.p11Context->FunctionList.C_SignInit( static_st.p11Context->Session,
							    &mechanism,
							    static_st.hPrivateKey);
	if(rv!= CKR_OK) {
	    pkcs11_error(rv,"C_SignInit");
	    goto err;
	}
    }

    if(EVP_PKEY_CTX_get_signature_md(ctx, &md)<=0) {
	P_ERR();
	goto err;
    }

    /* because CKM_RSA_PKCS is unaware of the hash algorithm, */
    /* we have to feed the DigestInfo ASN.1 structure,        */
    /* as found in RFC8017 section 9.2                        */

    /* step 1: retrieve the proper header, by matching hash alg */
    int i;
    
    for(i=0; i<sizeof hash_header_map / sizeof(hash_header_map_st); i++) {
	if(EVP_MD_type(md) == hash_header_map[i].nid) {
	    break;
	}
    }

    if(i==sizeof hash_header_map / sizeof(hash_header_map_st)) {
	/* not found */
	fprintf(stderr, "***Error, unsupported hashing algorithm\n");
	goto err;
    }

    /* step 2: copy the header to the digestinfo */
    memcpy(&digestinfo[0], hash_header_map[i].header, hash_header_map[i].len);

    /* step 3: append the data to be signed after the header */
    memcpy(&digestinfo[hash_header_map[i].len], tbs, tbslen);

    /* step 4: perform signature */
    if(static_st.fake) {
	/* the buffer that offered to us is in fact oversized, to support DER encoding supplement bytes */
	/* when invoking C_Sign(), p11siglen gets adjusted to the real value                            */
	/* we have to do the same for fake_sign: we must also adjust p11siglen,                         */
	/* so we can encapsulate the fake signature accordingly                                         */
	const RSA *rsa = EVP_PKEY_get0_RSA(EVP_PKEY_CTX_get0_pkey(ctx)); /* TODO error checking */
	const BIGNUM *rsa_n = RSA_get0_n(rsa);
	*siglen = BN_num_bytes(rsa_n); /* the signature size is the size of the modulus */
	fake_sign(sig,*siglen);
    } else {
	rv = static_st.p11Context->FunctionList.C_Sign(static_st.p11Context->Session,
						       (CK_BYTE_PTR)digestinfo,
						       hash_header_map[i].len + EVP_MD_size(md),
						       sig,
						       siglen);

	if(rv!= CKR_OK) {
	    pkcs11_error(rv,"C_Sign");
	    goto err;
	}
    }
    return 1;

err:
    return -1;
}


void pkcs11_rsa_method_setup()
{
    const EVP_PKEY_METHOD *orig_rsamethod;
    EVP_PKEY_METHOD *custom_rsamethod;

    /* customizing signing methods */
    /* we are doing SHA1 / RSA signing */
    orig_rsamethod = EVP_PKEY_meth_find(EVP_PKEY_RSA);
    if(orig_rsamethod==NULL) {
	ERR_print_errors_fp(stderr);
	exit(1);		/* TODO CHANGE THIS */
    }

    /* create a new EVP_PKEY_METHOD */
    custom_rsamethod = EVP_PKEY_meth_new( EVP_PKEY_RSA, EVP_PKEY_FLAG_AUTOARGLEN);
    if(custom_rsamethod==NULL) {
	ERR_print_errors_fp(stderr);
	exit(1);
    }
  
    /* copy all from the EVP_PKEY_METHOD we want to customize */
    EVP_PKEY_meth_copy( custom_rsamethod, orig_rsamethod);
    
    /* For the calls we want to tweak, recover the original fn pointers */
    int (*orig_rsasign_init) (EVP_PKEY_CTX *ctx);
    
    EVP_PKEY_meth_get_sign(orig_rsamethod,
			   &orig_rsasign_init,
			   &orig_rsasign );

    /* then adapt what we want to, in this case only the sign() fn */
    
    EVP_PKEY_meth_set_sign(custom_rsamethod,
			   orig_rsasign_init, /* duplicate it, we don't change it */
			   custom_rsasign ); /* the new, customized method */

    EVP_PKEY_meth_add0(custom_rsamethod);
    custom_rsamethod = NULL;	/* swallowed by EVP_PKEY_meth_add0 */
}


void pkcs11_rsa_method_pkcs11_context(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPrivateKey, bool fake)
{
    static_st.p11Context = p11Context;
    static_st.hPrivateKey = hPrivateKey;
    static_st.fake = fake;
}
