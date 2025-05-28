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
#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "pkcs11lib.h"
#include "pkcs11_ossl.h"

typedef struct {
    pkcs11Context *p11Context;
    CK_OBJECT_HANDLE hPrivateKey;
    bool fake;			/* set when we don't really want to sign */
} local_rsa_method_st ;


static local_rsa_method_st static_st; /* TODO use CTRL API to make reentrant */

static int (*orig_rsa_sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) = NULL;

/* local objects and methods*/
static int custom_rsa_sign_pkcs1( EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
static int custom_rsa_sign_pss( EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);

typedef struct {
    int nid;
    CK_RSA_PKCS_PSS_PARAMS pss_params;
} hash_alg_to_pss_params_st;

static const hash_alg_to_pss_params_st hash_alg_to_pss_params[] = {
    { NID_sha1, { CKM_SHA_1, CKG_MGF1_SHA1, -1 } },
    { NID_sha224, { CKM_SHA224, CKG_MGF1_SHA224, -1 } },
    { NID_sha256, { CKM_SHA256, CKG_MGF1_SHA256, -1 } },
    { NID_sha384, { CKM_SHA384, CKG_MGF1_SHA384, -1 } },
    { NID_sha512, { CKM_SHA512, CKG_MGF1_SHA512, -1 } }
};

static const CK_RSA_PKCS_PSS_PARAMS *get_pss_params(int nid)
{
    int i;
    for(i=0; i<sizeof hash_alg_to_pss_params / sizeof(hash_alg_to_pss_params_st); i++) {
	if(nid == hash_alg_to_pss_params[i].nid) {
	    return &hash_alg_to_pss_params[i].pss_params;
	}
    }
    return NULL;
}

static size_t get_modulus_bytes( EVP_PKEY_CTX *ctx) {
	/* use OpenSSL primitives to retrieve the RSA public key modulus length */
	const RSA *rsa = EVP_PKEY_get0_RSA(EVP_PKEY_CTX_get0_pkey(ctx)); 
	if (rsa == NULL) {
		fprintf(stderr, "Error: Unable to retrieve RSA structure\n");
		return 0;
	}
	const BIGNUM *rsa_n = RSA_get0_n(rsa);
	if (rsa_n == NULL) {
		fprintf(stderr, "Error: Unable to retrieve RSA modulus\n");
		return 0;
	}
	size_t attr_modulus_len = BN_num_bytes(rsa_n);

	return attr_modulus_len;
}


static int custom_rsa_sign( EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
    static bool entered = false;
    /* if entered is true, this means we are calling a PKCS#11 implementation */
    /* that uses also OpenSSL, which is also using the same EVP methods as us */
    /* In which case, we call the original method  (before customization)     */
    /* otherwise we would enter an endless recursion...                       */
    /* NOTE: this mechanism is NOT thread-safe                                */

    if( entered==true ) {
		return orig_rsa_sign(ctx, sig, siglen, tbs, tbslen);
    } else {
		entered = true;		/* set entered state */
		/* TODO: check if static_st is populated */
		int rc = 0;
		int paddingmode;

		EVP_PKEY_CTX_get_rsa_padding(ctx, &paddingmode);
		switch(paddingmode)	{
			case RSA_PKCS1_PADDING:
				rc = custom_rsa_sign_pkcs1(ctx, sig, siglen, tbs, tbslen);
				break;
			case RSA_PKCS1_PSS_PADDING:
				rc = custom_rsa_sign_pss(ctx, sig, siglen, tbs, tbslen);
				break;
			default:
				fprintf(stderr, "unexpected padding requested\n");
		}
		entered = false;
		return rc;
	}
}
	

static int custom_rsa_sign_pkcs1( EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
	int rc = 0;
	CK_RV rv;
	const EVP_MD *md;
	uint8_t digestinfo[19+64];	/* the longest supported is SHA512 */

	/* TODO: change this to dynamic build of the object */
	static const uint8_t header_sha1[] = {
	    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
	};

	static const uint8_t header_sha224[] = {
	    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
	    0x00, 0x04, 0x1c
	};
    
	static const uint8_t header_sha256[] = {
	    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	    0x00, 0x04, 0x20
	};

	static const uint8_t header_sha384[] = {
	    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
	    0x00, 0x04, 0x30
	};

	static const uint8_t header_sha512[] = {
	    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
	    0x00, 0x04, 0x30
	};

	typedef struct {
	    const unsigned int nid;
	    const uint8_t * header;
	    const size_t len;
	} hash_header_map_st;

	static const hash_header_map_st hash_header_map[] = {
	    { NID_sha1, header_sha1, sizeof header_sha1 / sizeof(uint8_t) },
	    { NID_sha224, header_sha224, sizeof header_sha224 / sizeof(uint8_t) },
	    { NID_sha256, header_sha256, sizeof header_sha256 / sizeof(uint8_t) },
	    { NID_sha384, header_sha384, sizeof header_sha384 / sizeof(uint8_t) },
	    { NID_sha512, header_sha512, sizeof header_sha512 / sizeof(uint8_t) },
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
							   (CK_ULONG_PTR)siglen);

	    if(rv!= CKR_OK) {
		pkcs11_error(rv,"C_Sign");
		goto err;
	    }
	}
	rc = 1;

    err:
	return rc;
}


static int custom_rsa_sign_pss( EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
    int rc = 0;
	CK_RV rv;
	const EVP_MD *md;
	
	/* retrieve the hashing algorithm from the context */
	if(EVP_PKEY_CTX_get_signature_md(ctx, &md)<=0) {
	    P_ERR();
	    goto err;
	}

	/* retrieve the appropriate PSS parameters */
	/* on this implementation, the hashing algorithm equals the mgf1 algorithm */
	/* also, the length is set to -1 */
	CK_RSA_PKCS_PSS_PARAMS const * const_pss_params = get_pss_params(EVP_MD_type(md));

	if(const_pss_params==NULL) {
	    fprintf(stderr, "***Error, unsupported hashing algorithm\n");
	    goto err;
	}

	CK_RSA_PKCS_PSS_PARAMS pss_params = *const_pss_params;		// make a copy of it on the stack

	/* set the length of the salt length to the lenght of the modulus minus length of the hash minus 2 */
	/* this is the recommended value for the salt length */
	/* we are using the modulus of the private key */
	int hash_len = EVP_MD_size(md);
	int modulus_len;

	if(!static_st.fake) {
	    modulus_len = get_modulus_bytes(ctx);

		if(modulus_len == 0) {
			fprintf(stderr, "Error: Unable to retrieve RSA modulus length\n");
			goto err;
		}

	    if (modulus_len <= hash_len + 2) {
	        fprintf(stderr, "Error: RSA modulus length is too small for the specified hash algorithm\n");
	        goto err;
	    }
	    pss_params.sLen = modulus_len - hash_len - 2;

	} else {
		// TODO: check what this yields in the fake case
	    modulus_len = EVP_PKEY_size(EVP_PKEY_CTX_get0_pkey(ctx));
	}

	/* now modulus_len is set, let's adjust the values for OpenSSL */
		

	CK_MECHANISM mechanism = { CKM_RSA_PKCS_PSS, &pss_params, sizeof(pss_params) };

	if(!static_st.fake) {
	    rv = static_st.p11Context->FunctionList.C_SignInit(static_st.p11Context->Session,
							       &mechanism,
							       static_st.hPrivateKey);
	    if(rv!= CKR_OK) {
		pkcs11_error(rv,"C_SignInit");
		goto err;
	    }
	}

	/* perform signature */
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
							   (CK_BYTE_PTR)tbs,
							   tbslen,
							   sig,
							   (CK_ULONG_PTR)siglen);

	    if(rv != CKR_OK) {
		pkcs11_error(rv, "C_Sign");
		goto err;
	    }
	}
	rc = 1;
err:
    return rc;
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
    int (*orig_rsa_sign_init) (EVP_PKEY_CTX *ctx);
    
    EVP_PKEY_meth_get_sign(orig_rsamethod,
			   &orig_rsa_sign_init,
			   &orig_rsa_sign );

    /* then adapt what we want to, in this case only the sign() fn */
    
    EVP_PKEY_meth_set_sign(custom_rsamethod,
			   orig_rsa_sign_init, /* duplicate it, we don't change it */
			   custom_rsa_sign ); /* the new, customized method */

    EVP_PKEY_meth_add0(custom_rsamethod);
    custom_rsamethod = NULL;	/* swallowed by EVP_PKEY_meth_add0 */
}


void pkcs11_rsa_method_pkcs11_context(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPrivateKey, bool fake)
{
    static_st.p11Context = p11Context;
    static_st.hPrivateKey = hPrivateKey;
    static_st.fake = fake;
}
