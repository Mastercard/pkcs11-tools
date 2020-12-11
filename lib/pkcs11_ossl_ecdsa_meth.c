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
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include "pkcs11lib.h"

typedef struct {
    pkcs11Context *p11Context;
    CK_OBJECT_HANDLE hPrivateKey;
} local_ecdsa_method_st ;


static local_ecdsa_method_st static_st; /* TODO use CTRL API to make reentrant */


static int (*orig_ecdsasign) (EVP_PKEY_CTX *ctx,
			    unsigned char *sig, size_t *siglen,
			    const unsigned char *tbs, size_t tbslen) = NULL;



static int custom_ecdsasign( EVP_PKEY_CTX *ctx,
			   unsigned char *sig,
			   size_t *siglen,
			   const unsigned char *tbs,
			   size_t tbslen) {

    /* TODO: check if static_st is populated */

    int rc = -1;
    CK_RV rv;
    BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG *ecdsasig = NULL;
    CK_C_SignInit pC_SignInit = static_st.p11Context->FunctionList.C_SignInit;
    CK_C_Sign pC_Sign = static_st.p11Context->FunctionList.C_Sign;

    CK_MECHANISM mechanism = { CKM_ECDSA, NULL_PTR, 0 };

    size_t p11siglen = *siglen;
    CK_BYTE_PTR p11sig = OPENSSL_zalloc(p11siglen);

    if(!p11sig) {
	P_ERR();
	goto err;
    }
    
    rv = pC_SignInit(static_st.p11Context->Session, &mechanism, static_st.hPrivateKey);
    if(rv!= CKR_OK) {
	pkcs11_error(rv,"C_SignInit");
	goto err;
    }

    rv = pC_Sign(static_st.p11Context->Session,
		 (CK_BYTE_PTR)tbs,
		 tbslen,
		 p11sig,
		 &p11siglen);

    if(rv!= CKR_OK) {
	pkcs11_error(rv,"C_Sign");
	goto err;
    }

    /* at this point, we must build a ECDSA_SIG object, using the result of the PKCS#11 computation */
    ecdsasig = ECDSA_SIG_new();
    if(!ecdsasig) {
	P_ERR();
	goto err;
    }

    /* making a wild guess here. We are supposed to know the size of our ECDSA signature */
    /* however, that information can't be inferred from here, unfortunately            */
    /* we will therefore trust the PKCS#11 function, and simply divide by two the signature */

    r = BN_bin2bn( &p11sig[0], p11siglen>>1, NULL);
    s = BN_bin2bn( &p11sig[p11siglen>>1], p11siglen>>1, NULL);

    if(r==NULL || r==NULL) {
	P_ERR();
	goto err;
    }
    
    if(!ECDSA_SIG_set0(ecdsasig,r,s)) { /* assign numbers */
	P_ERR();
	goto err;
    }
    r = s = NULL;		/* and forget them */

    int enclen = i2d_ECDSA_SIG(ecdsasig,NULL);
    if(enclen<0) {
	P_ERR();
	goto err;
    }

    if(*siglen<enclen) {
	fprintf(stderr,"Error: encoded signature buffer too small!\n");
	goto err;
    }

    enclen = i2d_ECDSA_SIG(ecdsasig, &sig);
    if(enclen<0) {
	P_ERR();
	goto err;
    }
    *siglen = enclen;
    rc = 1;
    
err:
    if(ecdsasig) { ECDSA_SIG_free(ecdsasig); }
    if(r) { BN_free(r); }
    if(s) { BN_free(s); }
    if(p11sig) { OPENSSL_free(p11sig); }
    
    return rc;
}


void pkcs11_ecdsa_method_setup()
{
    const EVP_PKEY_METHOD *orig_ecdsamethod;
    EVP_PKEY_METHOD *custom_ecdsamethod;

    /* customizing signing methods */
    /* we are doing SHA1 / ECDSA signing */
    orig_ecdsamethod = EVP_PKEY_meth_find(EVP_PKEY_EC);
    if(orig_ecdsamethod==NULL) {
	ERR_print_errors_fp(stderr);
	exit(1);		/* TODO CHANGE THIS */
    }

    /* create a new EVP_PKEY_METHOD */
    custom_ecdsamethod = EVP_PKEY_meth_new( EVP_PKEY_EC, EVP_PKEY_FLAG_AUTOARGLEN);
    if(custom_ecdsamethod==NULL) {
	ERR_print_errors_fp(stderr);
	exit(1);
    }
  
    /* copy all from the EVP_PKEY_METHOD we want to customize */
    EVP_PKEY_meth_copy( custom_ecdsamethod, orig_ecdsamethod);
    
    /* For the calls we want to tweak, recover the original fn pointers */
    int (*orig_ecdsasign_init) (EVP_PKEY_CTX *ctx);
    
    EVP_PKEY_meth_get_sign(orig_ecdsamethod,
			   &orig_ecdsasign_init,
			   &orig_ecdsasign );

    /* then adapt what we want to, in this case only the sign() fn */
    
    EVP_PKEY_meth_set_sign(custom_ecdsamethod,
			   orig_ecdsasign_init, /* duplicate it, we don't change it */
			   custom_ecdsasign ); /* the new, customized method */

    EVP_PKEY_meth_add0(custom_ecdsamethod);
    custom_ecdsamethod = NULL;	/* swallowed by EVP_PKEY_meth_add0 */
}


void pkcs11_ecdsa_method_pkcs11_context(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPrivateKey)
{
    static_st.p11Context = p11Context;
    static_st.hPrivateKey = hPrivateKey;
}
