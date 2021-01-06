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
#include <assert.h>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "pkcs11lib.h"
#include "pkcs11_ossl.h"

typedef struct {
    pkcs11Context *p11Context;
    CK_OBJECT_HANDLE hPrivateKey;
    bool fake;
} local_eddsa_method_st ;


static local_eddsa_method_st static_st; /* TODO use CTRL API to make reentrant */


/* EDDSA works with EVP and digestsign only, 
   and there is currently no pre-hash version available 
   only PureEdDSA is implemented 
*/

typedef int (*fn_digestsign_ptr) (EVP_MD_CTX *ctx,
				  unsigned char *sig, size_t *siglen,
				  const unsigned char *tbs, size_t tbslen);

static fn_digestsign_ptr orig_ed25519_digestsign = NULL;
static fn_digestsign_ptr orig_ed448_digestsign = NULL ;

static int custom_ed_digestsign( EVP_MD_CTX *ctx,
				 unsigned char *sig,
				 size_t *siglen,
				 const unsigned char *tbs,
				 size_t tbslen) {
    int rc = 0;
    CK_RV rv;
    CK_MECHANISM mechanism = { CKM_EDDSA, NULL_PTR, 0 }; /* OpenSSL supports only Pure EDDSA */

    /* recover signature size from algorithm */
    size_t p11siglen = EVP_PKEY_size( EVP_PKEY_CTX_get0_pkey( EVP_MD_CTX_pkey_ctx ( ctx ) ) );

    /* check that the buffer we received to place signature is large enough */
    if( p11siglen > *siglen ) {
	fprintf(stderr,"***Error: encoded signature buffer too small!\n");
	goto err;
    }

    if(static_st.fake) {
	fake_sign(sig, p11siglen);
    } else {

	rv = static_st.p11Context->FunctionList.C_SignInit(static_st.p11Context->Session,
							   &mechanism,
							   static_st.hPrivateKey);
	if(rv!= CKR_OK) {
	    pkcs11_error(rv,"C_SignInit");
	    goto err;
	}

	rv = static_st.p11Context->FunctionList.C_Sign(static_st.p11Context->Session,
						       (CK_BYTE_PTR)tbs,
						       tbslen,
						       sig,
						       (CK_ULONG_PTR)&p11siglen);

	if(rv!= CKR_OK) {
	    pkcs11_error(rv,"C_Sign");
	    goto err;
	}
    }
    rc = 1;
    
err:
    return rc;
}


static int custom_ed25519_digestsign( EVP_MD_CTX *ctx,
				      unsigned char *sig,
				      size_t *siglen,
				      const unsigned char *tbs,
				      size_t tbslen)
{
    static bool entered = false;
    int rc;
    
    /* if entered is true, this means we are calling a PKCS#11 implementation */
    /* that uses also OpenSSL, which is also using the same EVP methods as us */
    /* In which case, we call the original method  (before customization)     */
    /* otherwise we would enter an endless recursion...                       */
    /* NOTE: this mechanism is NOT thread-safe                                */

    if( entered==true ) {
	rc = orig_ed25519_digestsign(ctx, sig, siglen, tbs, tbslen);
    } else {
	entered = true;		/* set entered state */
	rc = custom_ed_digestsign(ctx, sig, siglen, tbs, tbslen);
	entered = false;	/* leave entered state */
    }
    return rc;
}


static int custom_ed448_digestsign( EVP_MD_CTX *ctx,
				    unsigned char *sig,
				    size_t *siglen,
				    const unsigned char *tbs,
				    size_t tbslen)
{
    static bool entered = false;
    int rc;
    
    /* if entered is true, this means we are calling a PKCS#11 implementation */
    /* that uses also OpenSSL, which is also using the same EVP methods as us */
    /* In which case, we call the original method  (before customization)     */
    /* otherwise we would enter an endless recursion...                       */
    /* NOTE: this mechanism is NOT thread-safe                                */

    if( entered==true ) {
	rc = orig_ed448_digestsign(ctx, sig, siglen, tbs, tbslen);
    } else {
	entered = true;		/* set entered state */
	rc = custom_ed_digestsign(ctx, sig, siglen, tbs, tbslen);
	entered = false;	/* leave entered state */
    }
    return rc;
}


static void eddsa_method_setup(int nid, fn_digestsign_ptr *orig_fn_ptr, fn_digestsign_ptr custom_fn_ptr)
{
    const EVP_PKEY_METHOD *orig_ed_method = NULL;
    EVP_PKEY_METHOD *custom_ed_method = NULL;

    /* customizing signing methods */
    orig_ed_method = EVP_PKEY_meth_find(nid);
    if(orig_ed_method==NULL) {
	P_ERR();
	goto err;
    }

    /* create a new EVP_PKEY_METHOD */
    /* caution: EVP_PKEY_FLAG_SIGCTX_CUSTOM is required for ED signature        */
    /*          unfortunately, OpenSSL does not copy flags from original method */
    custom_ed_method = EVP_PKEY_meth_new(nid, EVP_PKEY_FLAG_AUTOARGLEN | EVP_PKEY_FLAG_SIGCTX_CUSTOM );
    if(custom_ed_method==NULL) {
	P_ERR();
	goto err;
    }
  
    /* copy all from the EVP_PKEY_METHOD we want to customize */
    EVP_PKEY_meth_copy( custom_ed_method, orig_ed_method);
    
    EVP_PKEY_meth_get_digestsign( (EVP_PKEY_METHOD *)orig_ed_method, orig_fn_ptr );
    EVP_PKEY_meth_set_digestsign( custom_ed_method, custom_fn_ptr );
	
    if(!EVP_PKEY_meth_add0(custom_ed_method)) {
	P_ERR();
	goto err;
    }
    
    custom_ed_method = NULL;	/* swallowed by EVP_PKEY_meth_add0 */

err:
    if(custom_ed_method) { EVP_PKEY_meth_free(custom_ed_method); }

}

void pkcs11_eddsa_method_setup()
{
    static bool initialized = false;

    if(initialized) {
	fprintf(stderr, "Warning: EVP_PKEY sign method already customized, skipping setup\n");
    } else {
	eddsa_method_setup(EVP_PKEY_ED25519, &orig_ed25519_digestsign, custom_ed25519_digestsign);
	eddsa_method_setup(EVP_PKEY_ED448, &orig_ed448_digestsign, custom_ed448_digestsign);

	/* now, initialize static member */
	static_st.p11Context = NULL;
	static_st.hPrivateKey = NULL_PTR;
	static_st.fake = false;

	initialized = true;
    }
}


void pkcs11_eddsa_method_pkcs11_context(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPrivateKey, bool fake)
{
    static_st.p11Context = p11Context;
    static_st.hPrivateKey = hPrivateKey;
    static_st.fake = fake;
}
