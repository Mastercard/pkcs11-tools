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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <search.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "pkcs11lib.h"
#include "wrappedkey_lexer.h"
#include "wrappedkey_parser.h"


/* wrappedKeyContext will hold information about wrapping/unwrapping keys

   several wrapping methods are supported:
   - the regular wrapping methods ( PKCS#1, OAEP, CBC_PAD, AES_KEY_WRAP, AES_KEY_WRAP_PAD )
   - envelope wrapping, where a private key (RSA) wraps a symmetric key, that in turn wraps any kind of key

   to support both models, the structure contains a small array where actual wrapped key info is maintained.

   ...
   struct {
       CK_BYTE_PTR wrapped_key_buffer;
       CK_ULONG wrapped_key_len;
       enum wrappingmethod wrapping_meth;
   } key[2];
   ...

   the first element is always for the outer key, which is used only for envelope wrapping.
   the second element is either used as the inner key in envelope mode, or as the lone key for other wrapping algorithms.

 */


wrappedKeyCtx *pkcs11_new_wrappedkeycontext(pkcs11Context *p11Context)
{
    wrappedKeyCtx *ctx = NULL;

    if(p11Context) {
	ctx = calloc(1, sizeof (wrappedKeyCtx));

	if(ctx==NULL) {
	    fprintf(stderr, "Error: not enough memory when allocating memory for wrappedKeyCtx\n");
	    goto error;
	}

	ctx->p11Context = p11Context;

	ctx->oaep_params = calloc( 1, sizeof(CK_RSA_PKCS_OAEP_PARAMS) );
	if(ctx->oaep_params == NULL) {
	    fprintf(stderr, "Error: not enough memory when allocating memory for CK_RSA_PKCS_OAEP_PARAMS of wrappedKeyCtx\n");
	    goto error;
	}

	ctx->is_envelope = CK_FALSE;

	ctx->wrpkattribs = pkcs11_new_attribcontext();
	if(ctx->wrpkattribs == NULL) {
	    fprintf(stderr, "Error: not enough memory when allocating memory for wrpkattribs member\n");
	    goto error;
	}

	ctx->pubkattribs = pkcs11_new_attribcontext();
	if(ctx->pubkattribs == NULL) {
	    fprintf(stderr, "Error: not enough memory when allocating memory for pubkattribs member\n");
	    goto error;
	}
    }
    
    return ctx;

error:
    if(ctx) {
	if(ctx->wrpkattribs) pkcs11_free_attribcontext(ctx->wrpkattribs);
	if(ctx->pubkattribs) pkcs11_free_attribcontext(ctx->pubkattribs);	
	pkcs11_free_wrappedkeycontext(ctx);
    }
    return NULL;
}

inline void pkcs11_wctx_free_mechanisms(wrappedKeyCtx *wctx)
{
    if(wctx && wctx->allowedmechs) {
	free(wctx->allowedmechs);
	wctx->allowedmechs = NULL;
	wctx->allowedmechs_len = 0;
    }
}

/* to use only for transfer of ownership */
inline void pkcs11_wctx_forget_mechanisms(wrappedKeyCtx *wctx)
{
    if(wctx && wctx->allowedmechs) {
	wctx->allowedmechs = NULL;
	wctx->allowedmechs_len = 0;
    }
}

inline CK_MECHANISM_TYPE_PTR pkcs11_wctx_get_allowed_mechanisms(wrappedKeyCtx *ctx)
{
    return ctx ? ctx->allowedmechs : NULL;
}

inline size_t pkcs11_wctx_get_allowed_mechanisms_len(wrappedKeyCtx *ctx)
{
    return ctx ? ctx->allowedmechs_len : 0;
}


void pkcs11_free_wrappedkeycontext(wrappedKeyCtx *wctx)
{

    if( wctx ) {

	/* free up wrappingkeylabel */
	if(wctx->wrappingkeylabel) {
	    free(wctx->wrappingkeylabel);
	    wctx->wrappingkeylabel= NULL ;
	}

	/* free up wrappedkeylabel */
	if(wctx->wrappedkeylabel) {
	    free(wctx->wrappedkeylabel);
	    wctx->wrappedkeylabel = NULL ;
	}

	/* free up filename */
	if(wctx->filename) {
	    free(wctx->filename);
	    wctx->filename = NULL;
	}

	/* free up allowed mechanisms array */
	pkcs11_wctx_free_mechanisms(wctx);
	
	/* free up buffers */
	int i;
	for(i=0; i<2; ++i) {
	    if(wctx->key[i].wrapped_key_buffer) {
		free(wctx->key[i].wrapped_key_buffer);
		wctx->key[i].wrapped_key_buffer = NULL;
		wctx->key[i].wrapped_key_len = 0;
	    }
	}

	/* free up OAEP structure */
	if(wctx->oaep_params) {
	    if(wctx->oaep_params->pSourceData) {
		free(wctx->oaep_params->pSourceData);
		wctx->oaep_params->pSourceData=NULL;
		wctx->oaep_params->ulSourceDataLen=0L;
	    }
	    free(wctx->oaep_params);
	    wctx->oaep_params = NULL;
	}

	/* free up iv member */
	if(wctx->aes_params.iv) {
	    free(wctx->aes_params.iv);
	    wctx->aes_params.iv = NULL;
	    wctx->aes_params.iv_len = 0L;
	}

	/* free up pubk_pem_buffer */
	if(wctx->pubk_buffer) {
	    free(wctx->pubk_buffer);
	    wctx->pubk_buffer = NULL;
	    wctx->pubk_len=0;
	}

	/* free up wrappedkeyattribs */
	if(wctx->wrpkattribs) {
	    pkcs11_free_attribcontext(wctx->wrpkattribs);
	    wctx->wrpkattribs = NULL;
	}
	
	/* free up pubkeyattribs */
	if(wctx->pubkattribs) {
	    pkcs11_free_attribcontext(wctx->pubkattribs);
	    wctx->pubkattribs = NULL;
	}

	free(wctx);		/* eventually free up context mem */
    }
}
