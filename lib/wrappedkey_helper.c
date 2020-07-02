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

/* wrappedkey_helper.c: contains routines used during parsing of wrap files or strings */
/* see wrappedkey_lexer.l and wrappedkey_parser.y for calling methods                  */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>


#include "pkcs11lib.h"
#include "wrappedkey_helper.h"

/* private prototypes */

typedef enum e_parser_attr_target {
    target_wkey,
    target_pubk
} parser_attr_target;

static func_rc _wrappedkey_parser_append_attr(wrappedKeyCtx *wctx, CK_ATTRIBUTE_TYPE attrtyp, void *buffer, size_t len, parser_attr_target target );
static func_rc _wrappedkey_parser_append_from_b64(wrappedKeyCtx *wctx, unsigned char *b64buffer, int keyindex, parser_attr_target target);

/* TODO: move these two utility functions to a commodities lib */

/* memtostrdup: short func to duplicate a block of mem, and turn it into a null-terminated string. */
/* usefull with CKA_LABEL */
static inline void* memtostrdup(const void* d, size_t s) {
    void* p;
    return ((p = calloc(1,s+1))?memcpy(p, d, s):NULL);
}

/* comparison function for attributes */
static int compare_CKA( const void *a, const void *b)
{
    return ((CK_ATTRIBUTE_PTR)a)->type == ((CK_ATTRIBUTE_PTR)b)->type ? 0 : -1;
}


/* ------------------------------------------------------------------------ */

func_rc _wrappedkey_parser_wkey_set_wrapping_alg(wrappedKeyCtx *wctx, enum wrappingmethod meth, int keyindex)
{
    func_rc rc = rc_ok;

    switch(meth) {

    case w_envelope:
	wctx->is_envelope = CK_TRUE;
	/* the default with envelope, is to use OAEP/AES_CBC_PAD */
	wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrapping_meth = w_pkcs1_oaep;
	wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrapping_meth = w_cbcpad;
	wctx->oaep_params->hashAlg = CKM_SHA_1;
	wctx->oaep_params->mgf = CKG_MGF1_SHA1;
	wctx->oaep_params->source = CKZ_DATA_SPECIFIED;
	/* aes_params.iv and iv_len are set to 0/NULL, that's OK */
	break;

    case w_pkcs1_oaep:
	wctx->key[keyindex].wrapping_meth = meth;
	/* adjust content with default valued */
	/* default is: hash=sha1,mgf=mgf_sha1,source="" */
	wctx->oaep_params->hashAlg = CKM_SHA_1;
	wctx->oaep_params->mgf = CKG_MGF1_SHA1;
	wctx->oaep_params->source = CKZ_DATA_SPECIFIED;
	break;

    default:
	wctx->key[keyindex].wrapping_meth = meth;
	break;
    }

    return rc;
}

/* dealing with hash=xxxxx parameter */
/* parser/lexer guarantee we are with oaep */
func_rc _wrappedkey_parser_wkey_set_wrapping_param_hash(wrappedKeyCtx *wctx, CK_MECHANISM_TYPE hash)
{
    wctx->oaep_params->hashAlg = hash;
    return rc_ok;
}

/* dealing with mgf=xxxxx parameter */
/* parser/lexer guarantee we are with oaep */
func_rc _wrappedkey_parser_wkey_set_wrapping_param_mgf(wrappedKeyCtx *wctx, CK_MECHANISM_TYPE mgf)
{
    wctx->oaep_params->mgf = mgf;
    return rc_ok;
}

/* dealing with label=xxxxx parameter */
/* parser/lexer guarantee we are with oaep */
func_rc _wrappedkey_parser_wkey_set_wrapping_param_label(wrappedKeyCtx *wctx, void *buffer, size_t len)
{
    func_rc rc = rc_ok;

    if(len==0) {
	/* special case: if we receive the empty string, do not copy it */
	/* instead, set pSourceData to NULL and set a 0 in len */
	/* as specified in PKCS#11 v2.2 documentation */
	wctx->oaep_params->pSourceData=NULL;
	wctx->oaep_params->ulSourceDataLen = 0;
	wctx->oaep_params->source = CKZ_DATA_SPECIFIED;
    } else {
	wctx->oaep_params->pSourceData = malloc(len);

	if(wctx->oaep_params->pSourceData == NULL) {
	    fprintf(stderr, "Memory error\n");
	    rc = rc_error_memory;
	} else {
	    memcpy(wctx->oaep_params->pSourceData, buffer, len); /* copy the value */
	    wctx->oaep_params->ulSourceDataLen = len;
	    wctx->oaep_params->source = CKZ_DATA_SPECIFIED;
	}
    }
    return rc;
}

/* dealing with iv=xxxx parameter */
/* parser/lexer guarantee we are with pkcs7 */
func_rc _wrappedkey_parser_wkey_set_wrapping_param_iv(wrappedKeyCtx *wctx, void *buffer, size_t len)
{
    func_rc rc = rc_ok;

    wctx->aes_params.iv = malloc(len);

    if(wctx->aes_params.iv == NULL) {
	fprintf(stderr, "Memory error\n");
	rc = rc_error_memory;
    } else {
	memcpy(wctx->aes_params.iv, buffer, len); /* copy the value */
	wctx->aes_params.iv_len = len;
    }

    return rc;
}

/* dealing with flavour=xxx parameter */
/* parser/lexer guarantee we are with oaep */
func_rc _wrappedkey_parser_wkey_set_wrapping_param_flavour(wrappedKeyCtx *wctx, CK_MECHANISM_TYPE wrapalg)
{
    wctx->aes_params.aes_wrapping_mech = wrapalg;
    return rc_ok;
}

static func_rc _wrappedkey_parser_append_attr(wrappedKeyCtx *wctx, CK_ATTRIBUTE_TYPE attrtyp, void *buffer, size_t len, parser_attr_target target )
{

    func_rc rc = rc_ok;
    CK_ATTRIBUTE stuffing;
    CK_ATTRIBUTE_PTR match=NULL;

    CK_ATTRIBUTE **attrlist=NULL;
    CK_ULONG *attrlen;

    switch(target) {
    case target_wkey:
	attrlist = &wctx->attrlist;
	attrlen = &wctx->attrlen;
	break;

    case target_pubk:
	attrlist = &wctx->pubkattrlist;
	attrlen = &wctx->pubkattrlen;
	break;

    default:
	rc = rc_error_oops;
	goto error;
    }

    /* we need to create the buffer and stuff it with what is passed as parameter */
    stuffing.type   = attrtyp;
    stuffing.pValue = malloc(len);

    if(stuffing.pValue == NULL) {
	fprintf(stderr, "Memory error\n");
	rc = rc_error_memory;
	goto error;
    }

    memcpy(stuffing.pValue, buffer, len); /* copy the value */
    stuffing.ulValueLen = len;

    if(*attrlen==PARSING_MAX_ATTRS-1) {
	fprintf(stderr, "reached maximum number of attributes in parsing\n");
	rc = rc_error_memory;
	goto error;
    }

    size_t arglen = *attrlen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

    match = (CK_ATTRIBUTE_PTR ) lsearch ( &stuffing,
					  *attrlist,
					  &arglen,
					  sizeof(CK_ATTRIBUTE),
					  compare_CKA );

    *attrlen = arglen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

    if( match == &stuffing) { /* match, we may need to adjust the content */
	if(match->pValue) { free(match->pValue); /* just in case */ }
	match->ulValueLen = stuffing.ulValueLen;
	match->pValue = stuffing.pValue; /* we steal the pointer  */
	stuffing.pValue = NULL;		 /* forget it in stuffing */
    } else {
	/* have the value inserted */
	/* lsearch is stealing the whole "stuffing" object */
	/* forget it  */
	stuffing.pValue = NULL;
    }

error:
    /* clean up */
    if (stuffing.pValue != NULL) { free(stuffing.pValue); }

    return rc;
}

inline func_rc _wrappedkey_parser_wkey_append_attr(wrappedKeyCtx *wctx, CK_ATTRIBUTE_TYPE attrtyp, void *buffer, size_t len)
{
    return _wrappedkey_parser_append_attr(wctx, attrtyp, buffer, len, target_wkey);
}

inline func_rc _wrappedkey_parser_pubk_append_attr(wrappedKeyCtx *wctx, CK_ATTRIBUTE_TYPE attrtyp, void *buffer, size_t len)
{
    return _wrappedkey_parser_append_attr(wctx, attrtyp, buffer, len, target_pubk);
}

inline func_rc _wrappedkey_parser_wkey_append_cryptogram(wrappedKeyCtx *wctx, unsigned char *b64buffer, int keyindex)
{
    return _wrappedkey_parser_append_from_b64(wctx, b64buffer, keyindex, target_wkey);
}

inline func_rc _wrappedkey_parser_pubk_append_pem(wrappedKeyCtx *wctx, unsigned char *b64buffer)
{
    return _wrappedkey_parser_append_from_b64(wctx, b64buffer, WRAPPEDKEYCTX_NO_INDEX, target_pubk);
}

static func_rc _wrappedkey_parser_append_from_b64(wrappedKeyCtx *wctx, unsigned char *b64buffer, int keyindex, parser_attr_target target)
{
    func_rc rc = rc_ok;

    BIO *bmem = NULL, *b64 = NULL;
    size_t inlen=0, totallen=0;
    unsigned char inbuf[64];
    FILE *fp = NULL;
    int readlen=0;

    CK_BYTE_PTR *dest_buffer;
    CK_ULONG *dest_len;

    switch(target) {
    case target_wkey:
	dest_buffer = &wctx->key[keyindex].wrapped_key_buffer;
	dest_len = &wctx->key[keyindex].wrapped_key_len;
	break;

    case target_pubk:
	dest_buffer = &wctx->pubk_buffer;
	dest_len = &wctx->pubk_len;
	break;

    default:
	rc = rc_error_oops;
	goto err;
    }

    bmem = BIO_new_mem_buf( b64buffer, -1); /* NULL-terminated string */
    if(bmem==NULL) {
	P_ERR();
	rc = rc_error_openssl_api;
	goto err;
    }

    b64 = BIO_new( BIO_f_base64() );
    if(b64==NULL) {
	P_ERR();
	rc = rc_error_openssl_api;
	goto err;
    }

    bmem = BIO_push(b64, bmem);	/* append bmem to b64 and return bmem, never fails */

    while((inlen = BIO_read(bmem, inbuf, sizeof(inbuf))) > 0) {
	totallen += inlen;
    }

    /* allocate memory */
    *dest_buffer = calloc( totallen, sizeof(unsigned char));
    if(*dest_buffer==NULL) {
	fprintf(stderr, "Memory error\n");
	rc = rc_error_memory;
	goto err;
    } else {
	*dest_len = totallen;
    }

    /* reset BIO and start over */
    BIO_reset(bmem);
    readlen = BIO_read(bmem, *dest_buffer, *dest_len);
    if(readlen<0) {
	P_ERR();
	rc = rc_error_openssl_api;
	goto err;
    }

err:

    if(bmem) { BIO_free_all(bmem); bmem = NULL; }

    if(rc!=rc_ok) {
	if(*dest_buffer != NULL) {
	    free(*dest_buffer);
	    *dest_buffer = NULL;
	    *dest_len = 0L;
	}
    }
    return rc;
}


/* parser/lexer guarantee we are with pkcs7 */
func_rc _wrappedkey_parser_wkey_set_wrapping_key(wrappedKeyCtx *wctx, void *buffer, size_t len)
{
    func_rc rc = rc_ok;

    if( wctx->wrappingkeylabel != NULL ) {
	fprintf(stderr, "***Error: wrapping key label can only be specified once\n");
	rc =rc_error_parsing;
    } else {
	wctx->wrappingkeylabel = memtostrdup(buffer,len);
	if(wctx->wrappingkeylabel==NULL) {
	    fprintf(stderr, "***Error: memory allocation error\n");
	    rc = rc_error_memory;
	}
    }
    return rc;
}

