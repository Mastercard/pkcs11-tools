/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2021 Mastercard
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
#include "attribctx_lexer.h"
#include "attribctx_parser.h"

/* attribCtx contains attributes captured from command-line interface */
/* it is designed to hold attributes into three lists: */
/* - the main list */
/* - a wrap template list */
/* - an unwrap template list */


attribCtx *pkcs11_new_attribcontext()
{

    attribCtx *ctx = NULL;

    ctx = calloc(1, sizeof (wrappedKeyCtx));
    
    if(ctx==NULL) {
	fprintf(stderr, "Error: not enough memory when allocating memory for attribCtx\n");
	goto error;
    }

    int i;

    /* pre-allocate arrays for three attribute lists */
    for(i=0; i<3; i++) {
	ctx->attrs[i].attrlist = calloc( CMDLINE_MAX_ATTRS, sizeof(CK_ATTRIBUTE) );
	if(ctx->attrs[i].attrlist == NULL) {
	    fprintf(stderr, "Error: not enough memory when allocating memory for attribute array of wrappedKeyCtx\n");
	    goto error;
	}
    }

    return ctx;
    
error:
    if(ctx) { pkcs11_free_attribcontext(ctx); ctx=NULL; }
    /* when zeroed, the structure is initialized and ready */
    return ctx;
}


void pkcs11_free_attribcontext(attribCtx *ctx)
{

    if( ctx ) {
	
	int i;

	for(i=0;i<3;i++) {
	    /* free up attributes */
	    if(ctx->attrs[i].attrlist) {

		/* we need to walk through the attribute list and individually free up each member */
		int j;

		for(j=0; j<ctx->attrs[i].attrnum; j++) {
		    if(ctx->attrs[i].attrlist[j].pValue) {
			if(!pkcs11_attr_is_template(ctx->attrs[i].attrlist[j].type)) {
			    free(ctx->attrs[i].attrlist[j].pValue);
			}
			ctx->attrs[i].attrlist[j].pValue=NULL;
			ctx->attrs[i].attrlist[j].ulValueLen = 0L;
		    }
		}

		/* free the list itself */
		free(ctx->attrs[i].attrlist);
		ctx->attrs[i].attrlist = NULL;
		ctx->attrs[i].attrnum = 0;
	    }
	}

	free(ctx);		/* eventually free up context mem */
    }
}


func_rc pkcs11_parse_attribs_from_argv(attribCtx *ctx , int pos, int argc, char **argv, const char *additional)
{
    func_rc rc = rc_ok;
    int i;
    size_t len=0;
    char *parsebuf = NULL;
    YY_BUFFER_STATE bp;
    
    /* we need to allocate a buffer that can hold a concatenated list of argv[], */
    /* starting from pos, and ending at argc, */
    /* each argument being separated with a space */

    for (i=pos; i<argc; ++i) {
	len+=strlen(argv[i]) + 1; /* +1 accounts for additional space used as separator */
    }

    /* if additional specified, account space for " *additional" */
    if(additional) { len+=strlen(additional)+1; } 
    
    /* we need to add another one more YY_END_OF_BUFFER_CHAR  */
    /* as we will be using yy_scan_buffer() like function */
    ++len;
    
    /* allocate buffer */
    parsebuf = calloc(len, sizeof(char));
    /* since YY_END_OF_BUFFER_CHAR = 0, we don't need to add these characters */
    /* as the buffer will contain two trailing 0 bytes */
    /* to support yy_scan_buffer() like function */

    if(parsebuf == NULL) {
	fprintf(stderr, "Error: not enough memory when allocating memory for pubkattrlist member\n");
	rc = rc_error_memory;
	goto error;
    }

    /* put additional upfront, to prevent argv interfering */
    if(additional) {
	strncat(parsebuf, additional, len-1); /* add additional */
	strncat(parsebuf, " ", len-1); /* add space before the additional */
    }
    /* now concatenate to it */
    for (i=pos; i<argc; ++i) {
	strncat(parsebuf, argv[i], len-1);
	if(i!=argc-1) {
	    strncat(parsebuf, " ", len-1); /* add space (lazy way) */
	}
    }

    bp = cl_scan_bytes(parsebuf, len);
    if(bp==NULL) {
	fprintf(stderr, "Error: lexer cannot scan buffer\n");
	rc = rc_error_lexer;
	goto error;
    }
    
    /* OK now we can try to parse the buffer */
    cl_switch_to_buffer(bp);

    /* the following will enable parser debugging */
    /* cldebug=1; */
    /* clset_debug(1); */

    if(clparse(ctx)) {
	rc = rc_error_parsing;
    }
    
error:
    if(parsebuf) { free(parsebuf); }
    if(bp) { cl_delete_buffer(bp); }

    return rc;
}


inline CK_ATTRIBUTE_PTR pkcs11_get_attrlist_from_attribctx(attribCtx *ctx)
{
    return ctx->attrs[ctx->mainlist_idx].attrlist;
}

inline size_t pkcs11_get_attrnum_from_attribctx(attribCtx *ctx)
{
    return ctx->attrs[ctx->mainlist_idx].attrnum;
}

inline void pkcs11_adjust_attrnum_on_attribctx(attribCtx *ctx, size_t value)
{
    ctx->attrs[ctx->mainlist_idx].attrnum = value;
}
