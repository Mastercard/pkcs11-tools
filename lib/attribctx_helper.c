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

/* attribctx_helper.c: contains routines used during parsing of wrap files or strings */
/* see attribctx_lexer.l and cmdline_parser.y for calling methods                     */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>


#include "pkcs11lib.h"
#include "attribctx_helper.h"


/* comparison function for attributes */
static int compare_CKA( const void *a, const void *b)
{
    return ((CK_ATTRIBUTE_PTR)a)->type == ((CK_ATTRIBUTE_PTR)b)->type ? 0 : -1;
}

/* append an attribute to the attribute context */
/* when the attribute is a template, the buffer is simply transmitted (as it remains within the attribctx structure) */
/* when the attribute is CKM_ALLOWED_MECHANISMS, the buffer is stolen (note that the caller must free it) */
/* when the attribute is not a template attribute, the buffer is copied */

func_rc _attribctx_parser_append_attr(attribCtx *clctx, CK_ATTRIBUTE_TYPE attrtyp, void *buffer, size_t len)
{
    func_rc rc = rc_ok;
    CK_ATTRIBUTE stuffing;
    CK_ATTRIBUTE_PTR match=NULL;

    CK_ATTRIBUTE **attrlist=NULL;
    size_t *attrnum;

    /* point to the right (current) attribute list */
    attrlist = &clctx->attrs[clctx->current_idx].attrlist;
    attrnum  = &clctx->attrs[clctx->current_idx].attrnum;

    /* we need to create the buffer and stuff it with what is passed as parameter */
    stuffing.type   = attrtyp;

    if(pkcs11_attr_is_template(attrtyp) || pkcs11_attr_is_allowed_mechanisms(attrtyp)) {
	stuffing.pValue = buffer; /* we pass the pointer, we don't allocate */
    } else {
	stuffing.pValue = malloc(len);

	if(stuffing.pValue == NULL) {
	    fprintf(stderr, "Memory error\n");
	    rc = rc_error_memory;
	    goto error;
	}

	memcpy(stuffing.pValue, buffer, len); /* copy the value */
    }
    stuffing.ulValueLen = len;
    
    if(*attrnum==PARSING_MAX_ATTRS-1) {
	fprintf(stderr, "reached maximum number of attributes in parsing\n");
	rc = rc_error_memory;
	goto error;
    }

    size_t argnum = *attrnum; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

    match = (CK_ATTRIBUTE_PTR ) lsearch ( &stuffing,
					  *attrlist,
					  &argnum,
					  sizeof(CK_ATTRIBUTE),
					  compare_CKA );

    *attrnum = argnum; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

    if(match == &stuffing) { /* match, we may need to adjust the content */
	if(match->pValue != NULL && !pkcs11_attr_is_template(match->type)) {
	    free(match->pValue); /* just in case */
	}
	
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
    if(stuffing.pValue != NULL
       && !pkcs11_attr_is_template(stuffing.type)
       && !pkcs11_attr_is_allowed_mechanisms(stuffing.type)) {
	free(stuffing.pValue);
    }

    return rc;
}

func_rc _attribctx_parser_assign_list_to_template(attribCtx *clctx, CK_ATTRIBUTE_TYPE attrtyp)
{
    func_rc rc = rc_ok;

    switch(attrtyp) {
    case CKA_WRAP_TEMPLATE:
	if(clctx->has_wrap_template==true) {
	    fprintf(stderr, "***Error: a wrap template can only be specified once\n");
	    rc = rc_error_parsing;
	    goto error;
	}
//	clctx->wraptemplate_idx = clctx->saved_idx; /* saved_idx is set by lexer */
	clctx->has_wrap_template = true;
	break;

    case CKA_UNWRAP_TEMPLATE:
	if(clctx->has_unwrap_template==true) {
	    fprintf(stderr, "***Error: an unwrap template can only be specified once\n");
	    rc = rc_error_parsing;
	    goto error;
	}
//	clctx->unwraptemplate_idx = clctx->saved_idx; /* saved_idx is set by lexer */
	clctx->has_unwrap_template = true;
	break;

    case CKA_DERIVE_TEMPLATE:
	if(clctx->has_derive_template==true) {
	    fprintf(stderr, "***Error: a derive template can only be specified once\n");
	    rc = rc_error_parsing;
	    goto error;
	}
//	clctx->derivetemplate_idx = clctx->saved_idx; /* saved_idx is set by lexer */
	clctx->has_derive_template = true;
	break;

    default:
	fprintf(stderr, "***Error: invalid template type - internal error\n");
	rc = rc_error_oops;
	goto error;
    }

    /* now we need to add a template attribute to the main list */
    rc = _attribctx_parser_append_attr(clctx,
				       attrtyp,
				       clctx->attrs[clctx->saved_idx].attrlist,
				       clctx->attrs[clctx->saved_idx].attrnum * sizeof(CK_ATTRIBUTE) );
error:
    return rc;
}



/* EOF */
