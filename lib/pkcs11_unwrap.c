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


/*--------------------------------------------------------------------------------*/
/* PROTOTYPES */

static func_rc _unwrap_pkcs1_15(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs);
static func_rc _unwrap_pkcs1_oaep(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs);
static func_rc _unwrap_cbcpad(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs);
static func_rc _unwrap_aes_key_wrap_mech(pkcs11Context *p11Context, wrappedKeyCtx *wctx, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs, CK_MECHANISM_TYPE mech[], CK_ULONG mech_size);

/* INLINE FUNCS */
static inline func_rc _unwrap_rfc3394(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs) {
    return _unwrap_aes_key_wrap_mech(p11Context, ctx, wrappedkeylabel, attrs, numattrs, ctx->p11Context->rfc3394_mech, ctx->p11Context->rfc3394_mech_size);
}

static inline func_rc _unwrap_rfc5649(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs) {
    return _unwrap_aes_key_wrap_mech(p11Context, ctx, wrappedkeylabel, attrs, numattrs, ctx->p11Context->rfc5649_mech, ctx->p11Context->rfc5649_mech_size);
}

/*--------------------------------------------------------------------------------*/

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


wrappedKeyCtx *pkcs11_new_wrapped_key_from_file(pkcs11Context *p11Context, char *filename)
{

    int parserc = 0;
    FILE *fp;

    wrappedKeyCtx *wctx = pkcs11_new_wrappedkeycontext(p11Context);

    if((fp = fopen(filename, "r")) == NULL ) {
	perror("Cannot open file");
	goto error;
    }

    yyrestart(fp);

    do {
	parserc = yyparse(wctx);

    } while(!feof(yyin) && parserc==0);

    fclose(fp);

    if(parserc!=0) {
	fprintf(stderr, "***Error: parsing ended with an error (rc=%d)\n", parserc);
	goto error;
    }

    return wctx;

error:
    pkcs11_free_wrappedkeycontext(wctx);
    return NULL;
}



func_rc pkcs11_unwrap(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappingkeylabel, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs)
{
    func_rc rc;

    /* first of all, see if we have a wrappingkeylabel passed as argument.  */
    /* in which case, we override any label specified through the wrap file */
    if(wrappingkeylabel!=NULL) {
	if(ctx->wrappingkeylabel!=NULL) {
	    fprintf(stderr,"***Info: Using <%s> passed as command line argument instead of <%s> from file to unwrap the key\n", wrappingkeylabel, ctx->wrappingkeylabel);
	    free(ctx->wrappingkeylabel);
	    ctx->wrappingkeylabel=NULL;
	}
	ctx->wrappingkeylabel=strdup(wrappingkeylabel);
    } else {
	if(ctx->wrappingkeylabel==NULL) {
	    fprintf(stderr,"***Error: no wrapping key label specified\n");
	    rc = rc_error_invalid_label;
	    return rc;
	}
    }


    if(ctx!=NULL) {

	if(ctx->is_envelope==CK_TRUE) {
	    /* Do envelope unwrapping */
	    fprintf(stderr,"***NOT YET IMPLEMENTED\n");
	    rc = rc_error_unsupported;
	    return rc;
	} else { /* do regular unwrap */
	    switch(ctx->key[WRAPPEDKEYCTX_LONE_KEY_INDEX].wrapping_meth) {
	    case w_pkcs1_15:
		rc = _unwrap_pkcs1_15(p11Context, ctx, wrappedkeylabel, attrs, numattrs);
		break;

	    case w_pkcs1_oaep:
		rc = _unwrap_pkcs1_oaep(p11Context, ctx, wrappedkeylabel, attrs, numattrs);
		break;

	    case w_cbcpad:
		rc = _unwrap_cbcpad(p11Context, ctx, wrappedkeylabel, attrs, numattrs);
		break;

	    case w_rfc3394:
		rc = _unwrap_rfc3394(p11Context, ctx, wrappedkeylabel, attrs, numattrs);
		break;

	    case w_rfc5649:
		rc = _unwrap_rfc5649(p11Context, ctx, wrappedkeylabel, attrs, numattrs);
		break;

	    case w_unknown:
	    default:
		rc = rc_error_unknown_wrapping_alg;
	    }
	}
    } else {
	fprintf(stderr, "***Error: NULL wrapping context\n");
	rc = rc_error_usage;
    }
    return rc;
}

/* PKCS#1 1.5 Unwrapping */

static func_rc _unwrap_pkcs1_15(pkcs11Context *p11Context, wrappedKeyCtx *wctx, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs)
{
    func_rc rc = rc_ok;
    int i;
    char *label = NULL;
    
    CK_OBJECT_HANDLE hWrappingKey=NULL_PTR;
    CK_OBJECT_HANDLE hWrappedKey=NULL_PTR;
    pkcs11AttrList *wrappedkey_attrs = NULL, *wrappingkey_attrs = NULL;
    CK_ATTRIBUTE_PTR o_wrappingkey_bits, o_wrappedkey_bits, o_modulus;
    BIGNUM *bn_wrappingkey_bits = NULL;
    BIGNUM *bn_wrappedkey_bits = NULL;

    if(p11Context==NULL || wctx==NULL) {
	fprintf(stderr, "***Error: invalid argument to pkcs11_unwrap()\n");
	rc =rc_error_usage;
	goto error;
    }
    /* retrieve keys  */
    
    if (!pkcs11_findprivatekey(p11Context, wctx->wrappingkeylabel, &hWrappingKey)) {
	fprintf(stderr,"***Error: could not find a private key with label '%s'\n", wctx->wrappingkeylabel);
	rc = rc_error_object_not_found;
	goto error;
    }

    /* adjust CKA_LABEL with value from command line */    
    if(wrappedkeylabel !=NULL) {
	CK_ATTRIBUTE nameattr;
	CK_ULONG previouslen;

	nameattr.type = CKA_LABEL;
	nameattr.pValue = strdup(wrappedkeylabel); /* we cheat, as we alloc one more byte for '\0' */
	if(nameattr.pValue == NULL) {
	    fprintf(stderr, "***Error: memory allocation\n");
	    rc = rc_error_memory;
	    goto error;
	}	
	nameattr.ulValueLen = strlen(wrappedkeylabel);

	previouslen = wctx->attrlen;
	size_t arglen = wctx->attrlen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	
	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &nameattr,
							     wctx->attrlist, 
							     &arglen,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );

	wctx->attrlen = arglen;	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previouslen < wctx->attrlen) {
	    /* in this case, the content of attrs[i] has been copied */
	    /* nothing to do */
	} else {
	    /* specific case: we point to an pre-existing key, */
	    /* it means we need to change the content */

	    /* free up previous value */
	    if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }
	    
	}
	/* in all cases, we just want to copy over the value from the source */
	match->pValue = nameattr.pValue;
	match->ulValueLen = nameattr.ulValueLen;
	nameattr.pValue = NULL; /* indicate that the value has been stolen */
	
    }
    /* adjust context with attributes from argmunent list */

    /* TODO: force CKA_TOKEN=true */
    /* TODO: print up content */
    for(i=0; i<numattrs && wctx->attrlen<PARSING_MAX_ATTRS; i++)
    {
	/* lsearch will add the keys if not found in the template */

	CK_ULONG previouslen = wctx->attrlen;
	size_t arglen = wctx->attrlen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	
	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &attrs[i], 
							     wctx->attrlist, 
							     &arglen,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );
	
	wctx->attrlen = arglen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	
	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previouslen < wctx->attrlen) {
	    /* in this case, the content of attrs[i] has been copied */
	    /* nothing to do */
	} else {
	    /* specific case: we point to an pre-existing key, */
	    /* it means we need to change the content */

	    /* free up previous value */
	    if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }
	    
	}
	/* in all cases, we just want to copy over the value from the source */
	match->pValue = attrs[i].pValue;
	match->ulValueLen = attrs[i].ulValueLen;
	attrs[i].pValue = NULL; /* indicate that the value has been stolen */
    }

    /* check if we do not have a similar object on the token yet */
    {
	pkcs11AttrList * alist = pkcs11_cast_to_attrlist(p11Context, wctx->attrlist, wctx->attrlen);

	if(alist) {
	    /* let's find the CKA_LABEL from that list */
	    CK_ATTRIBUTE_PTR alabel = pkcs11_get_attr_in_attrlist ( alist, CKA_LABEL );

	    if ( alabel != NULL ) {
		
		label = memtostrdup( alabel->pValue, alabel->ulValueLen);
		
		if(label==NULL) {
		    fprintf(stderr,"memory allocation error\n");
		    rc = rc_error_memory;
		    goto error;
		}
		
		if(pkcs11_secretkey_exists(p11Context, label)) {
		    fprintf(stderr,"***Error: secret key with label '%s' already exists\n", label);
		    rc = rc_error_object_exists;
		    goto error;
		}
	    }
	    pkcs11_delete_attrlist(alist);
	}
    }

    /* now unwrap */

    {
	CK_RV rv;
	CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };/* PKCS #1 1.5 unwrap */

	
	rv = p11Context->FunctionList.C_UnwrapKey ( p11Context->Session,
						    &mechanism,
						    hWrappingKey,
						    wctx->wrapped_key_buffer,
						    wctx->wrapped_key_len,
						    wctx->attrlist,
						    wctx->attrlen,
						    &hWrappedKey );
	
	if(rv!=CKR_OK) {
	    pkcs11_error(rv, "C_UnwrapKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}
    }

    

error:
    if(label) { free(label); label=NULL; }
    
    return rc;
}


/* PKCS#1 OAEP Unwrapping */

static func_rc _unwrap_pkcs1_oaep(pkcs11Context *p11Context, wrappedKeyCtx *wctx, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs)
{
    func_rc rc = rc_ok;
    int i;
    char *label = NULL;
    
    CK_OBJECT_HANDLE hWrappingKey=NULL_PTR;
    CK_OBJECT_HANDLE hWrappedKey=NULL_PTR;
    pkcs11AttrList *wrappedkey_attrs = NULL, *wrappingkey_attrs = NULL;
    CK_ATTRIBUTE_PTR o_wrappingkey_bits, o_wrappedkey_bits, o_modulus;
    BIGNUM *bn_wrappingkey_bits = NULL;
    BIGNUM *bn_wrappedkey_bits = NULL;

    if(p11Context==NULL || wctx==NULL) {
	fprintf(stderr, "***Error: invalid argument to pkcs11_unwrap()\n");
	rc =rc_error_usage;
	goto error;
    }
    /* retrieve keys  */
    
    if (!pkcs11_findprivatekey(p11Context, wctx->wrappingkeylabel, &hWrappingKey)) {
	fprintf(stderr,"***Error: could not find a private key with label '%s'\n", wctx->wrappingkeylabel);
	rc = rc_error_object_not_found;
	goto error;
    }

    /* adjust CKA_LABEL with value from command line */    
    if(wrappedkeylabel !=NULL) {
	CK_ATTRIBUTE nameattr;
	CK_ULONG previouslen;

	nameattr.type = CKA_LABEL;
	nameattr.pValue = strdup(wrappedkeylabel); /* we cheat, as we alloc one more byte for '\0' */
	if(nameattr.pValue == NULL) {
	    fprintf(stderr, "***Error: memory allocation\n");
	    rc = rc_error_memory;
	    goto error;
	}	
	nameattr.ulValueLen = strlen(wrappedkeylabel);

	previouslen = wctx->attrlen;	
	size_t arglen = wctx->attrlen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	
	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &nameattr,
							     wctx->attrlist, 
							     &arglen,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );
	
	wctx->attrlen = arglen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/
	
	if(previouslen < wctx->attrlen) {
	    /* in this case, the content of attrs[i] has been copied */
	    /* nothing to do */
	} else {
	    /* specific case: we point to an pre-existing key, */
	    /* it means we need to change the content */

	    /* free up previous value */
	    if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }
	    
	}
	/* in all cases, we just want to copy over the value from the source */
	match->pValue = nameattr.pValue;
	match->ulValueLen = nameattr.ulValueLen;
	nameattr.pValue = NULL; /* indicate that the value has been stolen */
	
    }
    /* adjust context with attributes from argmunent list */


    /* TODO: force CKA_TOKEN=true */
    /* TODO: print up content */
    for(i=0; i<numattrs && wctx->attrlen<PARSING_MAX_ATTRS; i++)
    {
	/* lsearch will add the keys if not found in the template */

	CK_ULONG previouslen = wctx->attrlen;
	size_t arglen = wctx->attrlen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	
	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &attrs[i], 
							     wctx->attrlist, 
							     &arglen,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );

	wctx->attrlen = arglen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */	

        /* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previouslen < wctx->attrlen) {
	    /* in this case, the content of attrs[i] has been copied */
	    /* nothing to do */
	} else {
	    /* specific case: we point to an pre-existing key, */
	    /* it means we need to change the content */

	    /* free up previous value */
	    if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }
	    
	}
	/* in all cases, we just want to copy over the value from the source */
	match->pValue = attrs[i].pValue;
	match->ulValueLen = attrs[i].ulValueLen;
	attrs[i].pValue = NULL; /* indicate that the value has been stolen */
    }

    /* check if we do not have a similar object on the token yet */
    {
	pkcs11AttrList * alist = pkcs11_cast_to_attrlist(p11Context, wctx->attrlist, wctx->attrlen);

	if(alist) {
	    /* let's find the CKA_LABEL from that list */
	    CK_ATTRIBUTE_PTR alabel = pkcs11_get_attr_in_attrlist ( alist, CKA_LABEL );
	    
	    if ( alabel != NULL ) {
		
		label = memtostrdup( alabel->pValue, alabel->ulValueLen);
		
		if(label==NULL) {
		    fprintf(stderr,"memory allocation error\n");
		    rc = rc_error_memory;
		    goto error;
		}
		
		if(pkcs11_secretkey_exists(p11Context, label)) {
		    fprintf(stderr,"***Error: secret key with label '%s' already exists\n", label);
		    rc = rc_error_object_exists;
		    goto error;
		}
	    }
	    pkcs11_delete_attrlist(alist);	    
	}
    }    
    /* now unwrap */

    {
	CK_RV rv;
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_OAEP, wctx->oaep_params, sizeof(CK_RSA_PKCS_OAEP_PARAMS) };/* PKCS #1 OAEP unwrap */
	
	rv = p11Context->FunctionList.C_UnwrapKey ( p11Context->Session,
						    &mechanism,
						    hWrappingKey,
						    wctx->wrapped_key_buffer,
						    wctx->wrapped_key_len,
						    wctx->attrlist,
						    wctx->attrlen,
						    &hWrappedKey );
	
	if(rv!=CKR_OK) {
	    pkcs11_error(rv, "C_UnwrapKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}
    }

    

error:
    if(label) { free(label); label=NULL; }

    return rc;
}



/* CBC-PAD Unwrapping */
/* documentation: check PKCS#11 specification, at CKM_AES_CBC_PAD for an overview with AES. */

static func_rc _unwrap_cbcpad(pkcs11Context *p11Context, wrappedKeyCtx *wctx, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs)
{
    func_rc rc = rc_ok;
    int i;
    char *label = NULL;

    CK_OBJECT_HANDLE hWrappingKey=NULL_PTR;
    CK_OBJECT_HANDLE hWrappedKey=NULL_PTR;
    pkcs11AttrList *wrappedkey_attrs = NULL, *wrappingkey_attrs = NULL;
    CK_ATTRIBUTE_PTR o_wrappingkey_bits, o_wrappedkey_bits, o_modulus;
    BIGNUM *bn_wrappingkey_bits = NULL;
    BIGNUM *bn_wrappedkey_bits = NULL;
    pkcs11AttrList *alist = NULL;
    pkcs11AttrList *wklist = NULL;

    if(p11Context==NULL || wctx==NULL) {
	fprintf(stderr, "***Error: invalid argument to pkcs11_unwrap()\n");
	rc =rc_error_usage;
	goto error;
    }
    /* retrieve keys  */

    if (!pkcs11_findsecretkey(p11Context, wctx->wrappingkeylabel, &hWrappingKey)) {
	fprintf(stderr,"***Error: could not find a secret key with label '%s'\n", wctx->wrappingkeylabel);
	rc = rc_error_object_not_found;
	goto error;
    }

    /* adjust CKA_LABEL with value from command line */
    if(wrappedkeylabel !=NULL) {
	CK_ATTRIBUTE nameattr;
	CK_ULONG previouslen;

	nameattr.type = CKA_LABEL;
	nameattr.pValue = strdup(wrappedkeylabel); /* we cheat, as we alloc one more byte for '\0' */
	if(nameattr.pValue == NULL) {
	    fprintf(stderr, "***Error: memory allocation\n");
	    rc = rc_error_memory;
	    goto error;
	}
	nameattr.ulValueLen = strlen(wrappedkeylabel);

	previouslen = wctx->attrlen;
	size_t arglen = wctx->attrlen;
	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &nameattr,
							     wctx->attrlist,
							     &arglen,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );

	wctx->attrlen = arglen;	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previouslen < wctx->attrlen) {
	    /* in this case, the content of attrs[i] has been copied */
	    /* nothing to do */
	} else {
	    /* specific case: we point to an pre-existing key, */
	    /* it means we need to change the content */

	    /* free up previous value */
	    if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }

	}
	/* in all cases, we just want to copy over the value from the source */
	match->pValue = nameattr.pValue;
	match->ulValueLen = nameattr.ulValueLen;
	nameattr.pValue = NULL; /* indicate that the value has been stolen */

    }
    /* adjust context with attributes from argmunent list */


    /* TODO: force CKA_TOKEN=true */
    /* TODO: print up content */
    for(i=0; i<numattrs && wctx->attrlen<PARSING_MAX_ATTRS; i++)
    {
	CK_ULONG previouslen = wctx->attrlen;
	size_t arglen = wctx->attrlen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	/* lsearch will add the keys if not found in the template */
	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &attrs[i],
							     wctx->attrlist,
							     &arglen,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );

	wctx->attrlen = arglen;	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previouslen < wctx->attrlen) {
	    /* in this case, the content of attrs[i] has been copied */
	    /* nothing to do */
	} else {
	    /* specific case: we point to an pre-existing key, */
	    /* it means we need to change the content */

	    /* free up previous value */
	    if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }

	}
	/* in all cases, we just want to copy over the value from the source */
	match->pValue = attrs[i].pValue;
	match->ulValueLen = attrs[i].ulValueLen;
	attrs[i].pValue = NULL; /* indicate that the value has been stolen */
    }

    /* check if we do not have a similar object on the token yet */
    {
	pkcs11AttrList * tmplist = pkcs11_cast_to_attrlist(p11Context, wctx->attrlist, wctx->attrlen);

	if(tmplist) {
	    /* let's find the CKA_LABEL from that list */
	    CK_ATTRIBUTE_PTR alabel = pkcs11_get_attr_in_attrlist ( tmplist, CKA_LABEL );
	    CK_ATTRIBUTE_PTR akeytype = pkcs11_get_attr_in_attrlist ( tmplist, CKA_KEY_TYPE );

	    if ( alabel != NULL && akeytype != NULL) {

		label = memtostrdup( alabel->pValue, alabel->ulValueLen);

		if(label==NULL) {
		    fprintf(stderr,"memory allocation error\n");
		    rc = rc_error_memory;
		    goto error;
		}

		switch( *((CK_KEY_TYPE *)(akeytype->pValue)) ) {
		case CKK_DES:
		case CKK_DES2:
		case CKK_DES3:
		case CKK_AES:
		case CKK_GENERIC_SECRET:
		case CKK_SHA_1_HMAC:
		case CKK_SHA256_HMAC:
		case CKK_SHA224_HMAC:
		case CKK_SHA384_HMAC:
		case CKK_SHA512_HMAC:
		    if(pkcs11_secretkey_exists(p11Context, label)) {
			fprintf(stderr,"***Error: secret key with label '%s' already exists\n", label);
			rc = rc_error_object_exists;
			goto error;
		    }
		    break;

		case CKK_DH:
		case CKK_RSA:
		case CKK_EC:
		    if(pkcs11_privatekey_exists(p11Context, label)) {
			fprintf(stderr,"***Error: private key with label '%s' already exists\n", label);
			rc = rc_error_object_exists;
			goto error;
		    }
		    break;

		default:
		    fprintf(stderr, "unsupported key type for unwrapping. Sorry.\n");
		    rc =rc_error_unsupported;
		    goto error;
		}
	    }
	    pkcs11_delete_attrlist(tmplist);
	}
    }

    /* now unwrap */

    {
	CK_RV rv;
	CK_MECHANISM mechanism;
	CK_BYTE iv0[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	CK_ATTRIBUTE_PTR wkkeytype = NULL;

	/* we need to determine the mechanism, based on the wrapping key type */

	wklist = pkcs11_new_attrlist(p11Context, CKA_KEY_TYPE, _ATTR_END);
	if(!wklist) {
	    fprintf(stderr, "Memory allocation error\n");
	    rc = rc_error_memory;
	    goto error;
	}

	if( pkcs11_read_attr_from_handle (wklist, hWrappingKey) == CK_FALSE) {
	    fprintf(stderr, "***Error: cannot read attributes from wrapping key\n");
	    goto error;
	}

	wkkeytype = pkcs11_get_attr_in_attrlist ( wklist, CKA_KEY_TYPE );
	if(!wkkeytype) {
	    fprintf(stderr, "Memory allocation error\n");
	    rc = rc_error_memory;
	    goto error;
	}

	/* now we know what we have, lets also check if IV length is appropriate */
	switch( *((CK_KEY_TYPE *)(wkkeytype->pValue)) ) {
	case CKK_DES:
	    mechanism.mechanism = CKM_DES_CBC_PAD;
	    if(wctx->iv_len==0) { /* if no IV is given, that's fine. We assume the vector is filled with 0x00 */
		mechanism.pParameter = iv0;
		mechanism.ulParameterLen = 8;
	    } else if(wctx->iv_len==8) {
		mechanism.pParameter = wctx->iv;
		mechanism.ulParameterLen = wctx->iv_len;
	    } else {
		fprintf(stderr, "***Error: Invalid IV length for mechanism CKM_DES_CBC_PAD, this must be 8 bytes long\n");
		rc = rc_error_invalid_parameter_for_method;
		goto error;
	    }
	    break;

	case CKK_DES3:
	    mechanism.mechanism = CKM_DES3_CBC_PAD;
	if(wctx->iv_len==0) { /* if no IV is given, that's fine. We assume the vector is filled with 0x00 */
	    mechanism.pParameter = iv0;
	    mechanism.ulParameterLen = 8;
	} else if(wctx->iv_len==8) {
	    mechanism.pParameter = wctx->iv;
	    mechanism.ulParameterLen = wctx->iv_len;
	} else {
	    fprintf(stderr, "***Error: Invalid IV length for mechanism CKM_DES3_CBC_PAD, this must be 8 bytes long\n");
	    rc = rc_error_invalid_parameter_for_method;
	    goto error;
	}
	break;

	case CKK_AES:
	    mechanism.mechanism = CKM_AES_CBC_PAD;
	    if(wctx->iv_len==0) { /* if no IV is given, that's fine. We assume the vector is filled with 0x00 */
		mechanism.pParameter = iv0;
		mechanism.ulParameterLen = 16;
	    } else if(wctx->iv_len==16) {
		mechanism.pParameter = wctx->iv;
		mechanism.ulParameterLen = wctx->iv_len;
	    } else {
		fprintf(stderr, "***Error: Invalid IV length for mechanism CKM_DES_AES_PAD, this must be 16 bytes long\n");
		rc = rc_error_invalid_parameter_for_method;
		goto error;
	    }
	    break;

	case CKK_DES2:		/* DES2 has no unwrap mech defined !!?! */
	default:
	    fprintf(stderr, "***Error: Unsupported unwrapping algorithm for wrapping key type\n");
	    rc = rc_error_unsupported;
	    goto error;
	    break;
	}

	rv = p11Context->FunctionList.C_UnwrapKey ( p11Context->Session,
						    &mechanism,
						    hWrappingKey,
						    wctx->wrapped_key_buffer,
						    wctx->wrapped_key_len,
						    wctx->attrlist,
						    wctx->attrlen,
						    &hWrappedKey );

	if(rv!=CKR_OK) {
	    pkcs11_error(rv, "C_UnwrapKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}
    }



error:
    if(label) { free(label); label=NULL; }
    if(alist) { pkcs11_delete_attrlist(alist); alist=NULL; }
    if(wklist) { pkcs11_delete_attrlist(wklist); wklist=NULL; }
    return rc;
}

/**********************************************************************
  NIST SP 800-38F wrapping mechanisms

  There are two wrapping mechanism families available:
  - CKM_AES_KEY_WRAP and equivalents corresponds to AE-KW and AD-KW from NIST 800-38F, and
    is documented in RFC3394
  - CKM_AES_KEY_WRAP_PAD and equivalents corresponds to AE-KWP and AD-KWP from the same NIST document,
    and is documented in RFC5649

************************************************************************/

static func_rc _unwrap_aes_key_wrap_mech(pkcs11Context *p11Context, wrappedKeyCtx *wctx, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs, CK_MECHANISM_TYPE mech[], CK_ULONG mech_size)
{
    func_rc rc = rc_ok;
    int i;
    char *label = NULL;

    CK_OBJECT_HANDLE hWrappingKey=NULL_PTR;
    CK_OBJECT_HANDLE hWrappedKey=NULL_PTR;
    pkcs11AttrList *wrappedkey_attrs = NULL, *wrappingkey_attrs = NULL;
    CK_ATTRIBUTE_PTR o_wrappingkey_bits, o_wrappedkey_bits, o_modulus;
    BIGNUM *bn_wrappingkey_bits = NULL;
    BIGNUM *bn_wrappedkey_bits = NULL;
    pkcs11AttrList *alist = NULL;

    /* sanity check */
    if(p11Context==NULL || wctx==NULL) {
	fprintf(stderr, "***Error: invalid argument to pkcs11_unwrap()\n");
	rc =rc_error_usage;
	goto error;
    }

    if(mech_size==0 || mech_size>AES_WRAP_MECH_SIZE_MAX) {
	fprintf(stderr, "***Error: invalid unwrapping mechanism table size\n");
	rc = rc_error_invalid_parameter_for_method;
	goto error;
    }

    /* retrieve keys  */

    if (!pkcs11_findsecretkey(p11Context, wctx->wrappingkeylabel, &hWrappingKey)) {
	fprintf(stderr,"***Error: could not find a secret key with label '%s'\n", wctx->wrappingkeylabel);
	rc = rc_error_object_not_found;
	goto error;
    }

    /* adjust CKA_LABEL with value from command line */
    if(wrappedkeylabel !=NULL) {
	CK_ATTRIBUTE nameattr;
	CK_ULONG previouslen;

	nameattr.type = CKA_LABEL;
	nameattr.pValue = strdup(wrappedkeylabel); /* we cheat, as we alloc one more byte for '\0' */
	if(nameattr.pValue == NULL) {
	    fprintf(stderr, "***Error: memory allocation\n");
	    rc = rc_error_memory;
	    goto error;
	}
	nameattr.ulValueLen = strlen(wrappedkeylabel);

	previouslen = wctx->attrlen;
	size_t arglen = wctx->attrlen;
	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &nameattr,
							     wctx->attrlist,
							     &arglen,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );

	wctx->attrlen = arglen;	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previouslen < wctx->attrlen) {
	    /* in this case, the content of attrs[i] has been copied */
	    /* nothing to do */
	} else {
	    /* specific case: we point to an pre-existing key, */
	    /* it means we need to change the content */

	    /* free up previous value */
	    if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }

	}
	/* in all cases, we just want to copy over the value from the source */
	match->pValue = nameattr.pValue;
	match->ulValueLen = nameattr.ulValueLen;
	nameattr.pValue = NULL; /* indicate that the value has been stolen */

    }
    /* adjust context with attributes from argmunent list */


    /* TODO: force CKA_TOKEN=true */
    /* TODO: print up content */
    for(i=0; i<numattrs && wctx->attrlen<PARSING_MAX_ATTRS; i++)
    {
	CK_ULONG previouslen = wctx->attrlen;
	size_t arglen = wctx->attrlen; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	/* lsearch will add the keys if not found in the template */
	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &attrs[i],
							     wctx->attrlist,
							     &arglen,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );

	wctx->attrlen = arglen;	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previouslen < wctx->attrlen) {
	    /* in this case, the content of attrs[i] has been copied */
	    /* nothing to do */
	} else {
	    /* specific case: we point to an pre-existing key, */
	    /* it means we need to change the content */

	    /* free up previous value */
	    if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }

	}
	/* in all cases, we just want to copy over the value from the source */
	match->pValue = attrs[i].pValue;
	match->ulValueLen = attrs[i].ulValueLen;
	attrs[i].pValue = NULL; /* indicate that the value has been stolen */
    }

    /* check if we do not have a similar object on the token yet */
    {
	pkcs11AttrList * tmplist = pkcs11_cast_to_attrlist(p11Context, wctx->attrlist, wctx->attrlen);

	if(tmplist) {
	    /* let's find the CKA_LABEL from that list */
	    CK_ATTRIBUTE_PTR alabel = pkcs11_get_attr_in_attrlist ( tmplist, CKA_LABEL );
	    CK_ATTRIBUTE_PTR akeytype = pkcs11_get_attr_in_attrlist ( tmplist, CKA_KEY_TYPE );

	    if ( alabel != NULL && akeytype != NULL) {

		label = memtostrdup( alabel->pValue, alabel->ulValueLen);

		if(label==NULL) {
		    fprintf(stderr,"memory allocation error\n");
		    rc = rc_error_memory;
		    goto error;
		}

		switch( *((CK_KEY_TYPE *)(akeytype->pValue)) ) {
		case CKK_DES:
		case CKK_DES2:
		case CKK_DES3:
		case CKK_AES:
		case CKK_GENERIC_SECRET:
		case CKK_SHA_1_HMAC:
		case CKK_SHA256_HMAC:
		case CKK_SHA224_HMAC:
		case CKK_SHA384_HMAC:
		case CKK_SHA512_HMAC:
		    if(pkcs11_secretkey_exists(p11Context, label)) {
			fprintf(stderr,"***Error: secret key with label '%s' already exists\n", label);
			rc = rc_error_object_exists;
			goto error;
		    }
		    break;

		case CKK_DH:
		case CKK_RSA:
		case CKK_EC:
		    if(pkcs11_privatekey_exists(p11Context, label)) {
			fprintf(stderr,"***Error: private key with label '%s' already exists\n", label);
			rc = rc_error_object_exists;
			goto error;
		    }
		    break;

		default:
		    fprintf(stderr, "unsupported key type for unwrapping. Sorry.\n");
		    rc =rc_error_unsupported;
		    goto error;
		}
	    }
	    pkcs11_delete_attrlist(tmplist);
	}
    }

    /* now unwrap */

    {
	CK_RV rv;
	CK_MECHANISM mechanism = { 0L, NULL, 0L };
	CK_ULONG i;

	/* first call to know what will be the size output buffer */
	for(i=0;i< mech_size; i++) {
            /* let's try mechanisms one by one, unless the mechanism is already supplied  */
	    /* i.e. if wctx->aes_wrapping_mech != 0 */
	    mechanism.mechanism = wctx->aes_wrapping_mech != 0 ? wctx->aes_wrapping_mech : mech[i];
	    rv = p11Context->FunctionList.C_UnwrapKey ( p11Context->Session,
							&mechanism,
							hWrappingKey,
							wctx->wrapped_key_buffer,
							wctx->wrapped_key_len,
							wctx->attrlist,
							wctx->attrlen,
							&hWrappedKey );

	    if(rv!=CKR_OK) {
		pkcs11_error(rv, "C_UnwrapKey");
		fprintf(stderr, "***Warning: It didn't work with %s\n", get_mechanism_name(mechanism.mechanism));
	    } else {
		/* it worked, let's remember in wctx the actual mechanism used */
		/* unless it was already supplied */
		if(wctx->aes_wrapping_mech==0) {
		    wctx->aes_wrapping_mech = mech[i];
		}
		/* and escape loop */
		break;
	    }

	    if(wctx->aes_wrapping_mech != 0) {
		/* special case: if the wrapping mechanism was set by the parser */
		/* through option field, we will not try other mechanisms than the one  */
		/* specified. */
		break;
	    }
	}

	if(rv!=CKR_OK) {	/* we couldn't find a suitable mech */
	    fprintf(stderr, "***Error: tried all mechanisms, no one worked\n");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}
    }


error:
    if(label) { free(label); label=NULL; }
    if(alist) { pkcs11_delete_attrlist(alist); alist=NULL; }
    return rc;
}
