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

static func_rc _unwrap_rsa(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum, CK_MECHANISM_TYPE mech);
static func_rc _unwrap_cbcpad(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum);
static func_rc _unwrap_aes_key_wrap_mech(pkcs11Context *p11Context, wrappedKeyCtx *wctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum, CK_MECHANISM_TYPE mech[], CK_ULONG mech_size);
static func_rc _unwrap_envelope(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum);

/* INLINE FUNCS */
static inline func_rc _unwrap_rfc3394(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum) {
    return _unwrap_aes_key_wrap_mech(p11Context, ctx, wrappedkeylabel, attrlist, attrnum, ctx->p11Context->rfc3394_mech, ctx->p11Context->rfc3394_mech_size);
}

static inline func_rc _unwrap_rfc5649(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum) {
    return _unwrap_aes_key_wrap_mech(p11Context, ctx, wrappedkeylabel, attrlist, attrnum, ctx->p11Context->rfc5649_mech, ctx->p11Context->rfc5649_mech_size);
}

static inline func_rc _unwrap_pkcs1_15(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum) {
    return _unwrap_rsa(p11Context, ctx, wrappedkeylabel, attrlist, attrnum, CKM_RSA_PKCS);
}

static inline func_rc _unwrap_pkcs1_oaep(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum) {
    return _unwrap_rsa(p11Context, ctx, wrappedkeylabel, attrlist, attrnum, CKM_RSA_PKCS_OAEP);
}

inline const CK_OBJECT_HANDLE pkcs11_get_wrappedkeyhandle(wrappedKeyCtx *ctx)
{
    return ctx->is_envelope ? ctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrappedkeyhandle : ctx->key[WRAPPEDKEYCTX_LONE_KEY_INDEX].wrappedkeyhandle;
}

inline const CK_OBJECT_HANDLE pkcs11_get_publickeyhandle(wrappedKeyCtx *ctx)
{
    return ctx->pubkhandle;
}

/* some inline to shorten code */
static inline CK_ATTRIBUTE_PTR wrpk_get_attrlist(wrappedKeyCtx *wctx)
{
    return pkcs11_get_attrlist_from_attribctx(wctx->wrpkattribs);
}

static inline size_t wrpk_get_attrnum(wrappedKeyCtx *wctx)
{
    return pkcs11_get_attrnum_from_attribctx(wctx->wrpkattribs);
}

static inline void wrpk_set_attrnum(wrappedKeyCtx *wctx, size_t value)
{
    pkcs11_adjust_attrnum_on_attribctx(wctx->wrpkattribs, value);
}

static inline CK_ATTRIBUTE_PTR pubk_get_attrlist(wrappedKeyCtx *wctx)
{
    return pkcs11_get_attrlist_from_attribctx(wctx->pubkattribs);
}

static inline size_t pubk_get_attrnum(wrappedKeyCtx *wctx)
{
    return pkcs11_get_attrnum_from_attribctx(wctx->pubkattribs);
}

static inline void pubk_set_attrnum(wrappedKeyCtx *wctx, size_t value)
{
    pkcs11_adjust_attrnum_on_attribctx(wctx->pubkattribs, value);
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

func_rc pkcs11_unwrap(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappingkeylabel, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum, key_generation_t keygentype)
{
    func_rc rc;
    pkcs11AttrList *extended_attrs=NULL;

    if(ctx && p11Context) {
	CK_BBOOL cka_token = keygentype == kg_token ? CK_TRUE : CK_FALSE;
	CK_ATTRIBUTE token_attr[] = {
	    { CKA_TOKEN, &cka_token, sizeof cka_token },
	};

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

	/* Now, fix the attribute list. We want to enforce CKA_TOKEN value */
	/* if we unwrap, it must be set to CK_TRUE, regardless of the value found in file */

	extended_attrs = pkcs11_new_attrlist_from_array(NULL, attrlist, attrnum);
	if(extended_attrs == NULL) {
	    rc = rc_error_memory;
	    return rc;
	}

	pkcs11_attrlist_extend(extended_attrs, token_attr, sizeof token_attr / sizeof(CK_ATTRIBUTE) );

	/* in the very specific business where we want to unwrap as a session key, */
	/* we must also override any CKA_EXTRACTABLE attribute to CK_TRUE */
	if(keygentype==kg_session_for_wrapping) {
	    CK_BBOOL cka_extractable = CK_TRUE;
	    CK_ATTRIBUTE extractable_attr[] = {
		{ CKA_EXTRACTABLE, &cka_extractable, sizeof cka_extractable },
	    };

	    pkcs11_attrlist_extend(extended_attrs, extractable_attr, sizeof extractable_attr / sizeof(CK_ATTRIBUTE));
	}

	CK_ATTRIBUTE *extended_attrlist = pkcs11_attrlist_get_attributes_array(extended_attrs);
	CK_ULONG extended_attrlen = pkcs11_attrlist_get_attributes_len(extended_attrs);

	if(ctx->is_envelope==CK_TRUE) {
	    /* Do envelope unwrapping */
	    rc = _unwrap_envelope(p11Context, ctx, wrappedkeylabel, extended_attrlist, extended_attrlen);
	} else { /* do regular unwrap */
	    switch(ctx->key[WRAPPEDKEYCTX_LONE_KEY_INDEX].wrapping_meth) {
	    case w_pkcs1_15:
		rc = _unwrap_pkcs1_15(p11Context, ctx, wrappedkeylabel, extended_attrlist, extended_attrlen);
		break;

	    case w_pkcs1_oaep:
		rc = _unwrap_pkcs1_oaep(p11Context, ctx, wrappedkeylabel, extended_attrlist, extended_attrlen);
		break;

	    case w_cbcpad:
		rc = _unwrap_cbcpad(p11Context, ctx, wrappedkeylabel, extended_attrlist, extended_attrlen);
		break;

	    case w_rfc3394:
		rc = _unwrap_rfc3394(p11Context, ctx, wrappedkeylabel, extended_attrlist, extended_attrlen);
		break;

	    case w_rfc5649:
		rc = _unwrap_rfc5649(p11Context, ctx, wrappedkeylabel, extended_attrlist, extended_attrlen);
		break;

	    case w_unknown:
	    default:
		rc = rc_error_unknown_wrapping_alg;
	    }
	}

	if(rc==rc_ok && ctx->pubk_len>0 && pubk_get_attrnum(ctx)>0) {

	    pkcs11AttrList *pubk_extended_attrs = NULL;

	    pubk_extended_attrs = pkcs11_new_attrlist_from_array(NULL,
								 pubk_get_attrlist(ctx),
								 pubk_get_attrnum(ctx));
	    if(pubk_extended_attrs == NULL) {
		rc = rc_error_memory;
	    } else {
		/* force token behaviour, based on keygentype argument */
		pkcs11_attrlist_extend(pubk_extended_attrs, token_attr, sizeof token_attr / sizeof(CK_ATTRIBUTE) );

		CK_ATTRIBUTE *pubk_extended_attrlist = pkcs11_attrlist_get_attributes_array(pubk_extended_attrs);
		CK_ULONG pubk_extended_attrlen = pkcs11_attrlist_get_attributes_len(pubk_extended_attrs);

		ctx->pubkhandle = pkcs11_importpubk_from_buffer(p11Context,
								ctx->pubk_buffer,
								ctx->pubk_len,
								wrappedkeylabel,
								pubk_extended_attrlist,
								pubk_extended_attrlen );

		if(!ctx->pubkhandle) {
		    fprintf(stderr, "***Warning: could not import public key\n");
		    rc = rc_warning_not_entirely_completed;
		}
	    }
	    if(pubk_extended_attrs) pkcs11_delete_attrlist(pubk_extended_attrs);
	}
    } else {
	fprintf(stderr, "***Error: invalid arguments to pkcs11_unwrap()\n");
	rc = rc_error_usage;
    }

    if(extended_attrs) pkcs11_delete_attrlist(extended_attrs);
    return rc;
}

/* PKCS#1 1.5 and OAEP Unwrapping */

static func_rc _unwrap_rsa(pkcs11Context *p11Context, wrappedKeyCtx *wctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum, CK_MECHANISM_TYPE mech)
{
    func_rc rc = rc_ok;
    int i;
    char *label = NULL;

    CK_OBJECT_HANDLE wrappingkeyhandle=NULL_PTR;
    CK_OBJECT_HANDLE wrappedkeyhandle=NULL_PTR;
    CK_ATTRIBUTE *wrappedkeyattrlist=NULL_PTR;
    CK_ULONG wrappedkeyattrnum=0L;


    /* keyindex: in case of envelope wrapping, the index shall always be the outer */
    int keyindex = wctx->is_envelope ? WRAPPEDKEYCTX_OUTER_KEY_INDEX : WRAPPEDKEYCTX_LONE_KEY_INDEX;

    if(p11Context==NULL || wctx==NULL) {
	fprintf(stderr, "***Error: invalid argument to pkcs11_unwrap()\n");
	rc =rc_error_usage;
	goto error;
    }

    if(wctx->is_envelope) {
	/* in which case, we have to unwrap a temporary AES key */
	/* the template is passed as argument, we force its value */
	wrappingkeyhandle = wctx->key[keyindex].wrappingkeyhandle;
	wrappedkeyattrlist = attrlist;
	wrappedkeyattrnum = attrnum;
    } else {

	/* retrieve keys  */
	if (!pkcs11_findprivatekey(p11Context, wctx->wrappingkeylabel, &wrappingkeyhandle)) {
	    fprintf(stderr,"***Error: could not find a private key with label '%s'\n", wctx->wrappingkeylabel);
	    rc = rc_error_object_not_found;
	    goto error;
	}

	/* adjust CKA_LABEL with value received from argument */
	if(wrappedkeylabel !=NULL) {
	    CK_ATTRIBUTE nameattr;
	    CK_ULONG previousnum;

	    nameattr.type = CKA_LABEL;
	    nameattr.pValue = strdup(wrappedkeylabel); /* we cheat, as we alloc one more byte for '\0' */
	    if(nameattr.pValue == NULL) {
		fprintf(stderr, "***Error: memory allocation\n");
		rc = rc_error_memory;
		goto error;
	    }
	    nameattr.ulValueLen = strlen(wrappedkeylabel);

	    previousnum = wrpk_get_attrnum(wctx);
	    size_t argnum = previousnum; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	    CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &nameattr,
								 wrpk_get_attrlist(wctx),
								 &argnum,
								 sizeof(CK_ATTRIBUTE),
								 compare_CKA );

            /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	    wrpk_set_attrnum(wctx, argnum);

	    /* lsearch() returns a pointer to a matching member of  the  array, */
	    /* or to the newly added member if no match is found.	*/

	    if(previousnum < wrpk_get_attrnum(wctx)) {
		/* in this case, the content of attrlist[i] has been copied */
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

	/* TODO: print up content */
	for(i=0; i<attrnum && wrpk_get_attrnum(wctx)<PARSING_MAX_ATTRS; i++)
	{
	    /* lsearch will add the keys if not found in the template */

	    CK_ULONG previousnum = wrpk_get_attrnum(wctx);
	    size_t argnum = previousnum; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	    CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &attrlist[i],
								 wrpk_get_attrlist(wctx),
								 &argnum,
								 sizeof(CK_ATTRIBUTE),
								 compare_CKA );

            /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	    wrpk_set_attrnum(wctx, argnum);

	    /* lsearch() returns a pointer to a matching member of  the  array, */
	    /* or to the newly added member if no match is found.	*/

	    if(previousnum < wrpk_get_attrnum(wctx)) {
		/* in this case, the content of attrlist[i] has been copied */
		/* nothing to do */
	    } else {
		/* specific case: we point to an pre-existing key, */
		/* it means we need to change the content */

		/* free up previous value */
		if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }

	    }
	    /* in all cases, we just want to copy over the value from the source */
	    match->pValue = attrlist[i].pValue;
	    match->ulValueLen = attrlist[i].ulValueLen;
	    attrlist[i].pValue = NULL; /* indicate that the value has been stolen */
	}

	/* check if we do not have a similar object on the token yet */
	{
	    pkcs11AttrList * alist = pkcs11_cast_to_attrlist(p11Context,
							     wrpk_get_attrlist(wctx),
							     wrpk_get_attrnum(wctx));

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
#ifdef HAVE_DUPLICATES_ENABLED
				if(p11Context->can_duplicate) {
					fprintf(stdout,"***Warning: secret key with label '%s' already exists, duplicating\n", label);
				}
				else {
#endif
			fprintf(stderr,"***Error: secret key with label '%s' already exists\n", label);
			rc = rc_error_object_exists;
			goto error;
#ifdef HAVE_DUPLICATES_ENABLED
				}
#endif
		    }
		}
		pkcs11_delete_attrlist(alist);
	    }
	}
	wrappedkeyattrlist = wrpk_get_attrlist(wctx);
	wrappedkeyattrnum = wrpk_get_attrnum(wctx);

    }

    /* now unwrap */
    {
	CK_RV rv;
	CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };

	switch(mech) {
	case CKM_RSA_PKCS:	/* PKCS#1 1.5 */
	    break;

	case CKM_RSA_PKCS_OAEP: /* PKCS#1 OAEP */
	    mechanism.mechanism = CKM_RSA_PKCS_OAEP;
	    mechanism.pParameter = wctx->oaep_params;
	    mechanism.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
	    break;

	default:
	    rc = rc_error_oops;
	    goto error;
	}

	rv = p11Context->FunctionList.C_UnwrapKey ( p11Context->Session,
						    &mechanism,
						    wrappingkeyhandle,
						    wctx->key[keyindex].wrapped_key_buffer,
						    wctx->key[keyindex].wrapped_key_len,
						    wrappedkeyattrlist,
						    wrappedkeyattrnum,
						    &wrappedkeyhandle );

	if(rv!=CKR_OK) {
	    pkcs11_error(rv, "C_UnwrapKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	/* in case of envelope, save the middle key handle as the next wrappingkey handle */
	if(wctx->is_envelope) {
	    wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrappedkeyhandle = wrappedkeyhandle;
	    wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrappingkeyhandle = wrappedkeyhandle;
	} else {
	    wctx->key[WRAPPEDKEYCTX_LONE_KEY_INDEX].wrappedkeyhandle = wrappedkeyhandle;
	}
    }

error:
    if(label) { free(label); label=NULL; }

    return rc;
}



/* CBC-PAD Unwrapping */
/* documentation: check PKCS#11 specification, at CKM_AES_CBC_PAD for an overview with AES. */

static func_rc _unwrap_cbcpad(pkcs11Context *p11Context, wrappedKeyCtx *wctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum)
{
    func_rc rc = rc_ok;
    int i;
    char *label = NULL;

    CK_OBJECT_HANDLE wrappingkeyhandle=NULL_PTR;
    CK_OBJECT_HANDLE wrappedkeyhandle=NULL_PTR;
    pkcs11AttrList *alist = NULL;
    pkcs11AttrList *wklist = NULL;

    /* keyindex: in case of envelope wrapping, the index shall always be the outer */
    int keyindex = wctx->is_envelope ? WRAPPEDKEYCTX_INNER_KEY_INDEX : WRAPPEDKEYCTX_LONE_KEY_INDEX;

    if(p11Context==NULL || wctx==NULL) {
	fprintf(stderr, "***Error: invalid argument to pkcs11_unwrap()\n");
	rc =rc_error_usage;
	goto error;
    }

    /* retrieve keys  */
    if(wctx->is_envelope) {
	wrappingkeyhandle = wctx->key[keyindex].wrappingkeyhandle;
    } else {
	if (!pkcs11_findsecretkey(p11Context, wctx->wrappingkeylabel, &wrappingkeyhandle)) {
	    fprintf(stderr,"***Error: could not find a secret key with label '%s'\n", wctx->wrappingkeylabel);
	    rc = rc_error_object_not_found;
	    goto error;
	}
    }

    /* adjust CKA_LABEL with value from command line */
    if(wrappedkeylabel !=NULL) {
	CK_ATTRIBUTE nameattr;
	CK_ULONG previousnum;

	nameattr.type = CKA_LABEL;
	nameattr.pValue = strdup(wrappedkeylabel); /* we cheat, as we alloc one more byte for '\0' */
	if(nameattr.pValue == NULL) {
	    fprintf(stderr, "***Error: memory allocation\n");
	    rc = rc_error_memory;
	    goto error;
	}
	nameattr.ulValueLen = strlen(wrappedkeylabel);

	previousnum = wrpk_get_attrnum(wctx);
	size_t argnum = previousnum;
	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &nameattr,
							     wrpk_get_attrlist(wctx),
							     &argnum,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );

	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	wrpk_set_attrnum(wctx, argnum);

	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previousnum < wrpk_get_attrnum(wctx)) {
	    /* in this case, the content of attrlist[i] has been copied */
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


    /* TODO: print up content */
    for(i=0; i<attrnum && wrpk_get_attrnum(wctx)<PARSING_MAX_ATTRS; i++)
    {
	CK_ULONG previousnum = wrpk_get_attrnum(wctx);
	size_t argnum = previousnum; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	/* lsearch will add the keys if not found in the template */
	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &attrlist[i],
							     wrpk_get_attrlist(wctx),
							     &argnum,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );

	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	wrpk_set_attrnum(wctx, argnum);

	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previousnum < wrpk_get_attrnum(wctx)) {
	    /* in this case, the content of attrlist[i] has been copied */
	    /* nothing to do */
	} else {
	    /* specific case: we point to an pre-existing key, */
	    /* it means we need to change the content */

	    /* free up previous value */
	    if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }

	}
	/* in all cases, we just want to copy over the value from the source */
	match->pValue = attrlist[i].pValue;
	match->ulValueLen = attrlist[i].ulValueLen;
	attrlist[i].pValue = NULL; /* indicate that the value has been stolen */
    }

    /* check if we do not have a similar object on the token yet */
    {
	pkcs11AttrList * tmplist = pkcs11_cast_to_attrlist(p11Context,
							   wrpk_get_attrlist(wctx),
							   wrpk_get_attrnum(wctx));

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
#ifdef HAVE_DUPLICATES_ENABLED
			if(p11Context->can_duplicate) {
				fprintf(stdout,"***Warning: secret key with label '%s' already exists, duplicating\n", label);
			}
			else {
#endif
			fprintf(stderr,"***Error: secret key with label '%s' already exists\n", label);
			rc = rc_error_object_exists;
			goto error;
#ifdef HAVE_DUPLICATES_ENABLED
			}
#endif
		    }
		    break;

		case CKK_DH:
		case CKK_RSA:
		case CKK_EC:
		case CKK_EC_EDWARDS:
		    if(pkcs11_privatekey_exists(p11Context, label)) {
#ifdef HAVE_DUPLICATES_ENABLED
			if(p11Context->can_duplicate) {
				fprintf(stderr,"***Warning: private key with label '%s' already exists, duplicating\n", label);
			}
			else {	
#endif
			fprintf(stderr,"***Error: private key with label '%s' already exists\n", label);
			rc = rc_error_object_exists;
			goto error;
#ifdef HAVE_DUPLICATES_ENABLED
			}
#endif
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

	if( pkcs11_read_attr_from_handle (wklist, wrappingkeyhandle) == false) {
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
	    if(wctx->aes_params.iv_len==0) { /* if no IV is given, that's fine. We assume the vector is filled with 0x00 */
		mechanism.pParameter = iv0;
		mechanism.ulParameterLen = 8;
	    } else if(wctx->aes_params.iv_len==8) {
		mechanism.pParameter = wctx->aes_params.iv;
		mechanism.ulParameterLen = wctx->aes_params.iv_len;
	    } else {
		fprintf(stderr, "***Error: Invalid IV length for mechanism CKM_DES_CBC_PAD, this must be 8 bytes long\n");
		rc = rc_error_invalid_parameter_for_method;
		goto error;
	    }
	    break;

	case CKK_DES3:
	    mechanism.mechanism = CKM_DES3_CBC_PAD;
	if(wctx->aes_params.iv_len==0) { /* if no IV is given, that's fine. We assume the vector is filled with 0x00 */
	    mechanism.pParameter = iv0;
	    mechanism.ulParameterLen = 8;
	} else if(wctx->aes_params.iv_len==8) {
	    mechanism.pParameter = wctx->aes_params.iv;
	    mechanism.ulParameterLen = wctx->aes_params.iv_len;
	} else {
	    fprintf(stderr, "***Error: Invalid IV length for mechanism CKM_DES3_CBC_PAD, this must be 8 bytes long\n");
	    rc = rc_error_invalid_parameter_for_method;
	    goto error;
	}
	break;

	case CKK_AES:
	    mechanism.mechanism = CKM_AES_CBC_PAD;
	    if(wctx->aes_params.iv_len==0) { /* if no IV is given, that's fine. We assume the vector is filled with 0x00 */
		mechanism.pParameter = iv0;
		mechanism.ulParameterLen = 16;
	    } else if(wctx->aes_params.iv_len==16) {
		mechanism.pParameter = wctx->aes_params.iv;
		mechanism.ulParameterLen = wctx->aes_params.iv_len;
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
						    wrappingkeyhandle,
						    wctx->key[keyindex].wrapped_key_buffer,
						    wctx->key[keyindex].wrapped_key_len,
						    wrpk_get_attrlist(wctx),
						    wrpk_get_attrnum(wctx),
						    &wrappedkeyhandle );

	if(rv!=CKR_OK) {
	    pkcs11_error(rv, "C_UnwrapKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}
	wctx->key[keyindex].wrappedkeyhandle = wrappedkeyhandle; /* remember the recovered key */
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

static func_rc _unwrap_aes_key_wrap_mech(pkcs11Context *p11Context, wrappedKeyCtx *wctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum, CK_MECHANISM_TYPE mech[], CK_ULONG mech_size)
{
    func_rc rc = rc_ok;
    int i;
    char *label = NULL;

    CK_OBJECT_HANDLE wrappingkeyhandle=NULL_PTR;
    CK_OBJECT_HANDLE wrappedkeyhandle=NULL_PTR;
    pkcs11AttrList *alist = NULL;

    /* keyindex: in case of envelope wrapping, the index shall always be the outer */
    int keyindex = wctx->is_envelope ? WRAPPEDKEYCTX_INNER_KEY_INDEX : WRAPPEDKEYCTX_LONE_KEY_INDEX;

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

    if(wctx->is_envelope) {
	wrappingkeyhandle = wctx->key[keyindex].wrappingkeyhandle;
    } else {
	if (!pkcs11_findsecretkey(p11Context, wctx->wrappingkeylabel, &wrappingkeyhandle)) {
	    fprintf(stderr,"***Error: could not find a secret key with label '%s'\n", wctx->wrappingkeylabel);
	    rc = rc_error_object_not_found;
	    goto error;
	}
    }

    /* adjust CKA_LABEL with value from command line */
    if(wrappedkeylabel !=NULL) {
	CK_ATTRIBUTE nameattr;
	CK_ULONG previousnum;

	nameattr.type = CKA_LABEL;
	nameattr.pValue = strdup(wrappedkeylabel); /* we cheat, as we alloc one more byte for '\0' */
	if(nameattr.pValue == NULL) {
	    fprintf(stderr, "***Error: memory allocation\n");
	    rc = rc_error_memory;
	    goto error;
	}
	nameattr.ulValueLen = strlen(wrappedkeylabel);

	previousnum = wrpk_get_attrnum(wctx);
	size_t argnum = previousnum;
	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &nameattr,
							     wrpk_get_attrlist(wctx),
							     &argnum,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );

	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	wrpk_set_attrnum(wctx, argnum);

	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previousnum < wrpk_get_attrnum(wctx)) {
	    /* in this case, the content of attrlist[i] has been copied */
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

    /* TODO: print up content */
    for(i=0; i<attrnum && wrpk_get_attrnum(wctx)<PARSING_MAX_ATTRS; i++)
    {
	CK_ULONG previousnum = wrpk_get_attrnum(wctx);
	size_t argnum = previousnum; /* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */

	/* lsearch will add the keys if not found in the template */
	CK_ATTRIBUTE_PTR match = (CK_ATTRIBUTE_PTR) lsearch( &attrlist[i],
							     wrpk_get_attrlist(wctx),
							     &argnum,
							     sizeof(CK_ATTRIBUTE),
							     compare_CKA );

	/* trick to adapt on 32 bits architecture, as size(CK_ULONG)!=sizeof int */
	wrpk_set_attrnum(wctx, argnum);

	/* lsearch() returns a pointer to a matching member of  the  array, */
	/* or to the newly added member if no match is found.	*/

	if(previousnum < wrpk_get_attrnum(wctx)) {
	    /* in this case, the content of attrlist[i] has been copied */
	    /* nothing to do */
	} else {
	    /* specific case: we point to an pre-existing key, */
	    /* it means we need to change the content */

	    /* free up previous value */
	    if(match->pValue) { free(match->pValue); match->ulValueLen = 0L; }

	}
	/* in all cases, we just want to copy over the value from the source */
	match->pValue = attrlist[i].pValue;
	match->ulValueLen = attrlist[i].ulValueLen;
	attrlist[i].pValue = NULL; /* indicate that the value has been stolen */
    }

    /* check if we do not have a similar object on the token yet */
    {
	pkcs11AttrList * tmplist = pkcs11_cast_to_attrlist(p11Context,
							   wrpk_get_attrlist(wctx),
							   wrpk_get_attrnum(wctx));

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
#ifdef HAVE_DUPLICATES_ENABLED
			if(p11Context->can_duplicate) {
			fprintf(stderr,"***Warning: secret key with label '%s' already exists, duplicating\n", label);
			}
			else {
#endif
			fprintf(stderr,"***Error: secret key with label '%s' already exists\n", label);
			rc = rc_error_object_exists;
			goto error;
#ifdef HAVE_DUPLICATES_ENABLED
			}
#endif
		    }
		    break;

		case CKK_DH:
		case CKK_RSA:
		case CKK_EC:
		case CKK_EC_EDWARDS:
		    if(pkcs11_privatekey_exists(p11Context, label)) {
#ifdef HAVE_DUPLICATES_ENABLED
			if(p11Context->can_duplicate) {
				fprintf(stderr,"***Warning: private key with label '%s' already exists, duplicating\n", label);
			}
			else {
#endif
			fprintf(stderr,"***Error: private key with label '%s' already exists\n", label);
			rc = rc_error_object_exists;
			goto error;
#ifdef HAVE_DUPLICATES_ENABLED
			}
#endif
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
	    mechanism.mechanism = wctx->aes_params.aes_wrapping_mech != 0 ? wctx->aes_params.aes_wrapping_mech : mech[i];
	    rv = p11Context->FunctionList.C_UnwrapKey ( p11Context->Session,
							&mechanism,
							wrappingkeyhandle,
							wctx->key[keyindex].wrapped_key_buffer,
							wctx->key[keyindex].wrapped_key_len,
							wrpk_get_attrlist(wctx),
							wrpk_get_attrnum(wctx),
							&wrappedkeyhandle );

	    if(rv!=CKR_OK) {
		pkcs11_error(rv, "C_UnwrapKey");
		fprintf(stderr, "***Warning: It didn't work with %s\n", pkcs11_get_mechanism_name_from_type(mechanism.mechanism));
	    } else {
		/* it worked, let's remember in wctx the actual mechanism used */
		/* unless it was already supplied */
		if(wctx->aes_params.aes_wrapping_mech==0) {
		    wctx->aes_params.aes_wrapping_mech = mech[i];
		}
		/* and escape loop */
		break;
	    }

	    if(wctx->aes_params.aes_wrapping_mech != 0) {
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
	wctx->key[keyindex].wrappedkeyhandle = wrappedkeyhandle; /* remember the recovered key */
    }


error:
    if(label) { free(label); label=NULL; }
    if(alist) { pkcs11_delete_attrlist(alist); alist=NULL; }
    return rc;
}

/* envelope unwrapping */

static func_rc _unwrap_envelope(pkcs11Context *p11Context, wrappedKeyCtx *wctx, char *wrappedkeylabel, CK_ATTRIBUTE attrlist[], CK_ULONG attrnum)
{
    func_rc rc = rc_ok;
    char *label = NULL;

    CK_OBJECT_HANDLE wrappingkeyhandle=0, tempaes_handle=0;

    if(p11Context==NULL || wctx==NULL || wctx->is_envelope==0 ) {
	fprintf(stderr, "***Error: invalid argument to pkcs11_unwrap()\n");
	rc =rc_error_usage;
	goto error;
    }

    /* retrieve outer unwrapping key  */

    if (!pkcs11_findprivatekey(p11Context, wctx->wrappingkeylabel, &wrappingkeyhandle)) {
	fprintf(stderr,"***Error: could not find a private key with label '%s'\n", wctx->wrappingkeylabel);
	rc = rc_error_object_not_found;
	goto error;
    }

    wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrappingkeyhandle = wrappingkeyhandle;

    /* prepare for unwrapping */
    char tempaes_label[32];
    snprintf((char *)tempaes_label, sizeof tempaes_label, "tempaes-%ld", time(NULL));

    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;
    CK_OBJECT_CLASS cko_secret_key = CKO_SECRET_KEY;
    CK_KEY_TYPE ckk_aes = CKK_AES;

    CK_ATTRIBUTE tempaes_attrlist[] = {
	{ CKA_CLASS, &cko_secret_key, sizeof(cko_secret_key) },
	{ CKA_KEY_TYPE, &ckk_aes, sizeof(ckk_aes) },
	{ CKA_TOKEN, &ck_false, sizeof(ck_false) },
	{ CKA_UNWRAP, &ck_true, sizeof(ck_true) },
	{ CKA_EXTRACTABLE, &ck_false, sizeof(ck_false) }, /* the intermiediate key does not require to be extractable */
	{ CKA_LABEL, &tempaes_label, strlen(tempaes_label) }
    };

    switch(wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrapping_meth) {
    case w_pkcs1_15:
	rc = _unwrap_pkcs1_15(p11Context, wctx, tempaes_label, tempaes_attrlist, sizeof tempaes_attrlist / sizeof(CK_ATTRIBUTE));
	break;

    case w_pkcs1_oaep:
	rc = _unwrap_pkcs1_oaep(p11Context, wctx, tempaes_label, tempaes_attrlist, sizeof tempaes_attrlist / sizeof(CK_ATTRIBUTE));
	break;

    default:
	rc = rc_error_oops;
    }

    if(rc!=rc_ok) { goto error; }

    /* at this point, we have recovered a temporary unwrapping key */
    /* let's use it to unwrap the final key */

    switch(wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrapping_meth) {

    case w_cbcpad:
	rc = _unwrap_cbcpad(p11Context, wctx, wrappedkeylabel, attrlist, attrnum);
	break;

    case w_rfc3394:
	rc = _unwrap_rfc3394(p11Context, wctx, wrappedkeylabel, attrlist, attrnum);
	break;

    case w_rfc5649:
	rc = _unwrap_rfc5649(p11Context, wctx, wrappedkeylabel, attrlist, attrnum);
	break;

    default:
	rc = rc_error_oops;
    }

    if(rc!=rc_ok) { goto error; }

error:
    if(tempaes_handle!=0) {
	CK_RV rv = wctx->p11Context->FunctionList.C_DestroyObject(wctx->p11Context->Session, tempaes_handle);
	if(rv != CKR_OK) {
	    pkcs11_error( rv, "C_DestroyObject" );
	}
    }

    if(label) { free(label); label=NULL; }

    return rc;
}

