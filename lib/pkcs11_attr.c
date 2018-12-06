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
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "pkcs11lib.h"



/*--------*/

pkcs11AttrList *pkcs11_new_attrlist(pkcs11Context *p11Context, ...)
{

    va_list vl;
    CK_ATTRIBUTE_TYPE attrib;
    size_t cnt=0, i;

    pkcs11AttrList *retval=NULL;

    va_start(vl, p11Context);
    while( (attrib=va_arg(vl, CK_ATTRIBUTE_TYPE)) != _ATTR_END ) {
	++cnt;
    }
    va_end(vl);

    /* now cnt contains the size of the template array  */

    
    if( (retval=calloc(1,sizeof(pkcs11AttrList))) == NULL ) {
	goto error;
    }

    if(p11Context) {
	retval->p11Context = p11Context;	
	retval->GetAttributeValue  = p11Context->FunctionList.C_GetAttributeValue;
	retval->SetAttributeValue  = p11Context->FunctionList.C_SetAttributeValue;
    }

    if( (retval->attr_array=calloc(cnt,sizeof(CK_ATTRIBUTE))) == NULL) {
	goto error;
    }

    retval->allocated = cnt;

    /* rewalk to get the attributes and fill the array */

    va_start(vl, p11Context);

    for(i=0; i<cnt; i++) {
	retval->attr_array[i].type = va_arg(vl, CK_ATTRIBUTE_TYPE);
	retval->attr_array[i].pValue = NULL_PTR;
	retval->attr_array[i].ulValueLen = 0;
    }
    va_end(vl);

    return retval;

error:
    if(retval) {
	if(retval->attr_array) {
	    free(retval->attr_array); retval->attr_array=NULL;
	}
	free(retval); retval=NULL;
    }
    return retval;	    
}


pkcs11AttrList *pkcs11_cast_to_attrlist(pkcs11Context *p11Context, CK_ATTRIBUTE_PTR attrs, CK_ULONG numattrs)
{

    pkcs11AttrList *retval=NULL;
    
    if( (retval=calloc(1,sizeof(pkcs11AttrList))) == NULL ) {
	fprintf(stderr, "Memory allocation error\n");
	goto error;
    }

    if(p11Context) {
	retval->p11Context = p11Context;	
	retval->GetAttributeValue  = p11Context->FunctionList.C_GetAttributeValue;
	retval->SetAttributeValue  = p11Context->FunctionList.C_SetAttributeValue;
    }

    /* we increment a reference to the pointers */
    /* which means we don't want to take job of deleting them once done */
    retval->attr_array = attrs;
    retval->allocated = numattrs;
    retval->cast = 1;		/* remember we "created" the object from this API */
error:
    return retval;	    
}


void pkcs11_attrlist_assign_context(pkcs11AttrList *attrlist, pkcs11Context *p11Context)
{

    if(attrlist && p11Context) {
	attrlist->p11Context = p11Context;	
	attrlist->GetAttributeValue  = p11Context->FunctionList.C_GetAttributeValue;
	attrlist->SetAttributeValue  = p11Context->FunctionList.C_SetAttributeValue;
    }
}


CK_BBOOL pkcs11_set_attr_in_attrlist ( pkcs11AttrList *attrlist, 
				       CK_ATTRIBUTE_TYPE attrib,
				       CK_VOID_PTR pvalue,
				       CK_ULONG len )
{
    CK_BBOOL rc=CK_FALSE;
    
    if(attrlist) {
	int i;
	
	for(i=0; i<attrlist->allocated;i++) {
	    if(attrib==attrlist->attr_array[i].type) {
		/* if we have a match, first free previously assigned value */
		if(attrlist->attr_array[i].pValue) {
		    free(attrlist->attr_array[i].pValue);
		}
		
		/* allocate memory */
		attrlist->attr_array[i].pValue = malloc(len);

		if(attrlist->attr_array[i].pValue==NULL) {
		    fprintf(stderr, "oops malloc error\n");
		    break;
		}
		
		/* copy value into freshly allocated attrib */
		memcpy(attrlist->attr_array[i].pValue, pvalue, len);
		attrlist->attr_array[i].ulValueLen= len;
		rc = CK_TRUE;
		break;
	    }
	}
    }
    
    return rc;
}


CK_ATTRIBUTE_PTR pkcs11_get_attr_in_attrlist ( pkcs11AttrList *attrlist, 
					       CK_ATTRIBUTE_TYPE attrib )
{
    CK_ATTRIBUTE_PTR rc = NULL_PTR;

    if(attrlist) {
	int i;
	
	for(i=0; i<attrlist->allocated;i++) {
	    if(attrib==attrlist->attr_array[i].type) {
		rc = &(attrlist->attr_array[i]);
		break;		/* exit loop */
	    }
	}
    }
    
    return rc;
}


CK_BBOOL pkcs11_read_attr_from_handle ( pkcs11AttrList *attrlist, CK_OBJECT_HANDLE handle )
{
    CK_BBOOL rc=CK_FALSE;
    
    if(attrlist && attrlist->p11Context && handle) {
	CK_RV rv;
	int i;
	
	/* first of all cleanup everything */
	for(i=0; i<attrlist->allocated;i++) {
	    if(attrlist->attr_array[i].pValue) {
		free(attrlist->attr_array[i].pValue);
	    }
	    attrlist->attr_array[i].pValue = NULL_PTR;
	    attrlist->attr_array[i].ulValueLen = 0;
	}


	/* obtain buffer lengths to allocate */
	rv = attrlist->GetAttributeValue(attrlist->p11Context->Session, handle, attrlist->attr_array, attrlist->allocated);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
	    pkcs11_error( rv, "C_GetAttributeValue" );
	    goto error;
	}

	/* first of all cleanup everything */
	for(i=0; i<attrlist->allocated;i++) {
	    if( (long)(attrlist->attr_array[i].ulValueLen) == -1) { /* we need to check if we have -1. If so, skip alloc. */
		attrlist->attr_array[i].ulValueLen = 0L; /* force again value to 0 */
	    } else {
		if( (attrlist->attr_array[i].pValue=malloc(attrlist->attr_array[i].ulValueLen))==NULL ) {
		    fprintf(stderr, "malloc error");
		    goto error;
		}
	    }
	}
	    
	rv = attrlist->GetAttributeValue(attrlist->p11Context->Session, handle, attrlist->attr_array, attrlist->allocated);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID ) {
	    pkcs11_error( rv, "C_GetAttributeValue" );
	    goto error;
	}

	/* in case we have remaining invalid ulValueLen fields, adjust them */
	for(i=0; i<attrlist->allocated;i++) {
	    if( (long)(attrlist->attr_array[i].ulValueLen) == -1) { /* we need to check if we have -1. If so, skip alloc. */
		attrlist->attr_array[i].ulValueLen = 0L; /* force again value to 0 */
	    }
	}

	rc = CK_TRUE;
    }

error:
    return rc;
}

/* variadic arguments can specify a range of acceptable error codes from C_GetAttributeValue */
/* last item must be 0L */

CK_BBOOL pkcs11_read_attr_from_handle_ext ( pkcs11AttrList *attrlist, CK_OBJECT_HANDLE handle, ... )
{
    CK_BBOOL rc=CK_FALSE;
    va_list vl;
    CK_RV accepted_rv;
    
    if(attrlist && attrlist->p11Context && handle) {
	CK_RV rv;
	int i;
	
	/* first of all cleanup everything */
	for(i=0; i<attrlist->allocated;i++) {
	    if(attrlist->attr_array[i].pValue) {
		free(attrlist->attr_array[i].pValue);
	    }
	    attrlist->attr_array[i].pValue = NULL_PTR;
	    attrlist->attr_array[i].ulValueLen = 0;
	}


	/* obtain buffer lengths to allocate */
	rv = attrlist->GetAttributeValue(attrlist->p11Context->Session, handle, attrlist->attr_array, attrlist->allocated);

	/* skip accepted return codes */
	va_start(vl, handle);
	while( (accepted_rv=va_arg(vl, CK_RV)) != CKR_OK ) {
	    if(accepted_rv==rv) { 
		rv = CKR_OK;	/* force value and exit */
		break;
	    }
	}
	va_end(vl);

	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
	    pkcs11_error( rv, "C_GetAttributeValue" );
	    goto error;
	}

	/* first of all cleanup everything */
	for(i=0; i<attrlist->allocated;i++) {
	    if( (long)(attrlist->attr_array[i].ulValueLen) == -1) { /* we need to check if we have -1. If so, skip alloc. */
		attrlist->attr_array[i].ulValueLen = 0L; /* force again value to 0 */
	    } else {
		if( (attrlist->attr_array[i].pValue=malloc(attrlist->attr_array[i].ulValueLen))==NULL ) {
		    fprintf(stderr, "malloc error");
		    goto error;
		}
	    }
	}
	    
	rv = attrlist->GetAttributeValue(attrlist->p11Context->Session, handle, attrlist->attr_array, attrlist->allocated);

	/* skip accepted return codes */
	va_start(vl, handle);
	while( (accepted_rv=va_arg(vl, CK_RV)) != CKR_OK ) {
	    if(accepted_rv==rv) { 
		rv = CKR_OK;	/* force value and exit */
		break;
	    }
	}
	va_end(vl);

	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID ) {
	    pkcs11_error( rv, "C_GetAttributeValue" );
	    goto error;
	}

	/* in case we have remaining invalid ulValueLen fields, adjust them */
	for(i=0; i<attrlist->allocated;i++) {
	    if( (long)(attrlist->attr_array[i].ulValueLen) == -1) { /* we need to check if we have -1. If so, skip alloc. */
		attrlist->attr_array[i].ulValueLen = 0L; /* force again value to 0 */
	    }
	}

	rc = CK_TRUE;
    }

error:
    return rc;
}


void pkcs11_delete_attrlist(pkcs11AttrList *attrlist)
{
    if(attrlist) {
	/* we only free attrlist that were not cast */
	if(attrlist->cast==0 && attrlist->attr_array) {
	    int i;
	    for(i=0;i<attrlist->allocated;i++) {
		if(attrlist->attr_array[i].pValue) {
		    free(attrlist->attr_array[i].pValue);
		    attrlist->attr_array[i].pValue=NULL_PTR;
		    attrlist->attr_array[i].ulValueLen=0;
		}
	    }
	    free(attrlist->attr_array); 
	}
	free(attrlist);
    }
}


/* EOF */
