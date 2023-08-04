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
#include <stdbool.h>
#include "pkcs11lib.h"


/*--------*/

pkcs11AttrList *pkcs11_new_attrlist(pkcs11Context *p11Context, ...) {

    va_list vl;
    CK_ATTRIBUTE_TYPE attrib;
    size_t cnt = 0, i;

    pkcs11AttrList *retval = NULL;

    va_start(vl, p11Context);
    while ((attrib = va_arg(vl, CK_ATTRIBUTE_TYPE)) != _ATTR_END) {
	++cnt;
    }
    va_end(vl);

    /* now cnt contains the size of the template array  */


    if ((retval = calloc(1, sizeof(pkcs11AttrList))) == NULL) {
	goto error;
    }

    if (p11Context) {
	retval->p11Context = p11Context;
	retval->GetAttributeValue = p11Context->FunctionList.C_GetAttributeValue;
//        retval->SetAttributeValue = p11Context->FunctionList.C_SetAttributeValue;
    }

    if ((retval->attr_array = calloc(cnt, sizeof(CK_ATTRIBUTE))) == NULL) {
	goto error;
    }

    retval->allocated = cnt;

    /* rewalk to get the attributes and fill the array */

    va_start(vl, p11Context);

    for (i = 0; i < cnt; i++) {
	retval->attr_array[i].type = va_arg(vl, CK_ATTRIBUTE_TYPE);
	retval->attr_array[i].pValue = NULL_PTR;
	retval->attr_array[i].ulValueLen = 0;
    }
    va_end(vl);

    return retval;

    error:
    if (retval) {
	if (retval->attr_array) {
	    free(retval->attr_array);
	    retval->attr_array = NULL;
	}
	free(retval);
	retval = NULL;
    }
    return retval;
}

/* create  pkcs11AttrList * from an existing CK_ATTRIBUTE[] array (copy content) */
pkcs11AttrList *pkcs11_new_attrlist_from_array(pkcs11Context *p11Context, CK_ATTRIBUTE_PTR attrs, CK_ULONG attrlen) {

    pkcs11AttrList *retval = NULL;

    if ((retval = calloc(1, sizeof(pkcs11AttrList))) == NULL) {
	goto error;
    }

    if (p11Context) {
	retval->p11Context = p11Context;
	retval->GetAttributeValue = p11Context->FunctionList.C_GetAttributeValue;
//        retval->SetAttributeValue = p11Context->FunctionList.C_SetAttributeValue;
    }

    if ((retval->attr_array = calloc(attrlen, sizeof(CK_ATTRIBUTE))) == NULL) {
	goto error;
    }

    retval->allocated = attrlen;

    int i;
    for (i = 0; i < attrlen; i++) {
	retval->attr_array[i].type = attrs[i].type;
	retval->attr_array[i].pValue = malloc(attrs[i].ulValueLen);
	if (retval->attr_array[i].pValue == NULL) {
	    fprintf(stderr, "***Error : memory allocation\n");
	    goto error;
	}
	memcpy(retval->attr_array[i].pValue, attrs[i].pValue, attrs[i].ulValueLen);
	retval->attr_array[i].ulValueLen = attrs[i].ulValueLen;

	/* in case we copy a template attribute, we need also to clone the attributes value */
	if (pkcs11_attr_is_template(retval->attr_array[i].type)) {
	    /* pValue contains a list of attributes, that we need to cast and walk through. */
	    CK_ATTRIBUTE_PTR template_array = (CK_ATTRIBUTE_PTR) retval->attr_array[i].pValue;
	    size_t template_numelem = retval->attr_array[i].ulValueLen / sizeof(CK_ATTRIBUTE);

	    int j;
	    for (j = 0; j < template_numelem; j++) {
		/* we need first to allocate memory, using a temporary buffer */
		CK_VOID_PTR attribvalueclone;
		if ((attribvalueclone = malloc(template_array[j].ulValueLen)) == NULL) {
		    fprintf(stderr, "Memory allocation error");
		    goto error;    /* TODO better cleanup */
		}

		/* then we copy the content of the original attribute to the cloned one */
		memcpy(attribvalueclone, template_array[j].pValue, template_array[j].ulValueLen);

		/* finally we overwrite the previous pointer with the new one freshly allocated */
		template_array[j].pValue = attribvalueclone;
	    }
	}
    }

    return retval;

    error:
    if (retval) {
	if (retval->attr_array && retval->allocated > 0) {
	    int i;
	    for (i = 0; i < retval->allocated; i++) {
		if (retval->attr_array[i].pValue) {
		    free(retval->attr_array[i].pValue);
		    retval->attr_array[i].pValue = NULL;
		}
	    }
	    free(retval->attr_array);
	    retval->attr_array = NULL;
	}
	free(retval);
	retval = NULL;
    }
    return retval;
}

/* cast an array of CK_ATTRIBUTE into a pkcs11AttrList. Caution: this does not copy the attributes!!! */
pkcs11AttrList *pkcs11_cast_to_attrlist(pkcs11Context *p11Context, CK_ATTRIBUTE_PTR attrs, CK_ULONG numattrs) {

    pkcs11AttrList *retval = NULL;

    if ((retval = calloc(1, sizeof(pkcs11AttrList))) == NULL) {
	fprintf(stderr, "Memory allocation error\n");
	goto error;
    }

    if (p11Context) {
	retval->p11Context = p11Context;
	retval->GetAttributeValue = p11Context->FunctionList.C_GetAttributeValue;
//        retval->SetAttributeValue = p11Context->FunctionList.C_SetAttributeValue;
    }

    /* we increment a reference to the pointers */
    /* which means we don't want to take job of deleting them once done */
    retval->attr_array = attrs;
    retval->allocated = numattrs;
    retval->cast = true;        /* remember we "created" the object from this API */
    error:
    return retval;
}

void pkcs11_attrlist_assign_context(pkcs11AttrList *attrlist, pkcs11Context *p11Context) {

    if (attrlist && p11Context) {
	attrlist->p11Context = p11Context;
	attrlist->GetAttributeValue = p11Context->FunctionList.C_GetAttributeValue;
//        attrlist->SetAttributeValue = p11Context->FunctionList.C_SetAttributeValue;
    }
}


bool pkcs11_set_attr_in_attrlist(pkcs11AttrList *attrlist,
				 CK_ATTRIBUTE_TYPE attrib,
				 CK_VOID_PTR pvalue,
				 CK_ULONG len) {
    bool rc = false;

    if (attrlist) {
	int i;

	for (i = 0; i < attrlist->allocated; i++) {
	    if (attrib == attrlist->attr_array[i].type) {
		/* if we have a match, first free previously assigned value */
		if (attrlist->attr_array[i].pValue) {
		    free(attrlist->attr_array[i].pValue);
		}

		/* allocate memory */
		attrlist->attr_array[i].pValue = malloc(len);

		if (attrlist->attr_array[i].pValue == NULL) {
		    fprintf(stderr, "oops malloc error\n");
		    break;
		}

		/* copy value into freshly allocated attrib */
		memcpy(attrlist->attr_array[i].pValue, pvalue, len);
		attrlist->attr_array[i].ulValueLen = len;
		rc = true;
		break;
	    }
	}
    }

    return rc;
}


bool pkcs11_attrlist_has_attribute(const pkcs11AttrList *attrlist, CK_ATTRIBUTE_TYPE attrib) {
    bool rv = false;

    if (attrlist) {
	int i;

	for (i = 0; i < attrlist->allocated; i++) {
	    if (attrib == attrlist->attr_array[i].type) {
		rv = true;
		break;        /* exit loop */
	    }
	}
    }
    return rv;
}

CK_ATTRIBUTE_PTR pkcs11_get_attr_in_attrlist(pkcs11AttrList *attrlist,
					     CK_ATTRIBUTE_TYPE attrib) {
    CK_ATTRIBUTE_PTR rc = NULL_PTR;

    if (attrlist) {
	int i;

	for (i = 0; i < attrlist->allocated; i++) {
	    if (attrib == attrlist->attr_array[i].type) {
		rc = &(attrlist->attr_array[i]);
		break;        /* exit loop */
	    }
	}
    }

    return rc;
}

CK_ATTRIBUTE_PTR pkcs11_get_attr_in_array(CK_ATTRIBUTE_PTR array,
					  size_t arraysize,
					  CK_ATTRIBUTE_TYPE attrib) {
    CK_ATTRIBUTE_PTR rc = NULL_PTR;

    if (array && arraysize) {
	int i;

	for (i = 0; i < arraysize / sizeof(CK_ATTRIBUTE); i++) {
	    if (attrib == array[i].type) {
		rc = &array[i];
		break;        /* exit loop */
	    }
	}
    }
    return rc;
}


inline bool pkcs11_read_attr_from_handle(pkcs11AttrList *attrlist, CK_OBJECT_HANDLE handle) {
    return pkcs11_read_attr_from_handle_ext(attrlist, handle, 0L);
}

/* variadic arguments can specify a range of acceptable error codes from C_GetAttributeValue */
/* last item must be 0L, which is CKR_OK, i.e. not an error code                             */

bool pkcs11_read_attr_from_handle_ext(pkcs11AttrList *attrlist, CK_OBJECT_HANDLE handle, ...) {
    bool rc = false;
    va_list vl;
    CK_RV accepted_rv;

    if (attrlist && attrlist->p11Context && handle) {
	CK_RV rv;
	int i;

	/* first of all cleanup everything, and check if we have at least one template attribute */
	for (i = 0; i < attrlist->allocated; i++) {
	    if (attrlist->attr_array[i].pValue) {
		free(attrlist->attr_array[i].pValue);
	    }
	    attrlist->attr_array[i].pValue = NULL_PTR;
	    attrlist->attr_array[i].ulValueLen = 0;
	    if (attrlist->has_template == false
		&& pkcs11_attr_is_template(attrlist->attr_array[i].type) == true) {
		attrlist->has_template = true;
	    }
	}

	/* obtain buffer lengths to allocate */
	rv = attrlist->GetAttributeValue(attrlist->p11Context->Session, handle, attrlist->attr_array,
					 attrlist->allocated);

	/* skip accepted return codes */
	va_start(vl, handle);
	while ((accepted_rv = va_arg(vl, CK_RV)) != 0L) {
	    if (accepted_rv == rv) {
		rv = CKR_OK;    /* force value and exit */
		break;
	    }
	}
	va_end(vl);

	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
	    pkcs11_error(rv, "C_GetAttributeValue");
	    goto error;
	}

	/* populate array with buffers when requested */
	for (i = 0; i < attrlist->allocated; i++) {
	    if ((long) (attrlist->attr_array[i].ulValueLen) ==
		-1) { /* we need to check if we have -1. If so, skip alloc. */
		attrlist->attr_array[i].ulValueLen = 0L; /* force again value to 0 */
	    } else {
		/* we use calloc() because of attributes of type "Template" require to get clean buffers */
		/* so the content can be populated with expected lengths for buffers */
		if ((attrlist->attr_array[i].pValue = calloc(1, attrlist->attr_array[i].ulValueLen)) == NULL) {
		    fprintf(stderr, "Memory allocation error");
		    goto error;
		}
	    }
	}

	rv = attrlist->GetAttributeValue(attrlist->p11Context->Session, handle, attrlist->attr_array,
					 attrlist->allocated);

	/* skip accepted return codes */
	va_start(vl, handle);
	while ((accepted_rv = va_arg(vl, CK_RV)) != 0L) {
	    if (accepted_rv == rv) {
		rv = CKR_OK;    /* force value and exit */
		break;
	    }
	}
	va_end(vl);

	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
	    pkcs11_error(rv, "C_GetAttributeValue");
	    goto error;
	}

	/* in case we have remaining invalid ulValueLen fields, adjust them */
	for (i = 0; i < attrlist->allocated; i++) {
	    if ((long) (attrlist->attr_array[i].ulValueLen) ==
		-1) { /* we need to check if we have -1. If so, skip alloc. */
		attrlist->attr_array[i].ulValueLen = 0L; /* force again value to 0 */
	    }
	}

	/* special case: we have at least one template attribute */
	if (attrlist->has_template) {
	    for (i = 0; i < attrlist->allocated; i++) {
		if (pkcs11_attr_is_template(attrlist->attr_array[i].type)) {
		    /* pValue contains a list of attributes, that we need to cast and walk through. */
		    CK_ATTRIBUTE_PTR template_array = (CK_ATTRIBUTE_PTR) attrlist->attr_array[i].pValue;
		    size_t template_numelem = attrlist->attr_array[i].ulValueLen / sizeof(CK_ATTRIBUTE);

		    int j;
		    for (j = 0; j < template_numelem; j++) {
			if ((template_array[j].pValue = malloc(template_array[j].ulValueLen)) == NULL) {
			    fprintf(stderr, "Memory allocation error");
			    goto error;
			}
		    }
		}
	    }

	    /* OK, call GetAttributeValue for the third time */
	    rv = attrlist->GetAttributeValue(attrlist->p11Context->Session, handle, attrlist->attr_array,
					     attrlist->allocated);

	    /* skip accepted return codes */
	    va_start(vl, handle);
	    while ((accepted_rv = va_arg(vl, CK_RV)) != 0L) {
		if (accepted_rv == rv) {
		    rv = CKR_OK;    /* force value and exit */
		    break;
		}
	    }
	    va_end(vl);

	    if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		pkcs11_error(rv, "C_GetAttributeValue");
		goto error;
	    }

	    /* in case we have remaining invalid ulValueLen fields, adjust them */
	    for (i = 0; i < attrlist->allocated; i++) {
		if ((long) (attrlist->attr_array[i].ulValueLen) ==
		    -1) { /* we need to check if we have -1. If so, skip alloc. */
		    attrlist->attr_array[i].ulValueLen = 0L; /* force again value to 0 */
		}
	    }
	}
	rc = true;
    }

    error:                /* TODO: fix mem leaks resulting from errors in process */
    return rc;
}


void pkcs11_delete_attrlist(pkcs11AttrList *attrlist) {
    if (attrlist) {
	/* we only free attrlist that were not cast */
	if (attrlist->cast == false && attrlist->attr_array) {
	    int i;
	    for (i = 0; i < attrlist->allocated; i++) {
		if (attrlist->attr_array[i].pValue) {

		    /* special case: for templates, we need to free sub-buffers */
		    if (pkcs11_attr_is_template(attrlist->attr_array[i].type)) {
			/* pValue contains a list of attributes, that we need to cast and walk through. */
			CK_ATTRIBUTE_PTR template_array = (CK_ATTRIBUTE_PTR) attrlist->attr_array[i].pValue;
			size_t template_numelem = attrlist->attr_array[i].ulValueLen / sizeof(CK_ATTRIBUTE);

			int j;
			for (j = 0; j < template_numelem; j++) {
			    if (template_array[j].pValue) {
				free(template_array[j].pValue);
				template_array[j].pValue = NULL_PTR;
				template_array[j].ulValueLen = 0;
			    }
			}
		    }
		    free(attrlist->attr_array[i].pValue);
		    attrlist->attr_array[i].pValue = NULL_PTR;
		    attrlist->attr_array[i].ulValueLen = 0;
		}
	    }
	    free(attrlist->attr_array);
	}
	free(attrlist);
    }
}

inline CK_ATTRIBUTE *const pkcs11_attrlist_get_attributes_array(pkcs11AttrList *attrlist) {
    return attrlist->attr_array;
}

inline CK_ULONG const pkcs11_attrlist_get_attributes_len(pkcs11AttrList *attrlist) {
    return attrlist->allocated;
}


/* given an existing attrlist, extend with provided arguments */
pkcs11AttrList *pkcs11_attrlist_extend(pkcs11AttrList *attrlist, CK_ATTRIBUTE_PTR attrs, CK_ULONG numattrs) {
    pkcs11AttrList *retval = attrlist;

    if (attrlist && attrlist->cast == false) { /* we don't extend cast lists */
	if (numattrs > 0) {
	    int modified_inplace = 0;
	    int i;

	    /* first walk the attributes and change what can be changed, without reallocating */
	    for (i = 0; i < numattrs; i++) {
		if (pkcs11_set_attr_in_attrlist(attrlist, attrs[i].type, attrs[i].pValue, attrs[i].ulValueLen) == true) {
		    ++modified_inplace;
		}
	    }
	    if (modified_inplace < numattrs) { /* we have some attributes not existing in the current list */
		CK_ATTRIBUTE_PTR newlist = realloc(attrlist->attr_array,
						   (attrlist->allocated + numattrs - modified_inplace) *
						   sizeof(CK_ATTRIBUTE));
		if (newlist == NULL) {
		    fprintf(stderr, "***Error: memory reallocation\n");
		    goto error;
		}

		/* even if subsequent calls fail, we would keep the extended array */
		attrlist->attr_array = newlist; /* replace old list with new list */

		int extended_index;

		for (i = 0, extended_index = attrlist->allocated; i < numattrs; i++, extended_index++) {
		    /* if set_attr_in_attrlist returns CK_FALSE, it means we don't have a match ==> append it */
		    if (pkcs11_set_attr_in_attrlist(attrlist, attrs[i].type, attrs[i].pValue, attrs[i].ulValueLen) == CK_FALSE) {
			newlist[extended_index].type = attrs[i].type;
			newlist[extended_index].pValue = malloc(attrs[i].ulValueLen);
			if (newlist[extended_index].pValue == NULL) {
			    fprintf(stderr, "***Error: memory allocation\n");
			    goto error;
			}

			memcpy(newlist[extended_index].pValue, attrs[i].pValue,
			       attrs[i].ulValueLen); /* copy attribute */
			newlist[extended_index].ulValueLen = attrs[i].ulValueLen; /* adjust length */

			/* in case we extend a template attribute, we need also to clone the attributes value */
			if (pkcs11_attr_is_template(newlist[extended_index].type)) {
			    /* pValue contains a list of attributes, that we need to cast and walk through. */
			    CK_ATTRIBUTE_PTR template_array = (CK_ATTRIBUTE_PTR) newlist[extended_index].pValue;
			    size_t template_numelem = newlist[extended_index].ulValueLen / sizeof(CK_ATTRIBUTE);

			    int j;
			    for (j = 0; j < template_numelem; j++) {
				/* we need first to allocate memory, using a temporary buffer */
				CK_VOID_PTR attribvalueclone;
				if ((attribvalueclone = malloc(template_array[j].ulValueLen)) == NULL) {
				    fprintf(stderr, "Memory allocation error");
				    goto error;
				}

				/* then we copy the content of the original attribute to the cloned one */
				memcpy(attribvalueclone, template_array[j].pValue, template_array[j].ulValueLen);

				/* finally we overwrite the previous pointer with the new one freshly allocated */
				template_array[j].pValue = attribvalueclone;
			    }
			}

		    }
		}

		attrlist->allocated = attrlist->allocated + numattrs - modified_inplace; /* adjust array size */
	    }
	}
    }

    error:    /* TODO: fix mem leaks resulting from Error */
    return retval;
}

inline bool pkcs11_attr_is_template(CK_ATTRIBUTE_TYPE attrtype) {
    return attrtype == CKA_WRAP_TEMPLATE || attrtype == CKA_UNWRAP_TEMPLATE || attrtype == CKA_DERIVE_TEMPLATE;
}

inline bool pkcs11_attr_is_allowed_mechanisms(CK_ATTRIBUTE_TYPE attrtype) {
    return attrtype == CKA_ALLOWED_MECHANISMS;
}
/* EOF */
