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


#define P11SEARCH_NUM_HANDLES 64

/* Heap buffer used by pkcs11_alloc_fetch_all() to prefetch all matching object
   handles before a mutation (cp/mv/rm/setattr). The buffer starts at
   P11SEARCH_PREFETCH_INITIAL entries (~8 KB) and grows by doubling up to
   P11SEARCH_PREFETCH_MAX entries (~1 MB); beyond that the operation bails out. */
#define P11SEARCH_PREFETCH_INITIAL 1000
#define P11SEARCH_PREFETCH_MAX     128000


pkcs11Search * pkcs11_new_search( pkcs11Context *p11Context, CK_ATTRIBUTE_PTR search, CK_ULONG length)
{
    pkcs11Search *p11s = NULL;
    CK_RV retCode;

    p11s = calloc(1, sizeof(pkcs11Search));

    if(p11s==NULL) {
	fprintf(stderr, "Error: Can't allocate memory for pkcs11Search structure");
	goto error;
    }

    p11s->p11Context = p11Context;
    p11s->FindObjectsInit  = p11Context->FunctionList.C_FindObjectsInit;
    p11s->FindObjects      = p11Context->FunctionList.C_FindObjects;
    p11s->FindObjectsFinal = p11Context->FunctionList.C_FindObjectsFinal;

    p11s->handle_array = calloc( P11SEARCH_NUM_HANDLES, sizeof (CK_OBJECT_HANDLE));

    if(p11s->handle_array==NULL) {
	fprintf(stderr, "Error: Can't allocate memory for pkcs11Search handle array");
	goto error;
    }

    p11s->allocated = P11SEARCH_NUM_HANDLES;
    p11s->count = p11s->index = 0;


    if ( ( retCode = p11s->FindObjectsInit( p11Context->Session, search, length ) ) != CKR_OK )
    {
	pkcs11_error( retCode, "C_FindObjectsInit" );
	goto error;
    }

    return p11s;

error:
    if(p11s) {
	if(p11s->handle_array) {
	    free(p11s->handle_array);
	    p11s->handle_array=NULL;
	}
	free(p11s);
	p11s = NULL;
    }

    return p11s;
}


pkcs11Search * pkcs11_new_search_from_idtemplate( pkcs11Context *p11Context, pkcs11IdTemplate *idtmpl)
{
    pkcs11Search *p11s = NULL;
    
    if(p11Context && idtmpl) {
	p11s = pkcs11_new_search(p11Context, idtmpl->template, idtmpl->template_len);
    }
    return p11s;
}



CK_OBJECT_HANDLE pkcs11_fetch_next(pkcs11Search *p11s)
{

    CK_OBJECT_HANDLE rv = 0;

    if(p11s) {
	/* have we ever executed FindObjects? */
	if(p11s->count==0 || (p11s->count>0 && p11s->index==p11s->count) ) {
	    CK_RV retCode;    

	    if ( ( retCode = p11s->FindObjects( p11s->p11Context->Session, 
						p11s->handle_array,
						p11s->allocated, 
						&(p11s->count)  ) ) != CKR_OK )
	    {
		pkcs11_error( retCode, "C_FindObjects" );
		return NULL_PTR;
	    }
	    p11s->index=0;		/* reset index */
	}
	
	if(p11s->count>0 && p11s->index < p11s->count) {
	    rv = p11s->handle_array[p11s->index++];
	}
    }
    return rv;

}


/* pkcs11_alloc_fetch_all() prefetches every matching object handle into a
   single heap-allocated array. This is required before a mutation
   (cp/mv/rm/setattr): the search cursor cannot be safely iterated while the
   underlying objects are being modified, so all handles are collected first and
   the search is closed afterwards.

   The buffer starts at P11SEARCH_PREFETCH_INITIAL entries and grows by doubling
   up to P11SEARCH_PREFETCH_MAX entries; if more objects are found the function
   bails out with an error.

   On success, *out_handles points to an array of *out_count handles that the
   caller must release with pkcs11_free_handle_array(). Returns true on
   success, false on error. */
bool pkcs11_alloc_fetch_all(pkcs11Search *p11s, CK_OBJECT_HANDLE **out_handles, CK_ULONG *out_count)
{
    CK_OBJECT_HANDLE *handles = NULL;
    CK_ULONG capacity = 0;
    CK_ULONG count = 0;
    CK_OBJECT_HANDLE hndl;

    if(p11s==NULL || out_handles==NULL || out_count==NULL) {
	return false;
    }

    capacity = P11SEARCH_PREFETCH_INITIAL;
    handles = calloc(capacity, sizeof(CK_OBJECT_HANDLE));
    if(handles==NULL) {
	fprintf(stderr, "Error: can't allocate memory for prefetch handle array\n");
	return false;
    }

    while( (hndl = pkcs11_fetch_next(p11s)) != 0 ) {
	if(count == capacity) {
	    CK_OBJECT_HANDLE *tmp;
	    CK_ULONG new_capacity;

	    /* enforce the hard upper bound to cap memory usage */
	    if(capacity >= P11SEARCH_PREFETCH_MAX) {
		fprintf(stderr,
			"Error: too many objects to prefetch (limit=%lu)\n",
			(unsigned long)P11SEARCH_PREFETCH_MAX);
		free(handles);
		return false;
	    }

	    new_capacity = capacity * 2;
	    if(new_capacity > P11SEARCH_PREFETCH_MAX) {
		new_capacity = P11SEARCH_PREFETCH_MAX;
	    }

	    tmp = realloc(handles, new_capacity * sizeof(CK_OBJECT_HANDLE));
	    if(tmp==NULL) {
		fprintf(stderr, "Error: can't grow prefetch handle array\n");
		free(handles);
		return false;
	    }
	    handles = tmp;
	    capacity = new_capacity;
	}
	handles[count++] = hndl;
    }

    *out_handles = handles;
    *out_count = count;
    return true;
}


/* pkcs11_free_handle_array() releases an array previously allocated by
   pkcs11_alloc_fetch_all(). Safe to call with a NULL pointer. */
void pkcs11_free_handle_array(CK_OBJECT_HANDLE *handles)
{
    if(handles) {
	free(handles);
    }
}


void pkcs11_delete_search(pkcs11Search *p11s)
{

    if(p11s) {
	CK_RV retCode;    

	if ( ( retCode = p11s->FindObjectsFinal( p11s->p11Context->Session ) ) != CKR_OK ) {
	    pkcs11_error( retCode, "C_FindObjectsFinal" );
	}

	if(p11s->handle_array) {
	    free(p11s->handle_array);
	    p11s->handle_array=NULL;
	}
	free(p11s);
	p11s = NULL;
    }
}


/* high-level search functions */

static int pkcs11_object_with_class_exists(pkcs11Context *p11Context, char *label, CK_OBJECT_CLASS cla)
{

    int rv=0;
    pkcs11Search *search=NULL;
    CK_OBJECT_CLASS oclass = cla;

    CK_ATTRIBUTE searchTemplate[] = {
	{ CKA_CLASS, &oclass, sizeof oclass },
	{ CKA_LABEL, label, strlen(label) },
    };

    search = pkcs11_new_search( p11Context, searchTemplate, sizeof(searchTemplate) / sizeof(CK_ATTRIBUTE) );


    if(search) {		/* we just need one hit */
	rv = pkcs11_fetch_next(search)!=0 ? 1 : 0 ;
	pkcs11_delete_search(search);
    }

    return rv;
}

static CK_OBJECT_HANDLE pkcs11_find_object_with_class(pkcs11Context *p11Context, char *label, CK_OBJECT_CLASS cla)
{

    pkcs11Search *search=NULL;
    CK_OBJECT_CLASS oclass = cla;
    CK_OBJECT_HANDLE hndl=NULL_PTR;

    CK_ATTRIBUTE searchTemplate[] = {
	{ CKA_CLASS, &oclass, sizeof oclass },
	{ CKA_LABEL, label, strlen(label) },
    };

    search = pkcs11_new_search( p11Context, searchTemplate, sizeof(searchTemplate) / sizeof(CK_ATTRIBUTE) );


    if(search) {		/* we stop by the first hit */
	
	hndl = pkcs11_fetch_next(search);
    
	pkcs11_delete_search(search);

    }

    return hndl;
}


int pkcs11_label_exists(pkcs11Context *p11Context, char *label)
{

    int rv=0;
    pkcs11Search *search=NULL;
    CK_ATTRIBUTE searchTemplate[] = {
	{ CKA_LABEL, label, strlen(label) },
    };

    search = pkcs11_new_search( p11Context, searchTemplate, sizeof(searchTemplate) / sizeof(CK_ATTRIBUTE) );


    if(search) {		/* we just need one hit */
	rv = pkcs11_fetch_next(search)!=0 ? 1 : 0 ;
	pkcs11_delete_search(search);
    }

    return rv;
}


inline int pkcs11_privatekey_exists(pkcs11Context *p11Context, char *label)
{
    return pkcs11_object_with_class_exists(p11Context, label, CKO_PRIVATE_KEY);
}

inline int pkcs11_publickey_exists(pkcs11Context *p11Context, char *label)
{
    return pkcs11_object_with_class_exists(p11Context, label, CKO_PUBLIC_KEY);
}

inline int pkcs11_secretkey_exists(pkcs11Context *p11Context, char *label)
{
    return pkcs11_object_with_class_exists(p11Context, label, CKO_SECRET_KEY);
}

inline int pkcs11_certificate_exists(pkcs11Context *p11Context, char *label)
{
    return pkcs11_object_with_class_exists(p11Context, label, CKO_CERTIFICATE);
}

inline int pkcs11_data_exists(pkcs11Context *p11Context, char *label)
{
    return pkcs11_object_with_class_exists(p11Context, label, CKO_DATA);
}


int pkcs11_findkeypair(pkcs11Context *p11Context, char *label, CK_OBJECT_HANDLE_PTR hPublicKey, CK_OBJECT_HANDLE_PTR hPrivateKey)
{

    int rv=0;

    *hPrivateKey = pkcs11_find_object_with_class(p11Context, label, CKO_PRIVATE_KEY);
    *hPublicKey  = pkcs11_find_object_with_class(p11Context, label, CKO_PUBLIC_KEY);

    /* we need hPrivateKey. hPublicKey is optional. */
    if (*hPrivateKey != NULL_PTR) { 
	rv++;
	if (*hPublicKey != NULL_PTR) { 
	    rv++;
	} else {
	    fprintf(stderr, "Warning: no public key object found for label '%s'\n", label);
	}
    }

    return rv;
}

int pkcs11_findpublickey(pkcs11Context *p11Context, char *label, CK_OBJECT_HANDLE_PTR hPublicKey)
{

    int rv=0;

    *hPublicKey  = pkcs11_find_object_with_class(p11Context, label, CKO_PUBLIC_KEY);

    rv = *hPublicKey!=0;

    return rv;
}

int pkcs11_findprivatekey(pkcs11Context *p11Context, char *label, CK_OBJECT_HANDLE_PTR hPrivateKey)
{

    int rv=0;

    *hPrivateKey  = pkcs11_find_object_with_class(p11Context, label, CKO_PRIVATE_KEY);

    rv = *hPrivateKey!=0;

    return rv;
}

int pkcs11_findsecretkey(pkcs11Context *p11Context, char *label, CK_OBJECT_HANDLE_PTR hSecretKey)
{

    int rv=0;

    *hSecretKey = pkcs11_find_object_with_class(p11Context, label, CKO_SECRET_KEY);

    rv = *hSecretKey!=0;

    return rv;
}

int pkcs11_findprivateorsecretkey(pkcs11Context *p11Context, char *label, CK_OBJECT_HANDLE_PTR hKey, CK_OBJECT_CLASS *oclass)
{

    int rv=0;

    *hKey  = pkcs11_find_object_with_class(p11Context, label, CKO_PRIVATE_KEY);

    if(*hKey) {
	/* good, we have our private key */
	*oclass = CKO_PRIVATE_KEY;
	
    } else {
	*hKey  = pkcs11_find_object_with_class(p11Context, label, CKO_SECRET_KEY);

	if(*hKey) {
	    /* good, we have our secret key */
	    *oclass = CKO_SECRET_KEY;
	}
    }

    rv = *hKey!=0;

    return rv;
}


/* EOF */
