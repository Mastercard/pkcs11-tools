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
#include <ctype.h>
#include "pkcs11lib.h"


/* high-level search functions */

int pkcs11_cp_objects(pkcs11Context *p11Context, char *src, char *dest, int interactive, int verbose)
{

    int rv=0;
    pkcs11Search *search=NULL;
    pkcs11IdTemplate *idtmpl=NULL;
    char *destlabel;
    typedef enum { all, cert, pubk, prvk, seck }  objtype;

    objtype whatsrc = all, whatdest = all;

    

    /* check source */

    if(strncasecmp("prvk/", src, 5) ==0 ) { /* private key case */
	whatsrc = prvk;
    } else if (strncasecmp("pubk/", src, 5) ==0 ) { /* public key case */
	whatsrc = pubk;
    } else if (strncasecmp("seck/", src, 5) ==0 ) { /* secret key case */
	whatsrc = seck;
    } else if (strncasecmp("cert/", src, 5) ==0 ) { /* cert case */
	whatsrc = cert;
    } else {		/* generic case */
	whatsrc = all;	
    }


    /* check dest */

    if(strncasecmp("prvk/", dest, 5) ==0 ) { /* private key case */
	whatdest = prvk;
	destlabel = &dest[5];
    } else if (strncasecmp("pubk/", dest, 5) ==0 ) { /* public key case */
	whatdest = pubk;
	destlabel = &dest[5];
    } else if (strncasecmp("seck/", dest, 5) ==0 ) { /* secret key case */
	whatdest = seck;
	destlabel = &dest[5];
    } else if (strncasecmp("cert/", dest, 5) ==0 ) { /* cert case */
	whatdest = cert;
	destlabel = &dest[5];
    } else {		/* generic case */
	whatdest = all;	
	destlabel = dest;
    }

    /* compare src and dest */

    if (whatsrc != whatdest) {
	fprintf(stderr, "source and destination must be of the same kind. Use same prefix for both.\n");
	rv = RC_ERROR_USAGE;
	goto error;
    }


    switch(whatsrc) {

    case all:
	if(pkcs11_label_exists( p11Context, dest)) {
#ifdef HAVE_DUPLICATES_ENABLED
		if(p11Context->can_duplicate) {
			fprintf(stdout, "Warning: at least one object already exists for destination label '%s', duplicating.\n", dest);
		}
		else {
#endif
	    fprintf(stderr, "Error: at least one object already exists for destination label '%s'.\n", dest);
	    rv = RC_ERROR_OBJECT_EXISTS;
	    goto error;
#ifdef HAVE_DUPLICATES_ENABLED
		}
#endif
	}
	break;

    case prvk:
	if(pkcs11_privatekey_exists( p11Context, dest)) {
#ifdef HAVE_DUPLICATES_ENABLED
		if(p11Context->can_duplicate) {
			fprintf(stdout,"Warning: a private key already exists for destination label '%s', duplicating.\n", dest);
		}
		else {
#endif
	    fprintf(stderr,"Error: a private key already exists for destination label '%s'.\n", dest);
	    rv = RC_ERROR_OBJECT_EXISTS;
	    goto error;
#ifdef HAVE_DUPLICATES_ENABLED
		}
#endif
	}
	break;

    case pubk:
	if(pkcs11_publickey_exists( p11Context, dest)) {
#ifdef HAVE_DUPLICATES_ENABLED
		if(p11Context->can_duplicate) {
			fprintf(stdout,"Warning: a public key already exists for destination label '%s', duplicating.\n", dest);
		}
		else {
#endif
	    fprintf(stderr,"Error: a public key already exists for destination label '%s'.\n", dest);
	    rv = RC_ERROR_OBJECT_EXISTS;
	    goto error;
#ifdef HAVE_DUPLICATES_ENABLED
		}
#endif
	}
	break;

    case seck:
	if(pkcs11_secretkey_exists( p11Context, dest)) {
#ifdef HAVE_DUPLICATES_ENABLED
		if(p11Context->can_duplicate) {
			fprintf(stdout,"Warning: a secret key already exists for destination label '%s', duplicating.\n", dest);
		}
		else {
#endif
	    fprintf(stderr,"Error: a secret key already exists for destination label '%s'.\n", dest);
	    rv = RC_ERROR_OBJECT_EXISTS;
	    goto error;
#ifdef HAVE_DUPLICATES_ENABLED
		}
#endif
	}
	break;

    case cert:
	if(pkcs11_certificate_exists( p11Context, dest)) {
#ifdef HAVE_DUPLICATES_ENABLED
		if(p11Context->can_duplicate) {
			fprintf(stdout,"Warning: a certificate already exists for destination label '%s', duplicating.\n", dest);
		}
		else {
#endif
	    fprintf(stderr,"Error: a certificate already exists for destination label '%s'.\n", dest);
	    rv = RC_ERROR_OBJECT_EXISTS;
	    goto error;
#ifdef HAVE_DUPLICATES_ENABLED
		}
#endif
	}
	break;

    }    


    idtmpl = pkcs11_create_id(src);
    
    if(idtmpl && pkcs11_sizeof_idtemplate(idtmpl)>0) {
    
	search = pkcs11_new_search_from_idtemplate( p11Context, idtmpl );

	if(search) {

	    CK_OBJECT_HANDLE hndl=0;
	    int ok_to_copy=1;
	    char choice;

	    while( (hndl = pkcs11_fetch_next(search))!=0 ) {

		if(interactive) {
		    pkcs11AttrList *attrs;
		    char *prefixptr;
		    ok_to_copy=0;

		    attrs = pkcs11_new_attrlist(p11Context, 
						_ATTR(CKA_CLASS),
						_ATTR(CKA_LABEL),
						_ATTR_END );

		    if( pkcs11_read_attr_from_handle (attrs, hndl) == true) {

			CK_ATTRIBUTE_PTR oclass = pkcs11_get_attr_in_attrlist(attrs, CKA_CLASS);
			CK_ATTRIBUTE_PTR olabel = pkcs11_get_attr_in_attrlist(attrs, CKA_LABEL);

			if(oclass) {
			    switch(*(CK_OBJECT_CLASS *)(oclass->pValue)) {
			    case CKO_PRIVATE_KEY:
				prefixptr = "prvk/";
				break;

			    case CKO_PUBLIC_KEY:
				prefixptr = "pubk/";
				break;

			    case CKO_SECRET_KEY:
				prefixptr = "seck/";
				break;

			    case CKO_CERTIFICATE:
				prefixptr = "cert/";
				break;

			    default:
				prefixptr = "";
				break;
			    }

			    fflush(stdin);
		    
			    fprintf(stderr,
				    "copy %s%.*s to %s%.*s ? (y/N)", 
				    prefixptr,
				    (int)(olabel->ulValueLen),
				    (char *)(olabel->pValue),
				
				    prefixptr,
				    (int)strlen(destlabel),
				    destlabel );
			
			    fflush(stderr);

			    choice = getchar();
			    /* eat rest of the line + carriage return */
			    { int c; while( (c = getchar()) != EOF  && c!= '\n'); }

			    if ( tolower(choice) == 'y') {
				ok_to_copy = 1;
			    }
			}
		    }
		    pkcs11_delete_attrlist(attrs);
		}


		if(ok_to_copy) {		    
		    CK_RV rc;
		    CK_OBJECT_HANDLE tmp;

		    CK_ATTRIBUTE destattr[1] = {
			{ CKA_LABEL, NULL, 0L },
		    };


		    destattr[0].pValue = destlabel;
		    destattr[0].ulValueLen = strlen(destlabel);

		    rc = p11Context->FunctionList.C_CopyObject( p11Context->Session, hndl, destattr, (sizeof destattr)/sizeof(CK_ATTRIBUTE), &tmp);

		    if(rc != CKR_OK) {
			pkcs11_error( rc, "C_CopyObject" );
			rv = RC_ERROR_PKCS11_API;
			goto error;
		    }

		    /* destattr[0].pValue = &ck_true; */

		    /* rc = p11Context->FunctionList.C_CopyObject( p11Context->Session, tmp, destattr, 1, &target); */

		    /* if(rc != CKR_OK) { */
		    /* 	pkcs11_error( rc, "C_CopyObject" ); */
		    /* 	rv = RC_ERROR_PKCS11_API; */
		    /* 	/\* goto error; *\/ */
		    /* } */
		}	    
	    }
	}
    }
error:
    if(search) { pkcs11_delete_search(search); }
    if(idtmpl) { pkcs11_delete_idtemplate(idtmpl); }
    
    return rv;
}

/* EOF */
