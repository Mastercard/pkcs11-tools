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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "pkcs11lib.h"


func_rc pkcs11_change_object_attributes(pkcs11Context *p11Context, char *label, CK_ATTRIBUTE *p_attr, size_t cnt, int interactive)
{

    func_rc rv=rc_ok;
    pkcs11Search *search=NULL;
    pkcs11IdTemplate *idtmpl=NULL;
    
    idtmpl = pkcs11_create_id(label);
    
    if(idtmpl && pkcs11_sizeof_idtemplate(idtmpl)>0) {
    
	search = pkcs11_new_search_from_idtemplate( p11Context, idtmpl );

	if(search) {		/* we just need one hit */

	    CK_OBJECT_HANDLE hndl=0;

	    while( (hndl = pkcs11_fetch_next(search))!=0 ) {
		/* set the attributes */

		CK_RV rc;
		int ok_to_move=1;
		char choice;

		if(interactive) {
		    pkcs11AttrList *attrs;
		    char *prefixptr;
		    ok_to_move=0;

		    attrs = pkcs11_new_attrlist(p11Context, 
						_ATTR(CKA_CLASS),
						_ATTR(CKA_LABEL),
						_ATTR(CKA_ID),
						_ATTR_END );

		    if( pkcs11_read_attr_from_handle (attrs, hndl) == true) {
			char buffer[81];
			int buffer_len = sizeof buffer;

			CK_ATTRIBUTE_PTR oclass = pkcs11_get_attr_in_attrlist(attrs, CKA_CLASS);
			CK_ATTRIBUTE_PTR olabel = pkcs11_get_attr_in_attrlist(attrs, CKA_LABEL);
			CK_ATTRIBUTE_PTR oid    = pkcs11_get_attr_in_attrlist(attrs, CKA_LABEL);


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

			    case CKO_DATA:
				prefixptr = "data/";
				break;

			    default:
				prefixptr = "othr/";
				break;
			    }

			    label_or_id(olabel, oid, buffer, buffer_len);

			    fflush(stdin);
			    fprintf(stderr, "set attributes on %s%s ? (y/N)", prefixptr, buffer );
			    fflush(stderr);

			    choice = getchar();
			    /* eat rest of the line + carriage return */
			    { int c; while( (c = getchar()) != EOF  && c!= '\n'); }

			    if ( tolower(choice) == 'y') {
				ok_to_move = 1;
			    }
			}
		    }
		    pkcs11_delete_attrlist(attrs);
		}


		if(ok_to_move) {
		    
		    rc = p11Context->FunctionList.C_SetAttributeValue( p11Context->Session, hndl, p_attr, cnt );
		    
		    if ( rc != CKR_OK ) {
			pkcs11_error( rc, "C_SetAttributeValue" );
			rc = rc_error_pkcs11_api;
			/* we carry on anyway to cycle through all objects */
		    }
		}
	    }
	    pkcs11_delete_search(search);
	}
	pkcs11_delete_idtemplate(idtmpl);
    }

    return rv;
}
