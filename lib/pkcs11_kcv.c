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

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "pkcs11lib.h"

#if !defined(LABEL_WIDTH)
#define LABEL_WIDTH 32
#endif

/* target must point to a location with at least 3 bytes left */

void pkcs11_display_kcv( pkcs11Context *p11Context, char *label, unsigned hmacdatasize )
{

    pkcs11Search *search=NULL;
    pkcs11IdTemplate *idtmpl=NULL;
    CK_OBJECT_HANDLE *hndl_array=NULL;


    if(hmacdatasize>MAX_KCV_CLEARTEXT_SIZE) {
	fprintf(stderr, "Invalid HMAC block size specified (%d), must be between 0 and %d\n", hmacdatasize, MAX_KCV_CLEARTEXT_SIZE );
    }
    /* trick: we treat "cert", "pubk", "prvk", "seck" and "data" in front of the templating system */
    /* so these specific labels can be used as shortcut for the corresponding object classes       */

    if(label!=NULL && strcasecmp("seck",label)==0) {
	idtmpl = pkcs11_make_idtemplate(CLASS_SECK);
    } else {
	idtmpl = pkcs11_make_idtemplate(label);
    }

    if(idtmpl && pkcs11_sizeof_idtemplate(idtmpl)>0) {

	search = pkcs11_new_search_from_idtemplate( p11Context, idtmpl );

	if(search) {		/* we just need one hit */
	    CK_OBJECT_HANDLE hndl=0;
	    int count = 0, i=0, j=0;

	    while( (hndl = pkcs11_fetch_next(search))!=0 ) {
		count++;
	    }
	    pkcs11_delete_search(search); search=NULL;

	    /* allocate array */
	    hndl_array = calloc(count, sizeof(CK_OBJECT_HANDLE));

	    if(hndl_array==NULL) {
		goto error;
	    }

	    /* redo the same thing, but this time store the handles */
	    search = pkcs11_new_search_from_idtemplate( p11Context, idtmpl );

	    if(search) {
		while( (hndl = pkcs11_fetch_next(search))!=0 && i<count) {
		    hndl_array[i++] = hndl;
		}
		pkcs11_delete_search(search); search=NULL;
	    }

	    for(j=0; j<i; j++) {
		pkcs11AttrList *attrs;

		attrs = pkcs11_new_attrlist(p11Context,
					    _ATTR(CKA_KEY_TYPE),
					    _ATTR(CKA_ID),
					    _ATTR(CKA_LABEL),
					    _ATTR_END);

		if( attrs!=NULL) {
		    if (pkcs11_read_attr_from_handle (attrs, hndl_array[j]) == CK_TRUE) {
			CK_RV rv;
			CK_BYTE cleartext[MAX_KCV_CLEARTEXT_SIZE];
			CK_BYTE processed[64];
			CK_ULONG cleartext_len, processed_len;

			CK_MECHANISM des_ecb = { CKM_DES_ECB, NULL_PTR, 0 };
			CK_MECHANISM des3_ecb = { CKM_DES3_ECB, NULL_PTR, 0 };
			CK_MECHANISM aes_ecb = { CKM_AES_ECB, NULL_PTR, 0 };
			CK_MECHANISM sha1_hmac = { CKM_SHA_1_HMAC, NULL_PTR, 0 };
			CK_MECHANISM sha256_hmac = { CKM_SHA256_HMAC, NULL_PTR, 0 };
			CK_MECHANISM sha384_hmac = { CKM_SHA384_HMAC, NULL_PTR, 0 };
			CK_MECHANISM sha512_hmac = { CKM_SHA512_HMAC, NULL_PTR, 0 };

			enum { encrypt, sign } whattodo;


			CK_MECHANISM_PTR mechanism = NULL ;

			CK_ATTRIBUTE_PTR keytype = pkcs11_get_attr_in_attrlist ( attrs, CKA_KEY_TYPE );
			CK_ATTRIBUTE_PTR label   = pkcs11_get_attr_in_attrlist ( attrs, CKA_LABEL );
			CK_ATTRIBUTE_PTR id      = pkcs11_get_attr_in_attrlist ( attrs, CKA_ID );

			char buffer[81];
			int buffer_len = sizeof buffer;
			char *keytypestr = NULL;

			memset(cleartext,0x00,sizeof cleartext);

			label_or_id(label, id, buffer, buffer_len); /* first thing: retrieve label or id */

			if(keytype==NULL) {
			    fprintf(stderr, "Found no CKA_KEY_TYPE for object %s, skipping\n", buffer);
			    pkcs11_delete_attrlist(attrs);
			    continue;
			}

			switch( *((CK_KEY_TYPE *)keytype->pValue)) {
			case CKK_DES:
			    mechanism = &des_ecb;
			    cleartext_len = 8L;
			    processed_len = 8L;
			    keytypestr = "DES, single length";
			    whattodo=encrypt;
			    break;

			case CKK_DES2:
			    mechanism = &des3_ecb;
			    cleartext_len = 8L;
			    processed_len = 8L;
			    keytypestr = "3DES, double length";
			    whattodo=encrypt;
			    break;

			case CKK_DES3:
			    mechanism = &des3_ecb;
			    cleartext_len = 8L;
			    processed_len = 8L;
			    keytypestr = "3DES, triple length";
			    whattodo=encrypt;
			    break;

			case CKK_AES:
			    mechanism = &aes_ecb;
			    cleartext_len = 16L;
			    processed_len = 16L;
			    keytypestr = "AES";
			    whattodo=encrypt;
			    break;

			case CKK_SHA_1_HMAC:
			    mechanism = &sha1_hmac;
			    cleartext_len = hmacdatasize;
			    processed_len = 20L;
			    keytypestr = "HMAC(SHA1)";
			    whattodo=sign;
			    break;

			case CKK_SHA256_HMAC:
			case CKK_GENERIC_SECRET:
			    mechanism = &sha256_hmac;
			    cleartext_len = hmacdatasize;
			    processed_len = 32L;
			    keytypestr = "HMAC(SHA256)";
			    whattodo=sign;
			    break;

			case CKK_SHA384_HMAC:
			    mechanism = &sha384_hmac;
			    cleartext_len = hmacdatasize;
			    processed_len = 48L;
			    keytypestr = "HMAC(SHA384)";
			    whattodo=sign;
			    break;

			case CKK_SHA512_HMAC:
			    mechanism = &sha512_hmac;
			    cleartext_len = hmacdatasize;
			    processed_len = 64L;
			    keytypestr = "HMAC(SHA384)";
			    whattodo=sign;
			    break;

			default:
			    break;
			}

			if(mechanism==NULL) {
			    fprintf(stderr, "Unsupported mechanism for key %s, skipping\n", buffer);
			    pkcs11_delete_attrlist(attrs);
			    continue;
			}

			rv = whattodo == encrypt ?
			    p11Context->FunctionList.C_EncryptInit( p11Context->Session,
								    mechanism,
								    hndl_array[j]) :
			    p11Context->FunctionList.C_SignInit( p11Context->Session,
								 mechanism,
								 hndl_array[j]);

			if(rv!=CKR_OK) {
			    pkcs11_error(rv, whattodo == encrypt ? "C_EncryptInit" : "C_SignInit");
			    pkcs11_delete_attrlist(attrs);
			    continue;
			}

			rv = whattodo == encrypt ?
			    p11Context->FunctionList.C_Encrypt ( p11Context->Session,
								 cleartext,
								 cleartext_len,
								 processed,
								 &processed_len	) :
			    p11Context->FunctionList.C_Sign ( p11Context->Session,
							      cleartext,
							      cleartext_len,
							      processed,
							      &processed_len );
			if(rv!=CKR_OK) {
			    pkcs11_error(rv, whattodo == encrypt ? "C_Encrypt" : "C_Sign");
			    pkcs11_delete_attrlist(attrs);
			    continue;
			}

			/* now, the display job */
			printf("%-*s: KCV = %02.2x%02.2x%02.2x (%s)\n",
			       LABEL_WIDTH,
			       buffer,
			       processed[0],
			       processed[1],
			       processed[2],
			       keytypestr);
		    }
		    pkcs11_delete_attrlist(attrs);
		}
	    }
	}
    }
error:
    if(hndl_array) free(hndl_array);
    if(search) pkcs11_delete_search(search);
    if(idtmpl) pkcs11_delete_idtemplate(idtmpl);

}
