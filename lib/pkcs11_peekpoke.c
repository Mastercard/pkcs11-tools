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
#include "pkcs11lib.h"

/*
 * idorlabel contains either CKA_ID or CKA_LABEL
 */

CK_OBJECT_HANDLE pkcs11_getObjectHandle( pkcs11Context * p11Context, CK_OBJECT_CLASS oclass, CK_ATTRIBUTE_TYPE idorlabel, CK_BYTE_PTR byteArrayPtr, CK_ULONG byteArrayLen )
{
    CK_RV rc;
    CK_BBOOL token;
    CK_ULONG objectCount = 0;
    CK_ULONG oClassLen = sizeof( CK_OBJECT_CLASS );
    CK_ULONG tokenLen = sizeof( CK_BBOOL );
    CK_ULONG searchTemplateLen;
    CK_OBJECT_HANDLE hObject;

    CK_C_FindObjectsInit pC_FindObjectsInit;
    CK_C_FindObjects pC_FindObjects;
    CK_C_FindObjectsFinal pC_FindObjectsFinal;

    pC_FindObjectsInit = p11Context->FunctionList.C_FindObjectsInit;
    pC_FindObjects = p11Context->FunctionList.C_FindObjects;
    pC_FindObjectsFinal = p11Context->FunctionList.C_FindObjectsFinal;

    CK_ATTRIBUTE searchTemplate[] = {
	{ CKA_CLASS, NULL_PTR, 0x00 },
	{ idorlabel, NULL_PTR, 0x00 },
	{ CKA_TOKEN, NULL_PTR, 0x00 },
    };

    token = CK_TRUE;

    searchTemplateLen = ( sizeof( searchTemplate ) / sizeof( CK_ATTRIBUTE ) );

    searchTemplate[0].pValue = &oclass;
    searchTemplate[0].ulValueLen = oClassLen;
    searchTemplate[1].pValue = byteArrayPtr;
    searchTemplate[1].ulValueLen = byteArrayLen;
    searchTemplate[2].pValue = &token;
    searchTemplate[2].ulValueLen = tokenLen;

    if ( ( rc = pC_FindObjectsInit( p11Context->Session, searchTemplate, searchTemplateLen ) ) != CKR_OK )
    {
	pkcs11_error( rc, "C_FindObjectsInit" );
	return ( CK_INVALID_HANDLE );
    }

    if ( ( rc = pC_FindObjects( p11Context->Session, &hObject, 1, &objectCount ) ) != CKR_OK )
    {
	pkcs11_error( rc, "C_FindObjects" );
	return ( CK_INVALID_HANDLE );
    }

    if ( objectCount == 0 )
    {
	( void ) fprintf( stdout, "No object found with matching CKA_ID and or CKA_CLASS\n" );
	return ( CK_INVALID_HANDLE );
    }

    if ( ( rc = pC_FindObjectsFinal( p11Context->Session ) ) != CKR_OK )
	pkcs11_error( rc, "C_FindObjectsFinal" );

    return ( hObject );
}


void pkcs11_adjust_des_key_parity(CK_BYTE* pucKey, int nKeyLen)
{
    int cPar;
    int i, j;

    for( i = 0; i < nKeyLen; i++)
    {
	cPar = 0;
	for( j = 0; j < 8; j++) {
	    if(pucKey[i] & (001 << j))
		cPar = !cPar;
	}
	if(!cPar)
	    pucKey[i] ^= 001;
    }
}



int pkcs11_getObjectAttributes( pkcs11Context * p11Context, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE attr[], int attrlen )
{
    CK_RV rc;
    int i;

    for(i=0; i<attrlen; i++) {
      attr[i].pValue = NULL_PTR;
      attr[i].ulValueLen = 0;
    }

    CK_C_GetAttributeValue pC_GetAttributeValue = p11Context->FunctionList.C_GetAttributeValue;


    if ( ( rc = pC_GetAttributeValue( p11Context->Session, objectHandle, attr, attrlen ) ) == CKR_OK ) {
	for(i=0; i<attrlen; i++) {
	    attr[i].pValue = malloc( attr[i].ulValueLen );
	}
	if( (rc = pC_GetAttributeValue( p11Context->Session, objectHandle, attr, attrlen ) ) != CKR_OK ) {
	    pkcs11_error( rc, "C_GetAttributeValue" );
	    for(i=0; i<attrlen; i++) {
		free(attr[i].pValue);
		attr[i].pValue = NULL_PTR;
	    }
	}
    } else {
	pkcs11_error( rc, "C_GetAttributeValue" );
    }
    return rc;
}

void pkcs11_freeObjectAttributesValues( CK_ATTRIBUTE attr[], int attrlen)
{
    int i;
    for(i=0; i<attrlen; i++) {
	if (attr[i].pValue != NULL_PTR) {
	    free(attr[i].pValue);
	    attr[i].pValue = NULL_PTR;
	}
    }
}


CK_RV pkcs11_setObjectAttribute( pkcs11Context * p11Context, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE *attr )
{
    CK_RV rc;
    CK_ULONG setTemplateLen;

    CK_ATTRIBUTE setTemplate[] = {
	{ 0, NULL_PTR, 0 },
    };

    setTemplate[0] = *attr;
    setTemplateLen = 1;

    rc = p11Context->FunctionList.C_SetAttributeValue( p11Context->Session, objectHandle, setTemplate, setTemplateLen );

    if ( rc != CKR_OK ) {
	pkcs11_error( rc, "C_SetAttributeValue" );
    }

    return rc;
}

CK_RV pkcs11_setObjectAttributes( pkcs11Context * p11Context, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE *attr, size_t cnt )
{
    CK_RV rc;

    rc = p11Context->FunctionList.C_SetAttributeValue( p11Context->Session, objectHandle, attr, cnt );

    if ( rc != CKR_OK ) {
	pkcs11_error( rc, "C_SetAttributeValue" );
    }

    return rc;
}


/* adjust CKA_ID for RSA key pair, to set it to SHA1(modulus) for RSA and SHA1(ec_point) for EC */
func_rc pkcs11_adjust_keypair_id(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
    func_rc rc = rc_error_other_error;

    pkcs11AttrList *attrs;

    attrs = pkcs11_new_attrlist(p11Context,
				_ATTR(CKA_KEY_TYPE),
				_ATTR(CKA_MODULUS),
				_ATTR(CKA_EC_POINT),
				_ATTR(CKA_VALUE),
				_ATTR_END );

    if( pkcs11_read_attr_from_handle_ext (attrs, hPublicKey,
					  CKR_FUNCTION_FAILED, /* workaround for nCipher bug 30966 */
					  0L ) == true) {
	CK_ATTRIBUTE_PTR key_type, attr;

	key_type = pkcs11_get_attr_in_attrlist ( attrs, CKA_KEY_TYPE );

	switch(*(CK_KEY_TYPE *)(key_type->pValue)) {
	    /* if RSA, we hash the modulus */
	case CKK_RSA:
	    attr = pkcs11_get_attr_in_attrlist ( attrs, CKA_MODULUS );
	    break;

	    /* if EC or Edwards, we hash the point */
	case CKK_EC:
	case CKK_EC_EDWARDS:
	    attr = pkcs11_get_attr_in_attrlist ( attrs, CKA_EC_POINT );
	    break;

	    /* if DSA or DH, we hash the public key */
	case CKK_DSA:
	case CKK_DH:
	    attr = pkcs11_get_attr_in_attrlist( attrs, CKA_VALUE );
	    break;
	}

	if(attr!=NULL) {
	    CK_ATTRIBUTE id_attr = {CKA_ID, NULL_PTR, 0 };
	    id_attr.ulValueLen = pkcs11_openssl_alloc_and_sha1( attr[0].pValue, attr[0].ulValueLen, &id_attr.pValue);
	    if(id_attr.ulValueLen>0) {
		/* in the case of public key import, skip hPrivateKey */
		if(hPrivateKey!=NULL_PTR) {
		    pkcs11_setObjectAttribute( p11Context, hPrivateKey, &id_attr );
		};

		if(hPublicKey!=NULL_PTR) {
		    pkcs11_setObjectAttribute( p11Context, hPublicKey, &id_attr );
		} else {
		    fprintf(stderr, "Warning: no public key object found.");
		}
	    }
	    rc = rc_ok;

	    if(id_attr.pValue != NULL_PTR) pkcs11_openssl_free(&id_attr.pValue);
	    pkcs11_delete_attrlist(attrs);

	} else {
	    fprintf(stderr, "Warning: could not find a public value to hash for adjusting CKA_ID");
	}
    }
    return rc;
}



CK_ULONG pkcs11_get_object_size(pkcs11Context *p11ctx, CK_OBJECT_HANDLE obj)
{
    CK_ULONG size = 0;
    CK_RV rv ;

    rv = p11ctx->FunctionList.C_GetObjectSize(p11ctx->Session, obj, &size);

    if(rv!=CKR_OK) {
	pkcs11_error(rv, "C_GetObjectSize");
    }

    return size;
}


CK_BBOOL pkcs11_is_mech_supported(pkcs11Context *p11Context, CK_MECHANISM_TYPE m)
{
    CK_BBOOL rv = CK_FALSE;

    CK_MECHANISM_TYPE_PTR mechlist = NULL_PTR;
    CK_ULONG mechlist_len = 0L, i;

    if(p11Context!=NULL) {

	if (( rv = p11Context->FunctionList.C_GetMechanismList( p11Context->slot, NULL_PTR, &mechlist_len ) ) != CKR_OK ) {
	    pkcs11_error( rv, "C_GetMechanismList" );
	    goto error;
	}

	mechlist=calloc( mechlist_len, sizeof(CK_MECHANISM_TYPE) );

	if(mechlist==NULL) {
	    fprintf(stderr, "Ouch, memory error.\n");
	    goto error;
	}

	if (( rv = p11Context->FunctionList.C_GetMechanismList( p11Context->slot, mechlist, &mechlist_len ) ) != CKR_OK ) {
	    pkcs11_error( rv, "C_GetMechanismList" );
	    goto error;
	}

	for(i=0;i<mechlist_len;i++) {
	    if(mechlist[i]==m) {
		rv = CK_TRUE;
		break;
	    }
	}
    }

error:
    if(mechlist!=NULL) free(mechlist);

    return rv;
}



int pkcs11_get_rsa_modulus_bits(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl)
{
    int rv=0;
    pkcs11AttrList *attrs = NULL;

    attrs = pkcs11_new_attrlist(p11Context, _ATTR(CKA_MODULUS),	_ATTR_END );

    if(attrs) {

	if( pkcs11_read_attr_from_handle (attrs, hndl) == true) {
	    CK_ATTRIBUTE_PTR modulus = pkcs11_get_attr_in_attrlist ( attrs, CKA_MODULUS );
	    rv = (modulus->ulValueLen)<<3; /* this could be wrong, not bit-accurate */
	}

	pkcs11_delete_attrlist(attrs);
    }

    return rv;
}


int pkcs11_get_dsa_pubkey_bits(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl)
{
    int rv=0;
    pkcs11AttrList *attrs = NULL;

    attrs = pkcs11_new_attrlist(p11Context, _ATTR(CKA_VALUE), _ATTR_END );

    if(attrs) {

	if( pkcs11_read_attr_from_handle (attrs, hndl) == true) {
	    CK_ATTRIBUTE_PTR pubkey = pkcs11_get_attr_in_attrlist ( attrs, CKA_VALUE );
	    rv = (pubkey->ulValueLen)<<3; /* this could be wrong, not bit-accurate */
	}

	pkcs11_delete_attrlist(attrs);
    }

    return rv;
}


CK_OBJECT_CLASS pkcs11_get_object_class(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl)
{
    CK_OBJECT_CLASS rv = 0xFFFFFFFFUL; /* synthetic value, means "error" */

    pkcs11AttrList *attrs = NULL;

    /* extract object class from provided handle */
    attrs = pkcs11_new_attrlist(p11Context, _ATTR(CKA_CLASS), _ATTR_END );

    if(attrs) {

	if( pkcs11_read_attr_from_handle (attrs, hndl) == true) {
	    CK_ATTRIBUTE_PTR attr_ptr = pkcs11_get_attr_in_attrlist(attrs, CKA_CLASS);
	    rv = *(CK_OBJECT_CLASS *)(attr_ptr->pValue);
	}

    pkcs11_delete_attrlist(attrs);
    }

    return rv;
}

key_type_t pkcs11_get_key_type(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl)
{
    key_type_t rv = unknown;

    pkcs11AttrList *attrs = NULL;

    typedef struct {
	CK_KEY_TYPE p11_key_type;
	key_type_t key_type;
    } key_type_mapping_t;

    static const key_type_mapping_t key_type_mapping[] = {
	{ CKK_AES, aes, },
	{ CKK_DES, des, },
	{ CKK_DES2, des2, },	/* des3 double length */
	{ CKK_DES3, des3, },	/* des3 triple length */
	{ CKK_RSA, rsa, },
	{ CKK_EC, ec, },
	{ CKK_EC_EDWARDS, ed },
	{ CKK_DSA, dsa, },
	{ CKK_DH, dh, },
	{ CKK_GENERIC_SECRET, generic, },
#if defined(HAVE_NCIPHER)
	{ CKK_SHA_1_HMAC, hmacsha1, },
	{ CKK_SHA224_HMAC, hmacsha224, },
	{ CKK_SHA256_HMAC, hmacsha256, },
	{ CKK_SHA384_HMAC, hmacsha384, },
	{ CKK_SHA512_HMAC, hmacsha512 },
#endif
    };

    /* extract object class from provided handle */
    attrs = pkcs11_new_attrlist(p11Context, _ATTR(CKA_KEY_TYPE), _ATTR_END );

    if(attrs) {

	if( pkcs11_read_attr_from_handle (attrs, hndl) == true) {
	    CK_ATTRIBUTE_PTR attr_ptr = pkcs11_get_attr_in_attrlist(attrs, CKA_KEY_TYPE);
	    int i;
	    for(i=0; i<sizeof key_type_mapping / sizeof(key_type_mapping_t); i++) {
		if(*(CK_KEY_TYPE *)(attr_ptr->pValue)==key_type_mapping[i].p11_key_type) {
		    rv = key_type_mapping[i].key_type;
		    break;
		}
	    }
	}

    pkcs11_delete_attrlist(attrs);
    }

    return rv;
}

/* this function returns an allocated buffer to CKA_LABEL if found  */
char *pkcs11_alloclabelforhandle(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl)
{
    pkcs11AttrList *attrs = NULL;
    char *label = NULL;

    attrs = pkcs11_new_attrlist(p11Context, _ATTR(CKA_LABEL), _ATTR_END );

    if(attrs) {
	if( pkcs11_read_attr_from_handle (attrs, hndl) == true) {
	    CK_ATTRIBUTE_PTR attr_ptr = pkcs11_get_attr_in_attrlist(attrs, CKA_LABEL);
	    if(attr_ptr) {
		label = malloc( attr_ptr->ulValueLen+1 );
		if(label) {
		    memcpy( label, attr_ptr->pValue, attr_ptr->ulValueLen);
		    label[attr_ptr->ulValueLen]=0; /* end the string */
		}
	    }
	}
	pkcs11_delete_attrlist(attrs); /* cleanup after use */
    }

    return label;
}


/**************************************************************************/

