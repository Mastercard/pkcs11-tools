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

#if !defined(LABEL_WIDTH)
#define LABEL_WIDTH 32
#endif

#define LABELORID_MAXLEN 129

static char* value_for_boolattr( pkcs11AttrList *attrlist,
				 CK_ATTRIBUTE_TYPE attrtype,
				 char *ck_true,
				 char *ck_false,
				 char *ck_unknown )
{
    char *rv = ck_unknown;
    CK_ATTRIBUTE_PTR attr;
    CK_BBOOL * val;

    attr = pkcs11_get_attr_in_attrlist ( attrlist, attrtype );

    if(attr!=NULL_PTR && attr->pValue!=NULL_PTR) {
	val = (CK_BBOOL *) attr->pValue;
	switch( *val ) {

	case CK_TRUE:
	    rv = ck_true;
	    break;

	case CK_FALSE:
	    rv = ck_false;
	    break;

	}
    }
    return rv;
}

static char* value_for_array_content( pkcs11AttrList *attrlist,
				      CK_ATTRIBUTE_TYPE attrtype,
				      size_t itemsize,
				      char *ck_true,
				      char *ck_false )
{
    CK_ATTRIBUTE_PTR attr;

    attr = pkcs11_get_attr_in_attrlist ( attrlist, attrtype );

    if(attr==NULL) return ck_false;
    else if( attr!=NULL_PTR &&
	     attr->pValue!=NULL_PTR &&
	     attr->ulValueLen>0 &&
	     attr->ulValueLen % itemsize == 0) return ck_true;
    else return ck_false;
}

static inline char* value_for_template( pkcs11AttrList *attrlist,
					CK_ATTRIBUTE_TYPE attrtype,
					char *ck_true,
					char *ck_false ) {
    return value_for_array_content(attrlist, attrtype, sizeof(CK_ATTRIBUTE), ck_true, ck_false);
}

static inline char* value_for_allowed_mechanisms( pkcs11AttrList *attrlist,
						  char *ck_true,
						  char *ck_false ) {
    return value_for_array_content(attrlist, CKA_ALLOWED_MECHANISMS, sizeof(CK_MECHANISM_TYPE), ck_true, ck_false);
}

static char* value_for_keytype( pkcs11AttrList *attrlist )
{
    CK_ATTRIBUTE_PTR attr_kt;
    char *rv="";

    attr_kt = pkcs11_get_attr_in_attrlist ( attrlist, CKA_KEY_TYPE );

    if(attr_kt!=NULL_PTR && attr_kt->pValue!=NULL_PTR) {
	CK_KEY_TYPE *val = (CK_KEY_TYPE *) attr_kt->pValue;
	switch( *val ) {

	case CKK_RSA:
	    rv = "rsa";
	    {
		CK_ATTRIBUTE_PTR attr_kl = pkcs11_get_attr_in_attrlist ( attrlist, CKA_MODULUS );
		if(attr_kl!=NULL_PTR && attr_kl->pValue!=NULL_PTR) {
		    switch( attr_kl->ulValueLen ) {
		    case 1024/8:
			rv = "rsa(1024)";
			break;

		    case 2048/8:
			rv = "rsa(2048)";
			break;

		    case 4096/8:
			rv = "rsa(4096)";
			break;

		    default:
			rv = "rsa";
		    }
		}
	    }
	    break;

	case CKK_DES:
	    rv = "des(64)";
	    break;

	case CKK_DES2:
	    rv = "des(128)";
	    break;

	case CKK_DES3:
	    rv = "des(192)";
	    break;

	case CKK_AES:
	    rv = "aes";
	    {
		CK_ATTRIBUTE_PTR attr_kl = pkcs11_get_attr_in_attrlist ( attrlist, CKA_VALUE_LEN );
		if(attr_kl!=NULL_PTR && attr_kl->pValue!=NULL_PTR) {
		    CK_ULONG * aeslen = attr_kl->pValue;
		    switch( *aeslen ) {
		    case 128/8:
			rv = "aes(128)";
			break;

		    case 192/8:
			rv = "aes(192)";
			break;

		    case 256/8:
			rv = "aes(256)";
			break;

		    default:
			rv = "aes";
		    }
		}
	    }
	    break;

	case CKK_MD5_HMAC:
	    rv = "hmac-md5";
	    break;

	case CKK_SHA_1_HMAC:
	    rv = "hmac-sha1";
	    break;

	case CKK_SHA224_HMAC:
	    rv = "hmac-sha224";
	    break;

	case CKK_SHA256_HMAC:
	    rv = "hmac-sha256";
	    break;

	case CKK_SHA384_HMAC:
	    rv = "hmac-sha384";
	    break;

	case CKK_SHA512_HMAC:
	    rv = "hmac-sha512";
	    break;

	case CKK_GENERIC_SECRET:
	    rv = "generic";
	    break;

	default:
	    rv = "unknown";
	}
    }
    return rv;
}


static int ls_cert(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl)
{

    int rv=0;
    pkcs11AttrList *attrs;

    attrs = pkcs11_new_attrlist(p11Context,
				/* storage object attributes */
				_ATTR(CKA_TOKEN),
				_ATTR(CKA_PRIVATE),
				_ATTR(CKA_MODIFIABLE),
				_ATTR(CKA_LABEL),
				/* X509 atttibutes */
				_ATTR(CKA_ID),
				_ATTR(CKA_SUBJECT),
				_ATTR(CKA_ISSUER),
				_ATTR(CKA_VALUE),
				_ATTR(CKA_TRUSTED), /* NSS: unknown */
				_ATTR_END);

    if( attrs!=NULL) {
	if(pkcs11_read_attr_from_handle (attrs, hndl) == true) {
	    CK_ATTRIBUTE_PTR id, label;
	    char buffer[LABELORID_MAXLEN];
	    int buffer_len = sizeof buffer;

	    label      = pkcs11_get_attr_in_attrlist ( attrs, CKA_LABEL );
	    id         = pkcs11_get_attr_in_attrlist ( attrs, CKA_ID );

	    label_or_id(label, id, buffer, buffer_len);

	    printf("cert/%-*s %s%s%s%s\n",
		   LABEL_WIDTH,
		   buffer,
		   value_for_boolattr(attrs, CKA_TOKEN, "tok,", "ses,", ""),
		   value_for_boolattr(attrs, CKA_PRIVATE, "prv,", "pub,", ""),
		   value_for_boolattr(attrs, CKA_MODIFIABLE, "r/w,", "r/o,", ""),
		   value_for_boolattr(attrs, CKA_TRUSTED, "tru,", "", "")
		);
	}
	pkcs11_delete_attrlist(attrs);
    }
    return rv;
}


static int ls_pubk(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl)
{

    int rv=0;
    pkcs11AttrList *attrs, *specialized_attrs=NULL;

    attrs = pkcs11_new_attrlist(p11Context,
				/* storage object attributes */
				_ATTR(CKA_TOKEN),
				_ATTR(CKA_PRIVATE),
				_ATTR(CKA_MODIFIABLE),
				_ATTR(CKA_LABEL),

				/* KEY attributes */
				_ATTR(CKA_ID),
				_ATTR(CKA_START_DATE),
				_ATTR(CKA_END_DATE),
				_ATTR(CKA_DERIVE),
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle this */
				_ATTR(CKA_DERIVE_TEMPLATE),
#endif
				_ATTR(CKA_LOCAL),
				_ATTR(CKA_KEY_TYPE),
				_ATTR(CKA_KEY_GEN_MECHANISM), /* NSS: unknown? */
				_ATTR(CKA_ALLOWED_MECHANISMS),

				/* Public Key attributes */
				_ATTR(CKA_SUBJECT),
				_ATTR(CKA_ENCRYPT),
				_ATTR(CKA_VERIFY),
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle this */				
				_ATTR(CKA_VERIFY_RECOVER),
#endif
				_ATTR(CKA_WRAP),
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle this */
				_ATTR(CKA_WRAP_TEMPLATE),
#endif
				_ATTR(CKA_TRUSTED), /* NSS: unknown */

				_ATTR_END );

    if( attrs!=NULL) {
	if (pkcs11_read_attr_from_handle (attrs, hndl) == true) {
	    CK_ATTRIBUTE_PTR label, id, modulus, keytype, ec_params, prime;
	    char buffer[LABELORID_MAXLEN];
	    int  buffer_len = sizeof buffer;
	    char keykind[41];
	    char ecname[37];

	    id         = pkcs11_get_attr_in_attrlist ( attrs, CKA_ID );
	    label      = pkcs11_get_attr_in_attrlist ( attrs, CKA_LABEL );
	    keytype    = pkcs11_get_attr_in_attrlist ( attrs, CKA_KEY_TYPE );

	    switch( *((CK_KEY_TYPE *)(keytype->pValue)) ) {
	    case CKK_RSA:
		specialized_attrs = pkcs11_new_attrlist(p11Context,
							_ATTR(CKA_MODULUS),
							_ATTR_END );
		if(specialized_attrs && pkcs11_read_attr_from_handle (specialized_attrs, hndl) ) {
		    modulus = pkcs11_get_attr_in_attrlist ( specialized_attrs, CKA_MODULUS );
		    sprintf(keykind, "rsa(%d)", (int) ((modulus->ulValueLen)<<3));
		    
		}
		break;

	    case CKK_EC:
		specialized_attrs = pkcs11_new_attrlist(p11Context,
							_ATTR(CKA_EC_PARAMS),
							_ATTR_END );
		if(specialized_attrs && pkcs11_read_attr_from_handle (specialized_attrs, hndl) ) {
		    ec_params = pkcs11_get_attr_in_attrlist ( specialized_attrs, CKA_EC_PARAMS );
		    sprintf(keykind, "ec(%s)", pkcs11_ec_oid2curvename( (CK_BYTE*)(ec_params->pValue),
									ec_params->ulValueLen,
									ecname,
									sizeof ecname ));
		}
		break;

	    case CKK_EC_EDWARDS:
		specialized_attrs = pkcs11_new_attrlist(p11Context,
							_ATTR(CKA_EC_PARAMS),
							_ATTR_END );
		if(specialized_attrs && pkcs11_read_attr_from_handle (specialized_attrs, hndl) ) {
		    ec_params = pkcs11_get_attr_in_attrlist ( specialized_attrs, CKA_EC_PARAMS );
		    sprintf(keykind, "ed(%s)", pkcs11_ed_oid2curvename( (CK_BYTE*)(ec_params->pValue),
									ec_params->ulValueLen,
									ecname,
									sizeof ecname ));
		}
		break;

	    case CKK_DSA:
		specialized_attrs = pkcs11_new_attrlist(p11Context,
							_ATTR(CKA_PRIME),
							_ATTR_END );
		if(specialized_attrs && pkcs11_read_attr_from_handle (specialized_attrs, hndl) ) {
		    prime = pkcs11_get_attr_in_attrlist ( specialized_attrs, CKA_PRIME );
		    sprintf(keykind, "dsa(%d)", (int) ((prime->ulValueLen)<<3));
		}
		break;
		    

	    case CKK_DH:
		specialized_attrs = pkcs11_new_attrlist(p11Context,
							_ATTR(CKA_PRIME),
							_ATTR_END );
		if(specialized_attrs && pkcs11_read_attr_from_handle (specialized_attrs, hndl) ) {
		    prime = pkcs11_get_attr_in_attrlist ( specialized_attrs, CKA_PRIME );
		    sprintf(keykind, "dh(%d)", (int) ((prime->ulValueLen)<<3));
		}
		break;

	    default:
		sprintf(keykind, "unknown(\?\?\?)");
	    }

	    label_or_id(label, id, buffer, buffer_len);

	    printf("pubk/%-*s %s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
		   LABEL_WIDTH,
		   buffer,
		   value_for_boolattr(attrs,CKA_TOKEN, "tok,", "ses,", ""),
		   value_for_boolattr(attrs,CKA_PRIVATE, "prv,", "pub,", ""),
		   value_for_boolattr(attrs,CKA_MODIFIABLE, "r/w,", "r/o,", ""),

		   value_for_boolattr(attrs,CKA_LOCAL, "loc,", "imp,", ""),
		   value_for_boolattr(attrs,CKA_DERIVE, "drv,", "", ""),
		   value_for_boolattr(attrs,CKA_ENCRYPT, "enc,", "", ""),
		   value_for_boolattr(attrs,CKA_VERIFY, "vfy,", "", ""),
		   value_for_boolattr(attrs,CKA_VERIFY_RECOVER, "vre,", "", ""),
		   value_for_boolattr(attrs,CKA_WRAP, "wra,", "", ""),
		   value_for_boolattr(attrs,CKA_TRUSTED, "tru,", "", ""),
		   value_for_template(attrs,CKA_WRAP_TEMPLATE, "wrt,", ""),
		   value_for_template(attrs,CKA_DERIVE_TEMPLATE, "drt,", ""),
		   value_for_allowed_mechanisms(attrs, "alm,", ""),
		   keykind
		);
	}
	if(specialized_attrs) { pkcs11_delete_attrlist(specialized_attrs); }
	pkcs11_delete_attrlist(attrs);
    }

    return rv;

}


static int ls_prvk(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl)
{

    int rv=0;
    pkcs11AttrList *attrs, *specialized_attrs=NULL;

    attrs = pkcs11_new_attrlist(p11Context,
				/* storage object attributes */
				_ATTR(CKA_TOKEN),
				_ATTR(CKA_PRIVATE),
				_ATTR(CKA_MODIFIABLE),
				_ATTR(CKA_LABEL),

				/* KEY attributes */
				_ATTR(CKA_ID),
				_ATTR(CKA_START_DATE),
				_ATTR(CKA_END_DATE),
				_ATTR(CKA_DERIVE),
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle this */
				_ATTR(CKA_DERIVE_TEMPLATE),
#endif
				_ATTR(CKA_LOCAL),
				_ATTR(CKA_KEY_TYPE),
				_ATTR(CKA_KEY_GEN_MECHANISM), /* NSS: unknown? */
				_ATTR(CKA_ALLOWED_MECHANISMS),

				/* Private Key attributes */
				_ATTR(CKA_SUBJECT),
				_ATTR(CKA_DECRYPT),
				_ATTR(CKA_SIGN),
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle this */	
				_ATTR(CKA_SIGN_RECOVER),
#endif
				_ATTR(CKA_UNWRAP),
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle this */
				_ATTR(CKA_UNWRAP_TEMPLATE),
#endif
				_ATTR(CKA_SENSITIVE),
				_ATTR(CKA_ALWAYS_SENSITIVE),
				_ATTR(CKA_EXTRACTABLE),
				_ATTR(CKA_NEVER_EXTRACTABLE),
				_ATTR(CKA_ALWAYS_AUTHENTICATE),
				_ATTR(CKA_WRAP_WITH_TRUSTED),
#if 0
				/* RSA Public Key attributes */
				_ATTR(CKA_MODULUS),
				_ATTR(CKA_PUBLIC_EXPONENT),

				/* EC Public Key attribute */
				_ATTR(CKA_EC_PARAMS),
				_ATTR(CKA_EC_POINT),

				/* DH/DSA Public Key attribute - for key length determ. */
				_ATTR(CKA_PRIME),
#endif

				_ATTR_END );

    if(attrs!=NULL) {
	if (pkcs11_read_attr_from_handle (attrs, hndl) == true) {
	    CK_ATTRIBUTE_PTR label, id, modulus, keytype, ec_params, prime;
	    char buffer[LABELORID_MAXLEN];
	    int  buffer_len = sizeof buffer;
	    char keykind[41];
	    char ecname[37];

	    id         = pkcs11_get_attr_in_attrlist ( attrs, CKA_ID );
	    label      = pkcs11_get_attr_in_attrlist ( attrs, CKA_LABEL );
	    keytype    = pkcs11_get_attr_in_attrlist ( attrs, CKA_KEY_TYPE );

	    switch( *((CK_KEY_TYPE *)(keytype->pValue)) ) {
	    case CKK_RSA:
		specialized_attrs = pkcs11_new_attrlist(p11Context,
							_ATTR(CKA_MODULUS),
							_ATTR_END );
		if(specialized_attrs && pkcs11_read_attr_from_handle (specialized_attrs, hndl) ) {
		    modulus = pkcs11_get_attr_in_attrlist ( specialized_attrs, CKA_MODULUS );
		    sprintf(keykind, "rsa(%d)", (int) ((modulus->ulValueLen)<<3));
		}
		break;

	    case CKK_EC:
		specialized_attrs = pkcs11_new_attrlist(p11Context,
							_ATTR(CKA_EC_PARAMS),
							_ATTR_END );
		if(specialized_attrs && pkcs11_read_attr_from_handle (specialized_attrs, hndl) ) {
		    ec_params = pkcs11_get_attr_in_attrlist ( specialized_attrs, CKA_EC_PARAMS );
		    sprintf(keykind, "ec(%s)", pkcs11_ec_oid2curvename( (CK_BYTE*)(ec_params->pValue),
									ec_params->ulValueLen,
									ecname,
									sizeof ecname ));
		}
		break;

	    case CKK_EC_EDWARDS:
		specialized_attrs = pkcs11_new_attrlist(p11Context,
							_ATTR(CKA_EC_PARAMS),
							_ATTR_END );
		if(specialized_attrs && pkcs11_read_attr_from_handle (specialized_attrs, hndl) ) {
		    ec_params = pkcs11_get_attr_in_attrlist ( specialized_attrs, CKA_EC_PARAMS );
		    sprintf(keykind, "ed(%s)", pkcs11_ed_oid2curvename( (CK_BYTE*)(ec_params->pValue),
									ec_params->ulValueLen,
									ecname,
									sizeof ecname ));
		}
		break;

	    case CKK_DSA:
		specialized_attrs = pkcs11_new_attrlist(p11Context,
							_ATTR(CKA_PRIME),
							_ATTR_END );
		if(specialized_attrs && pkcs11_read_attr_from_handle (specialized_attrs, hndl) ) {
		    prime = pkcs11_get_attr_in_attrlist ( specialized_attrs, CKA_PRIME );
		    sprintf(keykind, "dsa(%d)", (int) ((prime->ulValueLen)<<3));
		}
		break;

	    case CKK_DH:
		specialized_attrs = pkcs11_new_attrlist(p11Context,
							_ATTR(CKA_PRIME),
							_ATTR_END );
		if(specialized_attrs && pkcs11_read_attr_from_handle (specialized_attrs, hndl) ) {
		    prime = pkcs11_get_attr_in_attrlist ( specialized_attrs, CKA_PRIME );
		    
		    sprintf(keykind, "dh(%d)", (int) ((prime->ulValueLen)<<3));
		}
		break;

	    default:
		sprintf(keykind, "unknown(\?\?\?)");
	    }

	    label_or_id(label, id, buffer, buffer_len);

	    printf("prvk/%-*s %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
		   LABEL_WIDTH,
		   buffer,
		   value_for_boolattr(attrs,CKA_TOKEN, "tok,", "ses,", ""),
		   value_for_boolattr(attrs,CKA_PRIVATE, "prv,", "pub,", ""),
		   value_for_boolattr(attrs,CKA_MODIFIABLE, "r/w,", "r/o,", ""),

		   value_for_boolattr(attrs,CKA_LOCAL, "loc,", "imp,", ""),
		   value_for_boolattr(attrs,CKA_DERIVE, "drv,", "", ""),
		   value_for_boolattr(attrs,CKA_DECRYPT, "dec,", "", ""),
		   value_for_boolattr(attrs,CKA_SIGN, "sig,", "", ""),
		   value_for_boolattr(attrs,CKA_SIGN_RECOVER, "sir,", "", ""),
		   value_for_boolattr(attrs,CKA_UNWRAP, "unw,", "", ""),
		   value_for_boolattr(attrs,CKA_SENSITIVE, "sen,", "NSE,", ""),
		   value_for_boolattr(attrs,CKA_ALWAYS_SENSITIVE, "ase,", "NAS,", ""),
		   value_for_boolattr(attrs,CKA_EXTRACTABLE, "XTR,", "", ""),
		   value_for_boolattr(attrs,CKA_NEVER_EXTRACTABLE, "nxt,", "WXT,", ""),
		   value_for_boolattr(attrs,CKA_ALWAYS_AUTHENTICATE, "AAU,", "", ""),
		   value_for_boolattr(attrs,CKA_WRAP_WITH_TRUSTED, "wwt,", "", ""),
		   value_for_template(attrs,CKA_UNWRAP_TEMPLATE, "uwt,", ""),
		   value_for_template(attrs,CKA_DERIVE_TEMPLATE, "drt,", ""),
		   value_for_allowed_mechanisms(attrs, "alm,", ""),
		   keykind
		);
	}
	pkcs11_delete_attrlist(attrs);
    }

    return rv;

}


static int ls_seck(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl)
{
    int rv=0;
    pkcs11AttrList *attrs;

    attrs = pkcs11_new_attrlist(p11Context,
				/* storage object attributes */
				_ATTR(CKA_TOKEN),
				_ATTR(CKA_PRIVATE),
				_ATTR(CKA_MODIFIABLE),
				_ATTR(CKA_LABEL),

				/* KEY attributes */
				_ATTR(CKA_KEY_TYPE),
				_ATTR(CKA_ID),
				_ATTR(CKA_START_DATE),
				_ATTR(CKA_END_DATE),
				_ATTR(CKA_DERIVE),
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle this */
				_ATTR(CKA_DERIVE_TEMPLATE),
#endif
				_ATTR(CKA_LOCAL),
				_ATTR(CKA_KEY_GEN_MECHANISM), /* NSS: unknown? */
				_ATTR(CKA_ALLOWED_MECHANISMS),

				/* Secret Key attributes */
				_ATTR(CKA_ENCRYPT),
				_ATTR(CKA_DECRYPT),
				_ATTR(CKA_SIGN),
				_ATTR(CKA_VERIFY),
				_ATTR(CKA_WRAP),
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle this */
				_ATTR(CKA_WRAP_TEMPLATE),
#endif
				_ATTR(CKA_UNWRAP),
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle this */
				_ATTR(CKA_UNWRAP_TEMPLATE),
#endif
				_ATTR(CKA_SENSITIVE),
				_ATTR(CKA_ALWAYS_SENSITIVE),
				_ATTR(CKA_EXTRACTABLE),
				_ATTR(CKA_NEVER_EXTRACTABLE),
				_ATTR(CKA_TRUSTED),
				_ATTR(CKA_WRAP_WITH_TRUSTED),
				_ATTR(CKA_VALUE_LEN),
				_ATTR_END );

    if( attrs!=NULL) {
	if(pkcs11_read_attr_from_handle (attrs, hndl) == true) {
	    CK_ATTRIBUTE_PTR label, id;
	    char buffer[LABELORID_MAXLEN];
	    int buffer_len = sizeof buffer;

	    id         = pkcs11_get_attr_in_attrlist ( attrs, CKA_ID );
	    label      = pkcs11_get_attr_in_attrlist ( attrs, CKA_LABEL );

	    label_or_id(label, id, buffer, buffer_len);

	    printf("seck/%-*s %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
		   LABEL_WIDTH,
		   buffer,
		   value_for_boolattr(attrs,CKA_TOKEN, "tok,", "ses,", ""),
		   value_for_boolattr(attrs,CKA_PRIVATE, "prv,", "pub,", ""),
		   value_for_boolattr(attrs,CKA_MODIFIABLE, "r/w,", "r/o,", ""),

		   value_for_boolattr(attrs,CKA_LOCAL, "loc,", "imp,", ""),
		   value_for_boolattr(attrs,CKA_DERIVE, "drv,", "", ""),
		   value_for_boolattr(attrs,CKA_ENCRYPT, "enc,", "", ""),
		   value_for_boolattr(attrs,CKA_DECRYPT, "dec,", "", ""),
		   value_for_boolattr(attrs,CKA_SIGN, "sig,", "", ""),
		   value_for_boolattr(attrs,CKA_VERIFY, "vfy,", "", ""),
		   value_for_boolattr(attrs,CKA_WRAP, "wra,", "", ""),
		   value_for_boolattr(attrs,CKA_UNWRAP, "unw,", "", ""),
		   value_for_boolattr(attrs,CKA_SENSITIVE, "sen,", "NSE,", ""),
		   value_for_boolattr(attrs,CKA_ALWAYS_SENSITIVE, "ase,", "NAS,", ""),
		   value_for_boolattr(attrs,CKA_EXTRACTABLE, "XTR,", "", ""),
		   value_for_boolattr(attrs,CKA_NEVER_EXTRACTABLE, "nxt,", "WXT,", ""),
		   value_for_boolattr(attrs,CKA_TRUSTED, "tru,", "", ""),
		   value_for_boolattr(attrs,CKA_WRAP_WITH_TRUSTED, "wwt,", "", ""),
		   value_for_template(attrs,CKA_WRAP_TEMPLATE, "wrt,", ""),
		   value_for_template(attrs,CKA_UNWRAP_TEMPLATE, "uwt,", ""),
		   value_for_template(attrs,CKA_DERIVE_TEMPLATE, "drt,", ""),
		   value_for_allowed_mechanisms(attrs, "alm,", ""),		   
		   value_for_keytype(attrs)
		);
	}
	pkcs11_delete_attrlist(attrs);
    }

    return rv;

}

static int ls_data(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl)
{

    int rv=0;
    pkcs11AttrList *attrs;

    attrs = pkcs11_new_attrlist(p11Context,
				/* storage object attributes */
				_ATTR(CKA_TOKEN),
				_ATTR(CKA_PRIVATE),
				_ATTR(CKA_MODIFIABLE),
				_ATTR(CKA_LABEL),

				/* OBJECT attributes */
//				_ATTR(CKA_APPLICATION),
//				_ATTR(CKA_OBJECT_ID),

				_ATTR_END );

    if(attrs!=NULL) {
	if( pkcs11_read_attr_from_handle (attrs, hndl) == true) {
	    CK_ATTRIBUTE_PTR label;
	    char buffer[LABELORID_MAXLEN];
	    int  buffer_len = sizeof buffer;

	    label      = pkcs11_get_attr_in_attrlist ( attrs, CKA_LABEL );
//	    objid      = pkcs11_get_attr_in_attrlist ( attrs, CKA_OBJECT_ID );
//	    applic     = pkcs11_get_attr_in_attrlist ( attrs, CKA_APPLICATION );

	    label_or_id(label, NULL, buffer, buffer_len);

	    printf("data/%-*s %s%s\n",
		   LABEL_WIDTH,
		   buffer,
		   value_for_boolattr(attrs,CKA_TOKEN, "tok,", "ses,", ""),
		   value_for_boolattr(attrs,CKA_PRIVATE, "prv,", "pub,", "")
		);
	}

	pkcs11_delete_attrlist(attrs);
    }

    return rv;

}


func_rc pkcs11_ls( pkcs11Context *p11Context, char *label)
{
    func_rc frc = rc_ok;

    pkcs11IdTemplate * idtmpl=NULL;
    pkcs11Search *search=NULL;

	CK_ATTRIBUTE* additional_attributes = NULL;
	CK_ULONG additional_attributes_len = 0;
    /* trick: we treat "cert", "pubk", "prvk", "seck" and "data" in front of the templating system */
    /* so these specific labels can be used as shortcut for the corresponding object classes       */

    if(label!=NULL) {
	if(strcasecmp("cert",label)==0) {
	    idtmpl = pkcs11_make_idtemplate(CLASS_CERT);
	} else if (strcasecmp("pubk",label)==0) {
	    idtmpl = pkcs11_make_idtemplate(CLASS_PUBK);
	} else if (strcasecmp("prvk",label)==0) {
	    idtmpl = pkcs11_make_idtemplate(CLASS_PRVK);
	} else if (strcasecmp("seck",label)==0) {
	    idtmpl = pkcs11_make_idtemplate(CLASS_SECK);
	} else if (strcasecmp("data",label)==0) {
	    idtmpl = pkcs11_make_idtemplate(CLASS_DATA);
	} else {
	    idtmpl = pkcs11_create_id(label);
	}
    }

    if(idtmpl) {
	search = pkcs11_new_search_from_idtemplate( p11Context, idtmpl );

	if(search) {		/* we just need one hit */

	    CK_OBJECT_HANDLE hndl=0;
	    int objcnt = 0;

	    while( (hndl = pkcs11_fetch_next(search))!=0 ) {

		pkcs11AttrList *attrs;

		++objcnt;

		attrs = pkcs11_new_attrlist(p11Context, _ATTR(CKA_CLASS), _ATTR_END);

		if(attrs) {

		    if( pkcs11_read_attr_from_handle_ext (attrs, hndl,
							  CKR_ATTRIBUTE_SENSITIVE, /* we skip over sensitive attributes */
							  CKR_FUNCTION_FAILED,     /* workaround for nCipher bug 30966 */
							  0L) == true) {

			CK_ATTRIBUTE_PTR objclass = pkcs11_get_attr_in_attrlist(attrs, CKA_CLASS);

			switch( *((CK_OBJECT_CLASS *)objclass->pValue) ) {
			case CKO_DATA:
			    ls_data(p11Context, hndl);
			    break;

			case CKO_CERTIFICATE:
			    ls_cert(p11Context, hndl);
			    break;

			case CKO_PUBLIC_KEY:
			    ls_pubk(p11Context, hndl);
			    break;

			case CKO_PRIVATE_KEY:
			    ls_prvk(p11Context, hndl);
			    break;

			case CKO_SECRET_KEY:
			    ls_seck(p11Context, hndl);
			    break;

			default:
			    break;
			}
		    }
		    pkcs11_delete_attrlist(attrs);
		}
	    }
	    pkcs11_delete_search(search);
	}
	else {
		fprintf(stderr, "Error: unable to create a search. - ['%s'].\n", label);
	}
	pkcs11_delete_idtemplate(idtmpl);
    }

    return frc;
}

/* EOF */
