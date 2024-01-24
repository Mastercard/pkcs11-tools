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

typedef enum { no_cast,
	       as_bool,
	       as_ulong,
	       as_string,
	       as_string_maybe,
	       as_object_class,
	       as_key_type,
	       as_cert_type,
	       as_mech_type,
	       as_template,
} ck_cast;


typedef struct {
    CK_ATTRIBUTE_TYPE attr;
    char *name;
    ck_cast cast;
} attrib_repr;


static attrib_repr list[] = {

    { CKA_CLASS, "CKA_CLASS", as_object_class },
    { CKA_TOKEN, "CKA_TOKEN", as_bool },
    { CKA_PRIVATE, "CKA_PRIVATE", as_bool },
    { CKA_LABEL, "CKA_LABEL", as_string },
    { CKA_APPLICATION, "CKA_APPLICATION", no_cast },
    { CKA_VALUE, "CKA_VALUE", no_cast },
    { CKA_OBJECT_ID, "CKA_OBJECT_ID", no_cast },
    { CKA_CERTIFICATE_TYPE, "CKA_CERTIFICATE_TYPE", as_cert_type },
    { CKA_ISSUER, "CKA_ISSUER", no_cast },
    { CKA_SERIAL_NUMBER, "CKA_SERIAL_NUMBER", no_cast },
    { CKA_AC_ISSUER, "CKA_AC_ISSUER", no_cast },
    { CKA_OWNER, "CKA_OWNER", no_cast },
    { CKA_ATTR_TYPES, "CKA_ATTR_TYPES", no_cast },
    { CKA_TRUSTED, "CKA_TRUSTED", as_bool },
    { CKA_CERTIFICATE_CATEGORY, "CKA_CERTIFICATE_CATEGORY", no_cast },
    { CKA_JAVA_MIDP_SECURITY_DOMAIN, "CKA_JAVA_MIDP_SECURITY_DOMAIN", no_cast },
    { CKA_URL, "CKA_URL", no_cast },
    { CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", no_cast },
    { CKA_HASH_OF_ISSUER_PUBLIC_KEY, "CKA_HASH_OF_ISSUER_PUBLIC_KEY", no_cast },
    { CKA_CHECK_VALUE, "CKA_CHECK_VALUE", no_cast },
    { CKA_KEY_TYPE, "CKA_KEY_TYPE", as_key_type },
    { CKA_SUBJECT, "CKA_SUBJECT", no_cast },
    { CKA_ID, "CKA_ID", as_string_maybe },
    { CKA_SENSITIVE, "CKA_SENSITIVE", as_bool },
    { CKA_ENCRYPT, "CKA_ENCRYPT", as_bool },
    { CKA_DECRYPT, "CKA_DECRYPT", as_bool },
    { CKA_WRAP, "CKA_WRAP", as_bool },
    { CKA_UNWRAP, "CKA_UNWRAP", as_bool },
    { CKA_SIGN, "CKA_SIGN", as_bool },
    { CKA_SIGN_RECOVER, "CKA_SIGN_RECOVER", as_bool },
    { CKA_VERIFY, "CKA_VERIFY", as_bool },
    { CKA_VERIFY_RECOVER, "CKA_VERIFY_RECOVER", as_bool },
    { CKA_DERIVE, "CKA_DERIVE", as_bool },
    { CKA_START_DATE, "CKA_START_DATE", no_cast },
    { CKA_END_DATE, "CKA_END_DATE", no_cast },
    { CKA_MODULUS, "CKA_MODULUS", no_cast },
    { CKA_MODULUS_BITS, "CKA_MODULUS_BITS", as_ulong },
    { CKA_PUBLIC_EXPONENT, "CKA_PUBLIC_EXPONENT", no_cast },
    { CKA_PRIVATE_EXPONENT, "CKA_PRIVATE_EXPONENT", no_cast },
    { CKA_PRIME_1, "CKA_PRIME_1", no_cast },
    { CKA_PRIME_2, "CKA_PRIME_2", no_cast },
    { CKA_EXPONENT_1, "CKA_EXPONENT_1", no_cast },
    { CKA_EXPONENT_2, "CKA_EXPONENT_2", no_cast },
    { CKA_COEFFICIENT, "CKA_COEFFICIENT", no_cast },
    { CKA_PRIME, "CKA_PRIME", no_cast },
    { CKA_SUBPRIME, "CKA_SUBPRIME", no_cast },
    { CKA_BASE, "CKA_BASE", no_cast },

    { CKA_PRIME_BITS, "CKA_PRIME_BITS", as_ulong },
    { CKA_SUBPRIME_BITS, "CKA_SUBPRIME_BITS", as_ulong },

    { CKA_VALUE_BITS, "CKA_VALUE_BITS", as_ulong },
    { CKA_VALUE_LEN, "CKA_VALUE_LEN", as_ulong },
    { CKA_EXTRACTABLE, "CKA_EXTRACTABLE", as_bool },
    { CKA_LOCAL, "CKA_LOCAL", as_bool },
    { CKA_NEVER_EXTRACTABLE, "CKA_NEVER_EXTRACTABLE", as_bool },
    { CKA_ALWAYS_SENSITIVE, "CKA_ALWAYS_SENSITIVE", as_bool },
    { CKA_KEY_GEN_MECHANISM, "CKA_KEY_GEN_MECHANISM", as_mech_type },

    { CKA_MODIFIABLE, "CKA_MODIFIABLE", as_bool },
    { CKA_COPYABLE, "CKA_COPYABLE", as_bool },
    { CKA_DESTROYABLE, "CKA_DESTROYABLE", as_bool },

    { CKA_EC_PARAMS, "CKA_EC_PARAMS", no_cast },

    { CKA_EC_POINT, "CKA_EC_POINT", no_cast },

/* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
 * are new for v2.10. Deprecated in v2.11 and onwards. */
    { CKA_SECONDARY_AUTH, "CKA_SECONDARY_AUTH", no_cast },
    { CKA_AUTH_PIN_FLAGS, "CKA_AUTH_PIN_FLAGS", no_cast },

    { CKA_ALWAYS_AUTHENTICATE, "CKA_ALWAYS_AUTHENTICATE", as_bool },

    { CKA_WRAP_WITH_TRUSTED, "CKA_WRAP_WITH_TRUSTED", as_bool },
    { CKA_WRAP_TEMPLATE, "CKA_WRAP_TEMPLATE", as_template },
    { CKA_UNWRAP_TEMPLATE, "CKA_UNWRAP_TEMPLATE", as_template },
    { CKA_DERIVE_TEMPLATE, "CKA_DERIVE_TEMPLATE", as_template },

    { CKA_OTP_FORMAT, "CKA_OTP_FORMAT", no_cast },
    { CKA_OTP_LENGTH, "CKA_OTP_LENGTH", no_cast },
    { CKA_OTP_TIME_INTERVAL, "CKA_OTP_TIME_INTERVAL", no_cast },
    { CKA_OTP_USER_FRIENDLY_MODE, "CKA_OTP_USER_FRIENDLY_MODE", no_cast },
    { CKA_OTP_CHALLENGE_REQUIREMENT, "CKA_OTP_CHALLENGE_REQUIREMENT", no_cast },
    { CKA_OTP_TIME_REQUIREMENT, "CKA_OTP_TIME_REQUIREMENT", no_cast },
    { CKA_OTP_COUNTER_REQUIREMENT, "CKA_OTP_COUNTER_REQUIREMENT", no_cast },
    { CKA_OTP_PIN_REQUIREMENT, "CKA_OTP_PIN_REQUIREMENT", no_cast },
    { CKA_OTP_COUNTER, "CKA_OTP_COUNTER", no_cast },
    { CKA_OTP_TIME, "CKA_OTP_TIME", no_cast },
    { CKA_OTP_USER_IDENTIFIER, "CKA_OTP_USER_IDENTIFIER", no_cast },
    { CKA_OTP_SERVICE_IDENTIFIER, "CKA_OTP_SERVICE_IDENTIFIER", no_cast },
    { CKA_OTP_SERVICE_LOGO, "CKA_OTP_SERVICE_LOGO", no_cast },
    { CKA_OTP_SERVICE_LOGO_TYPE, "CKA_OTP_SERVICE_LOGO_TYPE", no_cast },

    { CKA_GOSTR3410_PARAMS, "CKA_GOSTR3410_PARAMS", no_cast },
    { CKA_GOSTR3411_PARAMS, "CKA_GOSTR3411_PARAMS", no_cast },
    { CKA_GOST28147_PARAMS, "CKA_GOST28147_PARAMS", no_cast },

    { CKA_HW_FEATURE_TYPE, "CKA_HW_FEATURE_TYPE", no_cast },
    { CKA_RESET_ON_INIT, "CKA_RESET_ON_INIT", as_bool },
    { CKA_HAS_RESET, "CKA_HAS_RESET", as_bool },

    { CKA_PIXEL_X, "CKA_PIXEL_X", no_cast },
    { CKA_PIXEL_Y, "CKA_PIXEL_Y", no_cast },
    { CKA_RESOLUTION, "CKA_RESOLUTION", no_cast },
    { CKA_CHAR_ROWS, "CKA_CHAR_ROWS", no_cast },
    { CKA_CHAR_COLUMNS, "CKA_CHAR_COLUMNS", no_cast },
    { CKA_COLOR, "CKA_COLOR", no_cast },
    { CKA_BITS_PER_PIXEL, "CKA_BITS_PER_PIXEL", no_cast },
    { CKA_CHAR_SETS, "CKA_CHAR_SETS", no_cast },
    { CKA_ENCODING_METHODS, "CKA_ENCODING_METHODS", no_cast },
    { CKA_MIME_TYPES, "CKA_MIME_TYPES", no_cast },
    { CKA_MECHANISM_TYPE, "CKA_MECHANISM_TYPE", as_mech_type },
    { CKA_REQUIRED_CMS_ATTRIBUTES, "CKA_REQUIRED_CMS_ATTRIBUTES", no_cast },
    { CKA_DEFAULT_CMS_ATTRIBUTES, "CKA_DEFAULT_CMS_ATTRIBUTES", no_cast },
    { CKA_SUPPORTED_CMS_ATTRIBUTES, "CKA_SUPPORTED_CMS_ATTRIBUTES", no_cast },
    { CKA_ALLOWED_MECHANISMS, "CKA_ALLOWED_MECHANISMS", as_mech_type },

#if defined(HAVE_NCIPHER)	/* added only when nCipher support is requested */
    { CKA_NFKM_ID, "CKA_NFKM_ID", no_cast },
    { CKA_NFKM_APPNAME, "CKA_NFKM_APPNAME", no_cast },
    { CKA_NFKM_HASH, "CKA_NFKM_HASH", no_cast },
#endif

};


/* taken from linux kernel and modified */


static void hexdump (attrib_repr *item, void *addr, unsigned long len, bool template) {
    unsigned long i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;
    char *info;

    /* spot early invalid template condition */
    /* some HSM vendor are messing up with the CKA_XXX_TEMPLATE attributes,  */
    /* we will detect when it happens and skip them.  */
    if ( item && item->cast==as_template && ( len==0 || (len % sizeof(CK_ATTRIBUTE) != 0) ) ) {
	return;			/* bad template, return early, skip any printing */
    }
    
    printf (" %s%s:\n", template ? "| " : "" , item->name);

    switch(item->cast) {

    case as_ulong:
	for (i = 0; i < len; i++) {
	    if ((i % 16) == 0) {
		// Output the offset.
		printf ("%s  %04lx ", template ? "| ":"", i);
	    }

	    printf (" %02x", pc[i]);
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
	    printf ("   ");
	    i++;
	}

	// And print cast to CK_ULONG
	printf ("  %s%ld (0x%8.8lx)\n", template ? "" : "  ", *((CK_ULONG *)addr), *((CK_ULONG *)addr));
	break;

    case as_bool:
	for (i = 0; i < len; i++) {
	    if ((i % 16) == 0) {
		// Output the offset.
		printf (" %s %04lx ", template ? "| " : "", i);
	    }

	    printf (" %02x", pc[i]);
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
	    printf ("   ");
	    i++;
	}

	printf ("  %s%s\n", template ? "" : "  ", (CK_BBOOL)(pc[0])== CK_TRUE ? "CK_TRUE" : "CK_FALSE");
	break;

    case as_object_class:

	for (i = 0; i < len; i++) {
	    if ((i % 16) == 0) {
		// Output the offset.
		printf (" %s %04lx ", template ? "| " : "", i);
	    }

	    printf (" %02x", pc[i]);
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
	    printf ("   ");
	    i++;
	}

	switch( *(CK_OBJECT_CLASS *)addr ) {
	case CKO_DATA:
	    info = "CKO_DATA";
	    break;

	case CKO_CERTIFICATE:
	    info = "CKO_CERTIFICATE";
	    break;

	case CKO_PUBLIC_KEY:
	    info = "CKO_PUBLIC_KEY";
	    break;

	case CKO_PRIVATE_KEY:
	    info = "CKO_PRIVATE_KEY";
	    break;

	case CKO_SECRET_KEY:
	    info = "CKO_SECRET_KEY";
	    break;

	case CKO_HW_FEATURE:
	    info = "CKO_HW_FEATURE";
	    break;

	case CKO_DOMAIN_PARAMETERS:
	    info = "CKO_DOMAIN_PARAMETERS";
	    break;

	case CKO_MECHANISM:
	    info = "CKO_MECHANISM";
	    break;

	case CKO_OTP_KEY:
	    info = "CKO_OTP_KEY";
	    break;

	default:
	    info = (*(CK_OBJECT_CLASS *)addr) & CKO_VENDOR_DEFINED ? "CKO_VENDOR_DEFINED" : "??unknown object type" ;
	    break;
	}

	printf ("  %s%s\n", template ? "" : "  ", info);
	break;


    case as_key_type:

	for (i = 0; i < len; i++) {
	    if ((i % 16) == 0) {
		// Output the offset.
		printf (" %s %04lx ", template ? "| " : "", i);
	    }

	    printf (" %02x", pc[i]);
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
	    printf ("   ");
	    i++;
	}

	switch( *(CK_KEY_TYPE *)addr ) {

	case CKK_RSA:
	    info = "CKK_RSA";
	    break;

	case CKK_DSA:
	    info = "CKK_DSA";
	    break;

	case CKK_DH:
	    info = "CKK_DH";
	    break;

	case CKK_EC:
	    info = "CKK_EC";
	    break;

	case CKK_EC_EDWARDS:
	    info = "CKK_EC_EDWARDS";
	    break;

	case CKK_X9_42_DH:
	    info = "CKK_X9_42_DH";
	    break;

	case CKK_KEA:
	    info = "CKK_KEA";
	    break;

	case CKK_GENERIC_SECRET:
	    info = "CKK_GENERIC_SECRET";
	    break;

	case CKK_RC2:
	    info = "CKK_RC2";
	    break;

	case CKK_RC4:
	    info = "CKK_RC4";
	    break;

	case CKK_DES:
	    info = "CKK_DES";
	    break;

	case CKK_DES2:
	    info = "CKK_DES2";
	    break;

	case CKK_DES3:
	    info = "CKK_DES3";
	    break;

	case CKK_CAST:
	    info = "CKK_CAST";
	    break;

	case CKK_CAST3:
	    info = "CKK_CAST3";
	    break;

	case CKK_CAST128:
	    info = "CKK_CAST128";
	    break;

	case CKK_RC5:
	    info = "CKK_RC5";
	    break;

	case CKK_IDEA:
	    info = "CKK_IDEA";
	    break;

	case CKK_SKIPJACK:
	    info = "CKK_SKIPJACK";
	    break;

	case CKK_BATON:
	    info = "CKK_BATON";
	    break;

	case CKK_JUNIPER:
	    info = "CKK_JUNIPER";
	    break;

	case CKK_CDMF:
	    info = "CKK_CDMF";
	    break;

	case CKK_AES:
	    info = "CKK_AES";
	    break;

	case CKK_BLOWFISH:
	    info = "CKK_BLOWFISH";
	    break;

	case CKK_TWOFISH:
	    info = "CKK_TWOFISH";
	    break;

	case CKK_SECURID:
	    info = "CKK_SECURID";
	    break;

	case CKK_HOTP:
	    info = "CKK_HOTP";
	    break;

	case CKK_ACTI:
	    info = "CKK_ACTI";
	    break;

	case CKK_CAMELLIA:
	    info = "CKK_CAMELLIA";
	    break;

	case CKK_ARIA:
	    info = "CKK_ARIA";
	    break;

	case CKK_MD5_HMAC:
	    info = "CKK_MD5_HMAC";
	    break;

	case CKK_SHA_1_HMAC:
	    info = "CKK_SHA_1_HMAC";
	    break;

	case CKK_RIPEMD128_HMAC:
	    info = "CKK_RIPEMD128_HMAC";
	    break;

	case CKK_RIPEMD160_HMAC:
	    info = "CKK_RIPEMD160_HMAC";
	    break;

	case CKK_SHA256_HMAC:
	    info = "CKK_SHA256_HMAC";
	    break;

	case CKK_SHA384_HMAC:
	    info = "CKK_SHA384_HMAC";
	    break;

	case CKK_SHA512_HMAC:
	    info = "CKK_SHA512_HMAC";
	    break;

	case CKK_SHA224_HMAC:
	    info = "CKK_SHA224_HMAC";
	    break;

	case CKK_SEED:
	    info = "CKK_SEED";
	    break;

	case CKK_GOSTR3410:
	    info = "CKK_GOSTR3410";
	    break;

	case CKK_GOSTR3411:
	    info = "CKK_GOSTR3411";
	    break;

	case CKK_GOST28147:
	    info = "CKK_GOST28147";
	    break;

	default:
	    info = (*(CK_KEY_TYPE *)addr) & CKK_VENDOR_DEFINED ? "CKK_VENDOR_DEFINED" : "??unknown key type" ;
	    break;
	}

	printf ("  %s%s\n", template ? "" : "  ", info);
	break;

    case as_cert_type:

	for (i = 0; i < len; i++) {
	    if ((i % 16) == 0) {
		// Output the offset.
		printf (" %s %04lx ", template ? "| " : "", i);
	    }

	    printf (" %02x", pc[i]);
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
	    printf ("   ");
	    i++;
	}

	switch( *(CK_CERTIFICATE_TYPE *)addr ) {

	case CKC_X_509:
	    info = "CKC_X_509";
	    break;

	case CKC_X_509_ATTR_CERT:
	    info = "CKC_X_509_ATTR_CERT";
	    break;

	case CKC_WTLS:
	    info = "CKC_WTLS";
	    break;

	default:
	    info = (*(CK_CERTIFICATE_TYPE *)addr) & CKC_VENDOR_DEFINED ? "CKC_VENDOR_DEFINED" : "??unknown certificate type" ;
	    break;
	}

	printf ("  %s%s\n", template ? "" : "  ", info);
	break;

    case as_mech_type:
    {
	CK_MECHANISM_TYPE_PTR pmech = NULL;	
	for (i = 0; i < len; i++) {
	    if ( i % sizeof(CK_MECHANISM_TYPE) == 0) {
		// Output the offset.
		printf (" %s %04lx ", template ? "| " : "", i);
		/* the current position in buffer is a mechanism, remember it */
		/* tricky cast in action... */
		pmech = (CK_MECHANISM_TYPE_PTR) (&((uint8_t *)addr)[i]);
	    }

	    printf (" %02x", pc[i]);

	    if (i && ( i % sizeof(CK_MECHANISM_TYPE)) == sizeof(CK_MECHANISM_TYPE)-1 ) {
		/* a few words: a full line is displaying 16 hex bytes (separated by one space) */
		/* however, CK_MECHANISM_TYPE len may differ (depends on the platform) */
		/* we compensate by adding white characters */
		printf ("%*s  %s%s\n",
			(int)(16-sizeof(CK_MECHANISM_TYPE))*3,
			"",
			template ? "" : "  ", pkcs11_get_mechanism_name_from_type( *pmech ) );
	    }
	}
    }
    break;

    case no_cast:
    case as_string:
    case as_string_maybe:
	memset(buff,0,sizeof buff);
	// Process every byte in the data.
	for (i = 0; i < len; i++) {
	    // Multiple of 16 means new line (with line offset).

	    if ((i % 16) == 0) {
		// Just don't print ASCII for the zeroth line.
		if (i != 0) {
		    printf ("  %s%s\n", template ? "" : "  ", buff);
		}
		// Output the offset.
		printf (" %s %04lx ", template ? "| " : "", i);
	    }

	    // Now the hex code for the specific character.
	    printf (" %02x", pc[i]);

	    // And store a printable ASCII character for later.
	    if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
		buff[i % 16] = '.';
	    } else {
		buff[i % 16] = pc[i];
	    }
	    buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
	    printf ("   ");
	    i++;
	}

	// And print the final ASCII bit.
	printf ("  %s%s\n", template ? "" : "  ", buff);
	break;

    case as_template:
	/* we need to cast the buffer into an array of CK_ATTRIBUTE */
	for ( i=0; i< sizeof(list)/sizeof(attrib_repr); i++ ) {
	    
	    CK_ATTRIBUTE_PTR item = pkcs11_get_attr_in_array(addr, len, list[i].attr );

	    /* if the template does not have a compliant length, do not show it. */
	    if(item && item->pValue && item->ulValueLen) {
		hexdump( &list[i], item->pValue, item->ulValueLen, true);
	    }
	}	
	break;
    }
}


/* High-level search functions */

func_rc pkcs11_dump_object_with_label(pkcs11Context *p11Context, char *label)
{

    func_rc rc=rc_ok;
    pkcs11IdTemplate * idtmpl=NULL;
    pkcs11Search *search=NULL;

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

		attrs = pkcs11_new_attrlist(p11Context,
					    _ATTR(CKA_CLASS),
					    _ATTR(CKA_TOKEN),
					    _ATTR(CKA_PRIVATE),
					    _ATTR(CKA_LABEL),
					    _ATTR(CKA_APPLICATION),
					    _ATTR(CKA_VALUE),
					    _ATTR(CKA_OBJECT_ID),
					    _ATTR(CKA_CERTIFICATE_TYPE),
					    _ATTR(CKA_ISSUER),
					    _ATTR(CKA_SERIAL_NUMBER),
					    _ATTR(CKA_AC_ISSUER),
					    _ATTR(CKA_OWNER),
					    _ATTR(CKA_ATTR_TYPES),
					    _ATTR(CKA_TRUSTED),
					    _ATTR(CKA_CERTIFICATE_CATEGORY),
					    _ATTR(CKA_JAVA_MIDP_SECURITY_DOMAIN),
					    _ATTR(CKA_URL),
					    _ATTR(CKA_HASH_OF_SUBJECT_PUBLIC_KEY),
					    _ATTR(CKA_HASH_OF_ISSUER_PUBLIC_KEY),
					    _ATTR(CKA_CHECK_VALUE),
					    _ATTR(CKA_KEY_TYPE),
					    _ATTR(CKA_SUBJECT),
					    _ATTR(CKA_ID),
					    _ATTR(CKA_SENSITIVE),
					    _ATTR(CKA_ENCRYPT),
					    _ATTR(CKA_DECRYPT),
					    _ATTR(CKA_WRAP),
					    _ATTR(CKA_UNWRAP),
					    _ATTR(CKA_SIGN),
					    _ATTR(CKA_SIGN_RECOVER),
					    _ATTR(CKA_VERIFY),
					    _ATTR(CKA_VERIFY_RECOVER),
					    _ATTR(CKA_DERIVE),
					    _ATTR(CKA_START_DATE),
					    _ATTR(CKA_END_DATE),
					    _ATTR(CKA_MODULUS),
					    _ATTR(CKA_MODULUS_BITS),
					    _ATTR(CKA_PUBLIC_EXPONENT),
					    _ATTR(CKA_PRIVATE_EXPONENT),
					    _ATTR(CKA_PRIME_1),
					    _ATTR(CKA_PRIME_2),
					    _ATTR(CKA_EXPONENT_1),
					    _ATTR(CKA_EXPONENT_2),
					    _ATTR(CKA_COEFFICIENT),
					    _ATTR(CKA_PRIME),
					    _ATTR(CKA_SUBPRIME),
					    _ATTR(CKA_BASE),

					    _ATTR(CKA_PRIME_BITS),
					    _ATTR(CKA_SUBPRIME_BITS),

					    _ATTR(CKA_VALUE_BITS),
					    _ATTR(CKA_VALUE_LEN),
					    _ATTR(CKA_EXTRACTABLE),
					    _ATTR(CKA_LOCAL),
					    _ATTR(CKA_NEVER_EXTRACTABLE),
					    _ATTR(CKA_ALWAYS_SENSITIVE),
					    _ATTR(CKA_KEY_GEN_MECHANISM),

					    _ATTR(CKA_MODIFIABLE),
					    _ATTR(CKA_COPYABLE),
					    _ATTR(CKA_DESTROYABLE),

					    _ATTR(CKA_EC_PARAMS),

					    _ATTR(CKA_EC_POINT),

/* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
 * are new for v2.10. Deprecated in v2.11 and onwards. */
					    _ATTR(CKA_SECONDARY_AUTH),
					    _ATTR(CKA_AUTH_PIN_FLAGS),

					    _ATTR(CKA_ALWAYS_AUTHENTICATE),

					    _ATTR(CKA_WRAP_WITH_TRUSTED),
					    _ATTR(CKA_WRAP_TEMPLATE),
					    _ATTR(CKA_UNWRAP_TEMPLATE),
					    _ATTR(CKA_DERIVE_TEMPLATE),

					    _ATTR(CKA_OTP_FORMAT),
					    _ATTR(CKA_OTP_LENGTH),
					    _ATTR(CKA_OTP_TIME_INTERVAL),
					    _ATTR(CKA_OTP_USER_FRIENDLY_MODE),
					    _ATTR(CKA_OTP_CHALLENGE_REQUIREMENT),
					    _ATTR(CKA_OTP_TIME_REQUIREMENT),
					    _ATTR(CKA_OTP_COUNTER_REQUIREMENT),
					    _ATTR(CKA_OTP_PIN_REQUIREMENT),
					    _ATTR(CKA_OTP_COUNTER),
					    _ATTR(CKA_OTP_TIME),
					    _ATTR(CKA_OTP_USER_IDENTIFIER),
					    _ATTR(CKA_OTP_SERVICE_IDENTIFIER),
					    _ATTR(CKA_OTP_SERVICE_LOGO),
					    _ATTR(CKA_OTP_SERVICE_LOGO_TYPE),

					    _ATTR(CKA_GOSTR3410_PARAMS),
					    _ATTR(CKA_GOSTR3411_PARAMS),
					    _ATTR(CKA_GOST28147_PARAMS),

					    _ATTR(CKA_HW_FEATURE_TYPE),
					    _ATTR(CKA_RESET_ON_INIT),
					    _ATTR(CKA_HAS_RESET),

					    _ATTR(CKA_PIXEL_X),
					    _ATTR(CKA_PIXEL_Y),
					    _ATTR(CKA_RESOLUTION),
					    _ATTR(CKA_CHAR_ROWS),
					    _ATTR(CKA_CHAR_COLUMNS),
					    _ATTR(CKA_COLOR),
					    _ATTR(CKA_BITS_PER_PIXEL),
					    _ATTR(CKA_CHAR_SETS),
					    _ATTR(CKA_ENCODING_METHODS),
					    _ATTR(CKA_MIME_TYPES),
					    _ATTR(CKA_MECHANISM_TYPE),
					    _ATTR(CKA_REQUIRED_CMS_ATTRIBUTES),
					    _ATTR(CKA_DEFAULT_CMS_ATTRIBUTES),
					    _ATTR(CKA_SUPPORTED_CMS_ATTRIBUTES),
					    _ATTR(CKA_ALLOWED_MECHANISMS),

#if defined(HAVE_NCIPHER)
					    /* nCipher */
					    _ATTR(CKA_NFKM_ID),
					    _ATTR(CKA_NFKM_APPNAME),
					    _ATTR(CKA_NFKM_HASH),
#endif

					    _ATTR_END );

		if( pkcs11_read_attr_from_handle_ext (attrs, hndl,
						      CKR_ATTRIBUTE_SENSITIVE, /* we skip over sensitive attributes */
						      CKR_FUNCTION_FAILED,     /* workaround for nCipher bug 30966 */
						      0L) == true) {

		    int i;

		    if(label) {
			printf("%s:\n", label);
		    } else {
			printf("Item[%d]:\n", objcnt);
		    }

		    for ( i=0; i< sizeof(list)/sizeof(attrib_repr); i++ ) {

			CK_ATTRIBUTE_PTR item = pkcs11_get_attr_in_attrlist(attrs, list[i].attr );

			if(item && item->ulValueLen) {
			    hexdump( &list[i], item->pValue, item->ulValueLen, false);
			}
		    }
		    printf("\n");
		}
		pkcs11_delete_attrlist(attrs);

	    }
	    pkcs11_delete_search(search);
	}
	pkcs11_delete_idtemplate(idtmpl);
    }

    return rc;
}

/* EOF */
