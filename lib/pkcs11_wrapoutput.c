//
// Created by Lippold, Georg on 23/6/2023.
//

/*
 * Copyright (c) 2023 Mastercard
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
#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <search.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
//#include <openssl/x509.h>

#include "pkcs11lib.h"

#define INDENTATION_OFFSET 4

static func_rc _output_wrapped_key_header(wrappedKeyCtx *wctx, FILE *fp);

static func_rc _output_wrapped_key_attributes(wrappedKeyCtx *wctx, FILE *fp);

static func_rc _output_wrapped_keys_b64(wrappedKeyCtx *wctx, FILE *fp);

static func_rc _output_wrapped_key_attrs_jwk(wrappedKeyCtx *wctx, FILE *fp);

static func_rc _output_public_key_attributes(wrappedKeyCtx *wctx, FILE *fp);

static func_rc _output_wrapped_keys_jwk(wrappedKeyCtx *wctx, FILE *fp, char* wrapping_key_id);

static func_rc _output_public_key_b64(wrappedKeyCtx *wctx, FILE *fp);

/* private structs */
typedef struct {
    CK_ATTRIBUTE_TYPE attr_type;

    void (*func_ptr)(FILE *, char *, CK_ATTRIBUTE_PTR, bool, int);

    char *name;
    bool commented;
} attr_printer;

typedef struct {
    CK_ATTRIBUTE_TYPE attr_type;
    char *name;
} attr_jwk;


/* private function prototypes */
static char const *_get_str_for_wrapping_algorithm(enum wrappingmethod w, CK_MECHANISM_TYPE m);

static char const *get_wrapping_algorithm_short(wrappedKeyCtx *wctx);

static func_rc fprintf_wrapping_algorithm_full(FILE *fp, wrappedKeyCtx *wctx, char *buffer, size_t buffer_len, int keyindex);

static void fprintf_template_attr_member(FILE *fp, CK_ATTRIBUTE_PTR attr, int offset);

static void fprintf_key_type(FILE *fp, char *unused, CK_ATTRIBUTE_PTR attr, bool unused2, int offset);

static void fprintf_object_class(FILE *fp, char *unused, CK_ATTRIBUTE_PTR attr, bool unused2, int offset);

static void fprintf_boolean_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset);

static void fprintf_hex_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset);

static void _fprintf_str_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset);

static void fprintf_str_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset);

static void fprintf_date_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset);

static void fprintf_template_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset);

static void fprintf_mechanism_type_array(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset);

static char *sprintf_hex_buffer(CK_BYTE_PTR buffer, CK_ULONG len);

static char *_sprintf_str_buffer(CK_BYTE_PTR buffer, CK_ULONG len);

static char *sprintf_str_buffer_safe(CK_BYTE_PTR buffer, CK_ULONG len);

static void free_sprintf_str_buffer_safe_buf(char *ptr);

static char *const _mgfstring(CK_RSA_PKCS_MGF_TYPE mgf);

static char *const _hashstring(CK_MECHANISM_TYPE hash);

static char const *_get_str_for_wrapping_algorithm(enum wrappingmethod w, CK_MECHANISM_TYPE m) {
    char *rc;
    switch (w) {
	case w_pkcs1_15:
	    rc = "PKCS#1 1.5";
	    break;

	case w_pkcs1_oaep:
	    rc = "PKCS#1 OAEP";
	    break;

	case w_cbcpad:
	    rc = "PKCS#11 CKM_xxx_CBC_PAD, with PKCS#7 padding";
	    break;

	case w_rfc3394:
	    switch (m) {
		case CKM_AES_KEY_WRAP:
		    rc = "PKCS#11 CKM_AES_KEY_WRAP (RFC3394)";
		    break;

		case CKM_NSS_AES_KEY_WRAP:
		    rc = "NSS CKM_NSS_AES_KEY_WRAP (RFC3394)";
		    break;

#if defined(HAVE_LUNA)
		    case CKM_LUNA_AES_KW:
			rc = "Gemalto Safenet Luna CKM_AES_KW (RFC3394)";
			break;
#endif

		default:
		    rc = "Unknown???";
	    }
	    break;

	case w_rfc5649:
	    switch (m) {
		case CKM_AES_KEY_WRAP_PAD:
		    rc = "PKCS#11 v2.40 CKM_AES_KEY_WRAP_PAD (RFC5649)";
		    break;

		case CKM_NSS_AES_KEY_WRAP_PAD:
		    rc = "NSS CKM_NSS_AES_KEY_WRAP_PAD (!!<>RFC5649)";
		    break;

#if defined(HAVE_LUNA)
		    case CKM_LUNA_AES_KWP:
			rc = "Gemalto Safenet Luna CKM_AES_KWP (RFC5649)";
			break;
#endif

		default:
		    rc = "Unknown???";
	    }
	    break;

	default:
	    rc = "Unknown???";
    }

    return rc;
}

static char const *get_wrapping_algorithm_short(wrappedKeyCtx *wctx) {
    if (wctx->is_envelope) {
	return "Envelope";    /* TODO: recursive content */
    } else {
	return _get_str_for_wrapping_algorithm(wctx->key[WRAPPEDKEYCTX_LONE_KEY_INDEX].wrapping_meth,
					       wctx->aes_params.aes_wrapping_mech);
    }
}

static func_rc
fprintf_wrapping_algorithm_full(FILE *fp, wrappedKeyCtx *wctx, char *buffer, size_t buffer_len, int keyindex) {

    func_rc rc;
    /* when fp is non-null, we try to write to the file system. Otherwise, it means we are re-entered recursively */
    /* in which case we fill the received buffer */

    if (fp) {
	if (wctx->is_envelope) {
	    char inner[256];
	    char outer[256];

	    rc = fprintf_wrapping_algorithm_full(NULL, wctx, inner, sizeof inner, WRAPPEDKEYCTX_INNER_KEY_INDEX);
	    if (rc != rc_ok) { return rc; }
	    rc = fprintf_wrapping_algorithm_full(NULL, wctx, outer, sizeof outer, WRAPPEDKEYCTX_OUTER_KEY_INDEX);
	    if (rc != rc_ok) { return rc; }
	    fprintf(fp, "Wrapping-Algorithm: %s/1.0(inner=%s,outer=%s)\n", "envelope", inner, outer);
	} else {        /* standalone */
	    char alone[256];

	    if ((rc = fprintf_wrapping_algorithm_full(NULL, wctx, alone, sizeof alone, WRAPPEDKEYCTX_LONE_KEY_INDEX)) !=
		rc_ok) {
		return rc;
	    } /* exit prematurely */
	    fprintf(fp, "Wrapping-Algorithm: %s\n", alone);
	}
    } else {
	/* we have re-entered the function and need to deal with actual algoritm. We use snprintf here */
	switch (wctx->key[keyindex].wrapping_meth) {
	    case w_pkcs1_15:
		snprintf(buffer, buffer_len, "%s/1.0", "pkcs1");
		break;

		/* we have one additional parameter for oaep: the label (in PKCS#1), referred as source in PKCS#11 */
	    case w_pkcs1_oaep: {
		int nchar;
		char *labelstring = sprintf_str_buffer_safe(wctx->oaep_params->pSourceData,
							    wctx->oaep_params->ulSourceDataLen);

		nchar = snprintf(buffer,
				 buffer_len,
				 "%s/1.0(hash=%s,mgf=%s,label=%s)",
				 "oaep",
				 _hashstring(wctx->oaep_params->hashAlg),
				 _mgfstring(wctx->oaep_params->mgf),
				 wctx->oaep_params->pSourceData == NULL ? "\"\"" : labelstring);

		free_sprintf_str_buffer_safe_buf(labelstring);

		if (nchar >= buffer_len) {
		    fprintf(stderr, "Error: algorithm string (%d) too long for buffer size (%zu)\n", nchar, buffer_len);
		    return rc_error_memory;
		}
	    }
		break;

	    case w_cbcpad: {
		char *labelstring = sprintf_str_buffer_safe(wctx->aes_params.iv, wctx->aes_params.iv_len);

		snprintf(buffer,
			 buffer_len,
			 "%s/1.0(iv=%s)",
			 "cbcpad",
			 labelstring);

		free_sprintf_str_buffer_safe_buf(labelstring);
	    }
		break;

	    case w_rfc3394:
		snprintf(buffer,
			 buffer_len,
			 "%s/1.0",
			 "rfc3394");
		break;

	    case w_rfc5649:
		/* Because CKM_NSS_AES_KEY_WRAP_PAD is NOT fully compliant with RFC5649, */
		/* we want to flag it as is, to prevent hairy cases when someone */
		/* wants to unwrap it on a true RFC5649 compliant token */
		snprintf(buffer,
			 buffer_len,
			 "%s/1.0%s",
			 "rfc5649",
			 wctx->aes_params.aes_wrapping_mech == CKM_NSS_AES_KEY_WRAP_PAD ? "(flavour=nss)" : "");
		break;

	    default:
		fprintf(stderr, "Error: unsupported wrapping algorithm.\n");
		return rc_error_unknown_wrapping_alg;
	}
    }
    return rc_ok;
}


static void fprintf_key_type(FILE *fp, char *unused, CK_ATTRIBUTE_PTR attr, bool unused2, int offset) {

    char *value;
    switch (*(CK_KEY_TYPE *) attr->pValue) {

	case CKK_GENERIC_SECRET:
	    value = "CKK_GENERIC_SECRET";
	    break;

	case CKK_DES:
	    value = "CKK_DES";
	    break;

	case CKK_DES2:
	    value = "CKK_DES2";
	    break;

	case CKK_DES3:
	    value = "CKK_DES3";
	    break;

	case CKK_AES:
	    value = "CKK_AES";
	    break;

	case CKK_MD5_HMAC:
	    value = "CKK_MD5_HMAC";
	    break;

	case CKK_SHA_1_HMAC:
	    value = "CKK_SHA_1_HMAC";
	    break;

	case CKK_RIPEMD128_HMAC:
	    value = "CKK_RIPEMD128_HMAC";
	    break;

	case CKK_RIPEMD160_HMAC:
	    value = "CKK_RIPEMD160_HMAC";
	    break;

	case CKK_SHA256_HMAC:
	    value = "CKK_SHA256_HMAC";
	    break;

	case CKK_SHA384_HMAC:
	    value = "CKK_SHA384_HMAC";
	    break;

	case CKK_SHA512_HMAC:
	    value = "CKK_SHA512_HMAC";
	    break;

	case CKK_SHA224_HMAC:
	    value = "CKK_SHA224_HMAC";
	    break;

	case CKK_RSA:
	    value = "CKK_RSA";
	    break;

	case CKK_DSA:
	    value = "CKK_DSA";
	    break;

	case CKK_DH:
	    value = "CKK_DH";
	    break;

	case CKK_EC:
	    value = "CKK_EC";
	    break;

	case CKK_EC_EDWARDS:
	    value = "CKK_EC_EDWARDS";
	    break;

	default:
	    value = "unsupported";
    }

    fprintf(fp, "%*sCKA_KEY_TYPE: %s\n", offset, "", value);

}


static void fprintf_object_class(FILE *fp, char *unused, CK_ATTRIBUTE_PTR attr, bool unused2, int offset) {

    char *value;

    switch (*(CK_OBJECT_CLASS *) attr->pValue) {
	case CKO_DATA:
	    value = "CKO_DATA";
	    break;

	case CKO_CERTIFICATE:
	    value = "CKO_CERTIFICATE";
	    break;

	case CKO_PUBLIC_KEY:
	    value = "CKO_PUBLIC_KEY";
	    break;

	case CKO_PRIVATE_KEY:
	    value = "CKO_PRIVATE_KEY";
	    break;

	case CKO_SECRET_KEY:
	    value = "CKO_SECRET_KEY";
	    break;

	case CKO_HW_FEATURE:
	    value = "CKO_HW_FEATURE";
	    break;

	case CKO_DOMAIN_PARAMETERS:
	    value = "CKO_DOMAIN_PARAMETERS";
	    break;

	case CKO_MECHANISM:
	    value = "CKO_MECHANISM";
	    break;

	case CKO_OTP_KEY:
	    value = "CKO_OTP_KEY";
	    break;

	default:
	    value = (*(CK_OBJECT_CLASS *) attr->pValue) & CKO_VENDOR_DEFINED ? "CKO_VENDOR_DEFINED"
									     : "??unknown object type??";
	    break;
    }

    fprintf(fp, "%*sCKA_CLASS: %s\n", offset, "", value);
}


static void fprintf_boolean_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset) {
    fprintf(fp, "%s%*s%s: %s\n", commented ? "# " : "", offset, "", name,
	    *((CK_BBOOL * )(attr->pValue)) == CK_TRUE ? "true" : "false");
}

static void fprintf_hex_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset) {
    int i;

    fprintf(fp, "%s%*s%s: 0x", commented ? "# " : "", offset, "", name);
    for (i = 0; i < attr->ulValueLen; i++) {
	fprintf(fp, "%02x", ((unsigned char *) (attr->pValue))[i]);
    }

    fprintf(fp, "\n");
}

/* _fprintf_str_attr not meant to be used directly, as there is no check about printability */
/* use fprintf_str_attr or fprintf_date_attr instead */
static void _fprintf_str_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset) {
    fprintf(fp, "%s%*s%s: \"%.*s\"\n", commented ? "# " : "", offset, "", name, (int) (attr->ulValueLen),
	    (unsigned char *) (attr->pValue));
}


/* check if we can print it as a string (i.e. no special character) */
/* otherwise, print as hex. */

static void fprintf_str_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset) {
    bool seems_printable = false;
    int i;

    /* simple check: verify all can be printed */
    for (i = 0; i < attr->ulValueLen; i++) {
	if (!isprint(((unsigned char *) (attr->pValue))[i])) {
	    goto not_printable; /* exit loop prematurely */
	}
    }
    seems_printable = true;

    not_printable:
    /* do nothing, seems_printable worths 0 */

    seems_printable ? _fprintf_str_attr(fp, name, attr, commented, offset) : fprintf_hex_attr(fp, name, attr, commented,
											      offset);

}

/* date is a special case. If it looks like a date, print it in plain characters */
/* otherwise, take no risk and print as hex value */

static void fprintf_date_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset) {
    bool looks_like_a_date = false;

    if (attr->ulValueLen == 8) {
	int i;
	/* simple check: verify we have digits everywhere */
	/* a more sophisticated one would check if it looks like a REAL date... */
	for (i = 0; i < 8; i++) {
	    if (!isdigit(((unsigned char *) (attr->pValue))[i])) {
		goto not_a_date; /* exit loop prematurely */
	    }
	}
	looks_like_a_date = true;
    }

    not_a_date:
    /* do nothing, looks_like_a_date worths false */

    looks_like_a_date ? _fprintf_str_attr(fp, name, attr, commented, offset) : fprintf_hex_attr(fp, name, attr,
												commented, offset);
}

/* fprintf_template_attr() function and support functions */

static int compare_attr(const void *a, const void *b) {
    return ((CK_ATTRIBUTE_PTR) a)->type == ((CK_ATTRIBUTE_PTR) b)->type ? 0 : -1;
}


static void fprintf_mechanism_type_array(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset) {
    int i;
    CK_MECHANISM_TYPE_PTR mech_array = attr->pValue; /* attr_array will be used as the array to walk mechanisms */
    size_t mech_arrayitems = attr->ulValueLen / sizeof(CK_MECHANISM_TYPE);

    fprintf(fp, "%s%*s%s: {\n", commented ? "# " : "", offset, "", name);

    for (i = 0; i < mech_arrayitems; i++) {
	fprintf(fp, "%s%*s%s\n", commented ? "# " : "", offset + INDENTATION_OFFSET, "",
		pkcs11_get_mechanism_name_from_type(mech_array[i]));
    }

    fprintf(fp, "%s%*s}\n", commented ? "# " : "", offset, "");
}

static void fprintf_template_attr_member(FILE *fp, CK_ATTRIBUTE_PTR attr, int offset) {

    /* a collection of possible values found in templates */
    /* all attributes are uncommented */
    static const attr_printer attriblist[] = {
	    {CKA_ALLOWED_MECHANISMS, fprintf_mechanism_type_array, "CKA_ALLOWED_MECHANISMS", false},
	    {CKA_CHECK_VALUE,        fprintf_hex_attr,             "CKA_CHECK_VALUE",        true},
	    {CKA_CLASS,              fprintf_object_class,         "CKA_CLASS",              false},
	    {CKA_DECRYPT,            fprintf_boolean_attr,         "CKA_DECRYPT",            false},
	    {CKA_DERIVE,             fprintf_boolean_attr,         "CKA_DERIVE",             false},
	    {CKA_EC_PARAMS,          fprintf_hex_attr,             "CKA_EC_PARAMS",          true},
	    {CKA_ENCRYPT,            fprintf_boolean_attr,         "CKA_ENCRYPT",            false},
	    {CKA_END_DATE,           fprintf_date_attr,            "CKA_END_DATE",           false},
	    {CKA_EXTRACTABLE,        fprintf_boolean_attr,         "CKA_EXTRACTABLE",        false},
	    {CKA_ID,                 fprintf_str_attr,             "CKA_ID",                 false},
	    {CKA_KEY_TYPE,           fprintf_key_type,             "CKA_KEY_TYPE",           false},
	    {CKA_LABEL,              fprintf_str_attr,             "CKA_LABEL",              false},
	    {CKA_MODIFIABLE,         fprintf_boolean_attr,         "CKA_MODIFIABLE",         false},
	    {CKA_PRIVATE,            fprintf_boolean_attr,         "CKA_PRIVATE",            false},
	    {CKA_SENSITIVE,          fprintf_boolean_attr,         "CKA_SENSITIVE",          false},
	    {CKA_SIGN,               fprintf_boolean_attr,         "CKA_SIGN",               false},
	    {CKA_SIGN_RECOVER,       fprintf_boolean_attr,         "CKA_SIGN_RECOVER",       false},
	    {CKA_START_DATE,         fprintf_date_attr,            "CKA_START_DATE",         false},
	    {CKA_SUBJECT,            fprintf_hex_attr,             "CKA_SUBJECT",            false},
	    {CKA_TOKEN,              fprintf_boolean_attr,         "CKA_TOKEN",              false},
	    {CKA_UNWRAP,             fprintf_boolean_attr,         "CKA_UNWRAP",             false},
	    {CKA_VERIFY,             fprintf_boolean_attr,         "CKA_VERIFY",             false},
	    {CKA_VERIFY_RECOVER,     fprintf_boolean_attr,         "CKA_VERIFY_RECOVER",     false},
	    {CKA_WRAP,               fprintf_boolean_attr,         "CKA_WRAP",               false},
    };

    size_t nelem = sizeof attriblist / sizeof(attr_printer);
    attr_printer key = {attr->type, NULL, NULL, false};
    attr_printer *match = lfind(&key, attriblist, &nelem, sizeof(attr_printer), compare_attr);

    if (match) {
	match->func_ptr(fp, match->name, attr, false, offset); /* we ignore the comment argument */
    }

}

static void fprintf_template_attr(FILE *fp, char *name, CK_ATTRIBUTE_PTR attr, bool commented, int offset) {
    int i;
    CK_ATTRIBUTE_PTR attr_array = attr->pValue; /* attr_array will be used as the array to walk template */
    size_t attr_arrayitems = attr->ulValueLen / sizeof(CK_ATTRIBUTE);

    fprintf(fp, "%s%*s%s: {\n", commented ? "# " : "", offset, "", name);

    for (i = 0; i < attr_arrayitems; i++) {
	fprintf(fp, "%s", commented ? "# " : "");
	fprintf_template_attr_member(fp, &attr_array[i], offset + INDENTATION_OFFSET);
    }

    fprintf(fp, "%s%*s}\n", commented ? "# " : "", offset, "");
}

/*------------------------------------------------------------------------*/


static char *sprintf_hex_buffer(CK_BYTE_PTR buffer, CK_ULONG len) {

    char *allocated = malloc(len * 2 + 3);

    if (allocated == NULL) {
	fprintf(stderr, "***Error: memory allocation\n");
    } else {

	int i;

	allocated[0] = '0';
	allocated[1] = 'x';

	for (i = 0; i < len; i++) {
	    snprintf(&allocated[2 + i * 2], 3, "%02x", buffer[i]);
	}
    }

    return allocated;
}

/* _sprintf_str_buffer not meant to be used directly, as there is no check about printability */
/* use sprintf_str_buffer_safe instead */
static char *_sprintf_str_buffer(CK_BYTE_PTR buffer, CK_ULONG len) {
    char *allocated = malloc(len + 3);

    if (allocated == NULL) {
	fprintf(stderr, "***Error: memory allocation\n");
    } else {
	snprintf(allocated, len + 3, "\"%.*s\"", (int) len, buffer);
    }
    return allocated;
}


/* check if we can print the buffer as a string (i.e. no special character) */
/* otherwise, print as hex. */

static char *sprintf_str_buffer_safe(CK_BYTE_PTR buffer, CK_ULONG len) {
    int seems_printable = 0;
    int i;

    /* simple check: verify all can be printed */
    for (i = 0; i < len; i++) {
	if (!isprint(buffer[i])) {
	    goto not_printable; /* exit loop prematurely */
	}
    }
    seems_printable = 1;

    not_printable:
    /* do nothing, seems_printable worths 0 */

    return seems_printable ? _sprintf_str_buffer(buffer, len) : sprintf_hex_buffer(buffer, len);

}

static void free_sprintf_str_buffer_safe_buf(char *ptr) {
    if (ptr) { free(ptr); }
}

/*------------------------------------------------------------------------*/


static char *const _mgfstring(CK_RSA_PKCS_MGF_TYPE mgf) {
    char *retval = NULL;

    switch (mgf) {
	case CKG_MGF1_SHA1:
	    retval = "CKG_MGF1_SHA1";
	    break;

	case CKG_MGF1_SHA256:
	    retval = "CKG_MGF1_SHA256";
	    break;

	case CKG_MGF1_SHA384:
	    retval = "CKG_MGF1_SHA384";
	    break;

	case CKG_MGF1_SHA512:
	    retval = "CKG_MGF1_SHA512";
	    break;

	case CKG_MGF1_SHA224:
	    retval = "CKG_MGF1_SHA224";
	    break;

	default:
	    retval = "unsupported MGF1 function type";
	    break;

    }

    return retval;
}

static char *const _hashstring(CK_MECHANISM_TYPE hash) {
    char *retval = NULL;

    switch (hash) {
	case CKM_MD2:
	    retval = "CKM_MD2";
	    break;

	case CKM_MD5:
	    retval = "CKM_MD5";
	    break;

	case CKM_SHA_1:
	    retval = "CKM_SHA_1";
	    break;

	case CKM_RIPEMD128:
	    retval = "CKM_RIPEMD128";
	    break;

	case CKM_RIPEMD160:
	    retval = "CKM_RIPEMD160";
	    break;

	case CKM_SHA256:
	    retval = "CKM_SHA256";
	    break;

	case CKM_SHA224:
	    retval = "CKM_SHA224";
	    break;

	case CKM_SHA384:
	    retval = "CKM_SHA384";
	    break;

	case CKM_SHA512:
	    retval = "CKM_SHA512";
	    break;

	default:
	    retval = "unsupported hash type";
	    break;
    }

    return retval;

}

static func_rc _output_wrapped_key_header(wrappedKeyCtx *wctx, FILE *fp) {

    time_t now = time(NULL);
    char hostname[255];

    /* keyindex: in case of envelope wrapping, the index shall always be the outer */
    int keyindex = wctx->is_envelope ? WRAPPEDKEYCTX_INNER_KEY_INDEX : WRAPPEDKEYCTX_LONE_KEY_INDEX;

    char *wctxlabel = wctx->wrappedkeylabel;
    char *handlelabel = pkcs11_alloclabelforhandle(wctx->p11Context, wctx->key[keyindex].wrappedkeyhandle);
    char *wrappedkeylabel = wctxlabel ? wctxlabel : handlelabel ? handlelabel : "-no label found-";

    gethostname(hostname, 255);
    hostname[254] = 0;        /* just to be sure... */

    fprintf(fp, \
	"########################################################################\n"
	"#\n"
	"# key <%s> wrapped by key <%s>\n"
	"# wrapped on host <%s>\n"
	"# operation date and time (UTC): %s"
	"# wrapping algorithm: %s\n"
	"#\n"
	"# use p11unwrap from pkcs11-tools to unwrap key on dest. PKCS#11 token\n"
	"#\n"
	"# grammar for this file:\n"
	"# ----------------------\n"
	"#\n"
	"# - lines starting with '#' are ignored\n"
	"#\n"
	"# - [ATTRIBUTE] : [VALUE]\n"
	"#   where [ATTRIBUTE] is any of the following:\n"
	"#     Content-Type ( value is application/pkcs11-tools)\n"
	"#     Wrapping-Algorithm: execute p11wrap -h for syntax\n"
	"#     CKA_LABEL\n"
	"#     CKA_ID\n"
	"#     CKA_CLASS\n"
	"#     CKA_TOKEN\n"
	"#     CKA_KEY_TYPE\n"
	"#     CKA_ENCRYPT\n"
	"#     CKA_DECRYPT\n"
	"#     CKA_WRAP\n"
	"#     CKA_UNWRAP\n"
	"#     CKA_SIGN\n"
	"#     CKA_VERIFY\n"
	"#     CKA_DERIVE\n"
	"#     CKA_PRIVATE\n"
	"#     CKA_SENSITIVE\n"
	"#     CKA_EXTRACTABLE\n"
	"#     CKA_MODIFIABLE\n"
	"#     CKA_START_DATE\n"
	"#     CKA_END_DATE\n"
	"#     CKA_CHECK_VALUE\n"
	"#     CKA_WRAP_TEMPLATE\n"
	"#     CKA_UNWRAP_TEMPLATE\n"
	"#     CKA_ALLOWED_MECHANISMS\n"
	"#   where, depending on the attribute, [VALUE] can be one of the following:\n"
	"#     \"Hello world\" (printable string)\n"
	"#      0x1A2B3C4D (hex bytes)\n"
	"#      20150630   (date)\n"
	"#      true/false/CK_TRUE/CK_FALSE/yes/no (boolean)\n"
	"#      { attribute=value attribute=value ... }\n"
	"#      { mechanism mechanism ... }\n"
	"#\n"
	"# - wrapped key is contained between -----BEGIN WRAPPED KEY-----\n"
	"#   and -----END WRAPPED KEY----- marks and is Base64 encoded\n"
	"#\n"
	"########################################################################\n"
	"Content-Type: application/pkcs11-tools\n"
	"Grammar-Version: "
    SUPPORTED_GRAMMAR_VERSION
    "\n"
    "Wrapping-Key: \"%s\"\n",
	    wrappedkeylabel,
	    wctx->wrappingkeylabel,
	    hostname,
	    asctime(gmtime(&now)),
	    get_wrapping_algorithm_short(wctx),
	    wctx->wrappingkeylabel );

    free(handlelabel);        /* we must free this structure */

    if (fprintf_wrapping_algorithm_full(fp, wctx, NULL, 0, WRAPPEDKEYCTX_NO_INDEX) != rc_ok) {
	fprintf(stderr, "Error: unsupported wrapping algorithm.\n");
	return rc_error_unknown_wrapping_alg;
    }

    return rc_ok;
}

/**
 * Writes the wrapped key in JWK format for Citibank.
 * Command line usage would be like
 *     src/p11wrap -i citi_hmac_test_key -w citi_wrap -a 'oaep(mgf=CKG_MGF1_SHA256,hash=CKM_SHA256)'
 * @param wctx the wrapped key
 * @param fp the output filepointer, e.g. stdout
 * @return rc_ok if everything went well. Otherwise a defined error type.
 */
static func_rc _output_wrapped_keys_jwk(wrappedKeyCtx *wctx, FILE *fp, char* wrapping_key_id){
    func_rc rc = rc_ok;
    BIO *bio_stdout = NULL, *bio_b64 = NULL, *bio_mem = NULL;

    bio_b64 = BIO_new(BIO_f_base64());
    if (bio_b64 == NULL) {
	P_ERR();
	rc = rc_error_openssl_api;
	goto err;
    }

    bio_mem = BIO_new(BIO_s_mem());
    if (bio_mem == NULL) {
	P_ERR();
	rc = rc_error_openssl_api;
	goto err;
    }

    bio_stdout = BIO_new(BIO_s_file());
    if (bio_stdout == NULL) {
	P_ERR();
	rc = rc_error_openssl_api;
	goto err;
    }

    BIO_set_fp(bio_stdout, fp, BIO_NOCLOSE);


    if (wctx->is_envelope) {
	// we don't support envelope wrapping
	P_ERR();
	fprintf(stderr, "enveloped key wrapping not supported for JSON Web Key (JWK) output format.\n");
	rc = rc_error_envelope_wrapping_unsupported;
	goto err;
    }

    // we trick a bit here to output the JSON and the key parameters interlaced.
    // JSON header
    BIO_puts(bio_stdout, "{\n"
			 "  \"kty\":\"oct\",\n"
			 "  \"kid\":\"");
    BIO_flush(bio_stdout);

    // key name
    fprintf(fp, "%s", wctx->wrappedkeylabel);
    fflush(fp);
    BIO_puts(bio_stdout, "\",\n");

    // key operations
    bool prev_op = false;
    BIO_puts(bio_stdout, "  \"key_ops\":[");
    if((rc = _output_wrapped_key_attrs_jwk(wctx, fp)) != rc_ok){
	P_ERR();
	fprintf(stderr, "determining allowed key operations for wrapped key failed.\n");
	goto err;
    }
    BIO_puts(bio_stdout, "],\n"
			 "  \"k\":\"");
    BIO_flush(bio_stdout);

    // now use the b64 bio and let it write to a bio_mem. We can then use a simple search & replace to transform
    // base64 in base64url encoding (replace '+' with '-' and '/' with '_').

    // modify bio_b64, so it doesn't write newlines - Base64URLencode does not have newlines.
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

    // let bio_b64 write to bio_mem
    BIO_push(bio_b64, bio_mem);

    // write the wrapped key
    BIO_write(bio_b64,
	      wctx->key[WRAPPEDKEYCTX_INNER_OR_LONE_KEY_INDEX].wrapped_key_buffer,
	      wctx->key[WRAPPEDKEYCTX_INNER_OR_LONE_KEY_INDEX].wrapped_key_len);
    BIO_flush(bio_b64);

    // get the underlying memory buffer
    BUF_MEM *b64enc;
    BIO_get_mem_ptr(bio_mem, &b64enc);
    BIO_set_close(bio_mem, BIO_NOCLOSE);
    BIO_free(bio_mem);

    // rewrite from base64 to base64url
    int i = 0;
    while( i < b64enc->length){
	if(b64enc->data[i] == '+') { b64enc->data[i] = '-'; }
	if(b64enc->data[i] == '/') { b64enc->data[i] = '_'; }
	if(b64enc->data[i] == '=') { break;} // at end, we don't want the = as they're optional and not supported by b64url.
	i++;
    }

    // write our base64url encoded data to bio_stdout, taking length from previous for loop that excludes = signs at end
    BIO_write(bio_stdout, b64enc->data, i);
    BIO_flush(bio_stdout);
    free(b64enc);

    // write JSON footer
    BIO_puts(bio_stdout, "\"");
    BIO_flush(bio_stdout);

    // write correct wrapping algorithm identifier if supported by JWK
    char* alg = NULL;
    switch(wctx->key[WRAPPEDKEYCTX_LONE_KEY_INDEX].wrapping_meth) {
	/*
	 * matching wrapping identifiers in our source against the ones
	 * in https://www.rfc-editor.org/rfc/rfc7518.html#page-61
	w_pkcs1_15,    // PKCS#1 v1.5, uses an RSA key for un/wrapping
	w_pkcs1_oaep,  // PKCS#1 OAEP, uses an RSA key for un/wrapping
	w_cbcpad,      // wraps private key (PKCS#8), padding according to PKCS#7, then symmetric key in CBC mode
	w_rfc3394,     // wraps keys according to RFC3394
	w_rfc5649,     // wraps keys according to RFC5649
	w_envelope,    // envelope wrapping ( Private Key -> Symmetric Key -> Any Key)
	 */
	case w_pkcs1_15:
	    alg = "RSA1_5";
	    break;
	case w_pkcs1_oaep:
	    if ((wctx->oaep_params->hashAlg == CKM_SHA256) && (wctx->oaep_params->mgf == CKG_MGF1_SHA256)) {
		alg = "RSA-OAEP-256";
	    }
	    if ((wctx->oaep_params->hashAlg == CKM_SHA_1) && (wctx->oaep_params->mgf == CKG_MGF1_SHA1)) {
		alg = "RSA-OAEP";
	    }
	    break;
	case w_rfc3394:
	    //Select the correct identifier here
	    switch(wctx->aes_params.keysize){
		case 32:
		    alg = "A256KW";
		    break;
		case 24:
		    alg = "A192KW";
		    break;
		case 16:
		    alg = "A128KW";
		    break;
		default:
		    alg = NULL;
	    }
	    break;
	default:
	    // nothing - rfc5649 is not supported by the JWE spec https://www.rfc-editor.org/rfc/rfc7518.html#page-61
	    // and we do not support envelope either
	    alg = NULL;
    }
    if(alg){
	// we have a valid alg identifier, let's output it
	BIO_puts(bio_stdout, ",\n"
			     "  \"alg\":\"");
	BIO_flush(bio_stdout);
	fputs(alg, fp);
	fflush(fp);
	BIO_puts(bio_stdout, "\"");
    }

    if(wrapping_key_id){
	BIO_puts(bio_stdout, ",\n"
			     "  \"wrapping_key_id\":\"");
	BIO_flush(bio_stdout);
	fputs(wrapping_key_id, fp);
	fflush(fp);
	BIO_puts(bio_stdout, "\"");
    }

    // close the JSON structure
    BIO_puts(bio_stdout, "\n}\n");
    BIO_flush(bio_stdout);

    err:
    if (bio_stdout) BIO_free(bio_stdout);
    if (bio_b64) BIO_free(bio_b64);

    return rc;

}

static func_rc _output_wrapped_keys_b64(wrappedKeyCtx *wctx, FILE *fp) {
    func_rc rc = rc_ok;
    BIO *bio_stdout = NULL, *bio_b64 = NULL;

    bio_b64 = BIO_new(BIO_f_base64());
    if (bio_b64 == NULL) {
	P_ERR();
	rc = rc_error_openssl_api;
	goto err;
    }

    bio_stdout = BIO_new(BIO_s_file());
    if (bio_stdout == NULL) {
	P_ERR();
	rc = rc_error_openssl_api;
	goto err;
    }

    BIO_set_fp(bio_stdout, fp, BIO_NOCLOSE);

    if (wctx->is_envelope) {
	BIO_puts(bio_stdout, "-----BEGIN OUTER WRAPPED KEY-----\n");
	BIO_flush(bio_stdout);
	BIO_push(bio_b64, bio_stdout);
	BIO_write(bio_b64,
		  wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrapped_key_buffer,
		  wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrapped_key_len);
	BIO_flush(bio_b64);
	BIO_puts(bio_stdout, "-----END OUTER WRAPPED KEY-----\n");
	BIO_flush(bio_stdout);
    }

    BIO_puts(bio_stdout, wctx->is_envelope ? "-----BEGIN INNER WRAPPED KEY-----\n" : "-----BEGIN WRAPPED KEY-----\n");
    BIO_flush(bio_stdout);
    BIO_push(bio_b64, bio_stdout);
    BIO_write(bio_b64,
	      wctx->key[WRAPPEDKEYCTX_INNER_OR_LONE_KEY_INDEX].wrapped_key_buffer,
	      wctx->key[WRAPPEDKEYCTX_INNER_OR_LONE_KEY_INDEX].wrapped_key_len);
    BIO_flush(bio_b64);
    BIO_puts(bio_stdout, wctx->is_envelope ? "-----END INNER WRAPPED KEY-----\n" : "-----END WRAPPED KEY-----\n");
    BIO_flush(bio_stdout);

    err:
    if (bio_stdout) BIO_free(bio_stdout);
    if (bio_b64) BIO_free(bio_b64);

    return rc;
}

static func_rc _output_wrapped_key_attrs_jwk(wrappedKeyCtx *wctx, FILE *fp) {
    func_rc rc = rc_ok;

    pkcs11AttrList *wrappedkey_attrs = NULL;
    CK_ATTRIBUTE_PTR o_attr = NULL;
    size_t alist_len = 0;

    static attr_jwk alist[] = {
	    { CKA_ENCRYPT, "\"encrypt\""},
	    { CKA_DECRYPT, "\"decrypt\""},
	    { CKA_WRAP,    "\"wrap\""},
	    { CKA_UNWRAP,  "\"unwrap\""},
	    { CKA_SIGN,    "\"sign\""},
	    { CKA_VERIFY,  "\"verify\""},
	    { CKA_DERIVE,  "\"derive\""}
    };

    alist_len = sizeof(alist) / sizeof(attr_jwk);
    wrappedkey_attrs = pkcs11_new_attrlist(wctx->p11Context,
					   _ATTR(CKA_ENCRYPT),
					   _ATTR(CKA_DECRYPT),
					   _ATTR(CKA_WRAP),
					   _ATTR(CKA_UNWRAP),
					   _ATTR(CKA_SIGN),
					   _ATTR(CKA_VERIFY),
					   _ATTR(CKA_DERIVE),
					   _ATTR_END);

    if (pkcs11_read_attr_from_handle(wrappedkey_attrs,
				     wctx->key[WRAPPEDKEYCTX_INNER_OR_LONE_KEY_INDEX].wrappedkeyhandle) == false) {
	fprintf(stderr, "Error: could not read attributes from key with label '%s'\n", wctx->wrappedkeylabel);
	rc = rc_error_pkcs11_api;
	goto error;
    }

    {
	size_t i;
	bool havePrinted = false;
	for (i = 0; i < alist_len; i++) {
	    o_attr = pkcs11_get_attr_in_attrlist(wrappedkey_attrs, alist[i].attr_type);

	    if (o_attr == NULL) {
		fprintf(fp, "# %s attribute not found\n", alist[i].name);
	    } else if (o_attr->ulValueLen == 0) {
		fprintf(fp, "# %s attribute is empty\n", alist[i].name);
	    } else {
		if( *((CK_BBOOL *)o_attr->pValue) == CK_TRUE) {
		    // make sure first one does not have a leading comma
		    if(havePrinted){
			fputs(",", fp);
		    } else{
			havePrinted = true;
		    }
		    fputs(alist[i].name, fp);
		}
	    }
	}
    }


    error:

    pkcs11_delete_attrlist(wrappedkey_attrs);

    return rc;

}


static func_rc _output_wrapped_key_attributes(wrappedKeyCtx *wctx, FILE *fp) {
    func_rc rc = rc_ok;

    pkcs11AttrList *wrappedkey_attrs = NULL;
    CK_ATTRIBUTE_PTR o_attr = NULL;
    size_t alist_len = 0;

    static attr_printer seckalist[] = {
	    {CKA_LABEL,              fprintf_str_attr,             "CKA_LABEL",              false},
	    {CKA_ID,                 fprintf_str_attr,             "CKA_ID",                 false},
	    {CKA_CLASS,              fprintf_object_class,         "CKA_CLASS",              false},
	    {CKA_TOKEN,              fprintf_boolean_attr,         "CKA_TOKEN",              false},
	    {CKA_KEY_TYPE,           fprintf_key_type,             "CKA_KEY_TYPE",           false},
	    {CKA_ALLOWED_MECHANISMS, fprintf_mechanism_type_array, "CKA_ALLOWED_MECHANISMS", false},
	    {CKA_ENCRYPT,            fprintf_boolean_attr,         "CKA_ENCRYPT",            false},
	    {CKA_DECRYPT,            fprintf_boolean_attr,         "CKA_DECRYPT",            false},
	    {CKA_WRAP,               fprintf_boolean_attr,         "CKA_WRAP",               false},
	    {CKA_WRAP_TEMPLATE,      fprintf_template_attr,        "CKA_WRAP_TEMPLATE",      false},
	    {CKA_UNWRAP,             fprintf_boolean_attr,         "CKA_UNWRAP",             false},
	    {CKA_UNWRAP_TEMPLATE,    fprintf_template_attr,        "CKA_UNWRAP_TEMPLATE",    false},
	    {CKA_SIGN,               fprintf_boolean_attr,         "CKA_SIGN",               false},
	    {CKA_VERIFY,             fprintf_boolean_attr,         "CKA_VERIFY",             false},
	    {CKA_DERIVE,             fprintf_boolean_attr,         "CKA_DERIVE",             false},
	    {CKA_DERIVE_TEMPLATE,    fprintf_template_attr,        "CKA_DERIVE_TEMPLATE",    false},
	    {CKA_PRIVATE,            fprintf_boolean_attr,         "CKA_PRIVATE",            false},
	    {CKA_SENSITIVE,          fprintf_boolean_attr,         "CKA_SENSITIVE",          false},
	    {CKA_EXTRACTABLE,        fprintf_boolean_attr,         "CKA_EXTRACTABLE",        false},
	    {CKA_MODIFIABLE,         fprintf_boolean_attr,         "CKA_MODIFIABLE",         false},
	    {CKA_START_DATE,         fprintf_date_attr,            "CKA_START_DATE",         false},
	    {CKA_END_DATE,           fprintf_date_attr,            "CKA_END_DATE",           false},
	    {CKA_CHECK_VALUE,        fprintf_hex_attr,             "CKA_CHECK_VALUE",        true}, /* Not valid in C_Unwrap() template */
    };

    static attr_printer prvkalist[] = {
	    {CKA_LABEL,              fprintf_str_attr,             "CKA_LABEL",              false},
	    {CKA_ID,                 fprintf_str_attr,             "CKA_ID",                 false},
	    {CKA_CLASS,              fprintf_object_class,         "CKA_CLASS",              false},
	    {CKA_TOKEN,              fprintf_boolean_attr,         "CKA_TOKEN",              false},
	    {CKA_KEY_TYPE,           fprintf_key_type,             "CKA_KEY_TYPE",           false},
	    {CKA_ALLOWED_MECHANISMS, fprintf_mechanism_type_array, "CKA_ALLOWED_MECHANISMS", false},
	    {CKA_EC_PARAMS,          fprintf_hex_attr,             "CKA_EC_PARAMS",          true}, /* Not valid in C_Unwrap() template */
	    {CKA_SUBJECT,            fprintf_hex_attr,             "CKA_SUBJECT",            false},
	    {CKA_DECRYPT,            fprintf_boolean_attr,         "CKA_DECRYPT",            false},
	    {CKA_UNWRAP,             fprintf_boolean_attr,         "CKA_UNWRAP",             false},
	    {CKA_UNWRAP_TEMPLATE,    fprintf_template_attr,        "CKA_UNWRAP_TEMPLATE",    false},
	    {CKA_SIGN,               fprintf_boolean_attr,         "CKA_SIGN",               false},
	    {CKA_SIGN_RECOVER,       fprintf_boolean_attr,         "CKA_SIGN_RECOVER",       false},
	    {CKA_DERIVE,             fprintf_boolean_attr,         "CKA_DERIVE",             false},
	    {CKA_DERIVE_TEMPLATE,    fprintf_template_attr,        "CKA_DERIVE_TEMPLATE",    false},
	    {CKA_PRIVATE,            fprintf_boolean_attr,         "CKA_PRIVATE",            false},
	    {CKA_SENSITIVE,          fprintf_boolean_attr,         "CKA_SENSITIVE",          false},
	    {CKA_EXTRACTABLE,        fprintf_boolean_attr,         "CKA_EXTRACTABLE",        false},
	    {CKA_MODIFIABLE,         fprintf_boolean_attr,         "CKA_MODIFIABLE",         false},
	    {CKA_START_DATE,         fprintf_date_attr,            "CKA_START_DATE",         false},
	    {CKA_END_DATE,           fprintf_date_attr,            "CKA_END_DATE",           false},
    };

    attr_printer *alist = NULL;

    switch (wctx->key[WRAPPEDKEYCTX_INNER_OR_LONE_KEY_INDEX].wrappedkeyobjclass) {
	case CKO_SECRET_KEY:
	    alist = seckalist;
	    alist_len = sizeof(seckalist) / sizeof(attr_printer);
	    wrappedkey_attrs = pkcs11_new_attrlist(wctx->p11Context,
						   _ATTR(CKA_LABEL),
						   _ATTR(CKA_ID),
						   _ATTR(CKA_CLASS),
						   _ATTR(CKA_TOKEN),
						   _ATTR(CKA_KEY_TYPE),
						   _ATTR(CKA_ALLOWED_MECHANISMS),
						   _ATTR(CKA_ENCRYPT),
						   _ATTR(CKA_DECRYPT),
						   _ATTR(CKA_WRAP),
						   _ATTR(CKA_WRAP_TEMPLATE),
						   _ATTR(CKA_UNWRAP),
						   _ATTR(CKA_UNWRAP_TEMPLATE),
						   _ATTR(CKA_SIGN),
						   _ATTR(CKA_VERIFY),
						   _ATTR(CKA_DERIVE_TEMPLATE),
						   _ATTR(CKA_DERIVE),
						   _ATTR(CKA_PRIVATE),
						   _ATTR(CKA_SENSITIVE),
						   _ATTR(CKA_EXTRACTABLE),
						   _ATTR(CKA_MODIFIABLE),
						   _ATTR(CKA_START_DATE),
						   _ATTR(CKA_END_DATE),
						   _ATTR(CKA_CHECK_VALUE),
						   _ATTR_END);
	    break;

	case CKO_PRIVATE_KEY:
	    alist = prvkalist;
	    alist_len = sizeof(prvkalist) / sizeof(attr_printer);
	    wrappedkey_attrs = pkcs11_new_attrlist(wctx->p11Context,
						   _ATTR(CKA_LABEL),
						   _ATTR(CKA_ID),
						   _ATTR(CKA_CLASS),
						   _ATTR(CKA_TOKEN),
						   _ATTR(CKA_KEY_TYPE),
						   _ATTR(CKA_ALLOWED_MECHANISMS),
						   _ATTR(CKA_EC_PARAMS),
						   _ATTR(CKA_SUBJECT),
						   _ATTR(CKA_DECRYPT),
						   _ATTR(CKA_UNWRAP),
						   _ATTR(CKA_UNWRAP_TEMPLATE),
						   _ATTR(CKA_SIGN),
						   _ATTR(CKA_SIGN_RECOVER),
						   _ATTR(CKA_DERIVE),
						   _ATTR(CKA_DERIVE_TEMPLATE),
						   _ATTR(CKA_PRIVATE),
						   _ATTR(CKA_SENSITIVE),
						   _ATTR(CKA_EXTRACTABLE),
						   _ATTR(CKA_MODIFIABLE),
						   _ATTR(CKA_START_DATE),
						   _ATTR(CKA_END_DATE),
						   _ATTR_END);
	    break;

	default:
	    fprintf(stderr, "***Error: Oops... invalid object type, bailing out\n");
	    rc = rc_error_oops;
	    goto error;
    }


    if (pkcs11_read_attr_from_handle(wrappedkey_attrs,
				     wctx->key[WRAPPEDKEYCTX_INNER_OR_LONE_KEY_INDEX].wrappedkeyhandle) == false) {
	fprintf(stderr, "Error: could not read attributes from key with label '%s'\n", wctx->wrappedkeylabel);
	rc = rc_error_pkcs11_api;
	goto error;
    }

    {
	size_t i;

	for (i = 0; i < alist_len; i++) {
	    o_attr = pkcs11_get_attr_in_attrlist(wrappedkey_attrs, alist[i].attr_type);

	    if (o_attr == NULL) {
		fprintf(fp, "# %s attribute not found\n", alist[i].name);
	    } else if (o_attr->type == CKA_EXTRACTABLE) {
		/* security feature: unwrapped keys should not have CKA_EXTRACTABLE set to true */
		fprintf(fp, "CKA_EXTRACTABLE: false\n");
	    } else if (o_attr->type == CKA_TOKEN) {
		/* unwrapped keys always have CKA_TOKEN set to true */
		fprintf(fp, "CKA_TOKEN: true\n");
	    } else if (o_attr->ulValueLen == 0) {
		fprintf(fp, "# %s attribute is empty\n", alist[i].name);
	    } else if ((o_attr->type == CKA_UNWRAP_TEMPLATE ||
			o_attr->type == CKA_DERIVE_TEMPLATE ||
			o_attr->type == CKA_WRAP_TEMPLATE) &&
		       o_attr->ulValueLen % sizeof(CK_ATTRIBUTE) != 0) {
		/* on Safenet Luna, private keys have, by default, templates that are 1 byte long */
		/* which is not a valid content for templates */
		fprintf(fp, "# %s attribute invalid on the source token\n", alist[i].name);
	    } else {
		alist[i].func_ptr(fp, alist[i].name, o_attr, alist[i].commented, 0);
	    }
	}
    }


    error:

    pkcs11_delete_attrlist(wrappedkey_attrs);

    return rc;

}

static func_rc _output_public_key_b64(wrappedKeyCtx *wctx, FILE *fp) {
    func_rc rc = rc_ok;
    BIO *bio_stdout = NULL;

    bio_stdout = BIO_new(BIO_s_file());
    if (bio_stdout == NULL) {
	P_ERR();
	rc = rc_error_openssl_api;
	goto err;
    }

    BIO_set_fp(bio_stdout, fp, BIO_NOCLOSE);
    rc = pkcs11_cat_object_with_handle(wctx->p11Context, wctx->pubkhandle, 0, bio_stdout);

    err:
    if (bio_stdout) BIO_free(bio_stdout);

    return rc;
}

static func_rc _output_public_key_attributes(wrappedKeyCtx *wctx, FILE *fp) {
    func_rc rc = rc_ok;

    pkcs11AttrList *wrappedkey_attrs = NULL;
    CK_ATTRIBUTE_PTR o_attr = NULL;
    size_t alist_len = 0;

    static attr_printer alist[] = {
	    {CKA_LABEL,              fprintf_str_attr,             "CKA_LABEL",              false},
	    {CKA_ID,                 fprintf_str_attr,             "CKA_ID",                 false},
	    {CKA_CLASS,              fprintf_object_class,         "CKA_CLASS",              false},
	    {CKA_TOKEN,              fprintf_boolean_attr,         "CKA_TOKEN",              false},
	    {CKA_KEY_TYPE,           fprintf_key_type,             "CKA_KEY_TYPE",           false},
	    {CKA_ALLOWED_MECHANISMS, fprintf_mechanism_type_array, "CKA_ALLOWED_MECHANISMS", false},
	    {CKA_EC_PARAMS,          fprintf_hex_attr,             "CKA_EC_PARAMS",          true},
	    {CKA_SUBJECT,            fprintf_hex_attr,             "CKA_SUBJECT",            false},
	    {CKA_ENCRYPT,            fprintf_boolean_attr,         "CKA_ENCRYPT",            false},
	    {CKA_WRAP,               fprintf_boolean_attr,         "CKA_WRAP",               false},
	    {CKA_WRAP_TEMPLATE,      fprintf_template_attr,        "CKA_WRAP_TEMPLATE",      false},
	    {CKA_VERIFY,             fprintf_boolean_attr,         "CKA_VERIFY",             false},
	    {CKA_VERIFY_RECOVER,     fprintf_boolean_attr,         "CKA_VERIFY_RECOVER",     false},
	    {CKA_DERIVE,             fprintf_boolean_attr,         "CKA_DERIVE",             false},
	    {CKA_PRIVATE,            fprintf_boolean_attr,         "CKA_PRIVATE",            false},
	    {CKA_MODIFIABLE,         fprintf_boolean_attr,         "CKA_MODIFIABLE",         false},
	    {CKA_START_DATE,         fprintf_date_attr,            "CKA_START_DATE",         false},
	    {CKA_END_DATE,           fprintf_date_attr,            "CKA_END_DATE",           false},
    };

    alist_len = sizeof(alist) / sizeof(attr_printer);
    wrappedkey_attrs = pkcs11_new_attrlist(wctx->p11Context,
					   _ATTR(CKA_LABEL),
					   _ATTR(CKA_ID),
					   _ATTR(CKA_CLASS),
					   _ATTR(CKA_TOKEN),
					   _ATTR(CKA_KEY_TYPE),
					   _ATTR(CKA_ALLOWED_MECHANISMS),
					   _ATTR(CKA_EC_PARAMS),
					   _ATTR(CKA_SUBJECT),
					   _ATTR(CKA_ENCRYPT),
					   _ATTR(CKA_WRAP),
					   _ATTR(CKA_WRAP_TEMPLATE),
					   _ATTR(CKA_VERIFY),
					   _ATTR(CKA_VERIFY_RECOVER),
					   _ATTR(CKA_DERIVE),
					   _ATTR(CKA_PRIVATE),
					   _ATTR(CKA_MODIFIABLE),
					   _ATTR(CKA_START_DATE),
					   _ATTR(CKA_END_DATE),
					   _ATTR_END);

    if (pkcs11_read_attr_from_handle(wrappedkey_attrs, wctx->pubkhandle) == false) {
	fprintf(stderr, "Error: could not read attributes from key with label '%s'\n", wctx->wrappedkeylabel);
	rc = rc_error_pkcs11_api;
	goto error;
    }

    size_t i;

    for (i = 0; i < alist_len; i++) {
	o_attr = pkcs11_get_attr_in_attrlist(wrappedkey_attrs, alist[i].attr_type);

	if (o_attr == NULL) {
	    fprintf(fp, "# %s attribute not found\n", alist[i].name);
	} else if (o_attr->type == CKA_EXTRACTABLE) {
	    /* security feature: unwrapped keys should not have CKA_EXTRACTABLE set to true */
	    fprintf(fp, "CKA_EXTRACTABLE: false\n");
	} else if (o_attr->type == CKA_TOKEN) {
	    /* unwrapped keys always have CKA_TOKEN set to true */
	    fprintf(fp, "CKA_TOKEN: true\n");
	} else if (o_attr->ulValueLen == 0) {
	    fprintf(fp, "# %s attribute is empty\n", alist[i].name);
	} else {
	    alist[i].func_ptr(fp, alist[i].name, o_attr, alist[i].commented, 0);
	}
    }

    error:
    pkcs11_delete_attrlist(wrappedkey_attrs);
    return rc;
}

func_rc pkcs11_output_wrapped_key(wrappedKeyCtx *wctx, bool jwkoutput, char* wrapping_key_label) {
    func_rc rc = rc_ok;
    FILE *fp = stdout;

    if (wctx->filename) {
	fp = fopen(wctx->filename, "w");
	if (fp == NULL) {
	    perror("***Warning: cannot write to file - will output to standard output");
	    fp = stdout;
	}
    }

    if(jwkoutput){
	// handle JWK output separately and jump to end of function.
	rc = _output_wrapped_keys_jwk(wctx, fp, wrapping_key_label);
	if (rc != rc_ok) {
	    fprintf(stderr, "***Error: when outputting wrapped key\n");
	    goto error;
	}
	// jump to end of function to close fp.
	goto error;
    }

    rc = _output_wrapped_key_header(wctx, fp);
    if (rc != rc_ok) {
	fprintf(stderr, "***Error: during wrapped key header creation\n");
	goto error;
    }

    rc = _output_wrapped_key_attributes(wctx, fp);
    if (rc != rc_ok) {
	fprintf(stderr, "***Error: when outputting wrapped key attributes\n");
	goto error;
    }

    rc = _output_wrapped_keys_b64(wctx, fp);
    if (rc != rc_ok) {
	fprintf(stderr, "***Error: when outputting wrapped key\n");
	goto error;
    }

    /* do we have a handle to a public key? if so, output it as well */
    if (wctx->pubkhandle) {
	rc = _output_public_key_attributes(wctx, fp);
	if (rc != rc_ok) {
	    fprintf(stderr, "***Error: when outputting public key attributes\n");
	    goto error;
	}

	rc = _output_public_key_b64(wctx, fp);
	if (rc != rc_ok) {
	    fprintf(stderr, "***Error: when outputting public key\n");
	    goto error;
	}
    }

    error:
    if (fp && fp != stdout) {
	fclose(fp);
    }
    return rc;
}
