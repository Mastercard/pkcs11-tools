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
#include <stdbool.h>
#include <time.h>
#include <search.h>

#include <openssl/bio.h>
#include <openssl/pem.h>

#include "pkcs11lib.h"
#include "wrappedkey_lexer.h"
#include "wrappedkey_parser.h"

typedef enum {
    meth_label,
    meth_keyhandle
} wrap_source_method_t;

static func_rc _wrap_rfc3394(wrappedKeyCtx *wctx);

static func_rc _wrap_rfc5649(wrappedKeyCtx *wctx);

static func_rc _wrap_pkcs1_15(wrappedKeyCtx *wctx);

static func_rc _wrap_pkcs1_oaep(wrappedKeyCtx *wctx);

static func_rc _wrap_cbcpad(wrappedKeyCtx *wctx);

static func_rc _wrap_envelope(wrappedKeyCtx *wctx);

static func_rc _wrap_aes_key_wrap_mech(wrappedKeyCtx *wctx, CK_MECHANISM_TYPE mech[], CK_ULONG mech_size);

static inline func_rc _wrap_rfc3394(wrappedKeyCtx *wctx) {
    return _wrap_aes_key_wrap_mech(wctx, wctx->p11Context->rfc3394_mech, wctx->p11Context->rfc3394_mech_size);
}

static inline func_rc _wrap_rfc5649(wrappedKeyCtx *wctx) {
    return _wrap_aes_key_wrap_mech(wctx, wctx->p11Context->rfc5649_mech, wctx->p11Context->rfc5649_mech_size);
}

static func_rc _wrap(wrappedKeyCtx *wctx,
		     wrap_source_method_t wrap_source_method,
		     char *wrappedkeylabel,
		     CK_OBJECT_HANDLE wrappedkeyhandle,
		     CK_OBJECT_HANDLE pubkhandle);

inline func_rc pkcs11_wrap_from_label(wrappedKeyCtx *wctx, char *wrappedkeylabel) {
    return _wrap(wctx, meth_label, wrappedkeylabel, 0, 0);
}

inline func_rc pkcs11_wrap_from_handle(wrappedKeyCtx *wctx,
				       CK_OBJECT_HANDLE wrappedkeyhandle,
				       CK_OBJECT_HANDLE pubkhandle) {
    return _wrap(wctx, meth_keyhandle, NULL, wrappedkeyhandle, pubkhandle);
}

static func_rc _wrap_pkcs1_15(wrappedKeyCtx *wctx) {
    func_rc rc = rc_ok;

    CK_OBJECT_HANDLE wrappingkeyhandle = NULL_PTR;
    CK_OBJECT_HANDLE wrappedkeyhandle = NULL_PTR;
    CK_OBJECT_CLASS wrappedkeyobjclass;
    pkcs11AttrList *wrappedkey_attrs = NULL, *wrappingkey_attrs = NULL;
    CK_ATTRIBUTE_PTR o_wrappedkey_bytes, o_modulus, o_keytype;
    BIGNUM *bn_wrappingkey_bytes = NULL;
    BIGNUM *bn_wrappedkey_bytes = NULL;
    int bytelen;
    unsigned long keysizeinbytes;

    /* keyindex: in case of envelope wrapping, the index shall always be the outer */
    int keyindex = wctx->is_envelope ? WRAPPEDKEYCTX_OUTER_KEY_INDEX : WRAPPEDKEYCTX_LONE_KEY_INDEX;

    /* retrieve keys  */

    if (wctx->is_envelope) {
	/* if envelope encryption, keys have been already found by _wrap_envelope() */
	/* and wctx structure has been populated. */
	wrappedkeyhandle = wctx->key[keyindex].wrappedkeyhandle;
	wrappingkeyhandle = wctx->key[keyindex].wrappingkeyhandle;
    } else {
	if (!pkcs11_findpublickey(wctx->p11Context, wctx->wrappingkeylabel, &wrappingkeyhandle)) {
	    fprintf(stderr, "Error: could not find a public key with label '%s'\n", wctx->wrappingkeylabel);
	    rc = rc_error_object_not_found;
	    goto error;
	}

	/* if we called _wrap() with meth_keyhandle, then the wrappedkeylabel is NULL */
	/* and we can directly use the value in wrappedkeyhabndle */
	if (wctx->wrappedkeylabel == NULL) {
	    wrappedkeyhandle = wctx->key[keyindex].wrappedkeyhandle;
	    /* we need to retrieve the object class */
	    wrappedkeyobjclass = pkcs11_get_object_class(wctx->p11Context, wrappedkeyhandle);

	    if (wrappedkeyobjclass != CKO_SECRET_KEY) {
		fprintf(stderr,
			"***Error: PKCS#1 1.5 wrapping algorithm can only wrap secret keys, not private keys\n");
		rc = rc_error_wrong_object_class;
		goto error;
	    }
	} else {
	    if (!pkcs11_findsecretkey(wctx->p11Context, wctx->wrappedkeylabel, &wrappedkeyhandle)) {
		fprintf(stderr, "Error: secret key with label '%s' does not exists\n", wctx->wrappedkeylabel);
		rc = rc_error_object_not_found;
		goto error;
	    }
	}
    }

    /* retrieve length of wrapping key */
    wrappingkey_attrs = pkcs11_new_attrlist(wctx->p11Context,
					    _ATTR(CKA_MODULUS),
					    _ATTR_END);

    if (pkcs11_read_attr_from_handle(wrappingkey_attrs, wrappingkeyhandle) == false) {
	fprintf(stderr, "Error: could not read CKA_MODULUS_BITS attribute from public key with label '%s'\n",
		wctx->wrappingkeylabel);
	rc = rc_error_pkcs11_api;
	goto error;
    }

    o_modulus = pkcs11_get_attr_in_attrlist(wrappingkey_attrs, CKA_MODULUS);

    /* overwrite existing value */
    if ((bn_wrappingkey_bytes = BN_bin2bn(o_modulus->pValue, o_modulus->ulValueLen, NULL)) == NULL) {
	P_ERR();
	goto error;
    }

    /* extract number of bytes */
    bytelen = BN_num_bytes(bn_wrappingkey_bytes);

    /* and adjust value */
    BN_set_word(bn_wrappingkey_bytes, (unsigned long) bytelen);

    /* retrieve length of wrapped key */
    wrappedkey_attrs = pkcs11_new_attrlist(wctx->p11Context,
					   _ATTR(CKA_KEY_TYPE), /* for DES/DES2/DES3 */
					   _ATTR(CKA_VALUE_LEN), /* caution: value in bytes */
					   _ATTR_END);

    if (pkcs11_read_attr_from_handle(wrappedkey_attrs, wrappedkeyhandle) == false) {
	fprintf(stderr, "Error: could not read CKA_VALUE_LEN attribute from secret key with label '%s'\n",
		wctx->wrappedkeylabel);
	rc = rc_error_pkcs11_api;
	goto error;
    }

    o_wrappedkey_bytes = pkcs11_get_attr_in_attrlist(wrappedkey_attrs, CKA_VALUE_LEN);
    /* pkcs11_get_attr_in_attrlist returns the attribute, but we need to check */
    /* if there is actually a value attached to it */

    if (o_wrappedkey_bytes && o_wrappedkey_bytes->pValue) {


	/* BN_bin2bn works only with big endian, so we must alter data */
	/* if architecture is LE */

	*((CK_ULONG *) o_wrappedkey_bytes->pValue) =
	    pkcs11_ll_bigendian_ul( *((CK_ULONG * )(o_wrappedkey_bytes->pValue))); /* transform if required */

	if ((bn_wrappedkey_bytes = BN_bin2bn(o_wrappedkey_bytes->pValue, o_wrappedkey_bytes->ulValueLen, NULL)) == NULL) {
	    P_ERR();
	    goto error;
	}
    } else { /* can be the case for CKK_DES, CKK_DES2 and CKK_DES3 family */
	/* as these keys have no CKA_VALUE_LEN attribute */

	o_keytype = pkcs11_get_attr_in_attrlist(wrappedkey_attrs, CKA_KEY_TYPE);

	switch (*(CK_KEY_TYPE * )(o_keytype->pValue)) {
	    case CKK_DES:
		keysizeinbytes = 8;
		break;

	    case CKK_DES2:
		keysizeinbytes = 16;
		break;

	    case CKK_DES3:
		keysizeinbytes = 24;
		break;

	    default:
		fprintf(stderr, "***Error: unsupported key type for wrapping key\n");
		rc = rc_error_unsupported;
		goto error;
	}

	/* allocate BN */
	if ((bn_wrappedkey_bytes = BN_new()) == NULL) {
	    P_ERR();
	    goto error;
	}

	if (BN_set_word(bn_wrappedkey_bytes, keysizeinbytes) == 0) {
	    P_ERR();
	    goto error;
	}
    }


    /* now check that len(wrapped_key) < len(wrapping_key) - 11 */
    /* !! lengths being expressed in bytes */

    if (!BN_add_word(bn_wrappedkey_bytes, 11L)) {
	P_ERR();
	goto error;
    }

    /* if bn_wrapped_key  + 11 > bn_wrapping_key, then the wrapping key is too short.  */

    if (BN_cmp(bn_wrappedkey_bytes, bn_wrappingkey_bytes) > 0) {
	fprintf(stderr, "Error: wrapping key '%s' is too short to wrap key '%s'\n", wctx->wrappingkeylabel,
		wctx->wrappedkeylabel);
	rc = rc_error_wrapping_key_too_short;
	goto error;
    }


    /* we are good, let's allocate the memory and wrap */
    /* trick: we use now the CKA_MODULUS attribute to size the target buffer */

    wctx->key[keyindex].wrapped_key_buffer = calloc(o_modulus->ulValueLen, sizeof(unsigned char));

    if (wctx->key[keyindex].wrapped_key_buffer == NULL) {
	fprintf(stderr, "Error: memory\n");
	rc = rc_error_memory;
	goto error;
    }

    wctx->key[keyindex].wrapped_key_len = o_modulus->ulValueLen;

    /* now wrap */

    {
	CK_RV rv;
	CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};/* PKCS #1 1.5 wrap */

	rv = wctx->p11Context->FunctionList.C_WrapKey(wctx->p11Context->Session,
						      &mechanism,
						      wrappingkeyhandle,
						      wrappedkeyhandle,
						      wctx->key[keyindex].wrapped_key_buffer,
						      &(wctx->key[keyindex].wrapped_key_len));

	if (rv != CKR_OK) {
	    pkcs11_error(rv, "C_WrapKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}
	wctx->key[keyindex].wrappedkeyhandle = wrappedkeyhandle;
	wctx->key[keyindex].wrappedkeyobjclass = CKO_SECRET_KEY;

    }

    error:
    if (bn_wrappingkey_bytes != NULL) {
	BN_free(bn_wrappingkey_bytes);
	bn_wrappingkey_bytes = NULL;
    }
    if (bn_wrappedkey_bytes != NULL) {
	BN_free(bn_wrappedkey_bytes);
	bn_wrappedkey_bytes = NULL;
    }
    pkcs11_delete_attrlist(wrappingkey_attrs);
    pkcs11_delete_attrlist(wrappedkey_attrs);

    return rc;
}


static func_rc _wrap_cbcpad(wrappedKeyCtx *wctx) {
    func_rc rc = rc_ok;

    CK_OBJECT_HANDLE wrappingkeyhandle = NULL_PTR;
    CK_OBJECT_HANDLE wrappedkeyhandle = NULL_PTR;
    key_type_t keytype;
    CK_OBJECT_CLASS wrappedkeyobjclass;
    int blocklength;

    /* keyindex: in case of envelope wrapping, the index shall always be the outer */
    // FIXME: compiler says these are the same values...
    int keyindex = wctx->is_envelope ? WRAPPEDKEYCTX_INNER_KEY_INDEX : WRAPPEDKEYCTX_LONE_KEY_INDEX;

    /* retrieve keys  */

    /* wrapping key is a secret key */

    if (wctx->is_envelope) {
	/* if envelope encryption, keys have been already found by _wrap_envelope() */
	/* and wctx structure has been populated. */
	wrappedkeyhandle = wctx->key[keyindex].wrappedkeyhandle;
	wrappedkeyobjclass = wctx->key[keyindex].wrappedkeyobjclass;
	wrappingkeyhandle = wctx->key[keyindex].wrappingkeyhandle;
    } else {
	if (!pkcs11_findsecretkey(wctx->p11Context, wctx->wrappingkeylabel, &wrappingkeyhandle)) {
	    fprintf(stderr, "***Error: could not find a secret key with label '%s'\n", wctx->wrappingkeylabel);
	    rc = rc_error_object_not_found;
	    goto error;
	}

	/* if we called _wrap() with meth_keyhandle, then the wrappedkeylabel is NULL */
	/* and we can directly use the value in wrappedkeyhabndle */
	/* however, we are still lacking the object class, so we retrieve it from the handle */
	if (wctx->wrappedkeylabel == NULL) {
	    wrappedkeyhandle = wctx->key[keyindex].wrappedkeyhandle;
	    wrappedkeyobjclass = pkcs11_get_object_class(wctx->p11Context, wrappedkeyhandle);

	    if (wrappedkeyobjclass != CKO_SECRET_KEY && wrappedkeyobjclass != CKO_PRIVATE_KEY) {
		rc = rc_error_oops;
		goto error;
	    }
	} else {
	    /* we have a label, just retrieve handle and object class from label */
	    if (!pkcs11_findprivateorsecretkey(wctx->p11Context,
					       wctx->wrappedkeylabel,
					       &wrappedkeyhandle,
					       &wrappedkeyobjclass)) {
		fprintf(stderr, "***Error: key with label '%s' does not exists\n", wctx->wrappedkeylabel);
		rc = rc_error_object_not_found;
		goto error;
	    }
	}
    }

    /* in case of private key, see if we have a match for a public key as well (valid only for token keys) */
    if (wrappedkeyobjclass == CKO_PRIVATE_KEY && wctx->wrappedkeylabel) {
	if (!pkcs11_findpublickey(wctx->p11Context, wctx->wrappedkeylabel, &wctx->pubkhandle)) {
	    fprintf(stderr,
		    "***Warning: private key with label '%s' found, but there is no associated public key found with the same label\n",
		    wctx->wrappedkeylabel);
	}
    }

    /* determining block size of the block cipher. */
    /* retrieve length of wrapping key */
    keytype = pkcs11_get_key_type(wctx->p11Context, wrappingkeyhandle);

    switch (keytype) {
	case aes:
	    blocklength = 16;
	    break;

	case des:
	case des2:
	case des3:
	    blocklength = 8;
	    break;

	default:
	    fprintf(stderr, "***Error: unsupported key type for wrapping key\n");
	    rc = rc_error_unsupported;
	    goto error;
    }

    /* check length of iv */

    if (wctx->aes_params.iv_len == 0) {
	/* special case: no IV was given - We do one of our own */
	wctx->aes_params.iv = malloc(blocklength);
	if (wctx->aes_params.iv == NULL) {
	    fprintf(stderr, "***Error: memory allocation\n");
	    rc = rc_error_memory;
	    goto error;
	}
	wctx->aes_params.iv_len = blocklength;

	/* randomize it */
	pkcs11_getrandombytes(wctx->p11Context, wctx->aes_params.iv, blocklength);

    } else {
	if (wctx->aes_params.iv_len != blocklength) {
	    fprintf(stderr, "***Error: IV vector length(%d) mismatch - %d bytes are required\n",
		    (int) (wctx->aes_params.iv_len), (int) blocklength);
	    rc = rc_error_invalid_parameter_for_method;
	    goto error;
	}
    }

/* now wrap */

    {
	CK_RV rv;
	CK_MECHANISM mechanism = {0L, wctx->aes_params.iv, wctx->aes_params.iv_len};
	CK_ULONG wrappedkeybuffersize;

	switch (keytype) {
	    case aes:
		mechanism.mechanism = CKM_AES_CBC_PAD;
		break;

	    case des:
		mechanism.mechanism = CKM_DES_CBC_PAD;
		break;

	    case des2:        /* DES2 and DES3 both use the same mechanism */
	    case des3:
		mechanism.mechanism = CKM_DES3_CBC_PAD;
		break;

	    default:
		fprintf(stderr, "***Error: unsupported key type for wrapping key\n");
		rc = rc_error_unsupported;
		goto error;
	}

	/* first call to know what will be the size output buffer */
	rv = wctx->p11Context->FunctionList.C_WrapKey(wctx->p11Context->Session,
						      &mechanism,
						      wrappingkeyhandle,
						      wrappedkeyhandle,
						      NULL,
						      &wrappedkeybuffersize);

	if (rv != CKR_OK) {
	    pkcs11_error(rv, "C_WrapKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	wctx->key[keyindex].wrapped_key_buffer = malloc(wrappedkeybuffersize);
	if (wctx->key[keyindex].wrapped_key_buffer == NULL) {
	    fprintf(stderr, "***Error: memory allocation\n");
	    rc = rc_error_memory;
	    goto error;
	}
	wctx->key[keyindex].wrapped_key_len = wrappedkeybuffersize;

	/* now we can do the real call, with the real buffer */
	rv = wctx->p11Context->FunctionList.C_WrapKey(wctx->p11Context->Session,
						      &mechanism,
						      wrappingkeyhandle,
						      wrappedkeyhandle,
						      wctx->key[keyindex].wrapped_key_buffer,
						      &(wctx->key[keyindex].wrapped_key_len));


	if (rv != CKR_OK) {
	    pkcs11_error(rv, "C_WrapKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	wctx->key[keyindex].wrappedkeyobjclass = wrappedkeyobjclass;
	wctx->key[keyindex].wrappedkeyhandle = wrappedkeyhandle;
    }

    error:

    return rc;
}



/*------------------------------------------------------------------------*/
/* wrap a key using CKM_AES_KEY_WRAP or equivalent mechanism              */
/*------------------------------------------------------------------------*/

static func_rc _wrap_aes_key_wrap_mech(wrappedKeyCtx *wctx, CK_MECHANISM_TYPE mech[], CK_ULONG mech_size) {
    func_rc rc = rc_ok;

    CK_OBJECT_HANDLE wrappingkeyhandle = 0;
    CK_OBJECT_HANDLE wrappedkeyhandle = 0;
    CK_OBJECT_CLASS wrappedkeyobjclass;
    key_type_t keytype;

    /* no need for sanity check - compiler assures wctx is always != NULL */
    if (wctx == NULL) {
	fprintf(stderr, "***Error: invalid argument to _wrap_aes_key_wrap_mech()\n");
	rc = rc_error_invalid_parameter_for_method;
	goto error;
    }

    /* keyindex: in case of envelope wrapping, the index shall always be the outer */
    // FIXME: is this correct - compiler says it's the same values.
    int keyindex = wctx->is_envelope ? WRAPPEDKEYCTX_INNER_KEY_INDEX : WRAPPEDKEYCTX_LONE_KEY_INDEX;

    if (mech_size == 0 || mech_size > AES_WRAP_MECH_SIZE_MAX) {
	fprintf(stderr, "***Error: invalid wrapping mechanism table size\n");
	rc = rc_error_invalid_parameter_for_method;
	goto error;
    }

    /* retrieve keys  */

    /* wrapping key is a secret key */

    if (wctx->is_envelope) {
	/* if envelope encryption, keys have been already found by _wrap_envelope() */
	/* and wctx structure has been populated. */
	wrappedkeyhandle = wctx->key[keyindex].wrappedkeyhandle;
	wrappedkeyobjclass = wctx->key[keyindex].wrappedkeyobjclass;
	wrappingkeyhandle = wctx->key[keyindex].wrappingkeyhandle;
    } else {
	if (!pkcs11_findsecretkey(wctx->p11Context, wctx->wrappingkeylabel, &wrappingkeyhandle)) {
	    fprintf(stderr, "***Error: could not find a secret key with label '%s'\n", wctx->wrappingkeylabel);
	    rc = rc_error_object_not_found;
	    goto error;
	}

	/* if we called _wrap() with meth_keyhandle, then the wrappedkeylabel is NULL */
	/* and we can directly use the value in wrappedkeyhabndle */
	/* however, we are still lacking the object class, so we retrieve it from the handle */
	if (wctx->wrappedkeylabel == NULL) {
	    wrappedkeyhandle = wctx->key[keyindex].wrappedkeyhandle;
	    wrappedkeyobjclass = pkcs11_get_object_class(wctx->p11Context, wrappedkeyhandle);

	    if (wrappedkeyobjclass != CKO_SECRET_KEY && wrappedkeyobjclass != CKO_PRIVATE_KEY) {
		rc = rc_error_oops;
		goto error;
	    }
	} else {
	    /* we have a label, just retrieve handle and object class from label */
	    if (!pkcs11_findprivateorsecretkey(wctx->p11Context, wctx->wrappedkeylabel, &wrappedkeyhandle,
					       &wrappedkeyobjclass)) {
		fprintf(stderr, "***Error: key with label '%s' does not exists\n", wctx->wrappedkeylabel);
		rc = rc_error_object_not_found;
		goto error;
	    }
	}
    }

    /* in case of private key, see if we have a match for a public key as well (valid only for token keys) */
    if (wrappedkeyobjclass == CKO_PRIVATE_KEY && wctx->wrappedkeylabel) {
	if (!pkcs11_findpublickey(wctx->p11Context, wctx->wrappedkeylabel, &wctx->pubkhandle)) {
	    fprintf(stderr,
		    "***Warning: private key with label '%s' found, but there is no associated public key found with the same label\n",
		    wctx->wrappedkeylabel);
	}
    }

    /* determining block size of the block cipher. */
    /* retrieve length of wrapping key */
    keytype = pkcs11_get_key_type(wctx->p11Context, wrappingkeyhandle);

    if (keytype != aes) {
	fprintf(stderr, "Error: secret key with label '%s' is not an AES key\n", wctx->wrappingkeylabel);
	rc = rc_error_wrong_key_type;
	goto error;

    }

/* now wrap */

    {
	CK_RV rv;
	CK_MECHANISM mechanism = {0L, wctx->aes_params.iv, wctx->aes_params.iv_len};
	CK_ULONG wrappedkeybuffersize;
	CK_ULONG i;

	// determine key size for JWK key wrapping
	if(! (wrappedkeybuffersize = pkcs11_get_object_size(wctx->p11Context, wrappingkeyhandle))){
	    fprintf(stderr, "***Error: could not determine size of AES key, error was %lx\n", rv);
	    rc = rc_error_other_error;
	    goto error;
	}

	/* first call to know what will be the size output buffer */
	for (i = 0; i < mech_size; i++) {
	    /* let's try mechanisms one by one, unless the mechanism is already supplied  */
	    /* i.e. if wctx->aes_wrapping_mech != 0 */
	    mechanism.mechanism = wctx->aes_params.aes_wrapping_mech != 0 ?
		wctx->aes_params.aes_wrapping_mech :
		mech[i];

	    rv = wctx->p11Context->FunctionList.C_WrapKey(wctx->p11Context->Session,
							  &mechanism,
							  wrappingkeyhandle,
							  wrappedkeyhandle,
							  NULL,
							  &wrappedkeybuffersize);
	    if (rv != CKR_OK) {
		pkcs11_error(rv, "C_WrapKey");
		fprintf(stderr, "***Warning: It didn't work with %s\n",
			pkcs11_get_mechanism_name_from_type(mechanism.mechanism));
	    } else {
		/* it worked, let's remember in wctx the actual mechanism used */
		/* unless it was already supplied */
		if (wctx->aes_params.aes_wrapping_mech == 0) {
		    wctx->aes_params.aes_wrapping_mech = mech[i];
		}
		/* and escape loop */
		break;
	    }

	    if (wctx->aes_params.aes_wrapping_mech != 0) {
		/* special case: if the wrapping mechanism was set by the parser */
		/* through option field, we will not try other mechanisms than the one  */
		/* specified. */
		break;
	    }
	}

	if (rv != CKR_OK) {    /* we couldn't find a suitable mech */
	    fprintf(stderr, "***Error: tried all mechanisms, no one worked\n");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	wctx->key[keyindex].wrapped_key_buffer = malloc(wrappedkeybuffersize);
	if (wctx->key[keyindex].wrapped_key_buffer == NULL) {
	    fprintf(stderr, "***Error: memory allocation\n");
	    rc = rc_error_memory;
	    goto error;
	}
	wctx->key[keyindex].wrapped_key_len = wrappedkeybuffersize;

	/* now we can do the real call, with the real buffer */
	rv = wctx->p11Context->FunctionList.C_WrapKey(wctx->p11Context->Session,
						      &mechanism,
						      wrappingkeyhandle,
						      wrappedkeyhandle,
						      wctx->key[keyindex].wrapped_key_buffer,
						      &(wctx->key[keyindex].wrapped_key_len));


	if (rv != CKR_OK) {
	    pkcs11_error(rv, "C_WrapKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	wctx->key[keyindex].wrappedkeyobjclass = wrappedkeyobjclass;
	wctx->key[keyindex].wrappedkeyhandle = wrappedkeyhandle;
    }

    error:
    return rc;
}

/*------------------------------------------------------------------------*/
static func_rc _wrap_pkcs1_oaep(wrappedKeyCtx *wctx) {
    func_rc rc = rc_ok;

    CK_OBJECT_HANDLE wrappingkeyhandle = NULL_PTR;
    CK_OBJECT_HANDLE wrappedkeyhandle = NULL_PTR;
    CK_OBJECT_CLASS wrappedkeyobjclass;
    pkcs11AttrList *wrappedkey_attrs = NULL, *wrappingkey_attrs = NULL;
    CK_ATTRIBUTE_PTR o_wrappedkey_bytes, o_modulus, o_keytype;
    BIGNUM *bn_wrappingkey_bytes = NULL;
    BIGNUM *bn_wrappedkey_bytes = NULL;
    int bytelen;
    int sizeoverhead;
    unsigned long keysizeinbytes;

    /* keyindex: in case of envelope wrapping, the index shall always be the outer */
    int keyindex = wctx->is_envelope ? WRAPPEDKEYCTX_OUTER_KEY_INDEX : WRAPPEDKEYCTX_LONE_KEY_INDEX;

    /* retrieve keys  */

    if (wctx->is_envelope) {
	/* if envelope encryption, keys have been already found by _wrap_envelope() */
	/* and wctx structure has been populated. */
	wrappedkeyhandle = wctx->key[keyindex].wrappedkeyhandle;
	wrappingkeyhandle = wctx->key[keyindex].wrappingkeyhandle;
    } else {
	if (!pkcs11_findpublickey(wctx->p11Context, wctx->wrappingkeylabel, &wrappingkeyhandle)) {
	    fprintf(stderr, "Error: could not find a public key with label '%s'\n", wctx->wrappingkeylabel);
	    rc = rc_error_object_not_found;
	    goto error;
	}

	/* if we called _wrap() with meth_keyhandle, then the wrappedkeylabel is NULL */
	/* and we can directly use the value in wrappedkeyhabndle */
	if (wctx->wrappedkeylabel == NULL) {
	    wrappedkeyhandle = wctx->key[keyindex].wrappedkeyhandle;
	    /* we need to retrieve the object class */
	    wrappedkeyobjclass = pkcs11_get_object_class(wctx->p11Context, wrappedkeyhandle);

	    if (wrappedkeyobjclass != CKO_SECRET_KEY) {
		fprintf(stderr,
			"***Error: PKCS#1 OAEP wrapping algorithm can only wrap secret keys, not private keys\n");
		rc = rc_error_wrong_object_class;
		goto error;
	    }
	} else {
	    if (!pkcs11_findsecretkey(wctx->p11Context, wctx->wrappedkeylabel, &wrappedkeyhandle)) {
		fprintf(stderr, "Error: secret key with label '%s' does not exists\n", wctx->wrappedkeylabel);
		rc = rc_error_object_not_found;
		goto error;
	    }
	}
    }

    /* retrieve length of wrapping key */
    wrappingkey_attrs = pkcs11_new_attrlist(wctx->p11Context,
					    _ATTR(CKA_MODULUS),
					    _ATTR_END);

    if (pkcs11_read_attr_from_handle(wrappingkey_attrs, wrappingkeyhandle) == false) {
	fprintf(stderr, "Error: could not read CKA_MODULUS_BITS attribute from public key with label '%s'\n",
		wctx->wrappingkeylabel);
	rc = rc_error_pkcs11_api;
	goto error;
    }

    o_modulus = pkcs11_get_attr_in_attrlist(wrappingkey_attrs, CKA_MODULUS);

    /* overwrite existing value */
    if ((bn_wrappingkey_bytes = BN_bin2bn(o_modulus->pValue, o_modulus->ulValueLen, NULL)) == NULL) {
	P_ERR();
	goto error;
    }

    /* extract number of bytes */
    bytelen = BN_num_bytes(bn_wrappingkey_bytes);

    /* and adjust value */
    BN_set_word(bn_wrappingkey_bytes, (unsigned long) bytelen);

    /* retrieve length of wrapped key */
    wrappedkey_attrs = pkcs11_new_attrlist(wctx->p11Context,
					   _ATTR(CKA_KEY_TYPE), /* needed as CKA_VALUE_LEN might not always be present */
					   _ATTR(CKA_VALUE_LEN), /* caution: value in bytes */
					   _ATTR_END);

    if (pkcs11_read_attr_from_handle(wrappedkey_attrs, wrappedkeyhandle) == false) {
	fprintf(stderr, "Error: could not read attributes from secret key with label '%s'\n", wctx->wrappedkeylabel);
	rc = rc_error_pkcs11_api;
	goto error;
    }

    o_wrappedkey_bytes = pkcs11_get_attr_in_attrlist(wrappedkey_attrs, CKA_VALUE_LEN);
    /* pkcs11_get_attr_in_attrlist returns the attribute, but we need to check */
    /* if there is actually a value attached to it */

    if (o_wrappedkey_bytes && o_wrappedkey_bytes->pValue) {


	/* BN_bin2bn works only with big endian, so we must alter data */
	/* if architecture is LE */

	*((CK_ULONG *) o_wrappedkey_bytes->pValue) = pkcs11_ll_bigendian_ul( *((CK_ULONG * )(o_wrappedkey_bytes->pValue)));

	if ((bn_wrappedkey_bytes = BN_bin2bn(o_wrappedkey_bytes->pValue,
					     o_wrappedkey_bytes->ulValueLen,
					     NULL)) == NULL) {
	    P_ERR();
	    goto error;
	}
    } else { /* can be the case for CKK_DES, CKK_DES2 and CKK_DES3 family */
	/* as these keys have no CKA_VALUE_LEN attribute */

	o_keytype = pkcs11_get_attr_in_attrlist(wrappedkey_attrs, CKA_KEY_TYPE);

	switch (*(CK_KEY_TYPE * )(o_keytype->pValue)) {
	    case CKK_DES:
		keysizeinbytes = 8;
		break;

	    case CKK_DES2:
		keysizeinbytes = 16;
		break;

	    case CKK_DES3:
		keysizeinbytes = 24;
		break;

	    default:
		fprintf(stderr, "***Error: unsupported key type for wrapping key\n");
		rc = rc_error_unsupported;
		goto error;
	}

	/* allocate BN */
	if ((bn_wrappedkey_bytes = BN_new()) == NULL) {
	    P_ERR();
	    goto error;
	}

	if (BN_set_word(bn_wrappedkey_bytes, keysizeinbytes) == 0) {
	    P_ERR();
	    goto error;
	}
    }

    /* now check that len(wrapped_key) < len(wrapping_key) - 2 - 2 * hlen */
    /* !! lengths being expressed in bytes */
    /* in this version, Hash Algorithm set to SHA-1 and hardcoded */

    /* when SHA1, hlen=20, 2 * hlen + 2 = 42 */
    /* when SHA256, hlen=32,  2 * hlen + 2 = 66 */
    /* when SHA384, hlen=48,  2 * hlen + 2 = 98 */
    /* when SHA512, hlen=64,  2 * hlen + 2 = 130 */

    switch (wctx->oaep_params->hashAlg) {
	case CKM_SHA_1:
	    sizeoverhead = 42;
	    break;

	case CKM_SHA256:
	    sizeoverhead = 66;
	    break;

	case CKM_SHA384:
	    sizeoverhead = 98;
	    break;

	case CKM_SHA512:
	    sizeoverhead = 130;
	    break;

	default:
	    fprintf(stderr, "***Error: unsupported hashing algorithm for OAEP wrapping\n");
	    rc = rc_error_unsupported;
	    goto error;
    }


    if (!BN_add_word(bn_wrappedkey_bytes, sizeoverhead)) {
	P_ERR();
	goto error;
    }

    /* if bn_wrapped_key  + sizeoverhead > bn_wrapping_key, then the wrapping key is too short.  */

    if (BN_cmp(bn_wrappedkey_bytes, bn_wrappingkey_bytes) > 0) {
	fprintf(stderr,
		"Error: wrapping key '%s' is too short to wrap key '%s'\n",
		wctx->wrappingkeylabel,
		wctx->wrappedkeylabel);
	rc = rc_error_wrapping_key_too_short;
	goto error;
    }


    /* we are good, let's allocate the memory and wrap */
    /* trick: we use now the CKA_MODULUS attribute to size the target buffer */

    wctx->key[keyindex].wrapped_key_buffer = calloc(o_modulus->ulValueLen, sizeof(unsigned char));

    if (wctx->key[keyindex].wrapped_key_buffer == NULL) {
	fprintf(stderr, "Error: memory\n");
	rc = rc_error_memory;
	goto error;
    }

    wctx->key[keyindex].wrapped_key_len = o_modulus->ulValueLen;

    /* now wrap */

    {
	CK_RV rv;
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_OAEP,
				  wctx->oaep_params,
				  sizeof(CK_RSA_PKCS_OAEP_PARAMS)};/* PKCS #1 OAEP wrap */

	rv = wctx->p11Context->FunctionList.C_WrapKey(wctx->p11Context->Session,
						      &mechanism,
						      wrappingkeyhandle,
						      wrappedkeyhandle,
						      wctx->key[keyindex].wrapped_key_buffer,
						      &(wctx->key[keyindex].wrapped_key_len));

	if (rv != CKR_OK) {
	    pkcs11_error(rv, "C_WrapKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	wctx->key[keyindex].wrappedkeyhandle = wrappedkeyhandle; /* keep a copy, for the output */
	wctx->key[keyindex].wrappedkeyobjclass = CKO_SECRET_KEY; /* same story */
    }

    error:
    if (bn_wrappingkey_bytes != NULL) {
	BN_free(bn_wrappingkey_bytes);
	bn_wrappingkey_bytes = NULL;
    }
    if (bn_wrappedkey_bytes != NULL) {
	BN_free(bn_wrappedkey_bytes);
	bn_wrappedkey_bytes = NULL;
    }
    pkcs11_delete_attrlist(wrappingkey_attrs);
    pkcs11_delete_attrlist(wrappedkey_attrs);

    return rc;
}


/*------------------------------------------------------------------------*/
static func_rc _wrap_envelope(wrappedKeyCtx *wctx) {
    func_rc rc = rc_ok;
    CK_OBJECT_HANDLE wrappingkeyhandle = NULL_PTR;
    CK_OBJECT_HANDLE wrappedkeyhandle = NULL_PTR;
    CK_OBJECT_CLASS wrappedkeyobjclass;
    CK_OBJECT_HANDLE tempaes_handle = 0;
    CK_BBOOL ck_true = CK_TRUE;

    CK_ATTRIBUTE tempaes_attrs[] = {
	    {CKA_WRAP,        &ck_true, sizeof(ck_true)},
	    {CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)}
    };

    char tempaes_label[32];

    if (!pkcs11_findpublickey(wctx->p11Context, wctx->wrappingkeylabel, &wrappingkeyhandle)) {
	fprintf(stderr, "Error: could not find a public key with label '%s'\n", wctx->wrappingkeylabel);
	rc = rc_error_object_not_found;
	goto error;
    }

    /* if we called _wrap() with meth_keyhandle, then the wrappedkeylabel is NULL */
    /* and we can directly use the value in wrappedkeyhandle */
    /* however, we are still lacking the object class, so we retrieve it from the handle */
    if (wctx->wrappedkeylabel == NULL) {
	wrappedkeyhandle = wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrappedkeyhandle;

	/* extract object class from provided handle */
	wrappedkeyobjclass = pkcs11_get_object_class(wctx->p11Context, wrappedkeyhandle);

	if (wrappedkeyobjclass != CKO_SECRET_KEY && wrappedkeyobjclass != CKO_PRIVATE_KEY) {
	    rc = rc_error_oops;
	    goto error;
	}
    } else {
	/* we have a label, just retrieve handle and object class from label */
	if (!pkcs11_findprivateorsecretkey(wctx->p11Context, wctx->wrappedkeylabel, &wrappedkeyhandle,
					   &wrappedkeyobjclass)) {
	    fprintf(stderr, "***Error: key with label '%s' does not exists\n", wctx->wrappedkeylabel);
	    rc = rc_error_object_not_found;
	    goto error;
	}
    }

    /* step 1: setup wctx structure to remember the key handles */
    wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrappingkeyhandle = wrappingkeyhandle;
    wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrappedkeyhandle = wrappedkeyhandle;
    wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrappedkeyobjclass = wrappedkeyobjclass;

    /* step 2: generate the intermediate temporary key */
    /* will be an AES for now */

    snprintf((char *) tempaes_label, sizeof tempaes_label, "tempaes-%ld", time(NULL));

    /* TODO - adapt to support other symmetric types - detect on wrapping alg */
    rc = pkcs11_genAES(wctx->p11Context,
		       tempaes_label,
		       256,
		       tempaes_attrs,
		       sizeof tempaes_attrs / sizeof(CK_ATTRIBUTE),
		       &tempaes_handle,
		       kg_session_for_wrapping);

    if (rc != rc_ok) {
	fprintf(stderr, "Unable to generate temporary wrapping key\n");
	goto error;
    }

    /* step 3: remember our temporary key in wctx structure */
    wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrappedkeyhandle = tempaes_handle;
    wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrappedkeyobjclass = CKO_SECRET_KEY;
    wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrappingkeyhandle = tempaes_handle;

    /* step 4: wrap the inner key */
    switch (wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrapping_meth) {
	case w_cbcpad:
	    rc = _wrap_cbcpad(wctx);
	    break;

	case w_rfc3394:
	    rc = _wrap_rfc3394(wctx);
	    break;

	case w_rfc5649:
	    rc = _wrap_rfc5649(wctx);
	    break;

	default:
	    rc = rc_error_oops;
    }

    if (rc != rc_ok) {
	goto error;
    }

    /* step 5: wrap the outer key */
    switch (wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrapping_meth) {
	case w_pkcs1_15:
	    rc = _wrap_pkcs1_15(wctx);
	    break;

	case w_pkcs1_oaep:
	    rc = _wrap_pkcs1_oaep(wctx);
	    break;

	default:
	    rc = rc_error_oops;
    }

    if (rc != rc_ok) {
	goto error;
    }

    error:
    if (tempaes_handle != 0) {
	CK_RV rv = wctx->p11Context->FunctionList.C_DestroyObject(wctx->p11Context->Session, tempaes_handle);
	if (rv != CKR_OK) {
	    pkcs11_error(rv, "C_DestroyObject");
	}
    }
    return rc;

}


/*--------------------------------------------------------------------------------*/
/* PUBLIC INTERFACE                                                               */
/*--------------------------------------------------------------------------------*/
func_rc pkcs11_prepare_wrappingctx(wrappedKeyCtx *wctx, char *wrapjob) {

    func_rc rc = rc_ok;

    if (wctx != NULL && wrapjob != NULL) {
	int parserc;

	/* http://stackoverflow.com/questions/1907847/how-to-use-yy-scan-string-in-lex     */
	/* copy string into new buffer and Switch buffers*/
	YY_BUFFER_STATE yybufstate = yy_scan_string(wrapjob);

	/* parse string */
	parserc = yyparse(wctx);

	if (parserc != 0) {
	    fprintf(stderr, "***Error scanning wrapping job string '%s'\n", wrapjob);
	    rc = rc_error_invalid_argument;
	}

	/*Delete the new buffer*/
	yy_delete_buffer(yybufstate);
    } else {
	rc = rc_error_invalid_parameter_for_method;
    }

    return rc;
}

static func_rc _wrap(wrappedKeyCtx *wctx,
		     wrap_source_method_t wrap_source_method,
		     char *wrappedkeylabel,
		     CK_OBJECT_HANDLE wrappedkeyhandle,
		     CK_OBJECT_HANDLE pubkhandle) {
    func_rc rc = rc_ok;

    /* keyindex: in case of envelope wrapping, the index shall always be the outer */
    int keyindex = wctx->is_envelope ? WRAPPEDKEYCTX_INNER_KEY_INDEX : WRAPPEDKEYCTX_LONE_KEY_INDEX;

    switch (wrap_source_method) {
	case meth_label:
	    wctx->wrappedkeylabel = strdup(wrappedkeylabel);
	    wctx->key[keyindex].wrappedkeyhandle = 0;
	    break;

	case meth_keyhandle:
	    wctx->wrappedkeylabel = NULL;
	    wctx->key[keyindex].wrappedkeyhandle = wrappedkeyhandle;
	    wctx->pubkhandle = pubkhandle;
	    break;

	// future proofing in case somebody later extends wrap_source_method. This code is currently unreachable.
	default:
	    fprintf(stderr, "unsupported wrap source method");
	    rc = rc_error_unsupported;
	    goto err;
    }

    if (wctx->is_envelope) {
	/* envelope wrapping */
	rc = _wrap_envelope(wctx);
    } else {
	switch (wctx->key[keyindex].wrapping_meth) {
	    case w_pkcs1_15:
		/* TODO: check if I can wrap */
		rc = _wrap_pkcs1_15(wctx);
		break;

	    case w_pkcs1_oaep:
		/* TODO: check if I can wrap */
		rc = _wrap_pkcs1_oaep(wctx);
		break;

	    case w_cbcpad:
		rc = _wrap_cbcpad(wctx);
		break;

	    case w_rfc3394:
		rc = _wrap_rfc3394(wctx);
		break;

	    case w_rfc5649:
		rc = _wrap_rfc5649(wctx);
		break;

	    default:
		rc = rc_error_unknown_wrapping_alg;
		fprintf(stderr, "Error: unsupported wrapping algorithm.\n");
	}
    }
    err:

    return rc;
}
