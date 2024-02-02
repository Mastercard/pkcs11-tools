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
#include <time.h>
#include <search.h>
#include <assert.h>
#include <openssl/objects.h>
#include "pkcs11lib.h"

/***********************************************************************/
/* keys can be created either as token keys (permanent),               */
/* or as wrappable keys, in which case they are session keys and have  */
/* CKA_EXTRACTABLE set to true                                         */
/* this is reflected by the key_generation_t argument:                 */
/* - when kg_token, the key is a token key                             */
/* - when kg_session_for_wrapping, it is a session key, for wrapping   */
/***********************************************************************/

static int compare_CKA( const void *a, const void *b)
{
    return ((CK_ATTRIBUTE_PTR)a)->type == ((CK_ATTRIBUTE_PTR)b)->type ? 0 : -1;
}

static CK_BBOOL has_extractable(CK_ATTRIBUTE_PTR template, CK_ULONG template_len)
{
    CK_ATTRIBUTE extractable[] = {
	{ CKA_EXTRACTABLE, NULL, 0L }
    };

    size_t len = (size_t) template_len;

    CK_ATTRIBUTE_PTR match = lfind( &extractable[0],
				    template,
				    &len,
				    sizeof(CK_ATTRIBUTE),
				    compare_CKA );
    return match ? *(CK_BBOOL *)match->pValue : CK_FALSE;
}


func_rc pkcs11_genAES( pkcs11Context * p11ctx,
		       char *label,
		       CK_ULONG bits,
		       CK_ATTRIBUTE attrs[],
		       CK_ULONG numattrs,
		       CK_OBJECT_HANDLE_PTR seckhandleptr,
		       key_generation_t gentype)
{
    func_rc rc = rc_ok;
    CK_RV retcode;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BYTE id[16];
    CK_ULONG bytes;
    CK_MECHANISM mechanism = {
	CKM_AES_KEY_GEN, NULL_PTR, 0
    };

    if(bits != 128 && bits !=256 && bits!=192) {
	fprintf(stderr,"***Error: invalid key length: %d\n", (int)bits);
	rc = rc_error_invalid_parameter_for_method;
	goto error;
    }

    bytes = bits>>3;

    snprintf((char *)id, sizeof id, "aes%d-%ld", (int)bits, time(NULL));

    {
	int i;

	CK_ATTRIBUTE secktemplate[] = {
	    {CKA_TOKEN, gentype == kg_token ? &ck_true : &ck_false, sizeof(CK_BBOOL)},
	    {CKA_PRIVATE, &ck_true, sizeof ck_true},
	    {CKA_VALUE_LEN, &bytes, sizeof(bytes)},
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof ck_false},
	    {CKA_DECRYPT, &ck_false, sizeof ck_false},
	    {CKA_SIGN, &ck_false, sizeof ck_false},
	    {CKA_VERIFY, &ck_false, sizeof ck_false},
	    {CKA_WRAP, &ck_false, sizeof ck_false},
	    {CKA_UNWRAP, &ck_false, sizeof ck_false},
	    {CKA_DERIVE, &ck_false, sizeof ck_false},
	    {CKA_SENSITIVE, &ck_true, sizeof ck_true},
	    {CKA_EXTRACTABLE, gentype != kg_token ? &ck_true : &ck_false, sizeof ck_false},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t template_len_max = (sizeof(secktemplate)/sizeof(CK_ATTRIBUTE));
	size_t template_len_min = template_len_max - 5;
	size_t num_elems = template_len_min;

	for(i=0; i<numattrs && num_elems<template_len_max; i++)
	{
	    /* lsearch will add the keys if not found in the template */

	    CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
					      secktemplate,
					      &num_elems,
					      sizeof(CK_ATTRIBUTE),
					      compare_CKA );

	    /* if we have a match, take the value from the command line */
	    /* we are basically stealing the pointer from attrs array   */
	    if(match && match->ulValueLen == attrs[i].ulValueLen) {
		match->pValue = attrs[i].pValue;
	    }
	}

	retcode = p11ctx->FunctionList.C_GenerateKey(p11ctx->Session,
						     &mechanism,
						     secktemplate, num_elems,
						     seckhandleptr );

	if (retcode != CKR_OK ) {
	    pkcs11_error( retcode, "C_GenerateKey" );
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	/* special case: we want to keep a local copy of the wrapped key */
	if(gentype==kg_token_for_wrapping) {
	    CK_OBJECT_HANDLE copyhandle=0;
	    /* we don't want an extractable key, unless specified as an attribute */
	    /* when invoking the command */
	    CK_BBOOL ck_extractable = has_extractable(attrs, numattrs);

	    CK_ATTRIBUTE tokentemplate[] = {
		{ CKA_TOKEN, &ck_true, sizeof ck_true },
		{ CKA_EXTRACTABLE, &ck_extractable, sizeof ck_extractable }
	    };

	    retcode = p11ctx->FunctionList.C_CopyObject( p11ctx->Session,
							 *seckhandleptr,
							 tokentemplate,
							 sizeof tokentemplate / sizeof(CK_ATTRIBUTE),
							 &copyhandle );
	    if (retcode != CKR_OK ) {
		pkcs11_warning( retcode, "C_CopyObject" );
		fprintf(stderr, "***Warning: could not create a local copy for secret key '%s'. Retry key generation without wrapping, or with '-r' option.\n", label);
	    }
	}
    }
error:
    return rc;
}

func_rc pkcs11_genDESX( pkcs11Context * p11ctx,
			char *label,
			CK_ULONG bits,
			CK_ATTRIBUTE attrs[],
			CK_ULONG numattrs,
			CK_OBJECT_HANDLE_PTR seckhandleptr,
			key_generation_t gentype)
{
    func_rc rc = rc_ok;
    CK_RV retcode;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BYTE id[16];
    CK_MECHANISM mechanism = {
	CKM_DES_KEY_GEN, NULL_PTR, 0
    };

    switch(bits) {

    case 64:
	mechanism.mechanism = CKM_DES_KEY_GEN;
	break;

    case 128:
	mechanism.mechanism = CKM_DES2_KEY_GEN;
	break;

    case 192:
	mechanism.mechanism = CKM_DES3_KEY_GEN;
	break;

    default:
	fprintf(stderr,"***Error: invalid key length: %d\n", (int)bits);
	rc = rc_error_invalid_parameter_for_method;
	goto error;
    }

    snprintf((char *)id, sizeof id, "des%d-%ld", (int)bits, time(NULL));

    {
	int i;

	CK_ATTRIBUTE secktemplate[] = {
	    {CKA_TOKEN, gentype == kg_token ? &ck_true : &ck_false, sizeof(CK_BBOOL)},
	    /* CKA_VALUE_LEN is never specified for DES keys, implicit with key type */
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof ck_false},
	    {CKA_DECRYPT, &ck_false, sizeof ck_false},
	    {CKA_SIGN, &ck_false, sizeof ck_false},
	    {CKA_VERIFY, &ck_false, sizeof ck_false},
	    {CKA_WRAP, &ck_false, sizeof ck_false},
	    {CKA_UNWRAP, &ck_false, sizeof ck_false},
	    {CKA_DERIVE, &ck_false, sizeof ck_false},
	    {CKA_SENSITIVE, &ck_true, sizeof ck_true},
	    {CKA_EXTRACTABLE, gentype != kg_token ? &ck_true : &ck_false, sizeof ck_false},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t template_len_max = (sizeof(secktemplate)/sizeof(CK_ATTRIBUTE));
	size_t template_len_min = template_len_max - 5;
	size_t num_elems = template_len_min;

	for(i=0; i<numattrs && num_elems<template_len_max; i++)
	{
	    /* lsearch will add the keys if not found in the template */

	    CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
					      secktemplate,
					      &num_elems,
					      sizeof(CK_ATTRIBUTE),
					      compare_CKA );

	    /* if we have a match, take the value from the command line */
	    /* we are basically stealing the pointer from attrs array   */
	    if(match && match->ulValueLen == attrs[i].ulValueLen) {
		match->pValue = attrs[i].pValue;
	    }
	}

	retcode = p11ctx->FunctionList.C_GenerateKey(p11ctx->Session,
						     &mechanism,
						     secktemplate, num_elems,
						     seckhandleptr );

	if (retcode != CKR_OK ) {
	  pkcs11_error( retcode, "C_GenerateKey" );
	  rc = rc_error_pkcs11_api;
	  goto error;
	}

	/* special case: we want to keep a local copy of the wrapped key */
	if(gentype==kg_token_for_wrapping) {
	    CK_OBJECT_HANDLE copyhandle=0;
	    /* we don't want an extractable key, unless specified as an attribute */
	    /* when invoking the command */
	    CK_BBOOL ck_extractable = has_extractable(attrs, numattrs);

	    CK_ATTRIBUTE tokentemplate[] = {
		{ CKA_TOKEN, &ck_true, sizeof ck_true },
		{ CKA_EXTRACTABLE, &ck_extractable, sizeof ck_extractable }
	    };

	    retcode = p11ctx->FunctionList.C_CopyObject( p11ctx->Session,
							 *seckhandleptr,
							 tokentemplate,
							 sizeof tokentemplate / sizeof(CK_ATTRIBUTE),
							 &copyhandle );
	    if (retcode != CKR_OK ) {
		pkcs11_warning( retcode, "C_CopyObject" );
		fprintf(stderr, "***Warning: could not create a local copy for secret key '%s'. Retry key generation without wrapping, or with '-r' option.\n", label);
	    }
	}
    }
error:
    return rc;
}

/* Generate Generic/HMAC keys */
/* PKCS#11 standard is somewhat flawed, as it specifies that keys used for HMAC */
/* should be generic keys, which normally support only key derivation mechanism */
/* however, HMAC requires signature/verification */
/* to accomodate this contradiction, each vendor has its specific way: */
/* NSS allows generic keys to perform signature/verification */
/* nCipher has vendor-defined HMAC key generation methods */
/* this routine attempts to accomodate for these two implementations */

func_rc pkcs11_genGeneric( pkcs11Context * p11ctx,
			   char *label,
			   key_type_t kt,
			   CK_ULONG bits,
			   CK_ATTRIBUTE attrs[],
			   CK_ULONG numattrs,
			   CK_OBJECT_HANDLE_PTR seckhandleptr,
			   key_generation_t gentype)
{
    func_rc rc = rc_ok;
    CK_RV retcode;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BYTE id[16];
    CK_ULONG bytes;
    CK_MECHANISM mechanism = {
	0, NULL_PTR, 0
    };

    if(bits <= 56 ) {
	fprintf(stderr,"***Error: insecure generic key length (%d)\n", (int)bits);
	rc = rc_error_insecure;
	goto error;
    }

    if( bits %8 ) {
	fprintf(stderr, "***Warning: requested length (%d) is rounded up to (%d)\n", (int)bits, (int) (((bits>>3)+1)<<3) ) ;
    }

    /* we round up to the next byte boundary.  */
    bytes = (bits>>3) + ( (bits%8) ? 1 : 0 );

    snprintf((char *)id, sizeof id, "gen%d-%ld", (int)bits, time(NULL));

    /* choose key generation algorithm */
    switch(kt) {
    case generic:
	mechanism.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
	break;

#if defined(HAVE_NCIPHER)
    case hmacsha1:		/* nCipher-specific */
	mechanism.mechanism = CKM_NC_SHA_1_HMAC_KEY_GEN;
	break;

    case hmacsha224:
	mechanism.mechanism = CKM_NC_SHA224_HMAC_KEY_GEN;
	break;

    case hmacsha256:
	mechanism.mechanism = CKM_NC_SHA256_HMAC_KEY_GEN;
	break;

    case hmacsha384:
	mechanism.mechanism = CKM_NC_SHA384_HMAC_KEY_GEN;
	break;

    case hmacsha512:
	mechanism.mechanism = CKM_NC_SHA512_HMAC_KEY_GEN;
	break;
#endif

    default:
	fprintf(stderr,"***Error: illegal key generation mechanism specified\n");
	rc = rc_error_invalid_parameter_for_method;
	goto error;
    }

    {
	int i;

	CK_ATTRIBUTE secktemplate[] = {
	    {CKA_TOKEN, gentype == kg_token ? &ck_true : &ck_false, sizeof(CK_BBOOL)},
	    {CKA_VALUE_LEN, &bytes, sizeof(bytes)},

	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof ck_false},
	    {CKA_DECRYPT, &ck_false, sizeof ck_false},
	    {CKA_SIGN, &ck_false, sizeof ck_false},
	    {CKA_VERIFY, &ck_false, sizeof ck_false},
	    {CKA_WRAP, &ck_false, sizeof ck_false},
	    {CKA_UNWRAP, &ck_false, sizeof ck_false},
	    {CKA_DERIVE, &ck_false, sizeof ck_false},
	    {CKA_SENSITIVE, &ck_true, sizeof ck_true},
	    {CKA_EXTRACTABLE, gentype != kg_token ? &ck_true : &ck_false, sizeof ck_false},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t template_len_max = (sizeof(secktemplate)/sizeof(CK_ATTRIBUTE));
	size_t template_len_min = template_len_max - 5;
	size_t num_elems = template_len_min;

	for(i=0; i<numattrs && num_elems<template_len_max; i++)
	{
	    /* lsearch will add the keys if not found in the template */

	    CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
					      secktemplate,
					      &num_elems,
					      sizeof(CK_ATTRIBUTE),
					      compare_CKA );

	    /* if we have a match, take the value from the command line */
	    /* we are basically stealing the pointer from attrs array   */
	    if(match && match->ulValueLen == attrs[i].ulValueLen) {
		match->pValue = attrs[i].pValue;
	    }
	}

	retcode = p11ctx->FunctionList.C_GenerateKey(p11ctx->Session,
						     &mechanism,
						     secktemplate, num_elems,
						     seckhandleptr );

	if (retcode != CKR_OK ) {
	  pkcs11_error( retcode, "C_GenerateKey" );
	  rc = rc_error_pkcs11_api;
	}

	/* special case: we want to keep a local copy of the wrapped key */
	if(gentype==kg_token_for_wrapping) {
	    CK_OBJECT_HANDLE copyhandle=0;
	    /* we don't want an extractable key, unless specified as an attribute */
	    /* when invoking the command */
	    CK_BBOOL ck_extractable = has_extractable(attrs, numattrs);

	    CK_ATTRIBUTE tokentemplate[] = {
		{ CKA_TOKEN, &ck_true, sizeof ck_true },
		{ CKA_EXTRACTABLE, &ck_extractable, sizeof ck_extractable }
	    };

	    retcode = p11ctx->FunctionList.C_CopyObject( p11ctx->Session,
							 *seckhandleptr,
							 tokentemplate,
							 sizeof tokentemplate / sizeof(CK_ATTRIBUTE),
							 &copyhandle );
	    if (retcode != CKR_OK ) {
		pkcs11_warning( retcode, "C_CopyObject" );
		fprintf(stderr, "***Warning: could not create a local copy for secret key '%s'. Retry key generation without wrapping, or with '-r' option.\n", label);
	    }
	}
    }
error:
    return rc;
}


func_rc pkcs11_genRSA( pkcs11Context * p11ctx,
		       char *label,
		       CK_ULONG bits,
		       uint32_t public_exponent,
		       CK_ATTRIBUTE attrs[],
		       CK_ULONG numattrs,
		       CK_OBJECT_HANDLE_PTR pubkhandleptr,
		       CK_OBJECT_HANDLE_PTR prvkhandleptr,
		       key_generation_t gentype)
{
    func_rc rc = rc_ok;
    CK_RV retcode;
    int i;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;
    CK_ULONG modulusBits = bits;
    CK_BYTE publicExponent[3];
	size_t publicExponentLen = 0;

	/* first, find what is the most significant bit of public_exponent */
	/* we need to know how many bytes we need to encode it */

	unsigned long pe = public_exponent;
	int n=0;
	while(pe) {
		pe >>= 8;
		n++;
	}
	if(n>3) {
		fprintf(stderr,"***Error: public exponent too large\n");
		rc = rc_error_invalid_parameter_for_method;
		goto error;
	}

	/* then, encode it, as big-endian */
	for(i=0; i<n; i++) {
		publicExponent[i] = (public_exponent >> (8*(n-i-1))) & 0xff;
	}
	publicExponentLen = n;

	/* now fill pu*/

    CK_MECHANISM mechanism = {
	CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };

    CK_BYTE id[32];
    snprintf((char *)id, sizeof id, "rsa%d-%ld", (int)bits, time(NULL));

    {
	CK_ATTRIBUTE pubktemplate[] = {
	    {CKA_TOKEN, gentype == kg_token ? &ck_true : &ck_false, sizeof(CK_BBOOL)},
	    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
	    {CKA_PUBLIC_EXPONENT, publicExponent, publicExponentLen},

	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof ck_false},
	    {CKA_WRAP, &ck_false, sizeof ck_false},
	    {CKA_VERIFY, &ck_false, sizeof ck_false},
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle CKA_SIGN_RECOVER or CKA_VERIFY_RECOVER */
	    {CKA_VERIFY_RECOVER, &ck_false, sizeof ck_false},
#endif
	    {CKA_DERIVE, &ck_false, sizeof ck_false},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t pubk_template_len_max = (sizeof(pubktemplate)/sizeof(CK_ATTRIBUTE));
	size_t pubk_template_len_min = pubk_template_len_max - 5;
	size_t pubk_num_elems = pubk_template_len_min;


	CK_ATTRIBUTE prvktemplate[] = {
	    {CKA_TOKEN, gentype == kg_token ? &ck_true : &ck_false, sizeof(CK_BBOOL)},
	    {CKA_PRIVATE, &ck_true, sizeof ck_true},
	    {CKA_SENSITIVE, &ck_true, sizeof ck_true},
	    {CKA_EXTRACTABLE, gentype != kg_token ? &ck_true : &ck_false, sizeof ck_false},

	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },

	    {CKA_DECRYPT, &ck_false, sizeof ck_false},
	    {CKA_UNWRAP, &ck_false, sizeof ck_false},
	    {CKA_SIGN, &ck_false, sizeof ck_false},
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle CKA_SIGN_RECOVER or CKA_VERIFY_RECOVER */
	    {CKA_SIGN_RECOVER, &ck_false, sizeof ck_false},
#endif
	    {CKA_DERIVE, &ck_false, sizeof ck_false},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t prvk_template_len_max = (sizeof(prvktemplate)/sizeof(CK_ATTRIBUTE));
	size_t prvk_template_len_min = prvk_template_len_max - 5;
	size_t prvk_num_elems = prvk_template_len_min;

	/* adjust private key */
	/* some attributes are not applicable to private key, so we filter out first */
	for(i=0; i<numattrs && prvk_num_elems<prvk_template_len_max; i++)
	{
	    switch(attrs[i].type) {
	    case CKA_SENSITIVE:
	    case CKA_EXTRACTABLE:
	    case CKA_LABEL:
	    case CKA_ID:
	    case CKA_DECRYPT:
	    case CKA_UNWRAP:
	    case CKA_SIGN:
	    case CKA_SIGN_RECOVER:
	    case CKA_DERIVE:
	    case CKA_TRUSTED:
	    case CKA_MODIFIABLE:
	    case CKA_DERIVE_TEMPLATE:
	    case CKA_UNWRAP_TEMPLATE:
	    case CKA_ALLOWED_MECHANISMS:
	    {
		CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
						  prvktemplate,
						  &prvk_num_elems,
						  sizeof(CK_ATTRIBUTE),
						  compare_CKA );

		/* if we have a match, take the value from the command line */
		/* we are basically stealing the pointer from attrs array   */
		if(match && match->ulValueLen == attrs[i].ulValueLen) {
		    match->pValue = attrs[i].pValue;
		}
	    }
	    break;

	    default:
		/* pass */
		break;
	    }
	}

	/* adjust public key */
	for(i=0; i<numattrs && pubk_num_elems<pubk_template_len_max; i++)
	{

	    switch(attrs[i].type) {
	    case CKA_LABEL:
	    case CKA_ID:
	    case CKA_ENCRYPT:
	    case CKA_WRAP:
	    case CKA_VERIFY:
	    case CKA_VERIFY_RECOVER:
	    case CKA_DERIVE:
	    case CKA_TRUSTED:
	    case CKA_MODIFIABLE:
	    case CKA_WRAP_TEMPLATE:
	    case CKA_DERIVE_TEMPLATE:
	    case CKA_ALLOWED_MECHANISMS:
	    {
		CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
						  pubktemplate,
						  &pubk_num_elems,
						  sizeof(CK_ATTRIBUTE),
						  compare_CKA );

		/* if we have a match, take the value from the command line */
		/* we are basically stealing the pointer from attrs array   */
		if(match && match->ulValueLen == attrs[i].ulValueLen) {
		    match->pValue = attrs[i].pValue;
		}
	    }
	    break;

	    default:
		/* pass */
		break;
	    }
	}

	retcode = p11ctx->FunctionList.C_GenerateKeyPair(p11ctx->Session,
							 &mechanism,
							 pubktemplate, pubk_num_elems,
							 prvktemplate, prvk_num_elems,
							 pubkhandleptr, prvkhandleptr);

	if (retcode != CKR_OK ) {
	    pkcs11_error( retcode, "C_GenerateKeyPair" );
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	/* special case: we want to keep a local copy of the wrapped key */
	if(gentype==kg_token_for_wrapping) {
	    CK_OBJECT_HANDLE copyhandle=0;
	    /* we don't want an extractable key, unless specified as an attribute */
	    /* when invoking the command */
	    CK_BBOOL ck_extractable = has_extractable(attrs, numattrs);

	    CK_ATTRIBUTE tokentemplate[] = {
		{ CKA_TOKEN, &ck_true, sizeof ck_true },
		{ CKA_EXTRACTABLE, &ck_extractable, sizeof ck_extractable }
	    };

	    /* copy the private key first */
	    retcode = p11ctx->FunctionList.C_CopyObject( p11ctx->Session,
							 *prvkhandleptr,
							 tokentemplate,
							 sizeof tokentemplate / sizeof(CK_ATTRIBUTE),
							 &copyhandle );
	    if (retcode != CKR_OK ) {
		pkcs11_warning( retcode, "C_CopyObject" );
		fprintf(stderr, "***Warning: could not create a local copy for private key '%s'. Retry key generation without wrapping, or with '-r' option.\n", label);
	    }

	    /* then the public key */
	    retcode = p11ctx->FunctionList.C_CopyObject( p11ctx->Session,
							 *pubkhandleptr,
							 tokentemplate,
							 1, /* CKA_EXTRACTABLE is for private/secret keys only, so index is limited to CKA_TOKEN */
							 &copyhandle );
	    if (retcode != CKR_OK ) {
		pkcs11_warning( retcode, "C_CopyObject" );
		fprintf(stderr, "***Warning: could not create a local copy for public key '%s'. Retry key generation without wrapping, or with '-r' option.\n", label);
	    }
	}
    }
error:
    return rc;
}


static func_rc pkcs11_genEX( pkcs11Context * p11ctx,
			     key_type_t keytype,
			     char *label,
			     char *param,
			     CK_ATTRIBUTE attrs[],
			     CK_ULONG numattrs,
			     CK_OBJECT_HANDLE_PTR pubkhandleptr,
			     CK_OBJECT_HANDLE_PTR prvkhandleptr,
			     key_generation_t gentype)
{
    func_rc rc = rc_ok;
    CK_RV retcode;
    int i;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;

    CK_BYTE  *ex_param;
    CK_ULONG ex_param_len;

    CK_MECHANISM mechanism = {
	0 , NULL_PTR, 0
    };

    CK_BYTE id[32];

    switch(keytype) {
    case ec:
	mechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
	snprintf((char *)id, sizeof id, "ec-%s-%ld", param, time(NULL));
	break;

    case ed:
	mechanism.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;
	snprintf((char *)id, sizeof id, "ed-%s-%ld", param, time(NULL));
	break;

    default:
	fprintf(stderr, "***Error: unmanaged keytype\n");
	assert(0);
    }

    /* adjust EC parameter */
    if( pkcs11_ex_curvename2oid(param, &ex_param, &ex_param_len, keytype) == false) {
	fprintf(stderr,"***Error: unknown/unsupported %s curve parameter name '%s'\n",
		keytype == ed ? "Edwards" : "elliptic",
		param);
	rc = rc_error_invalid_parameter_for_method;
	goto error;
    }

    {
	CK_ATTRIBUTE pubktemplate[] = {
	    {CKA_TOKEN, gentype == kg_token ? &ck_true : &ck_false, sizeof(CK_BBOOL)},
	    {CKA_EC_PARAMS, ex_param, ex_param_len },
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof ck_false},
	    {CKA_WRAP, &ck_false, sizeof ck_false},
	    {CKA_VERIFY, &ck_false, sizeof ck_false},
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle CKA_SIGN_RECOVER or CKA_VERIFY_RECOVER */
	    {CKA_VERIFY_RECOVER, &ck_false, sizeof ck_false},
#endif
	    {CKA_DERIVE, &ck_false, sizeof ck_false},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t pubk_template_len_max = (sizeof(pubktemplate)/sizeof(CK_ATTRIBUTE));
	size_t pubk_template_len_min = pubk_template_len_max - 5;
	size_t pubk_num_elems = pubk_template_len_min;


	CK_ATTRIBUTE prvktemplate[] = {
	    {CKA_TOKEN, gentype == kg_token ? &ck_true : &ck_false, sizeof ck_true},
	    {CKA_PRIVATE, &ck_true, sizeof ck_true},
	    {CKA_SENSITIVE, &ck_true, sizeof ck_true},
	    {CKA_EXTRACTABLE, gentype != kg_token ? &ck_true : &ck_false, sizeof ck_false},

	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_DECRYPT, &ck_false, sizeof ck_false},
	    {CKA_UNWRAP, &ck_false, sizeof ck_false},
	    {CKA_SIGN, &ck_false, sizeof ck_false},
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle CKA_SIGN_RECOVER or CKA_VERIFY_RECOVER */
	    {CKA_SIGN_RECOVER, &ck_false, sizeof ck_false},
#endif
	    {CKA_DERIVE, &ck_false, sizeof ck_false},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t prvk_template_len_max = (sizeof(prvktemplate)/sizeof(CK_ATTRIBUTE));
	size_t prvk_template_len_min = prvk_template_len_max - 5;
	size_t prvk_num_elems = prvk_template_len_min;

	/* adjust private key */
	/* some attributes are not applicable to private key, so we filter out first */
	for(i=0; i<numattrs && prvk_num_elems<prvk_template_len_max; i++)
	{
	    switch(attrs[i].type) {
	    case CKA_SENSITIVE:
	    case CKA_EXTRACTABLE:
	    case CKA_LABEL:
	    case CKA_ID:
	    case CKA_DECRYPT:
	    case CKA_UNWRAP:
	    case CKA_SIGN:
	    case CKA_SIGN_RECOVER:
	    case CKA_DERIVE:
	    case CKA_TRUSTED:
	    case CKA_MODIFIABLE:
	    case CKA_UNWRAP_TEMPLATE:
	    case CKA_DERIVE_TEMPLATE:
	    case CKA_ALLOWED_MECHANISMS:
	    {
		CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
						  prvktemplate,
						  &prvk_num_elems,
						  sizeof(CK_ATTRIBUTE),
						  compare_CKA );

		/* if we have a match, take the value from the command line */
		/* we are basically stealing the pointer from attrs array   */
		if(match && match->ulValueLen == attrs[i].ulValueLen) {
		    match->pValue = attrs[i].pValue;
		}
	    }
	    break;

	    default:
		/* pass */
		break;
	    }
	}

	/* adjust public key */
	for(i=0; i<numattrs && pubk_num_elems<pubk_template_len_max; i++)
	{

	    switch(attrs[i].type) {
	    case CKA_LABEL:
	    case CKA_ID:
	    case CKA_ENCRYPT:
	    case CKA_WRAP:
	    case CKA_VERIFY:
	    case CKA_VERIFY_RECOVER:
	    case CKA_DERIVE:
	    case CKA_TRUSTED:
	    case CKA_MODIFIABLE:
	    case CKA_WRAP_TEMPLATE:
	    case CKA_DERIVE_TEMPLATE:
	    case CKA_ALLOWED_MECHANISMS:
	    {
		CK_ATTRIBUTE_PTR match = lsearch( &attrs[i],
						  pubktemplate,
						  &pubk_num_elems,
						  sizeof(CK_ATTRIBUTE),
						  compare_CKA );

		/* if we have a match, take the value from the command line */
		/* we are basically stealing the pointer from attrs array   */
		if(match && match->ulValueLen == attrs[i].ulValueLen) {
		    match->pValue = attrs[i].pValue;
		}
	    }
	    break;

	    default:
		/* pass */
		break;
	    }
	}

	retcode = p11ctx->FunctionList.C_GenerateKeyPair(p11ctx->Session,
							 &mechanism,
							 pubktemplate, pubk_num_elems,
							 prvktemplate, prvk_num_elems,
							 pubkhandleptr, prvkhandleptr);

	if (retcode != CKR_OK ) {
	  pkcs11_error( retcode, "C_GenerateKeyPair" );
	  rc = rc_error_pkcs11_api;
	  goto error;
	}

	/* special case: we want to keep a local copy of the wrapped key */
	if(gentype==kg_token_for_wrapping) {
	    CK_OBJECT_HANDLE copyhandle=0;
	    /* we don't want an extractable key, unless specified as an attribute */
	    /* when invoking the command */
	    CK_BBOOL ck_extractable = has_extractable(attrs, numattrs);

	    CK_ATTRIBUTE tokentemplate[] = {
		{ CKA_TOKEN, &ck_true, sizeof ck_true },
		{ CKA_EXTRACTABLE, &ck_extractable, sizeof ck_extractable }
	    };

	    /* copy the private key first */
	    retcode = p11ctx->FunctionList.C_CopyObject( p11ctx->Session,
							 *prvkhandleptr,
							 tokentemplate,
							 sizeof tokentemplate / sizeof(CK_ATTRIBUTE),
							 &copyhandle );
	    if (retcode != CKR_OK ) {
		pkcs11_warning( retcode, "C_CopyObject" );
		fprintf(stderr, "***Warning: could not create a local copy for private key '%s'. Retry key generation without wrapping, or with '-r' option.\n", label);
	    }

	    /* then the public key */
	    retcode = p11ctx->FunctionList.C_CopyObject( p11ctx->Session,
							 *pubkhandleptr,
							 tokentemplate,
							 1, /* CKA_EXTRACTABLE is for private/secret keys only, so index is limited to CKA_TOKEN */
							 &copyhandle );
	    if (retcode != CKR_OK ) {
		pkcs11_warning( retcode, "C_CopyObject" );
		fprintf(stderr, "***Warning: could not create a local copy for public key '%s'. Retry key generation without wrapping, or with '-r' option.\n", label);
	    }
	}
    }

error:
    if(ex_param) { pkcs11_ec_freeoid(ex_param); }

    return rc;
}

inline func_rc pkcs11_genEC( pkcs11Context * p11ctx,
			     char *label,
			     char *param,
			     CK_ATTRIBUTE attrs[],
			     CK_ULONG numattrs,
			     CK_OBJECT_HANDLE_PTR pubkhandleptr,
			     CK_OBJECT_HANDLE_PTR prvkhandleptr,
			     key_generation_t gentype) {
    return pkcs11_genEX(p11ctx, ec, label, param, attrs, numattrs, pubkhandleptr, prvkhandleptr, gentype);
}


inline func_rc pkcs11_genED( pkcs11Context * p11ctx,
			     char *label,
			     char *param,
			     CK_ATTRIBUTE attrs[],
			     CK_ULONG numattrs,
			     CK_OBJECT_HANDLE_PTR pubkhandleptr,
			     CK_OBJECT_HANDLE_PTR prvkhandleptr,
			     key_generation_t gentype) {
    return pkcs11_genEX(p11ctx, ed, label, param, attrs, numattrs, pubkhandleptr, prvkhandleptr, gentype);
}




int pkcs11_testgenEC_support( pkcs11Context * p11ctx, const char *param)
{

    CK_RV retcode;
    int rc=0;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;

    CK_BYTE  *ec_param;
    CK_ULONG ec_param_len;

    CK_MECHANISM mechanism = {
	CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0
    };

    CK_OBJECT_HANDLE pubkhandle;
    CK_OBJECT_HANDLE prvkhandle;


    char id[32];
    char * label = id;
    snprintf((char *)id, sizeof id, "testecdsa-%ld", time(NULL));


    /* adjust EC parameter */
    if( pkcs11_ec_curvename2oid((char *)param, &ec_param, &ec_param_len) == false ) {
//	fprintf(stderr,"***Error: unknown/unsupported elliptic curve parameter name '%s'\n", param);
	goto cleanup;
    }

    {
	CK_ATTRIBUTE pubktemplate[] = {
	    {CKA_TOKEN, &ck_false, sizeof ck_false},
	    {CKA_EC_PARAMS, ec_param, ec_param_len },
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof ck_false},
	    {CKA_WRAP, &ck_false, sizeof ck_false},
	    {CKA_VERIFY, &ck_true, sizeof ck_false},
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle CKA_SIGN_RECOVER or CKA_VERIFY_RECOVER */
	    {CKA_VERIFY_RECOVER, &ck_false, sizeof ck_false},
#endif
	    {CKA_DERIVE, &ck_false, sizeof ck_false},
	};

	CK_ATTRIBUTE prvktemplate[] = {
	    {CKA_TOKEN, &ck_false, sizeof ck_false},
	    {CKA_PRIVATE, &ck_true, sizeof ck_true},
	    {CKA_SENSITIVE, &ck_true, sizeof ck_true},
	    {CKA_EXTRACTABLE, &ck_false, sizeof ck_false},

	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_DECRYPT, &ck_false, sizeof ck_false},
	    {CKA_UNWRAP, &ck_false, sizeof ck_false},
	    {CKA_SIGN, &ck_true, sizeof ck_false},
#if !defined(HAVE_AWSCLOUDHSM)	/* AWS CloudHSM cannot handle CKA_SIGN_RECOVER or CKA_VERIFY_RECOVER */
	    {CKA_SIGN_RECOVER, &ck_false, sizeof ck_false},
#endif
	    {CKA_DERIVE, &ck_false, sizeof ck_false},
	};

	retcode = p11ctx->FunctionList.C_GenerateKeyPair(p11ctx->Session,
							 &mechanism,
							 pubktemplate, sizeof(pubktemplate)/sizeof(CK_ATTRIBUTE),
							 prvktemplate, sizeof(prvktemplate)/sizeof(CK_ATTRIBUTE),
							 &pubkhandle, &prvkhandle);

	/* not nice, because we *guess* param is not supported only if CKR_DOMAIN_PARAMS_INVALID is returned */
	/* may vary amongst lib implementations... */
	if (retcode != CKR_DOMAIN_PARAMS_INVALID)  {
	    rc = 1;
	}
    }

cleanup:
    if(ec_param) { pkcs11_ec_freeoid(ec_param); }

    return rc;
}

