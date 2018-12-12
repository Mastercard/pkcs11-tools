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
#include "pkcs11lib.h"


/***********************************************************************/

static int compare_CKA( const void *a, const void *b)
{
    return ((CK_ATTRIBUTE_PTR)a)->type == ((CK_ATTRIBUTE_PTR)b)->type ? 0 : -1;
}

int pkcs11_genAES( pkcs11Context * p11Context, 
		   char *label, 
		   CK_ULONG bits,
		   CK_ATTRIBUTE attrs[],
		   CK_ULONG numattrs,
		   CK_OBJECT_HANDLE_PTR hSecretKey)
{
    
    CK_RV retCode;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BYTE id[16];
    CK_ULONG bytes;
    CK_MECHANISM mechanism = {
	CKM_AES_KEY_GEN, NULL_PTR, 0
    };

    if(bits != 128 && bits !=256 && bits!=192) {
	fprintf(stderr,"unsupported key length: %d\n", (int)bits);
	return 0;
    } else {
	bytes = bits>>3;
    }

    snprintf((char *)id, sizeof id, "aes%d-%ld", (int)bits, time(NULL));

    {
	int i;

	CK_ATTRIBUTE secretKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
	    {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
	    {CKA_VALUE_LEN, &bytes, sizeof(bytes)},
	    
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_DECRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_SIGN, &ck_false, sizeof(ck_false)},
	    {CKA_VERIFY, &ck_false, sizeof(ck_false)},
	    {CKA_WRAP, &ck_false, sizeof(ck_false)},
	    {CKA_UNWRAP, &ck_false, sizeof(ck_false)},
	    {CKA_DERIVE, &ck_false, sizeof(ck_false)},
	    {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
	    {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t template_len_max = (sizeof(secretKeyTemplate)/sizeof(CK_ATTRIBUTE));
	size_t template_len_min = template_len_max - 5;
	size_t num_elems = template_len_min;

	for(i=0; i<numattrs && num_elems<template_len_max; i++)
	{
	    /* lsearch will add the keys if not found in the template */

	    CK_ATTRIBUTE_PTR match = lsearch( &attrs[i], 
					      secretKeyTemplate, 
					      &num_elems,
					      sizeof(CK_ATTRIBUTE),
					      compare_CKA );

	    /* if we have a match, take the value from the command line */
	    /* we are basically stealing the pointer from attrs array   */
	    if(match && match->ulValueLen == attrs[i].ulValueLen) { 
		match->pValue = attrs[i].pValue;
	    }
	}

	CK_C_GenerateKey pC_GenerateKey = p11Context->FunctionList.C_GenerateKey;

	retCode = pC_GenerateKey(p11Context->Session, 
				 &mechanism,
				 secretKeyTemplate, num_elems,
				 hSecretKey );
	
	if (retCode != CKR_OK ) {
	    pkcs11_error( retCode, "C_GenerateKey" );
	    return 0;
	}
    }
    
    return 1;
}



int pkcs11_genDESX( pkcs11Context * p11Context, 
		    char *label, 
		    CK_ULONG bits,
		    CK_ATTRIBUTE attrs[],
		    CK_ULONG numattrs,
		    CK_OBJECT_HANDLE_PTR hSecretKey)
{
    
    CK_RV retCode;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BYTE id[16];
    CK_ULONG bytes;
    CK_MECHANISM mechanism = {
	CKM_DES_KEY_GEN, NULL_PTR, 0
    };

    if(bits != 64 && bits !=128 && bits != 192) {
	fprintf(stderr,"unsupported key length: %d\n", (int)bits);
	return 0;
    } else {
	bytes = bits>>3;
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
	}
    }

    snprintf((char *)id, sizeof id, "des%d-%ld", (int)bits, time(NULL));

    {
	int i;

	CK_ATTRIBUTE secretKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
/*	    {CKA_VALUE_LEN, &bytes, sizeof(bytes)}, */ // implicit with DES2/DES3
	    
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_DECRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_SIGN, &ck_false, sizeof(ck_false)},
	    {CKA_VERIFY, &ck_false, sizeof(ck_false)},
	    {CKA_WRAP, &ck_false, sizeof(ck_false)},
	    {CKA_UNWRAP, &ck_false, sizeof(ck_false)},
	    {CKA_DERIVE, &ck_false, sizeof(ck_false)},
	    {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
	    {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t template_len_max = (sizeof(secretKeyTemplate)/sizeof(CK_ATTRIBUTE));
	size_t template_len_min = template_len_max - 5;
	size_t num_elems = template_len_min;

	for(i=0; i<numattrs && num_elems<template_len_max; i++)
	{
	    /* lsearch will add the keys if not found in the template */

	    CK_ATTRIBUTE_PTR match = lsearch( &attrs[i], 
					      secretKeyTemplate, 
					      &num_elems,
					      sizeof(CK_ATTRIBUTE),
					      compare_CKA );

	    /* if we have a match, take the value from the command line */
	    /* we are basically stealing the pointer from attrs array   */
	    if(match && match->ulValueLen == attrs[i].ulValueLen) { 
		match->pValue = attrs[i].pValue;
	    }
	}

	CK_C_GenerateKey pC_GenerateKey = p11Context->FunctionList.C_GenerateKey;

	retCode = pC_GenerateKey(p11Context->Session, 
				 &mechanism,
				 secretKeyTemplate, num_elems,
				 hSecretKey );

	if (retCode != CKR_OK ) {
	  pkcs11_error( retCode, "C_GenerateKey" );
	  return 0;
	}
    }
    
    return 1;
}

/* Generate Generic/HMAC keys */
/* PKCS#11 standard is somewhat flawed, as it specifies that keys used for HMAC */
/* should be generic keys, which normally support only key derivation mechanism */
/* however, HMAC requires signature/verification */
/* to accomodate this contradiction, each vendor has its specific way: */
/* NSS allows generic keys to perform signature/verification */
/* nCipher has vendor-defined HMAC key generation methods */
/* this routine attempts to accomodate for these two implementations */

int pkcs11_genGeneric( pkcs11Context * p11Context, 
		       char *label, 
		       enum keytype kt,
		       CK_ULONG bits,
		       CK_ATTRIBUTE attrs[],
		       CK_ULONG numattrs,
		       CK_OBJECT_HANDLE_PTR hSecretKey)
{
    
    CK_RV retCode;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BYTE id[16];
    CK_ULONG bytes;
    CK_MECHANISM mechanism = {
	0, NULL_PTR, 0
    };

    if(bits <= 56 ) {
	fprintf(stderr,"***Error:: insecure generic key length (%d)\n", (int)bits);
	return 0;
    }

    if( bits %8 ) {
	fprintf(stderr, "***Warning:: requested length (%d) is rounded up to (%d)\n", (int)bits, (int) (((bits>>3)+1)<<3) ) ;
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
	fprintf(stderr,"***Error:: illegal key generation mechanism specified\n");
	return 0;
	
    }

    {
	int i;

	CK_ATTRIBUTE secretKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
	    {CKA_VALUE_LEN, &bytes, sizeof(bytes)}, 
	    
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_DECRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_SIGN, &ck_false, sizeof(ck_false)},
	    {CKA_VERIFY, &ck_false, sizeof(ck_false)},
	    {CKA_WRAP, &ck_false, sizeof(ck_false)},
	    {CKA_UNWRAP, &ck_false, sizeof(ck_false)},
	    {CKA_DERIVE, &ck_false, sizeof(ck_false)},
	    {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
	    {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t template_len_max = (sizeof(secretKeyTemplate)/sizeof(CK_ATTRIBUTE));
	size_t template_len_min = template_len_max - 5;
	size_t num_elems = template_len_min;

	for(i=0; i<numattrs && num_elems<template_len_max; i++)
	{
	    /* lsearch will add the keys if not found in the template */

	    CK_ATTRIBUTE_PTR match = lsearch( &attrs[i], 
					      secretKeyTemplate, 
					      &num_elems,
					      sizeof(CK_ATTRIBUTE),
					      compare_CKA );

	    /* if we have a match, take the value from the command line */
	    /* we are basically stealing the pointer from attrs array   */
	    if(match && match->ulValueLen == attrs[i].ulValueLen) { 
		match->pValue = attrs[i].pValue;
	    }
	}

	CK_C_GenerateKey pC_GenerateKey = p11Context->FunctionList.C_GenerateKey;

	retCode = pC_GenerateKey(p11Context->Session, 
				 &mechanism,
				 secretKeyTemplate, num_elems,
				 hSecretKey );

	if (retCode != CKR_OK ) {
	  pkcs11_error( retCode, "C_GenerateKey" );
	  return 0;
	}
    }
    
    return 1;
}


int pkcs11_genRSA( pkcs11Context * p11Context, 
		   char *label, 
		   CK_ULONG bits, 
		   CK_ATTRIBUTE attrs[],
		   CK_ULONG numattrs,
		   CK_OBJECT_HANDLE_PTR hPublicKey, 
		   CK_OBJECT_HANDLE_PTR hPrivateKey)
{
    
    CK_RV retCode;
    int i;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;
    CK_ULONG modulusBits = bits;
    CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01  };

    CK_MECHANISM mechanism = {
	CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };

    CK_BYTE id[32];
    snprintf((char *)id, sizeof id, "rsa%d-%ld", (int)bits, time(NULL));
    
    {
	CK_ATTRIBUTE publicKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
	    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
	    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof (publicExponent)},
	    
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_WRAP, &ck_false, sizeof(ck_false)},
	    {CKA_VERIFY, &ck_false, sizeof(ck_false)},
	    {CKA_VERIFY_RECOVER, &ck_false, sizeof(ck_false)},
	    {CKA_DERIVE, &ck_false, sizeof(ck_false)},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t pubk_template_len_max = (sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE));
	size_t pubk_template_len_min = pubk_template_len_max - 5;
	size_t pubk_num_elems = pubk_template_len_min;


	CK_ATTRIBUTE privateKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
	    {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
	    {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
	    {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
	    
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    
	    {CKA_DECRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_UNWRAP, &ck_false, sizeof(ck_false)},
	    {CKA_SIGN, &ck_false, sizeof(ck_false)},
	    {CKA_SIGN_RECOVER, &ck_false, sizeof(ck_false)},
	    {CKA_DERIVE, &ck_false, sizeof(ck_false)},
	    /* leave room for up to 5 additional attributes */
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	    {0L, NULL, 0L},
	};

	size_t prvk_template_len_max = (sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE));
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
	    {
		CK_ATTRIBUTE_PTR match = lsearch( &attrs[i], 
						  privateKeyTemplate, 
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
	    {
		CK_ATTRIBUTE_PTR match = lsearch( &attrs[i], 
						  publicKeyTemplate, 
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

	CK_C_GenerateKeyPair pC_GenerateKeyPair = p11Context->FunctionList.C_GenerateKeyPair;

	retCode = pC_GenerateKeyPair(p11Context->Session, 
				     &mechanism,
				     publicKeyTemplate, pubk_num_elems,
				     privateKeyTemplate, prvk_num_elems,
				     hPublicKey, hPrivateKey);

	if (retCode != CKR_OK ) {
	  pkcs11_error( retCode, "C_GenerateKeyPair" );
	  return 0;
	}
    }
    
    return 1;
}


int pkcs11_genECDSA( pkcs11Context * p11Context, 
		     char *label, 
		     char *param, 
		     CK_ATTRIBUTE attrs[],
		     CK_ULONG numattrs,
		     CK_OBJECT_HANDLE_PTR hPublicKey, 
		     CK_OBJECT_HANDLE_PTR hPrivateKey)
{
    
    CK_RV retCode;
    int i, rc=0;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;

    CK_BYTE  *ec_param;
    CK_ULONG ec_param_len;

    CK_MECHANISM mechanism = {
	CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0
    };

    CK_BYTE id[32];
    snprintf((char *)id, sizeof id, "ecdsa-%s-%ld", param, time(NULL));


    /* adjust EC parameter */
    if( pkcs11_ec_curvename2oid(param, &ec_param, &ec_param_len) == CK_FALSE ) {
	fprintf(stderr,"***Error: unknown/unsupported elliptic curve parameter name '%s'\n", param);
	goto cleanup;
    }
    
    {
	CK_ATTRIBUTE publicKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
	    {CKA_EC_PARAMS, ec_param, ec_param_len },
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_WRAP, &ck_false, sizeof(ck_false)},
	    {CKA_VERIFY, &ck_false, sizeof(ck_false)},
	    {CKA_VERIFY_RECOVER, &ck_false, sizeof(ck_false)},
	    {CKA_DERIVE, &ck_false, sizeof(ck_false)},
	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
	    {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
	    {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
	    {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
	    
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },	    
	    /* what can we do with this key */
	    {CKA_DECRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_UNWRAP, &ck_false, sizeof(ck_false)},
	    {CKA_SIGN, &ck_false, sizeof(ck_false)},
	    {CKA_SIGN_RECOVER, &ck_false, sizeof(ck_false)},
	    {CKA_DERIVE, &ck_false, sizeof(ck_false)},
	};

	   
	/* adjust private key */
	for(i=0; i<numattrs; i++)
	{
	    size_t num_elems = sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE);

	    CK_ATTRIBUTE_PTR match = lfind( &attrs[i], 
					    privateKeyTemplate, 
					    &num_elems,
					    sizeof(CK_ATTRIBUTE),
					    compare_CKA );
	    
	    /* if we have a match, take the value from the command line */
	    /* we are basically stealing the pointer from attrs array   */
	    if(match && match->ulValueLen == attrs[i].ulValueLen) { 
		match->pValue = attrs[i].pValue;
	    }
	}

	/* adjust public key */
	for(i=0; i<numattrs; i++)
	{
	    size_t num_elems = sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE);

	    CK_ATTRIBUTE_PTR match = lfind( &attrs[i], 
					    publicKeyTemplate, 
					    &num_elems,
					    sizeof(CK_ATTRIBUTE),
					    compare_CKA );
	    
	    /* if we have a match, take the value from the command line */
	    /* we are basically stealing the pointer from attrs array   */
	    if(match && match->ulValueLen == attrs[i].ulValueLen) { 
		match->pValue = attrs[i].pValue;
	    }
	}

	CK_C_GenerateKeyPair pC_GenerateKeyPair = p11Context->FunctionList.C_GenerateKeyPair;

	retCode = pC_GenerateKeyPair(p11Context->Session, 
				     &mechanism,
				     publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
				     privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
				     hPublicKey, hPrivateKey);

	if (retCode != CKR_OK ) {
	  pkcs11_error( retCode, "C_GenerateKeyPair" );
	} else {
	    rc = 1;
	}
    }

cleanup:
    if(ec_param) { pkcs11_ec_freeoid(ec_param); }

    return rc;
}


int pkcs11_testgenECDSA_support( pkcs11Context * p11Context, const char *param)
{
    
    CK_RV retCode;
    int i, rc=0;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;

    CK_BYTE  *ec_param;
    CK_ULONG ec_param_len;

    CK_MECHANISM mechanism = {
	CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0
    };

    CK_OBJECT_HANDLE hPublicKey;
    CK_OBJECT_HANDLE hPrivateKey;


    char id[32];
    char * label = id;
    snprintf((char *)id, sizeof id, "testecdsa-%ld", time(NULL));


    /* adjust EC parameter */
    if( pkcs11_ec_curvename2oid((char *)param, &ec_param, &ec_param_len) == CK_FALSE ) {
//	fprintf(stderr,"***Error: unknown/unsupported elliptic curve parameter name '%s'\n", param);
	goto cleanup;
    }
    
    {
	CK_ATTRIBUTE publicKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
	    {CKA_EC_PARAMS, ec_param, ec_param_len },
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    /* what can we do with this key */
	    {CKA_ENCRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_WRAP, &ck_false, sizeof(ck_false)},
	    {CKA_VERIFY, &ck_true, sizeof(ck_false)},
	    {CKA_VERIFY_RECOVER, &ck_false, sizeof(ck_false)},
	    {CKA_DERIVE, &ck_false, sizeof(ck_false)},
	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
	    {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
	    {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
	    {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
	    
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },	    
	    /* what can we do with this key */
	    {CKA_DECRYPT, &ck_false, sizeof(ck_false)},
	    {CKA_UNWRAP, &ck_false, sizeof(ck_false)},
	    {CKA_SIGN, &ck_true, sizeof(ck_false)},
	    {CKA_SIGN_RECOVER, &ck_false, sizeof(ck_false)},
	    {CKA_DERIVE, &ck_false, sizeof(ck_false)},
	};

	
	CK_C_GenerateKeyPair pC_GenerateKeyPair = p11Context->FunctionList.C_GenerateKeyPair;

	retCode = pC_GenerateKeyPair(p11Context->Session, 
				     &mechanism,
				     publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
				     privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
				     &hPublicKey, &hPrivateKey);

	/* not nice, because we *guess* param is not supported only if CKR_DOMAIN_PARAMS_INVALID is returned */
	/* may vary amongst lib implementations... */
	if (retCode != CKR_DOMAIN_PARAMS_INVALID)  {
	    rc = 1;
	}
    }

cleanup:
    if(ec_param) { pkcs11_ec_freeoid(ec_param); }

    return rc;
}

