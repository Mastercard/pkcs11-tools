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


typedef struct s_p11_keycomp {
    pkcs11Context *p11Context;
    CK_OBJECT_HANDLE unwrappingkey;
    CK_OBJECT_HANDLE sessionkey;
    char *targetlabel;
    RSA *rsa;
    int cnt;
    CK_C_UnwrapKey C_UnwrapKey;
    CK_C_DeriveKey C_DeriveKey;
    CK_C_CopyObject C_CopyObject;
    int wrappedkeylen;
} _KeyImportCtx;


KeyImportCtx *pkcs11_import_component_init(pkcs11Context *p11Context, char *unwrappinglabel, char *targetlabel)
{

    _KeyImportCtx *kctx = NULL;
    CK_OBJECT_HANDLE hPublicKey=NULL_PTR; 
    CK_OBJECT_HANDLE hPrivateKey=NULL_PTR;
    int fkp_rc;
    pkcs11AttrList *attrs = NULL;
    CK_ATTRIBUTE_PTR omod, oexp;

    RSA *rsa = NULL;
    BIGNUM *bn_modulus = NULL;
    BIGNUM *bn_exponent = NULL;

    /* make openssl public key from PKCS#11 private or public key label */

    if(pkcs11_secretkey_exists(p11Context, targetlabel)) {
#ifdef HAVE_DUPLICATES_ENABLED
		if(p11Context->can_duplicate) {
			fprintf(stdout,"Error: secret key with label '%s' already exists, duplicating.\n", targetlabel);
		}
		else {
#endif
	fprintf(stderr,"Error: secret key with label '%s' already exists\n", targetlabel);
	goto error;
#ifdef HAVE_DUPLICATES_ENABLED
		}
#endif
    }

    fkp_rc = pkcs11_findkeypair(p11Context, unwrappinglabel, &hPublicKey, &hPrivateKey);
    
    if (fkp_rc==0) {
	fprintf(stderr,"Error: could not find a private key with label '%s'\n", unwrappinglabel);
	goto error;
    }

    attrs = pkcs11_new_attrlist(p11Context, 
				_ATTR(CKA_MODULUS), /* on pubk/privk */
				_ATTR(CKA_PUBLIC_EXPONENT), /* on pubk/privk */
				_ATTR_END );
    
    if( pkcs11_read_attr_from_handle (attrs, fkp_rc==1 ? hPrivateKey : hPublicKey) == false) {
	fprintf(stderr,"Error: could not find a public or private key with label '%s'\n", unwrappinglabel);
	goto error;
    } 

    omod = pkcs11_get_attr_in_attrlist(attrs, CKA_MODULUS);
    oexp = pkcs11_get_attr_in_attrlist(attrs, CKA_PUBLIC_EXPONENT);

    
    /* 1. first we take care of the public key information */
    if ( (bn_modulus = BN_bin2bn(omod->pValue, omod->ulValueLen, NULL)) == NULL ) {
	goto error;
    }

    if ( (bn_exponent = BN_bin2bn(oexp->pValue, oexp->ulValueLen, NULL)) == NULL ) {
	goto error;
    }

    if( (rsa=RSA_new()) == NULL ) {
	goto error;
    }
    RSA_set0_key(rsa, bn_modulus, bn_exponent, NULL);
    bn_modulus = NULL; /* forget, moved to rsa */
    bn_exponent = NULL; /* forget, moved to rsa */

    /* allocate structure */
    kctx = calloc(1, sizeof(_KeyImportCtx));
    
    if(kctx == NULL) {
	fprintf(stderr, "Memory error\n");
	goto error;
    }

    kctx->p11Context = p11Context;
    kctx->rsa = rsa; rsa = NULL;
    kctx->cnt = 0;
    kctx->unwrappingkey = hPrivateKey;
    kctx->targetlabel = targetlabel;

    kctx->C_UnwrapKey  = p11Context->FunctionList.C_UnwrapKey;
    kctx->C_DeriveKey  = p11Context->FunctionList.C_DeriveKey;
    kctx->C_CopyObject  = p11Context->FunctionList.C_CopyObject;
    

    /* keep it for future use */

error:
    if(bn_modulus != NULL) { BN_free(bn_modulus); bn_modulus=NULL; }
    if(bn_exponent != NULL) { BN_free(bn_exponent); bn_exponent=NULL; }
    if(rsa!=NULL) { RSA_free(rsa); rsa=NULL; }
    pkcs11_delete_attrlist(attrs);

    return (KeyImportCtx)kctx;
}

func_rc pkcs11_import_component(KeyImportCtx *kctx, unsigned char * comp, size_t len)
{
    func_rc rc = rc_ok;
    unsigned char * pkcs1 = NULL;
    size_t pkcs1_len = 0L;

    _KeyImportCtx *_kctx = (_KeyImportCtx *)kctx;

    /* if first component: */

    if(_kctx->cnt==0) {

	/* because the key that will be unwrapped might be checked for parity */
	/* we need first to adjust it before injection */
	pkcs11_adjust_des_key_parity(comp, len);

	/* encrypt component with openssl using PKCS#1 1.5 as DATA */
	/* unwrap as session key with PKCS#11 token using CKM_RSA_PKCS */

	if(!(len<RSA_size(_kctx->rsa)-11)) {
	    fprintf(stderr,"RSA key too short to wrap %d bytes of component\n", (int)len);
	    rc = rc_error_wrapping_key_too_short;
	    goto error;
	}
	
	pkcs1_len = RSA_size(_kctx->rsa);
	pkcs1 = calloc(pkcs1_len, sizeof(unsigned char));
	
	if (pkcs1==NULL) {
	    fprintf(stderr,"memory error\n");
	    rc = rc_error_memory;
	    goto error;
	}

	if(RSA_public_encrypt(len, comp, pkcs1, _kctx->rsa, RSA_PKCS1_PADDING) == -1) {
	    P_ERR();
	    rc = rc_error_openssl_api;
	    goto error;
	}
	
	/* now load it into PKCS#11 token */

	{
	    CK_RV rv;
	    CK_BBOOL ck_false = CK_FALSE;
	    CK_BBOOL ck_true = CK_TRUE;
	    CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };/* PKCS #1 1.5 unwrap */
	    CK_OBJECT_CLASS keyclass = CKO_SECRET_KEY;
	    CK_KEY_TYPE keytype = CKK_DES2;
	    CK_ATTRIBUTE attrs[] = {
		{CKA_CLASS, &keyclass, sizeof(keyclass)},
		{CKA_KEY_TYPE, &keytype, sizeof(keytype)},

		{CKA_TOKEN, &ck_false, sizeof(ck_false)}, /* we want a session key */
		{CKA_DERIVE, &ck_true, sizeof(ck_true)},		
	    };


	    rv = _kctx->C_UnwrapKey ( _kctx->p11Context->Session,
				      &mechanism,
				      _kctx->unwrappingkey,
				      pkcs1,
				      pkcs1_len,
				      attrs,
				      sizeof (attrs) / sizeof(CK_ATTRIBUTE),
				      &_kctx->sessionkey  );
	    
	    if(rv!=CKR_OK) {
		pkcs11_error(rv, "C_UnwrapKey");
		rc = rc_error_pkcs11_api;
		goto error;
	    }
	    ++_kctx->cnt;
	    _kctx->wrappedkeylen = len;
	}
    } else {
    /* else: */
    /* derive new key using CKM_XOR_BASE_AND_DATA mechanism */
    /* keep reference to new handle */

	CK_KEY_DERIVATION_STRING_DATA derivation_data = { comp, len } ;
	
	CK_RV rv;
	CK_BBOOL ck_false = CK_FALSE;
	CK_BBOOL ck_true = CK_TRUE;
	CK_OBJECT_HANDLE newkey;
	CK_MECHANISM mechanism = { CKM_XOR_BASE_AND_DATA, &derivation_data, sizeof derivation_data };
	CK_OBJECT_CLASS keyclass = CKO_SECRET_KEY;
	CK_KEY_TYPE keytype = CKK_DES2;
	CK_ATTRIBUTE attrs[] = {
	    {CKA_CLASS, &keyclass, sizeof(keyclass)},
	    {CKA_KEY_TYPE, &keytype, sizeof(keytype)},
	    
	    {CKA_TOKEN, &ck_false, sizeof(ck_false)}, /* we want a session key */
	    {CKA_DERIVE, &ck_true, sizeof(ck_true)},
	};
	
	
	rv = _kctx->C_DeriveKey ( _kctx->p11Context->Session,
				  &mechanism,
				  _kctx->sessionkey,
				  attrs,
				  sizeof (attrs) / sizeof(CK_ATTRIBUTE),
				  &newkey  );
	
	
	if(rv!=CKR_OK) {
	    pkcs11_error(rv, "C_DeriveKey");
	    rc = rc_error_pkcs11_api;
	    goto error;
	}
		
	_kctx->sessionkey = newkey;
	++_kctx->cnt;
    }

error:

    if(pkcs1) { free(pkcs1); }
    return rc;
}

CK_OBJECT_HANDLE pkcs11_import_component_final(KeyImportCtx *kctx)
{
    /* copy key object to token */
    /* compute KCV */
    /* free structure */

    CK_OBJECT_HANDLE unwrappedkey = NULL_PTR;

    _KeyImportCtx *_kctx = (_KeyImportCtx *)kctx;

    if(_kctx->cnt>0) {

	CK_BYTE_PTR comp;
	CK_KEY_DERIVATION_STRING_DATA derivation_data = { NULL_PTR, 0L } ;
    
	CK_RV rv;
	CK_BBOOL ck_false = CK_FALSE;
	CK_BBOOL ck_true = CK_TRUE;
	CK_OBJECT_HANDLE newkey;
	CK_MECHANISM mechanism = { CKM_XOR_BASE_AND_DATA, &derivation_data, sizeof derivation_data };
	CK_OBJECT_CLASS keyclass = CKO_SECRET_KEY;
	CK_KEY_TYPE keytype = CKK_DES2;
	CK_ATTRIBUTE attrs[] = {
	    {CKA_CLASS, &keyclass, sizeof(keyclass)},
	    {CKA_KEY_TYPE, &keytype, sizeof(keytype)},
	    
	    {CKA_TOKEN, &ck_false, sizeof(ck_false)}, /* we want a session key */
	    {CKA_DERIVE, &ck_true, sizeof(ck_true)},
	    {CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
	    {CKA_DECRYPT, &ck_true, sizeof(ck_true)},
	    {CKA_SIGN, &ck_true, sizeof(ck_true)},
	    {CKA_VERIFY, &ck_true, sizeof(ck_true)},
	    {CKA_SENSITIVE, &ck_true, sizeof(ck_true)}
	};

	CK_ATTRIBUTE copyattrs[] = {
	    { CKA_LABEL, _kctx->targetlabel, strlen(_kctx->targetlabel) },
	    { CKA_TOKEN, &ck_true, sizeof(ck_true) },
	};

	pkcs11AttrList *kcv_attrs = NULL;

	comp = calloc( _kctx->wrappedkeylen, sizeof(CK_BYTE));

	if(!comp) {
	    fprintf(stderr, "Memory error\n");
	    goto error;
	}
	
	derivation_data.pData = comp;
	derivation_data.ulLen = _kctx->wrappedkeylen;

	/* we do a final XOR with 0s to allow all key usages on the key */
	rv = _kctx->C_DeriveKey ( _kctx->p11Context->Session,
				  &mechanism,
				  _kctx->sessionkey,
				  attrs,
				  sizeof (attrs) / sizeof(CK_ATTRIBUTE),
				  &newkey  );
	

	if(rv!=CKR_OK) {
	    pkcs11_error(rv, "C_DeriveKey");
	    goto error;
	}
	 
	rv = _kctx->C_CopyObject ( _kctx->p11Context->Session,
				   newkey,
				   copyattrs,
				   sizeof(copyattrs) / sizeof(CK_ATTRIBUTE),
				   &unwrappedkey );
	
	if(rv!=CKR_OK) {
	    pkcs11_error(rv, "C_CopyObject");
	    goto error;
	}

	printf("Key with label '%s' successfully imported\n", _kctx->targetlabel);

	/* OK we are done, return KCV */
	kcv_attrs = pkcs11_new_attrlist(_kctx->p11Context,
					/* storage object attributes */
					_ATTR(CKA_CHECK_VALUE),
					_ATTR_END );
	
	if(kcv_attrs != NULL) { 

	    if(pkcs11_read_attr_from_handle (kcv_attrs, unwrappedkey) == true) {
		CK_ATTRIBUTE_PTR kcv = pkcs11_get_attr_in_attrlist ( kcv_attrs, CKA_CHECK_VALUE );
		
		if(kcv && kcv->pValue!=NULL_PTR && kcv->ulValueLen!=0 ) {
		    printf("KCV = %2.2x%2.2x%2.2x\n", 
			   ((char *)kcv->pValue)[0], 
			   ((char *)kcv->pValue)[1], 
			   ((char *)kcv->pValue)[2]);
		} else {
		    /* we need to encrypt 8 00 in ECB and output the 3 first bytes */
		    CK_BYTE cleartext[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };
		    CK_BYTE encrypted[8];
		    CK_ULONG cleartext_len=8L, encrypted_len=8L;
		    CK_MECHANISM des3_ecb = { CKM_DES3_ECB, NULL_PTR, 0 };
		    
		    rv = _kctx->p11Context->FunctionList.C_EncryptInit(
			_kctx->p11Context->Session, 
			&des3_ecb,
			unwrappedkey);
		    
		    if(rv!=CKR_OK) {
			pkcs11_error(rv, "C_EncryptInit");
			goto error;
		    }
		    
		    rv = _kctx->p11Context->FunctionList.C_Encrypt (
			_kctx->p11Context->Session,
			cleartext,
			cleartext_len,
			encrypted,
			&encrypted_len
			);
		    
		    if(rv!=CKR_OK) {
			pkcs11_error(rv, "C_EncryptInit");
			goto error;
		    }

		    printf("KCV = %2.2x%2.2x%2.2x\n", 
			   encrypted[0], 
			   encrypted[1], 
			   encrypted[2]);
		}
	    }
	}


    error:
	if(kcv_attrs) { pkcs11_delete_attrlist(kcv_attrs); }
	if (comp) { free(comp); }
	
    }

    return unwrappedkey;
}
