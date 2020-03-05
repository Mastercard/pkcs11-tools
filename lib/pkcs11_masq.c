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
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pkcs11lib.h"


static X509_REQ * new_X509_REQ_from_file(char *filename);
static void free_X509_REQ_handle(X509_REQ * hndl);
static CK_BBOOL get_X509_REQ_pubk(X509_REQ *hndl, CK_ATTRIBUTE_PTR modulus, CK_ATTRIBUTE_PTR exponent );


static X509_REQ * new_X509_REQ_from_file(char *filename)
{

    X509_REQ * rv = NULL;
    
    FILE *fp = NULL;

    fp = fopen(filename,"rb"); /* open in binary mode */
    
    if(fp) {
	X509_REQ *csr;
	
	/* try DER first */
	csr = d2i_X509_REQ_fp(fp, NULL);
	fclose(fp);
	
	if(csr) {
	    rv = csr;
	} else {
	    fp = fopen(filename,"r"); /* reopen in text mode */
	    
	    if(fp) {
		csr = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
		fclose(fp);
	    
		if(csr) {
		    rv = csr;
		}
	    } else {
		perror("Error opening file");
	    }
	}
    } else {
	perror("Error opening file");
    }

    return rv;
}


static void free_X509_REQ_handle(X509_REQ * hndl)
{

    if(hndl) {
	OPENSSL_free( hndl );
    }
}



static CK_BBOOL get_X509_REQ_pubk(X509_REQ *hndl, 
				  CK_ATTRIBUTE_PTR modulus,
				  CK_ATTRIBUTE_PTR exponent )
{
    EVP_PKEY *pubkey;
    
    CK_BBOOL rv=CK_FALSE;

    if( hndl ) {
	
	pubkey = X509_REQ_get_pubkey(hndl);
	
	if(pubkey && EVP_PKEY_base_id(pubkey)==EVP_PKEY_RSA) {
	  
	    RSA *rsa;
      const BIGNUM *rsa_n;
      const BIGNUM *rsa_e;

	    rsa = EVP_PKEY_get1_RSA(pubkey);
	    if(rsa) {

	      RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);

		    CK_BYTE_PTR bn_n = OPENSSL_malloc(BN_num_bytes(rsa_n));
		    CK_BYTE_PTR bn_e = OPENSSL_malloc(BN_num_bytes(rsa_e));

		if(bn_n && bn_e) {
		    int bn_n_len = BN_bn2bin(rsa_n, bn_n);
		    int bn_e_len = BN_bn2bin(rsa_e, bn_e);
		    
		    modulus->type = CKA_MODULUS;
		    modulus->ulValueLen = BN_num_bytes(rsa_n);
		    modulus->pValue = bn_n;

		    exponent->type = CKA_PUBLIC_EXPONENT;
		    exponent->ulValueLen = BN_num_bytes(rsa_e);
		    exponent->pValue = bn_e;
		    
		    rv = CK_TRUE;
		} else {
		    if(bn_n) OPENSSL_free(bn_n);
		    if(bn_e) OPENSSL_free(bn_e);
		}
	    }
	}
    }	    
    return rv;
}


CK_BBOOL pkcs11_extract_pubk_from_X509_REQ(char *csrfilename, CK_ATTRIBUTE_PTR modulus, CK_ATTRIBUTE_PTR exponent)
{

    CK_BBOOL rv = CK_FALSE;
    
    X509_REQ * csr =  new_X509_REQ_from_file(csrfilename);

    if(csr) {
	rv = get_X509_REQ_pubk( csr, modulus, exponent );
    }
    return rv;
}


void pkcs11_free_X509_REQ_attributes(CK_ATTRIBUTE_PTR modulus, CK_ATTRIBUTE_PTR exponent)
{
    if(modulus && modulus->pValue) {
	OPENSSL_free(modulus->pValue);
	modulus->pValue = NULL_PTR;
	modulus->ulValueLen = 0L;
    }

    if(exponent && exponent->pValue) {
	OPENSSL_free(exponent->pValue);
	exponent->pValue = NULL_PTR;
	exponent->ulValueLen = 0L;
    }
}


int pkcs11_fakesign_X509_REQ(CK_VOID_PTR req, int pubkeybits, CK_MECHANISM_TYPE mechtype)
{
    int retval=0;
    unsigned char *inbuf = NULL;
    CK_ULONG inlen;

    unsigned char *outbuf = NULL;
    CK_ULONG outlen;

    EVP_MD *type;
    int pkey_type;

    switch( mechtype ) {
    case CKM_SHA1_RSA_PKCS:
	type = (EVP_MD *) EVP_sha1();
	break;
	
    case CKM_SHA256_RSA_PKCS:
	type = (EVP_MD*) EVP_sha256();
	break;

    case CKM_SHA384_RSA_PKCS:
	type = (EVP_MD*) EVP_sha384();
	break;

    case CKM_SHA512_RSA_PKCS:
	type = (EVP_MD*) EVP_sha512();
	break;

    default:
	printf("Unsupported mechanism for signing");
	goto err;
    }

    X509_ALGOR *a;
    ASN1_BIT_STRING *signature;

    X509_REQ_get0_signature((X509_REQ*)req, (const ASN1_BIT_STRING **)&signature, (const X509_ALGOR **) &a);

    /* first of all extract stuff to be signed */
    if((inlen = i2d_re_X509_REQ_tbs((X509_REQ*)req, &inbuf))==0) {
	goto err;
    }

    /* then allocate memory for output */
    outlen=pubkeybits/8;	/* TODO change this to get it from private key */
    outbuf=(unsigned char *)OPENSSL_malloc((unsigned int)outlen);

    /* at this point, inbuf contains the stuff to sign. */

    /* pretend we sign */
    {
      int i;
      unsigned char repeat[] = {'(', 0xc4, 0xbe};
      pkey_type = EVP_MD_pkey_type(type);

      for (i = 0; i < outlen; i++) {
        outbuf[i] = repeat[i % sizeof repeat];
      }
    }

    /* fix req->sig_alg to make it match */
    /* borrowed/inspired by openssl/crypto/asn1/a_sign.c */
    if (pkey_type == NID_dsaWithSHA1 ||
        pkey_type == NID_ecdsa_with_SHA1) {
      /* special case: RFC 3279 tells us to omit 'parameters'
       * with id-dsa-with-sha1 and ecdsa-with-SHA1 */
      ASN1_TYPE_free(a->parameter);
      a->parameter = NULL;
    }  else if ((a->parameter == NULL) ||
                (a->parameter->type != V_ASN1_NULL)) {
      ASN1_TYPE_free(a->parameter);
      if ((a->parameter=ASN1_TYPE_new()) == NULL) goto err;
      a->parameter->type=V_ASN1_NULL;
    }
    ASN1_OBJECT_free(a->algorithm);
    a->algorithm=OBJ_nid2obj(pkey_type);
    if (a->algorithm == NULL)  {
      ASN1err(ASN1_F_ASN1_ITEM_SIGN,ASN1_R_UNKNOWN_OBJECT_TYPE);
      goto err;
    }
    if (OBJ_length(a->algorithm) == 0)  {
      ASN1err(ASN1_F_ASN1_ITEM_SIGN,ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
      goto err;
    }
    /* end of borrow */

    /* fix req->signature to contain our stuff  */
    if (signature->data != NULL) OPENSSL_free(signature->data);
    signature->data=outbuf;
    outbuf=NULL;
    signature->length=outlen;
    /* In the interests of compatibility, I'll make sure that
   * the bit string has a 'not-used bits' value of 0
   */
  signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
  signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;

  retval = 1;

  err:
  /* todo - proper cleanup */
  
  if(outbuf) { OPENSSL_free(outbuf); outbuf=NULL; }
  if(inbuf) { OPENSSL_free(inbuf); inbuf=NULL; }

  return retval;

}
