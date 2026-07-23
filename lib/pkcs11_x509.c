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
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>

#include "pkcs11lib.h"



static X509 * new_X509_from_file(char *filename)
{

    X509 * rv = NULL;

    FILE *fp = NULL;

    fp = fopen(filename,"rb"); /* open in binary mode */

    if(fp) {
	X509 *cert;

	/* try DER first */
	cert = d2i_X509_fp(fp, NULL);
	fclose(fp);

	if(cert) {
	    puts("DER format detected");
	    rv = cert;
	} else {
	    fp = fopen(filename,"r"); /* reopen in text mode */

	    if(fp) {
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
		fclose(fp);

		if(cert) {
		    puts("PEM format detected");
		    rv = cert;
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

static CK_ULONG get_X509_subject_der(X509 *hndl, CK_BYTE_PTR * buf)
{
    X509_NAME *subject;
    CK_ULONG rv=0;

    if( hndl ) {
	subject = X509_get_subject_name(hndl);
	if(subject) {

	    rv = i2d_X509_NAME(subject, NULL);	/* first call to fetch buffer size. */

	    if( rv>0 ) {
		CK_BYTE_PTR p;

		p = *buf = OPENSSL_malloc(rv);

		if(*buf) {
		    rv = i2d_X509_NAME(subject, &p); /* second call. p is incremented. */

		    /* if we fail here, we would free up requested memory */
		    if(rv==0) {
			OPENSSL_free(*buf);
		    }
		}
	    }
	}
    }
    return rv;
}

static CK_ULONG get_X509_issuer_der(X509 *hndl, CK_BYTE_PTR *buf) {

  X509_NAME *issuer;
  CK_ULONG rv = 0;

  if (hndl) {
    issuer = X509_get_issuer_name(hndl);
    if (issuer) {

      rv = i2d_X509_NAME(issuer, NULL);  /* first call to fetch buffer size. */

      if (rv > 0) {
        CK_BYTE_PTR p;

        p = *buf = OPENSSL_malloc(rv);

        if (*buf) {
          rv = i2d_X509_NAME(issuer, &p); /* second call. p is incremented. */

          /* if we fail here, we would free up requested memory */
          if (rv == 0) {
            OPENSSL_free(*buf);
          }
        }
      }
    }
  }
  return rv;
}


static CK_ULONG get_X509_cert_der(X509 *hndl, CK_BYTE_PTR *buf) {
  CK_ULONG rv = 0;

  if (hndl) {
    rv = i2d_X509(hndl, NULL);

    if (rv > 0) {
      CK_BYTE_PTR p;

      p = *buf = OPENSSL_malloc(rv);

      if (*buf) {
        rv = i2d_X509(hndl, &p);

        /* if we fail here, we would free up requested memory */
        if (rv == 0) {
          OPENSSL_free(*buf);
        }
      }
    }
  }
  return rv;
}


static CK_ULONG get_X509_serial_number_hex(X509 *hndl, CK_BYTE_PTR *buf) {

  ASN1_INTEGER *serialnumber;
  CK_ULONG rv = 0;

  if (hndl) {

    serialnumber = X509_get_serialNumber(hndl);
    if (serialnumber) {

      rv = i2d_ASN1_INTEGER(serialnumber, NULL);

      if (rv > 0) {
        CK_BYTE_PTR p;

        p = *buf = OPENSSL_malloc(rv);

        if (*buf) {
          rv = i2d_ASN1_INTEGER(serialnumber, &p);

          /* if we fail here, we would free up requested memory */
          if (rv == 0) {
            OPENSSL_free(*buf);
          }
        }
      }
    }
  }
  return rv;
}


/*  get_X509_pubkey_sha1: will retrieve RSA public key and compute SHA-1 digest
			  on modulus, represented as big-endian binary digit,
			  with no leading 0x00.
			  This is what IBM JCE provider for PKCS#11 uses for setting CKA_ID.

			  for DSA, SHA-1 digest of CKA_PUBKEY is used instead.

*/


static CK_ULONG get_X509_pubkey_sha1(X509 *hndl, CK_BYTE_PTR *buf)
{
    EVP_PKEY *pubkey;
    CK_ULONG rv = 0;

    if (!hndl) {
	return 0;
    }
    pubkey = X509_get_pubkey(hndl);
    if (!pubkey) {
	return 0;
    }

    switch (EVP_PKEY_base_id(pubkey)) {

    case EVP_PKEY_RSA: {
	/* SHA-1 of the modulus (big-endian, no leading 0x00). */
	BIGNUM *n = NULL;
	if (pkcs11_pkey_get_bn(pubkey, OSSL_PKEY_PARAM_RSA_N, &n) == 1 && n) {
	    int n_len = BN_num_bytes(n);
	    unsigned char *bn_buf = OPENSSL_malloc(n_len > 0 ? n_len : 1);
	    if (bn_buf) {
		int written = BN_bn2bin(n, bn_buf);
		unsigned char *out = NULL;
		size_t md = pkcs11_pkey_sha1_to_buf(bn_buf, (size_t)written, &out);
		if (md > 0) {
		    *buf = (CK_BYTE_PTR)out;
		    rv = (CK_ULONG)md;
		}
		OPENSSL_free(bn_buf);
	    }
	    BN_free(n);
	}
	break;
    }

    case EVP_PKEY_DSA: {
	/* SHA-1 of CKA_VALUE i.e. of the public key BIGNUM. */
	BIGNUM *pub = NULL;
	if (pkcs11_pkey_get_bn(pubkey, OSSL_PKEY_PARAM_PUB_KEY, &pub) == 1 && pub) {
	    int pub_len = BN_num_bytes(pub);
	    unsigned char *bn_buf = OPENSSL_malloc(pub_len > 0 ? pub_len : 1);
	    if (bn_buf) {
		int written = BN_bn2bin(pub, bn_buf);
		unsigned char *out = NULL;
		size_t md = pkcs11_pkey_sha1_to_buf(bn_buf, (size_t)written, &out);
		if (md > 0) {
		    *buf = (CK_BYTE_PTR)out;
		    rv = (CK_ULONG)md;
		}
		OPENSSL_free(bn_buf);
	    }
	    BN_free(pub);
	}
	break;
    }

    case EVP_PKEY_EC:
    case EVP_PKEY_ED25519:
    case EVP_PKEY_ED448:
    {
 	/* SHA-1 of the DER-encoded ASN1_OCTET_STRING wrapping public key bytes.
	   Match historical CKA_ID derivation for EC and ED keys. */
	unsigned char *point = NULL;
	size_t point_len = 0;

	if (pkcs11_pkey_get_octets(pubkey, OSSL_PKEY_PARAM_PUB_KEY,
				   &point, &point_len) == 1 && point_len > 0) {
	    ASN1_OCTET_STRING *wrapped = ASN1_OCTET_STRING_new();
	    if (wrapped) {
		if (ASN1_STRING_set(wrapped, point, (int)point_len) != 0) {
		    int i2dlen = i2d_ASN1_OCTET_STRING(wrapped, NULL);
		    if (i2dlen > 0) {
			unsigned char *wrapbuf = OPENSSL_malloc((size_t)i2dlen);
			if (wrapbuf) {
			    unsigned char *p = wrapbuf;
			    i2dlen = i2d_ASN1_OCTET_STRING(wrapped, &p);
			    if (i2dlen > 0) {
				unsigned char *out = NULL;
				size_t md = pkcs11_pkey_sha1_to_buf(wrapbuf,
								   (size_t)i2dlen,
								   &out);
				if (md > 0) {
				    *buf = (CK_BYTE_PTR)out;
				    rv = (CK_ULONG)md;
				}
			    }
			    OPENSSL_free(wrapbuf);
			}
		    }
		}
		ASN1_OCTET_STRING_free(wrapped);
	    }
	    OPENSSL_free(point);
	}
	break;
    }

    default:
	break;
    }

    EVP_PKEY_free(pubkey);
    return rv;
}



static void free_X509_buf(CK_BYTE_PTR buf)
{
    if(buf) {
	OPENSSL_free( buf );
    }
}


static void free_X509_handle(X509 * hndl)
{

    if(hndl) {
	OPENSSL_free( hndl );
    }
}


CK_OBJECT_HANDLE pkcs11_importcert( pkcs11Context * p11Context, char *filename, void *x509, char *label, int trusted)
{
    CK_OBJECT_HANDLE hCert = NULL_PTR;

    CK_RV retCode;
    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;

    CK_BYTE_PTR serial_number = NULL;
    CK_BYTE_PTR subject = NULL;
    CK_BYTE_PTR issuer = NULL;
    CK_BYTE_PTR cert_ber = NULL;
    CK_BYTE_PTR modulus_hash = NULL;

    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;

    CK_ATTRIBUTE certTemplate[] = {
	{CKA_CLASS, &certClass, sizeof certClass },          /* 0  */
	{CKA_CERTIFICATE_TYPE, &certType, sizeof certType }, /* 1  */
	{CKA_ID, NULL, 0},				     /* 2  */
	{CKA_LABEL, label, strlen(label) },		     /* 3  */
	{CKA_TOKEN, &ck_true, sizeof ck_true},		     /* 4  */
	{CKA_SUBJECT, NULL, 0 },			     /* 5  */
	{CKA_ISSUER, NULL, 0 },				     /* 6  */
	{CKA_VALUE, NULL, 0 },				     /* 7  */
	{CKA_SERIAL_NUMBER, NULL, 0 },			     /* 8  */
	{CKA_TRUSTED, &ck_true, sizeof ck_true },	     /* 9  */
	{CKA_MODIFIABLE, &ck_false, sizeof ck_false }	     /* 10 */
	/* CKA_TRUSTED and CKA_MODIFIABLE set at the end          */
	/* We don't present them unless required by -T            */
	/* This is to accomodate with unreliable token libraries  */
    };

#define CERT_TEMPLATE_SIZE_TRUSTED (sizeof(certTemplate)/sizeof(CK_ATTRIBUTE))
#define CERT_TEMPLATE_SIZE_NORMAL  (CERT_TEMPLATE_SIZE_TRUSTED-2)

    X509 *cert = NULL;


    CK_C_CreateObject pC_CreateObject;

    pC_CreateObject = p11Context->FunctionList.C_CreateObject;

    /* if x509 is not null, use it, otherwise get a cert from the file. */
    cert = x509 ? (X509 *)x509 : new_X509_from_file(filename);

    if(cert) {

	CK_ULONG subject_len;
	CK_ULONG issuer_len;
	CK_ULONG cert_ber_len;
	CK_ULONG serial_number_len;
	CK_ULONG modulus_hash_len;

	subject_len = get_X509_subject_der( cert, &subject);

	if(subject_len>0) {

	    issuer_len = get_X509_issuer_der( cert, &issuer);

	    if( issuer_len>0 ) {
		cert_ber_len = get_X509_cert_der( cert, &cert_ber);

		if( cert_ber_len >0 ) {

		    serial_number_len = get_X509_serial_number_hex( cert, &serial_number);
		    if( serial_number_len >0 ) {

			modulus_hash_len = get_X509_pubkey_sha1( cert, &modulus_hash);
			if( modulus_hash_len >0 ) {

			    /* we have everything, let's fill in the template */

			    certTemplate[2].pValue = modulus_hash;
			    certTemplate[2].ulValueLen = modulus_hash_len;

			    certTemplate[5].pValue = subject;
			    certTemplate[5].ulValueLen = subject_len;

			    certTemplate[6].pValue = issuer;
			    certTemplate[6].ulValueLen = issuer_len;

			    certTemplate[7].pValue = cert_ber;
			    certTemplate[7].ulValueLen = cert_ber_len;

			    certTemplate[8].pValue = serial_number;
			    certTemplate[8].ulValueLen = serial_number_len;

			    /* if trusted flag is set, our template contains CKA_TRUSTED=true and CKA_MODIFIABLE=false*/
			    retCode = pC_CreateObject(p11Context->Session,
						      certTemplate,
						      (trusted ? CERT_TEMPLATE_SIZE_TRUSTED : CERT_TEMPLATE_SIZE_NORMAL),
						      &hCert);

			    if(retCode != CKR_OK) {
				pkcs11_error( retCode, "CreateObject" );
			    }

			    /* if we are here, we have to free up memory anyway */
			    free_X509_buf(modulus_hash);
			}
			free_X509_buf(serial_number);
		    }
		    free_X509_buf(cert_ber);
		}
		free_X509_buf(issuer);
	    }
	    free_X509_buf(subject);
	}
	if(filename) { free_X509_handle(cert); } /* we free only if the cert was retrieved from a file */
    }
    return hCert;
}
