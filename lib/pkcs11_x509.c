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

    CK_ULONG rv=0;
    if( hndl ) {

	pubkey = X509_get_pubkey(hndl);

	if(pubkey) {
	    switch(EVP_PKEY_base_id(pubkey)) {
		case EVP_PKEY_RSA:
		{
		    RSA *rsa;
		    const BIGNUM *rsa_n;

		    rsa = EVP_PKEY_get1_RSA(pubkey);
		    if(rsa) {
		      RSA_get0_key(rsa, &rsa_n, NULL, NULL);
			    CK_BYTE_PTR bn_buf = OPENSSL_malloc(BN_num_bytes(rsa_n)); /* we allocate before converting */
		  	if(bn_buf) {
			    int bn_buf_len = BN_bn2bin(rsa_n, bn_buf);
			    {
				/* SHA-1 block */
				EVP_MD_CTX *mdctx;
				const EVP_MD *md;
				unsigned int md_len, i;

				*buf = OPENSSL_malloc(SHA_DIGEST_LENGTH); /* we allocate the buffer, and return it. */

				if(*buf) {
				    md = EVP_sha1();
				    mdctx = EVP_MD_CTX_create();
				    EVP_DigestInit_ex(mdctx, md, NULL);
				    EVP_DigestUpdate(mdctx, bn_buf, bn_buf_len);
				    EVP_DigestFinal_ex(mdctx, *buf, &md_len);
				    EVP_MD_CTX_destroy(mdctx);
				    rv = md_len;
				}
			    }
			    OPENSSL_free(bn_buf);
			}
		    }
		}
		break;


		case EVP_PKEY_DSA:
		{
		    DSA *dsa;
		    const BIGNUM *dsa_pub;

		    dsa = EVP_PKEY_get1_DSA(pubkey);
		    if(dsa) {
		      DSA_get0_key(dsa, &dsa_pub, NULL);
			CK_BYTE_PTR bn_buf = OPENSSL_malloc(BN_num_bytes(dsa_pub)); /* we allocate before converting */
			if(bn_buf) {
			    int bn_buf_len = BN_bn2bin(dsa_pub, bn_buf);
			    {
				/* SHA-1 block */
				EVP_MD_CTX *mdctx;
				const EVP_MD *md;
				unsigned int md_len, i;

				*buf = OPENSSL_malloc(SHA_DIGEST_LENGTH); /* we allocate the buffer, and return it. */

				if(*buf) {
				    md = EVP_sha1();
				    mdctx = EVP_MD_CTX_create();
				    EVP_DigestInit_ex(mdctx, md, NULL);
				    EVP_DigestUpdate(mdctx, bn_buf, bn_buf_len);
				    EVP_DigestFinal_ex(mdctx, *buf, &md_len);
				    EVP_MD_CTX_destroy(mdctx);
				    rv = md_len;
				}
			    }
			    OPENSSL_free(bn_buf);
			}
		    }
		}
		break;



	    case EVP_PKEY_EC:
	    {
		EC_KEY *ec;

		ec = EVP_PKEY_get1_EC_KEY(pubkey);
		if(ec==NULL) {
		    P_ERR();
		} else {
		    const EC_POINT *ec_point = EC_KEY_get0_public_key(ec);
		    const EC_GROUP *ec_group = EC_KEY_get0_group(ec);


		    if(ec_point==NULL) {
			P_ERR();
		    }else if (ec_group==NULL) {
			P_ERR();
		    } else {

			/* first call to assess length of target buffer */
			size_t ec_buflen = EC_POINT_point2oct(ec_group, ec_point,
							      POINT_CONVERSION_UNCOMPRESSED,
							      NULL, 0, NULL);

			if(ec_buflen==0) {
			    P_ERR();
			} else {

			    unsigned char *p, *ec_buf;

			    p = ec_buf = OPENSSL_malloc( ec_buflen );

			    if(ec_buf==NULL) {
				P_ERR();
			    } else {
				/* second call to obtain DER-encoded point */
				rv = (CK_ULONG) EC_POINT_point2oct(ec_group, ec_point,
								   POINT_CONVERSION_UNCOMPRESSED,
								   p, ec_buflen, NULL);
				if(rv==0) {
				    P_ERR();
				} else {

				    /* now start the wrapping to OCTET STRING business */

				    ASN1_OCTET_STRING *wrapped = ASN1_OCTET_STRING_new();

				    if(wrapped==NULL) {
					P_ERR();
				    } else {
					if( ASN1_STRING_set(wrapped, ec_buf, ec_buflen) == 0 ) {
					    P_ERR();
					} else {
					    /* wrapped contains the data we need to set into buf */

					    /* determine length of buffer */
					    int i2dlen = i2d_ASN1_OCTET_STRING(wrapped, NULL);

					    if(i2dlen<0) {
						P_ERR();
					    } else {

						CK_BYTE_PTR p = NULL, wrapbuf = NULL;

						wrapbuf = OPENSSL_malloc(i2dlen);

						if(wrapbuf==NULL) {
						    P_ERR();
						} else {

						    p = wrapbuf;

						    i2dlen = i2d_ASN1_OCTET_STRING(wrapped, &p);

						    if(i2dlen<0) {
							P_ERR();
						    } else {

							/* SHA-1 block */
							EVP_MD_CTX *mdctx;
							const EVP_MD *md;
							unsigned int md_len, i;

							*buf = OPENSSL_malloc(SHA_DIGEST_LENGTH); /* we allocate the buffer, and return it. */

							if(*buf ==NULL) {
							    P_ERR();
							} else {
							    md = EVP_sha1();
							    mdctx = EVP_MD_CTX_create();
							    EVP_DigestInit_ex(mdctx, md, NULL);
							    EVP_DigestUpdate(mdctx, wrapbuf, i2dlen);
							    EVP_DigestFinal_ex(mdctx, *buf, &md_len);
							    EVP_MD_CTX_destroy(mdctx);
							    rv = md_len;
							}
						    }
						    OPENSSL_free(wrapbuf);
						}
					    }
					}
					ASN1_OCTET_STRING_free(wrapped);
				    }
				}
				OPENSSL_free(ec_buf);
			    }
			    /* get0 on ec_point & ec_group, we can safely forget */
			}
		    }
		    EC_KEY_free(ec);
		}
	    }
	    break;


	    default:
		break;

	    }
	}
    }
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
	{CKA_MODIFIABLE, &ck_true, sizeof ck_true },	     /* 9  */
	{CKA_TRUSTED, &ck_true, sizeof ck_true },	     /* 10 */
	/* CKA_TRUSTED set at last position   */
	/* this flag is FALSE by default      */
	/* So we don't present it in case     */
	/* library does not support attribute */
	/* if trust flag is needed, then we expand */
	/* the size of the structure by 1     */
    };

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

			    /* if -T is set: we want trusted */
			    if(trusted) {
				certTemplate[9].pValue = &ck_false; /* then CKA_MODIFIABLE must be CK_FALSE */
			    }

			    retCode = pC_CreateObject(p11Context->Session,
						      certTemplate,
						      (trusted ? sizeof(certTemplate) : sizeof(certTemplate)-2) / sizeof(CK_ATTRIBUTE),
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
