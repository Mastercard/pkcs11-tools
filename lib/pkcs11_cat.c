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
#include <unistd.h>
#include "pkcs11lib.h"

#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>


static void write_X509(X509* cert)
{

    BIO *bio_stdout = NULL;

    bio_stdout = BIO_new( BIO_s_file() );

    if(bio_stdout==NULL) {
      fprintf(stderr, "Error: Can't create BIO objects.\n");
      goto err;
    }

    BIO_set_fp(bio_stdout, stdout, BIO_NOCLOSE);
    PEM_write_bio_X509(bio_stdout,cert); /* PEM output */
    
 err:    
    if(bio_stdout) BIO_free(bio_stdout);
}


static void write_pubk(EVP_PKEY* pk, int openssl_native_flag)
{

    BIO *bio_stdout = NULL;

    bio_stdout = BIO_new( BIO_s_file() );

    if(bio_stdout==NULL) {
	P_ERR();
	goto err;
    }

    BIO_set_fp(bio_stdout, stdout, BIO_NOCLOSE);

    if(openssl_native_flag==1) {	/* openssl native format */
    /* first write params, if any */
	switch(EVP_PKEY_type(pk->type)) {
	case EVP_PKEY_RSA:	/* RSA is the only key type with native openssl format */
	    PEM_write_bio_RSAPublicKey(bio_stdout, EVP_PKEY_get1_RSA(pk));
	    break;

	case EVP_PKEY_DSA:
	    PEM_write_bio_DSAparams(bio_stdout, EVP_PKEY_get1_DSA(pk));
	    break;

	case EVP_PKEY_DH:
	    PEM_write_bio_DHparams(bio_stdout, EVP_PKEY_get1_DH(pk));
	    break;

	case EVP_PKEY_EC:
	    PEM_write_bio_ECPKParameters(bio_stdout, EC_KEY_get0_group(EVP_PKEY_get1_EC_KEY(pk)));
	    break;

	default:
	    PEM_write_bio_PUBKEY(bio_stdout,pk); /* encapsulated format */
	    break;
	}
	
    } else {
	PEM_write_bio_PUBKEY(bio_stdout,pk); /* encapsulated format */
    }
	
 err:    
    if(bio_stdout) BIO_free(bio_stdout);
}


/* high-level search functions */

func_rc pkcs11_cat_object_with_label(pkcs11Context *p11Context, char *label, int openssl_native_flag)
{

    func_rc rc=rc_ok;
    pkcs11Search *search=NULL;


    pkcs11IdTemplate *idtmpl=NULL;
    
    /* trick: we treat "cert", "pubk", "prvk", "seck" and "data" in front of the templating system */
    /* so these specific labels can be used as shortcut for the corresponding object classes       */

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
	idtmpl = pkcs11_make_idtemplate(label);
    }
    
    if(idtmpl && pkcs11_sizeof_idtemplate(idtmpl)>0) {

	search = pkcs11_new_search_from_idtemplate( p11Context, idtmpl );
	
	if(search) {		/* we just need one hit */

	    CK_OBJECT_HANDLE hndl=0;

	    while( (hndl = pkcs11_fetch_next(search))!=0 ) {

		pkcs11AttrList *attrs;

		attrs = pkcs11_new_attrlist(p11Context, 
					    _ATTR(CKA_CLASS),
					    _ATTR(CKA_LABEL),
					    _ATTR(CKA_KEY_TYPE), /* to determine key type */
					    _ATTR(CKA_VALUE), /* on cert */
					    _ATTR(CKA_MODULUS), /* on RSA pubk */
					    _ATTR(CKA_PUBLIC_EXPONENT), /* on RSA pubk */
					    _ATTR(CKA_PRIME), /* DSA/DH */
					    _ATTR(CKA_SUBPRIME), /* DSA */
					    _ATTR(CKA_BASE), /* DSA/DH */
					    _ATTR(CKA_EC_PARAMS), /* EC */
					    _ATTR(CKA_EC_POINT),  /* EC */
					    _ATTR_END );

		if( pkcs11_read_attr_from_handle_ext (attrs, hndl, 
						      CKR_ATTRIBUTE_SENSITIVE, /* we skip over sensitive attributes */
						      CKR_FUNCTION_FAILED,     /* workaround for nCipher bug 30966 */
						      0L) == CK_TRUE) {

		    CK_ATTRIBUTE_PTR oclass = pkcs11_get_attr_in_attrlist(attrs, CKA_CLASS);
		    CK_ATTRIBUTE_PTR oktype = pkcs11_get_attr_in_attrlist(attrs, CKA_KEY_TYPE);
		    CK_ATTRIBUTE_PTR olabel = pkcs11_get_attr_in_attrlist(attrs, CKA_LABEL);

		    if(oclass) {
			switch(*(CK_OBJECT_CLASS *)(oclass->pValue)) {
			case CKO_PUBLIC_KEY:
			    switch(*(CK_OBJECT_CLASS *)(oktype->pValue)) {
				
			    case CKK_RSA: {
				RSA *rsa = NULL;
				EVP_PKEY *pk = NULL;
				BIGNUM *bn_modulus = NULL;
				BIGNUM *bn_exponent = NULL;

				CK_ATTRIBUTE_PTR omod = pkcs11_get_attr_in_attrlist(attrs, CKA_MODULUS);
				CK_ATTRIBUTE_PTR oexp = pkcs11_get_attr_in_attrlist(attrs, CKA_PUBLIC_EXPONENT);

				if ( (bn_modulus = BN_bin2bn(omod->pValue, omod->ulValueLen, NULL)) == NULL ) {
				    P_ERR();
				    goto key_rsa_error;
				}

				if ( (bn_exponent = BN_bin2bn(oexp->pValue, oexp->ulValueLen, NULL)) == NULL ) {
				    P_ERR();
				    goto key_rsa_error;
				}

				if( (rsa=RSA_new()) == NULL ) {
				    P_ERR();
				    goto key_rsa_error;
				}

				if ((pk=EVP_PKEY_new()) == NULL) {
				    P_ERR();
				    goto key_rsa_error;
				}
				
				/* free is pre-allocated */
				if(rsa->n !=NULL ) { BN_free(rsa->n); rsa->n = NULL; }
				if(rsa->e !=NULL ) { BN_free(rsa->e); rsa->e = NULL; }

				rsa->n = bn_modulus;     bn_modulus = NULL; /* forget, moved to rsa */
				rsa->e = bn_exponent;    bn_exponent = NULL; /* forget, moved to rsa */

				if (!EVP_PKEY_assign_RSA(pk,rsa)) {
				    P_ERR();
				    goto key_rsa_error;
				}
				rsa=NULL;	/* forget it, moved to pk */
			
				write_pubk(pk, openssl_native_flag);
			
				key_rsa_error:
				if(bn_modulus)  { BN_free(bn_modulus); }
				if(bn_exponent) { BN_free(bn_exponent); }
				if(rsa)         { RSA_free(rsa); }
				if(pk)          { EVP_PKEY_free(pk); }
			    }
				break;
				/* end of case_CKK_RSA */


			    case CKK_DSA: {
				DSA *dsa = NULL;
				EVP_PKEY *pk = NULL;
				BIGNUM *bn_prime = NULL;
				BIGNUM *bn_subprime = NULL;
				BIGNUM *bn_base = NULL;
				BIGNUM *bn_pubkey = NULL;
				
				CK_ATTRIBUTE_PTR oprim = pkcs11_get_attr_in_attrlist(attrs, CKA_PRIME);
				CK_ATTRIBUTE_PTR osubp = pkcs11_get_attr_in_attrlist(attrs, CKA_SUBPRIME);
				CK_ATTRIBUTE_PTR obase = pkcs11_get_attr_in_attrlist(attrs, CKA_BASE);
				CK_ATTRIBUTE_PTR opubk = pkcs11_get_attr_in_attrlist(attrs, CKA_VALUE);


				if ( (bn_prime = BN_bin2bn(oprim->pValue, oprim->ulValueLen, NULL)) == NULL ) {
				    P_ERR();
				    goto key_dsa_error;
				}

				if ( (bn_subprime = BN_bin2bn(osubp->pValue, osubp->ulValueLen, NULL)) == NULL ) {
				    P_ERR();
				    goto key_dsa_error;
				}

				if ( (bn_base = BN_bin2bn(obase->pValue, obase->ulValueLen, NULL)) == NULL ) {
				    P_ERR();
				    goto key_dsa_error;
				}

				if ( (bn_pubkey = BN_bin2bn(opubk->pValue, opubk->ulValueLen, NULL)) == NULL ) {
				    P_ERR();
				    goto key_dsa_error;
				}

				if( (dsa=DSA_new()) == NULL ) {
				    P_ERR();
				    goto key_dsa_error;
				}

				if ((pk=EVP_PKEY_new()) == NULL) {
				    P_ERR();
				    goto key_dsa_error;
				}

				if(dsa->p !=NULL ) { BN_free(dsa->p); dsa->p = NULL; }
				if(dsa->q !=NULL ) { BN_free(dsa->q); dsa->q = NULL; }
				if(dsa->g !=NULL ) { BN_free(dsa->g); dsa->g = NULL; }
				if(dsa->pub_key !=NULL ) { BN_free(dsa->pub_key); dsa->pub_key = NULL; }

				dsa->p = bn_prime;        bn_prime = NULL;    /* forget, moved to dsa */
				dsa->q = bn_subprime;     bn_subprime = NULL; /* forget, moved to dsa */
				dsa->g = bn_base;         bn_base = NULL;     /* forget, moved to dsa */
				dsa->pub_key = bn_pubkey; bn_pubkey = NULL;   /* forget, moved to dsa */

				if (!EVP_PKEY_assign_DSA(pk,dsa)) {
				    P_ERR();
				    goto key_dsa_error;
				}
				dsa=NULL;	/* forget it, moved to pk */
			
				write_pubk(pk, openssl_native_flag);
			
				key_dsa_error:
				if(bn_prime)    { BN_free(bn_prime); }
				if(bn_subprime) { BN_free(bn_subprime); }
				if(bn_base)     { BN_free(bn_base); }
				if(bn_pubkey)   { BN_free(bn_pubkey); }
				if(dsa)         { DSA_free(dsa); }
				if(pk)          { EVP_PKEY_free(pk); }
			    
			    }
				break;
				/* end of case_CKK_DSA */
			

			    case CKK_DH: {
				DH *dh = NULL;
				EVP_PKEY *pk = NULL;
				BIGNUM *bn_prime = NULL;
				BIGNUM *bn_base = NULL;
				BIGNUM *bn_pubkey = NULL;
				
				CK_ATTRIBUTE_PTR oprim = pkcs11_get_attr_in_attrlist(attrs, CKA_PRIME);
				CK_ATTRIBUTE_PTR obase = pkcs11_get_attr_in_attrlist(attrs, CKA_BASE);
				CK_ATTRIBUTE_PTR opubk = pkcs11_get_attr_in_attrlist(attrs, CKA_VALUE);


				if ( (bn_prime = BN_bin2bn(oprim->pValue, oprim->ulValueLen, NULL)) == NULL ) {
				    P_ERR();
				    goto key_dh_error;
				}

				if ( (bn_base = BN_bin2bn(obase->pValue, obase->ulValueLen, NULL)) == NULL ) {
				    P_ERR();
				    goto key_dh_error;
				}

				if ( (bn_pubkey = BN_bin2bn(opubk->pValue, opubk->ulValueLen, NULL)) == NULL ) {
				    P_ERR();
				    goto key_dh_error;
				}

				if( (dh=DH_new()) == NULL ) {
				    P_ERR();
				    goto key_dh_error;
				}

				if ((pk=EVP_PKEY_new()) == NULL) {
				    P_ERR();
				    goto key_dh_error;
				}

				if(dh->p !=NULL ) { BN_free(dh->p); dh->p = NULL; }
				if(dh->g !=NULL ) { BN_free(dh->g); dh->g = NULL; }
				if(dh->pub_key !=NULL ) { BN_free(dh->pub_key); dh->pub_key = NULL; }

				dh->p = bn_prime;        bn_prime = NULL;    /* forget, moved to dh */
				dh->g = bn_base;         bn_base = NULL;     /* forget, moved to dh */
				dh->pub_key = bn_pubkey; bn_pubkey = NULL;   /* forget, moved to dh */

				if (!EVP_PKEY_assign_DH(pk,dh)) {
				    P_ERR();
				    goto key_dh_error;
				}
				dh=NULL;	/* forget it, moved to pk */
			
				write_pubk(pk, openssl_native_flag);
			
				key_dh_error:
				if(bn_prime)    { BN_free(bn_prime); }
				if(bn_base)     { BN_free(bn_base); }
				if(bn_pubkey)   { BN_free(bn_pubkey); }
				if(dh)          { DH_free(dh); }
				if(pk)          { EVP_PKEY_free(pk); }
			    
			    }
				break;
				/* end of case_CKK_DH */


			    case CKK_EC: {
				EC_KEY *ec = NULL;
				EC_GROUP *ec_group = NULL;
				ASN1_OCTET_STRING *ec_point_container = NULL;
				EC_POINT *ec_point = NULL;
				EVP_PKEY *pk = NULL;
				
				CK_ATTRIBUTE_PTR oecparams = pkcs11_get_attr_in_attrlist(attrs, CKA_EC_PARAMS);
				CK_ATTRIBUTE_PTR oecpoint  = pkcs11_get_attr_in_attrlist(attrs, CKA_EC_POINT);
				const unsigned char * pp;
				
				if( (ec=EC_KEY_new()) == NULL ) {
				    P_ERR();
				    goto key_ec_error;
				}

				/* extract CKA_EC_PARAMS into EC_GROUP (which is auto-allocated by call) */
				pp = oecparams->pValue; /* copy the pointer */

				if(d2i_ECPKParameters(&ec_group, &pp, oecparams->ulValueLen) == NULL ) {
				    P_ERR();
				    goto key_ec_error;
				}

				/* assign group to key */
				if(EC_KEY_set_group(ec, ec_group) == 0) {
				    P_ERR();
				    goto err;
				}

				/* create point */
				if( (ec_point=EC_POINT_new(ec_group)) == NULL ) {
				    P_ERR();
				    goto key_ec_error;
				}

				/* create point container (OCTET STRING) */
				if( (ec_point_container=ASN1_OCTET_STRING_new()) == NULL ) {
				    P_ERR();
				    goto key_ec_error;
				}
				/* extract point value into ASN1_OCTET_STRING structure */
				/* openssl pattern: &pp will be incremented beyond size of DER struct */
				pp = oecpoint->pValue; /* copy the pointer */
				if(d2i_ASN1_OCTET_STRING(&ec_point_container, &pp, oecpoint->ulValueLen) == NULL ) {
				    P_ERR();
				    goto key_ec_error;
				}
				
				/* extract point from PKCS#11 attribute */
				/* embedded into ec_point_container     */
				if(EC_POINT_oct2point(ec_group, ec_point, ec_point_container->data, ec_point_container->length, NULL) == 0 ) {
				    P_ERR();
				    goto key_ec_error;
				}

				/* assign point to key */
				if( EC_KEY_set_public_key(ec, ec_point) == 0) {
				    P_ERR();
				    goto key_ec_error;
				} 
				ec_point = NULL; /* forget it */

				/* create PKEY object */
				if ((pk=EVP_PKEY_new()) == NULL) {
				    goto key_ec_error;
				}
				
				/* assign EC key to PKEY */
				if (!EVP_PKEY_assign_EC_KEY(pk, ec)) {
				    P_ERR();
				    goto key_ec_error;
				}
				ec=NULL;	/* forget it, moved to pk */
			
				write_pubk(pk, openssl_native_flag);
			
				key_ec_error:
				if(ec_point!=NULL) { EC_POINT_free(ec_point); }
				if(ec_group!=NULL) { EC_GROUP_free(ec_group); }
				if(ec!=NULL)       { EC_KEY_free(ec); }
				if(pk)             { EVP_PKEY_free(pk); }
			    
			    }
				break;
				/* end of case_CKK_EC */

			    default:
				fprintf(stderr, "Sorry, (yet) unsupported key type\n");
				break;
			    }
			
			case CKO_CERTIFICATE: { 
			    CK_ATTRIBUTE_PTR ovalue = pkcs11_get_attr_in_attrlist(attrs, CKA_VALUE);
			    const unsigned char *p = (unsigned char *)(ovalue->pValue);
			    X509 *x = d2i_X509(NULL, &p, ovalue->ulValueLen);
			    if(x) {
				write_X509(x);
				OPENSSL_free(x);
			    }			    
			}
			    break;
			
			case CKO_SECRET_KEY:
			case CKO_PRIVATE_KEY:
			    fprintf(stderr,"***WARNING: secret/private key object, can't be disclosed\n" );
			    break;

			case CKO_DATA: {
			    CK_ATTRIBUTE_PTR ovalue = pkcs11_get_attr_in_attrlist(attrs, CKA_VALUE);

			    if(ovalue) {
				pkcs11_ll_set_binary(stdout);
				write( fileno(stdout), ovalue->pValue, ovalue->ulValueLen);
			    }
			}
			    break;
			    
			default:
			    fprintf(stderr,"***WARNING: no method to output this object type\n" );
			    break;
			}
		    }
		    
		    pkcs11_delete_attrlist(attrs);
		}
	    
	    }
	    pkcs11_delete_search(search);
	}
	pkcs11_delete_idtemplate(idtmpl);
    }
    err:

    return rc;
}

/* EOF */
