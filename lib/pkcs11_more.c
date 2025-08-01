/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2018-2021 Mastercard
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

#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>


static void more_X509(X509* cert)
{

    BIO *bio_stdout = NULL;

    bio_stdout = BIO_new( BIO_s_file() );

    if(bio_stdout==NULL) {
	fprintf(stderr, "Error: Can't create BIO objects.\n");
	goto err;
    }

    BIO_set_fp(bio_stdout, stdout, BIO_NOCLOSE);
    X509_print(bio_stdout,cert); /* PEM output */

err:
    if(bio_stdout) BIO_free(bio_stdout);
}


static void more_pubk(EVP_PKEY* pk)
{

    BIO *bio_stdout = NULL;

    if ( (bio_stdout = BIO_new( BIO_s_file() )) == NULL ) {
	P_ERR();
	goto err;
    }

    if( BIO_set_fp(bio_stdout, stdout, BIO_NOCLOSE) == 0 ) {
	P_ERR();
	goto err;
    }

    if( EVP_PKEY_print_public(bio_stdout, pk, 0, NULL)<1 ) {
	P_ERR();
	goto err;
    }

err:
    if(bio_stdout) BIO_free(bio_stdout);
}


/* high-level search functions */

func_rc pkcs11_more_object_with_label(pkcs11Context *p11Context, char *label)
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
	idtmpl = pkcs11_create_id(label);
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
						      0L) == true) {

		    CK_ATTRIBUTE_PTR oclass = pkcs11_get_attr_in_attrlist(attrs, CKA_CLASS);
		    CK_ATTRIBUTE_PTR oktype = pkcs11_get_attr_in_attrlist(attrs, CKA_KEY_TYPE);

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

				RSA_set0_key(rsa, bn_modulus, bn_exponent, NULL);
				bn_modulus = NULL; /* forget, moved to rsa */
				bn_exponent = NULL; /* forget, moved to rsa */

				if (!EVP_PKEY_assign_RSA(pk,rsa)) {
				    P_ERR();
				    goto key_rsa_error;
				}
				rsa=NULL;	/* forget it, moved to pk */

				more_pubk(pk);

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

				DSA_set0_pqg(dsa, bn_prime, bn_subprime, bn_base);
				bn_prime = NULL;    /* forget, moved to dsa */
				bn_subprime = NULL; /* forget, moved to dsa */
				bn_base = NULL;     /* forget, moved to dsa */
				DSA_set0_key(dsa, bn_pubkey, NULL);
				bn_pubkey = NULL;   /* forget, moved to dsa */

				if (!EVP_PKEY_assign_DSA(pk,dsa)) {
				    P_ERR();
				    goto key_dsa_error;
				}
				dsa=NULL;	/* forget it, moved to pk */

				more_pubk(pk);

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

				DH_set0_pqg(dh, bn_prime, NULL, bn_base);
				bn_prime = NULL;    /* forget, moved to dh */
				bn_base = NULL;     /* forget, moved to dh */
				DH_set0_key(dh, bn_pubkey, NULL);
				bn_pubkey = NULL;   /* forget, moved to dh */

				if (!EVP_PKEY_assign_DH(pk,dh)) {
				    P_ERR();
				    goto key_dh_error;
				}
				dh=NULL;	/* forget it, moved to pk */

				more_pubk(pk);

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
				/* openssl pattern: &pp will be incremented beyond size of DER struct */
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

				/* extract point value into ASN1_OCTET_STRING structure */
				/* openssl pattern: &pp will be incremented beyond size of DER struct */
				pp = oecpoint->pValue; /* copy the pointer */
				if(d2i_ASN1_OCTET_STRING(&ec_point_container, &pp, oecpoint->ulValueLen) == NULL ) {
				    fprintf(stderr, "Warning: CKA_EC_POINT format likely not compliant, trying alternate way to decode public key\n");
				    /* d2i_TYPE() will NULLify the destination pointer in case of error (??!) */
				    /* we need to reset the value */
				    if( (ec_point_container=ASN1_OCTET_STRING_new()) == NULL ) {
					P_ERR();
					goto key_ec_error;
				    }

				    if(ASN1_OCTET_STRING_set(ec_point_container, oecpoint->pValue, oecpoint->ulValueLen) == 0) {
					P_ERR();
					goto key_ec_error;
				    }
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

				more_pubk(pk);

				key_ec_error:
				if(ec_point_container!=NULL) { ASN1_OCTET_STRING_free(ec_point_container); }
				if(ec_point!=NULL) { EC_POINT_free(ec_point); }
				if(ec_group!=NULL) { EC_GROUP_free(ec_group); }
				if(ec!=NULL)       { EC_KEY_free(ec); }
				if(pk)             { EVP_PKEY_free(pk); }

			    }
				break;
				/* end of case_CKK_EC */

				/* again, since support for EDWARDS curve is poor in OpenSSL */
				/* we need to use sideways.  */
				/* we create an X509_PUBKEY, that we populate, then we turn it */
				/* into a EVP_PKEY. See pkcs11_cat for more details */
			    case CKK_EC_EDWARDS: {
				ASN1_OCTET_STRING *ed_point = NULL;
				ASN1_OBJECT * ed_oid = NULL;
				X509_PUBKEY *x509pk = NULL;
				EVP_PKEY *pk = NULL;
				CK_ATTRIBUTE_PTR oecparams = NULL;
				CK_ATTRIBUTE_PTR oecpoint  = NULL;
				uint8_t *output = NULL;
				size_t outputlen = 0;
				const uint8_t * pp ;


				oecparams = pkcs11_get_attr_in_attrlist(attrs, CKA_EC_PARAMS);
				oecpoint  = pkcs11_get_attr_in_attrlist(attrs, CKA_EC_POINT);

				if(oecparams==NULL || oecpoint==NULL) {
				    fprintf(stderr, "Error: object missing attribute(s) CKA_EC_PARAMS and/or CKA_EC_POINT\n");
				    goto key_ed_error;
				}

				/* extract point into octet string */
				pp = oecpoint->pValue;
				if( (ed_point = d2i_ASN1_OCTET_STRING(NULL, &pp, oecpoint->ulValueLen)) == NULL ) {
				    P_ERR();
				    goto key_ed_error;
				}

				/* extract param into OID */
				/* for Edwards curve, it may come it two flavours: 
				 * - as an OID, in which case it will be parsed by d2i_ASN1_OBJECT
				 * - as a PrintableString 'edwards25519' or 'edwards448'
				 * the later case cannot be converted directly to an OID
				 * and is therefore detected upfront.
				 */
				pp = oecparams->pValue;
				if(pkcs11_is_ed_param_named_25519(pp, oecparams->ulValueLen)) {
				    ed_oid = OBJ_nid2obj(NID_ED25519);
				} else if(pkcs11_is_ed_param_named_448(pp, oecparams->ulValueLen)) {
				    ed_oid = OBJ_nid2obj(NID_ED448);
				} else {
				    ed_oid = d2i_ASN1_OBJECT(NULL, &pp, oecparams->ulValueLen);
				}
				if( ed_oid == NULL ) {
				    P_ERR();
				    goto key_ed_error;
				}

				/* create new X509_PUBKEY object and assign point and params */
				if( (x509pk = X509_PUBKEY_new()) ==NULL ) {
				    P_ERR();
				    goto key_ed_error;
				}

				if(!X509_PUBKEY_set0_param(x509pk, ed_oid, V_ASN1_UNDEF, NULL, ed_point->data, ed_point->length)) {
				    P_ERR();
				    goto key_ed_error;
				}
				ed_oid = NULL; ed_point = NULL; /* ownership transferred to x509pk */

				/* convert to DER */
				if( (outputlen = i2d_X509_PUBKEY(x509pk, &output)) == 0 ) {
				    P_ERR();
				    goto key_ed_error;
				}

				/* now the magic: convert that back to an EVP_PKEY object */
				pp = output;
				if( (pk = d2i_PUBKEY(NULL, &pp, outputlen)) == 0 ) {
				    P_ERR();
				    goto key_ed_error;
				}

				more_pubk(pk);

				key_ed_error:
				if(ed_point) { ASN1_OCTET_STRING_free(ed_point); }
				if(ed_oid) { ASN1_OBJECT_free(ed_oid); }
				if(x509pk) { X509_PUBKEY_free(x509pk); }
				if(pk) { EVP_PKEY_free(pk); }
				if(output) { OPENSSL_free(output); }
				/* free stuff */
			    }
				break;
				/* end of case CKK_EC_EDWARDS */

			    default:
				fprintf(stderr, "Sorry, (yet) unsupported key type\n");
				break;
			    }

			case CKO_CERTIFICATE: {
			    CK_ATTRIBUTE_PTR ovalue = pkcs11_get_attr_in_attrlist(attrs, CKA_VALUE);
			    const unsigned char *p = (unsigned char *)(ovalue->pValue);
			    X509 *x = d2i_X509(NULL, &p, ovalue->ulValueLen);
			    if(x) {
				more_X509(x);
				OPENSSL_free(x);
			    }
			}
			    break;

			case CKO_SECRET_KEY:
			case CKO_PRIVATE_KEY:
			    fprintf(stderr,"***WARNING: secret/private key object, can't be disclosed\n" );
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
