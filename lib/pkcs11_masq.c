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
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pkcs11lib.h"
#include "pkcs11_provider.h"


static X509_REQ * new_X509_REQ_from_file(char *filename);
static void free_X509_REQ_handle(X509_REQ * hndl);


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


inline static void free_X509_REQ_handle(X509_REQ * hndl)
{
    if(hndl) { OPENSSL_free( hndl ); }
}


static bool req_add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex) {
	P_ERR();
	return false;
    }

    if(!sk_X509_EXTENSION_push(sk, ex)) {
	P_ERR();
	return false;
    }

    return true;
}

/* public interface */


inline x509_req_handle_t *pkcs11_get_X509_REQ_from_file(char *csrfilename) {
    return (x509_req_handle_t *) new_X509_REQ_from_file(csrfilename);
}

inline void x509_req_handle_t_free(x509_req_handle_t *hndl)
{
    free_X509_REQ_handle((X509_REQ *) hndl);
}

bool pkcs11_masq_X509_REQ(x509_req_handle_t *req,
			  char *dn,
			  bool reverse,
			  char *san[],
			  int sancnt,
			  bool ext_ski) 
{
    bool retval = false;
    EVP_PKEY *pk = NULL;
    EVP_PKEY *signing_pk = NULL;
    OSSL_LIB_CTX *prov_libctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    key_type_t key_type;
    X509_NAME *name=NULL;
    X509_REQ *xreq = (X509_REQ *)req;
    
    STACK_OF(X509_EXTENSION) *exts = NULL;

    /* step 1: retrieve key type */

    
    if(!(pk = X509_REQ_get0_pubkey(xreq))) {
	P_ERR();
	goto err;
    }
	  
    /* step 2: do key-type specific business*/
    switch(EVP_PKEY_base_id(pk)) {

    case EVP_PKEY_RSA:
	key_type = rsa;
	break;
	
    case EVP_PKEY_DSA:
	key_type = dsa;
	break;
	
    case EVP_PKEY_EC:
	key_type = ec;
	break;

    default:
	fprintf(stderr, "Error: unsupported signing algorithm\n");
	goto err;
    }

    /* Route forged signing through the pkcs11tools OpenSSL 3 provider. */
    if(!pkcs11_provider_install(&prov_libctx)) {
	fprintf(stderr, "Error: failed to install pkcs11tools provider\n");
	goto err;
    }
    signing_pk = pkcs11_provider_make_pkey(prov_libctx, key_type, pk, NULL_PTR, 0, true);
    if(signing_pk == NULL) {
	goto err;
    }

    /* step 3: parse subject DN (which becomes issuer DN) */
    if((name = pkcs11_DN_new_from_string(dn, MBSTRING_UTF8, false, reverse))==NULL) {
	P_ERR();
	goto err;
    }

    /* TODO: fix mem leak with previous value? */
    if (!X509_REQ_set_subject_name(xreq, name)) {
	P_ERR();
	goto err;
    }

    /* next steps are optional, as we do not necessarily have extensions to add */
    if(ext_ski || sancnt>0) {
	/* retrieve extention structure */
	if(!(exts = sk_X509_EXTENSION_new_null())) {
	    P_ERR();
	    goto err;
	}

	/* step 4: add SAN if specified */
	/* TODO extract and error checking */
	if(sancnt>0)
	{
	    int i;
	    size_t size=0;
	    char *sanfield=NULL;

	    for(i=0; i<sancnt; i++) {
		size += strlen(san[i]) + 1;	/* we add one for the ',' */
	    }
	    size++;		/* add a supplementary byte for allowing extra last ',' with strcat() */

	    if((sanfield=OPENSSL_malloc(size))!=NULL) {
	    sanfield[0]=0;	/* clear first byte */
	    for(i=0;i<sancnt;i++) {
		strcat(sanfield,san[i]);
		strcat(sanfield,",");
	    }

	    sanfield[strlen(sanfield)-1] = '\0'; /* erase last comma */
	    req_add_ext(exts, NID_subject_alt_name, sanfield);
	    OPENSSL_free(sanfield);
	    }
	}
    
	/* step 5: add SKI if specified */
	if(ext_ski) {
	    char *value=NULL;
	    uint8_t *ski=NULL;
	    size_t ski_len=0;

	    if((ski_len=pkcs11_new_SKI_value_from_pubk(pk, &ski)) ==0 ) {
		fprintf(stderr, "Error: could not determine SKI from public key\n");
		goto err;
	    }
	    /* retrieve the value */

	    value=(char *) OPENSSL_zalloc( ski_len * 2  + 1);

	    if(value) {
		int i;

		for(i=0; i<ski_len; i++) {
		    sprintf(&value[i*2], "%2.2x", ski[i]);
		}

		req_add_ext(exts, NID_subject_key_identifier, &value[0]);
		OPENSSL_free(value);
	    }
	    if(ski) { OPENSSL_free(ski); }
	}

	/* Step 9: add extensions to the PKCS#10 structure */
	if(!X509_REQ_add_extensions(xreq, exts)) {
	    P_ERR();
	    goto err;
	}
    }    

    /* step 10: sign PKCS#10 (forged signature via pkcs11tools provider). */
    {
	int sig_nid = X509_REQ_get_signature_nid(xreq);
	int md_nid = NID_undef;
	int pkey_nid = NID_undef;
	const char *mdname = NULL;
	bool is_pss = false;

	if(sig_nid == NID_rsassaPss) {
	    /* PSS — recover digest from the embedded PSS parameters. */
	    const X509_ALGOR *sig_alg = NULL;
	    const ASN1_OBJECT *aobj = NULL;
	    int ptype = 0;
	    const void *pval = NULL;
	    X509_REQ_get0_signature(xreq, NULL, &sig_alg);
	    if(sig_alg) {
		X509_ALGOR_get0(&aobj, &ptype, &pval, sig_alg);
		if(ptype == V_ASN1_SEQUENCE && pval) {
		    const ASN1_STRING *str = (const ASN1_STRING *)pval;
		    const unsigned char *p = str->data;
		    RSA_PSS_PARAMS *pss = d2i_RSA_PSS_PARAMS(NULL, &p, str->length);
		    if(pss && pss->hashAlgorithm) {
			md_nid = OBJ_obj2nid(pss->hashAlgorithm->algorithm);
		    }
		    RSA_PSS_PARAMS_free(pss);
		}
	    }
	    if(md_nid == NID_undef) {
		md_nid = NID_sha1;      /* RFC 4055 default */
	    }
	    is_pss = true;
	} else {
	    OBJ_find_sigid_algs(sig_nid, &md_nid, &pkey_nid);
	}
	mdname = (md_nid != NID_undef) ? OBJ_nid2sn(md_nid) : NULL;

	if((mdctx = EVP_MD_CTX_new()) == NULL) {
	    P_ERR();
	    goto err;
	}

	if(key_type == rsa) {
	    OSSL_PARAM rsa_params[6];
	    OSSL_PARAM *rsa_p = rsa_params;
	    int saltlen_max = -1;
	    const char *pad_pkcs1 = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
	    const char *pad_pss   = OSSL_PKEY_RSA_PAD_MODE_PSS;
	    if(is_pss) {
		*rsa_p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
							    (char *)pad_pss, 0);
		*rsa_p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST,
							    (char *)mdname, 0);
		*rsa_p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
						    &saltlen_max);
	    } else {
		*rsa_p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
							    (char *)pad_pkcs1, 0);
	    }
	    *rsa_p = OSSL_PARAM_construct_end();
	    if(!EVP_DigestSignInit_ex(mdctx, &pctx, mdname, prov_libctx, NULL, signing_pk, rsa_params)) {
		P_ERR();
		goto err;
	    }
	} else {
	    if(!EVP_DigestSignInit_ex(mdctx, &pctx, mdname, prov_libctx, NULL, signing_pk, NULL)) {
		P_ERR();
		goto err;
	    }
	}

	if(!X509_REQ_sign_ctx(xreq, mdctx)) {
	    P_ERR();
	    goto err;
	}
    }
    
    retval = true;

err:
    /* cleanup */
    if(mdctx) { EVP_MD_CTX_free(mdctx); mdctx=NULL; }
    if(exts != NULL) { sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free); exts=NULL; }    if(name != NULL) { X509_NAME_free(name); }
    if(signing_pk!=NULL) { EVP_PKEY_free(signing_pk); signing_pk=NULL; }
    if(prov_libctx!=NULL) { OSSL_LIB_CTX_free(prov_libctx); prov_libctx=NULL; }
    /* memory management */

    return retval;
}


/* EOF */
