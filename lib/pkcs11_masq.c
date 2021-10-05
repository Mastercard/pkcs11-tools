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
	/* hook our crypto to OpenSSL methods */
	pkcs11_rsa_method_setup();
	pkcs11_rsa_method_pkcs11_context(NULL_PTR, 0, true);
	break;
	
    case EVP_PKEY_DSA:
	/* hook our crypto to OpenSSL methods */
	pkcs11_dsa_method_setup();
	pkcs11_dsa_method_pkcs11_context(NULL_PTR, 0, true);
	break;
	
    case EVP_PKEY_EC:
	/* hook our crypto to OpenSSL methods */
	pkcs11_ecdsa_method_setup();
	pkcs11_ecdsa_method_pkcs11_context(NULL_PTR, 0, true);
	break;

    default:
	fprintf(stderr, "Error: unsupported signing algorithm\n");
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

    /* step 10: sign PKCS#10 */
    const EVP_MD *md = EVP_get_digestbynid(X509_REQ_get_signature_nid(xreq));
    if(!X509_REQ_sign(xreq, pk, md)) {
	P_ERR();
	goto err;
    }
    
    retval = true;

err:
    /* cleanup */
    if(exts != NULL) { sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free); exts=NULL; }    if(name != NULL) { X509_NAME_free(name); }
    /* memory management */

    return retval;
}


/* EOF */
