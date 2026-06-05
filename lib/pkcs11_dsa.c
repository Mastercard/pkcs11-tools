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
#include <search.h>
#include "pkcs11lib.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>


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


/* Load DSA parameters from a file (auto-detects DER or PEM via OSSL_DECODER). */
static inline EVP_PKEY * new_dsaparam_from_file(char *filename)
{
    EVP_PKEY *rv = NULL;
    FILE *fp = NULL;

    fp = fopen(filename,"rb"); /* binary; OSSL_DECODER copes with both DER and PEM */
    if(fp == NULL) {
	perror("Error opening file");
	return NULL;
    }
    rv = pkcs11_pkey_read_params_fp(fp, "DSA");
    fclose(fp);
    if(rv == NULL) {
	P_ERR();
    }
    return rv;
}


static inline void free_DSAparam_handle(EVP_PKEY * hndl)
{
    if(hndl) {
	EVP_PKEY_free(hndl);
    }
}

static inline void free_OPENSSL_bytes(CK_BYTE_PTR buf)
{
    if(buf) {
	OPENSSL_free( buf );
    }
}


static CK_ULONG get_OPENSSL_bytes_for_BIGNUM(const BIGNUM *b, CK_BYTE_PTR *buf)
{
    CK_ULONG rv=0;

    if ( b && buf ) {

	*buf = OPENSSL_malloc(BN_num_bytes(b));

	if(*buf==NULL) {
	    P_ERR();
	    return rv;
	}

	rv = BN_bn2bin(b, *buf);

	/* if we fail here, we would free up requested memory */
	if(rv==0) {
	    P_ERR();
	    OPENSSL_free(*buf);
	    *buf = NULL;
	}
    }
    return rv;
}


static inline CK_ULONG get_DSAparam_p(EVP_PKEY *hndl, CK_BYTE_PTR *buf) {
    BIGNUM *dsa_p = NULL;
    CK_ULONG rv = 0;
    if (hndl != NULL &&
	pkcs11_pkey_get_bn(hndl, OSSL_PKEY_PARAM_FFC_P, &dsa_p) == 1) {
	rv = get_OPENSSL_bytes_for_BIGNUM(dsa_p, buf);
    }
    if (dsa_p) BN_free(dsa_p);
    return rv;
}

static inline CK_ULONG get_DSAparam_q(EVP_PKEY *hndl, CK_BYTE_PTR *buf) {
    BIGNUM *dsa_q = NULL;
    CK_ULONG rv = 0;
    if (hndl != NULL &&
	pkcs11_pkey_get_bn(hndl, OSSL_PKEY_PARAM_FFC_Q, &dsa_q) == 1) {
	rv = get_OPENSSL_bytes_for_BIGNUM(dsa_q, buf);
    }
    if (dsa_q) BN_free(dsa_q);
    return rv;
}

static inline CK_ULONG get_DSAparam_g(EVP_PKEY *hndl, CK_BYTE_PTR *buf) {
    BIGNUM *dsa_g = NULL;
    CK_ULONG rv = 0;
    if (hndl != NULL &&
	pkcs11_pkey_get_bn(hndl, OSSL_PKEY_PARAM_FFC_G, &dsa_g) == 1) {
	rv = get_OPENSSL_bytes_for_BIGNUM(dsa_g, buf);
    }
    if (dsa_g) BN_free(dsa_g);
    return rv;
}

func_rc pkcs11_genDSA (pkcs11Context * p11ctx,
		       char *label,
		       char *param,
		       CK_ATTRIBUTE attrs[],
		       CK_ULONG numattrs,
		       CK_OBJECT_HANDLE_PTR pubkhandleptr,
		       CK_OBJECT_HANDLE_PTR prvkhandleptr,
		       key_generation_t gentype
    )
{
    func_rc rc= rc_ok;
    CK_RV retcode;
    int i;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;

    CK_BYTE id[32];

    EVP_PKEY *dsa = NULL;
    CK_BYTE_PTR dsa_p = NULL;
    CK_BYTE_PTR dsa_q = NULL;
    CK_BYTE_PTR dsa_g = NULL;
    CK_ULONG dsa_p_len = 0L;
    CK_ULONG dsa_q_len = 0L;
    CK_ULONG dsa_g_len = 0L;

    dsa = new_dsaparam_from_file(param);

    if(dsa==NULL) {
	fprintf(stderr,"***Error: no parameter file\n");
	rc = rc_error_invalid_parameter_for_method;
	goto error;
    }

    dsa_p_len = get_DSAparam_p(dsa, &dsa_p);
    dsa_q_len = get_DSAparam_q(dsa, &dsa_q);
    dsa_g_len = get_DSAparam_g(dsa, &dsa_g);


    if(dsa_p_len==0 || dsa_p_len==0 || dsa_p_len==0) {
	fprintf(stderr,"***Error: something wrong with DSA params, exiting\n");
	rc = rc_error_invalid_parameter_for_method;
	goto error;
    }


    {
	CK_MECHANISM mechanism = {
	    CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0
	};

	CK_ATTRIBUTE pubktemplate[] = {
	    {CKA_TOKEN, gentype == kg_token ? &ck_true : &ck_false, sizeof ck_true},
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },

	    /* key params */
	    {CKA_PRIME, dsa_p, dsa_p_len},
	    {CKA_SUBPRIME, dsa_q, dsa_q_len},
	    {CKA_BASE, dsa_g, dsa_g_len},

	    /* what can we do with this key */
	    {CKA_VERIFY, &ck_false, sizeof ck_false},
	};

	CK_ATTRIBUTE prvktemplate[] = {
	    {CKA_TOKEN, gentype == kg_token ? &ck_true : &ck_false, sizeof ck_true},
	    {CKA_PRIVATE, &ck_true, sizeof ck_true},
	    {CKA_SENSITIVE, &ck_true, sizeof ck_true},
	    {CKA_EXTRACTABLE, gentype == kg_session_for_wrapping ? &ck_true : &ck_false, sizeof ck_false},

	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    {CKA_SIGN, &ck_false, sizeof ck_false},
	};

	/* adjust private key */
	for(i=0; i<numattrs; i++)
	{
	    size_t num_elems = sizeof prvktemplate / sizeof(CK_ATTRIBUTE);

	    CK_ATTRIBUTE_PTR match = lfind( &attrs[i],
					    prvktemplate,
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
	    size_t num_elems = sizeof pubktemplate / sizeof(CK_ATTRIBUTE);

	    CK_ATTRIBUTE_PTR match = lfind( &attrs[i],
					    pubktemplate,
					    &num_elems,
					    sizeof(CK_ATTRIBUTE),
					    compare_CKA );

	    /* if we have a match, take the value from the command line */
	    /* we are basically stealing the pointer from attrs array   */
	    if(match && match->ulValueLen == attrs[i].ulValueLen) {
		match->pValue = attrs[i].pValue;
	    }
	}

	/* generate here */
	retcode = p11ctx->FunctionList.C_GenerateKeyPair ( p11ctx->Session,
							   &mechanism,
							   pubktemplate,
							   sizeof pubktemplate / sizeof(CK_ATTRIBUTE),
							   prvktemplate,
							   sizeof prvktemplate / sizeof(CK_ATTRIBUTE),
							   pubkhandleptr, prvkhandleptr
	    );

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
    if(dsa_p) free_OPENSSL_bytes(dsa_p);
    if(dsa_q) free_OPENSSL_bytes(dsa_q);
    if(dsa_g) free_OPENSSL_bytes(dsa_g);
    if(dsa) free_DSAparam_handle(dsa);
    return rc;
}
