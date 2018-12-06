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
#include <openssl/pem.h>
#include <openssl/dh.h>


static int compare_CKA( const void *a, const void *b)
{
    return ((CK_ATTRIBUTE_PTR)a)->type == ((CK_ATTRIBUTE_PTR)b)->type ? 0 : -1;
}


/* A few words about these pragmas:
   Openssl macro system seems flawed when it comes to use d2i_xxxx_fp function. And GCC/CLANG are reporting
   warning about incompatible pointer types.
   As a last resort, a pragma sent to GCC disables the warning from showing up.
   Ugly but works :-(
*/

#if defined(__GNUC__) || defined(__MINGW32__)
/* Show no warning in case incompatible pointer types are used. */
#define GCC_VERSION                                                            \
	(__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if GCC_VERSION >= 40500
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#endif /* GCC_VERSION >= 40500 */
#endif /* defined(__GNUC__) || defined(__MINGW32__) */
#if defined(__clang__)
/* Show no warning in case incompatible pointer types are used. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
#endif

static inline DH * new_dhparam_from_file(char *filename)
{

    DH * rv = NULL;

    FILE *fp = NULL;

    fp = fopen(filename,"rb"); /* open in binary mode */

    if(fp) {
	DH *dhparam;

	/* try DER first */

	dhparam = d2i_DHparams_fp(fp, NULL);

	fclose(fp);

	if(dhparam) {
	    puts("DER format detected");
	    rv = dhparam;
	} else {
	    fp = fopen(filename,"r"); /* reopen in text mode */

	    if(fp) {
		dhparam = PEM_read_DHparams(fp, NULL, NULL, NULL);
		fclose(fp);

		if(dhparam) {
		    puts("PEM format detected");
		    rv = dhparam;
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

#if defined(__GNUC__) || defined(__MINGW32__)
/* Show no warning in case incompatible pointer types are used. */
#if GCC_VERSION >= 40500
#pragma GCC diagnostic pop
#endif /* GCC_VERSION >= 40500 */
#endif /* defined(__GNUC__) || defined(__MINGW32__) */
#if defined(__clang__)
/* Show no warning in case system functions are not used. */
#pragma clang diagnostic pop
#endif


static inline void free_DHparam_handle(DH * hndl)
{
    if(hndl) {
	OPENSSL_free( hndl );
    }
}

static inline void free_OPENSSL_bytes(CK_BYTE_PTR buf)
{
    if(buf) {
	OPENSSL_free( buf );
    }
}


static CK_ULONG get_OPENSSL_bytes_for_BIGNUM(BIGNUM *b, CK_BYTE_PTR *buf)
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


static inline CK_ULONG get_DHparam_p(DH *hndl, CK_BYTE_PTR *buf) {
    return hndl!=NULL ? get_OPENSSL_bytes_for_BIGNUM(hndl->p, buf) : 0L;
}

static inline CK_ULONG get_DHparam_g(DH *hndl, CK_BYTE_PTR *buf) {
    return hndl!=NULL ? get_OPENSSL_bytes_for_BIGNUM(hndl->g, buf) : 0L;
}

int pkcs11_genDH (pkcs11Context * p11Context,
		      char *label,
		      char *param,
		      CK_ATTRIBUTE attrs[],
		      CK_ULONG numattrs,
		      CK_OBJECT_HANDLE_PTR hPublicKey,
		      CK_OBJECT_HANDLE_PTR hPrivateKey)
{
    int rc=0;
    CK_RV retCode;
    int i;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;

    CK_BYTE id[32];

    DH *dh = NULL;
    CK_BYTE_PTR dh_p = NULL;
    CK_BYTE_PTR dh_g = NULL;
    CK_ULONG dh_p_len = 0L;
    CK_ULONG dh_g_len = 0L;

    dh = new_dhparam_from_file(param);

    if(dh==NULL) {
	fprintf(stderr,"have no parameter file, exiting\n");
	goto cleanup;
    }

    dh_p_len = get_DHparam_p(dh, &dh_p);
    dh_g_len = get_DHparam_g(dh, &dh_g);


    if(dh_p_len==0 || dh_p_len==0 || dh_p_len==0) {
	fprintf(stderr,"something wrong with DH params, exiting\n");
	goto cleanup;
    }


    {
	CK_MECHANISM mechanism = {
	    CKM_DH_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
	};

	CK_ATTRIBUTE publicKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },

	    /* key params */
	    {CKA_PRIME, dh_p, dh_p_len},
	    {CKA_BASE, dh_g, dh_g_len},

	    /* what can we do with this key */
	    {CKA_VERIFY, &ck_false, sizeof(ck_false)},
	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
	    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
	    {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
	    {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
	    {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},

	    {CKA_LABEL, label, strlen(label) },
	    {CKA_ID, id, strlen((const char *)id) },
	    {CKA_SIGN, &ck_false, sizeof(ck_false)},
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

	/* generate here */

	retCode = p11Context->FunctionList.C_GenerateKeyPair (
	    p11Context->Session,
	    &mechanism,
	    publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
	    privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
	    hPublicKey, hPrivateKey
	    );

	if (retCode != CKR_OK ) {
	    pkcs11_error( retCode, "C_GenerateKeyPair" );
	    goto cleanup;
	}

	rc = 1;
    }

cleanup:

    free_OPENSSL_bytes(dh_p);
    free_OPENSSL_bytes(dh_g);
    free_DHparam_handle(dh);
    return rc;
}
