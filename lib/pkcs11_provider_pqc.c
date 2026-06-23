/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2026 Mastercard
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

/*
 * ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) KEYMGMT and SIGNATURE for the
 * pkcs11tools provider.
 *
 * Like EdDSA, both algorithms are one-shot, "pure" signatures: OpenSSL never
 * passes an external digest (mdname must be NULL) and the whole to-be-signed
 * message is handed to the token in a single C_Sign call. The PKCS#11
 * mechanisms are CKM_ML_DSA and CKM_SLH_DSA respectively.
 *
 * Each parameter set (ML-DSA-44/65/87, the twelve SLH-DSA sets) is registered
 * under its own keymgmt name in pkcs11_provider_core.c, but they all share the
 * two keymgmt dispatch tables below (one per family) and a single signature
 * dispatch table. The family is recorded as the keydata algo tag; the
 * parameter-set-specific AlgorithmIdentifier is precomputed at make_pkey()
 * time and served back through OSSL_SIGNATURE_PARAM_ALGORITHM_ID.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "pkcs11lib.h"
#include "pkcs11_ossl.h"
#include "pkcs11_provider.h"
#include "pkcs11_provider_internal.h"

#if defined(HAVE_PQC_OPENSSL)

/* ------------------------------------------------------------------------- */
/* KEYMGMT                                                                    */
/* ------------------------------------------------------------------------- */

/* Custom OSSL_PARAM key used by pkcs11_provider_make_pkey() to inject a
 * pre-built pkcs11_keydata template into our import() callback. */
#define PKCS11_KEYDATA_PARAM "pkcs11-keydata-ptr"

/*
 * keymgmt query_operation_name() callback (ML-DSA family): OpenSSL fetches a
 * SIGNATURE under this name once an ML-DSA key starts a signing operation.
 * All three parameter sets resolve to the single "ML-DSA" signature, which
 * reads the actual mechanism and AID from the bound keydata.
 */
static const char *mldsa_query_operation_name(int operation_id)
{
    (void)operation_id;
    return "ML-DSA";
}

/*
 * keymgmt query_operation_name() callback (SLH-DSA family): analogous to the
 * ML-DSA one, mapping every SLH-DSA parameter set to the "SLH-DSA" signature.
 */
static const char *slhdsa_query_operation_name(int operation_id)
{
    (void)operation_id;
    return "SLH-DSA";
}

/* Single-entry import_types table: only our private keydata pointer is
 * accepted (no standard pub-key bytes import is supported). */
static const OSSL_PARAM pqc_import_types_arr[] = {
    OSSL_PARAM_octet_string(PKCS11_KEYDATA_PARAM, NULL, 0),
    OSSL_PARAM_END
};

/*
 * keymgmt import_types() callback: advertise the OSSL_PARAM keys our
 * import() understands. Key-pair selection only.
 */
static const OSSL_PARAM *pqc_import_types(int selection)
{
    if((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
	return NULL;
    }
    return pqc_import_types_arr;
}

/*
 * keymgmt import() callback: shared between ML-DSA and SLH-DSA. Receives the
 * custom "pkcs11-keydata-ptr" parameter and moves its fields (including the
 * precomputed AlgorithmIdentifier) into the framework-allocated keydata. The
 * algo tag set by pkcs11_keymgmt_new_mldsa / _slhdsa is used to detect
 * template mismatches.
 */
static int pqc_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    pkcs11_keydata *target = (pkcs11_keydata *)vkey;
    const OSSL_PARAM *p;
    pkcs11_keydata *src;

    if(target == NULL) {
	return 0;
    }
    if((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
	return 0;
    }

    p = OSSL_PARAM_locate_const(params, PKCS11_KEYDATA_PARAM);
    if(p == NULL || p->data == NULL || p->data_size != sizeof(pkcs11_keydata *)) {
	fprintf(stderr, "Error: pkcs11tools PQC import: missing or malformed %s\n",
		PKCS11_KEYDATA_PARAM);
	return 0;
    }

    src = *(pkcs11_keydata **)p->data;
    if(src == NULL || src->algo != target->algo) {
	fprintf(stderr, "Error: pkcs11tools PQC import: keydata template mismatch\n");
	return 0;
    }

    /* Move fields out of src into target. The caller owns and frees src. */
    target->pubkey = src->pubkey;   src->pubkey = NULL;
    target->p11ctx = src->p11ctx;
    target->hkey   = src->hkey;
    target->fake   = src->fake;
    target->aidlen = src->aidlen;
    if(src->aidlen > 0 && src->aidlen <= sizeof(target->aid)) {
	memcpy(target->aid, src->aid, src->aidlen);
    }
    return 1;
}

/*
 * ML-DSA keymgmt dispatch table, shared by ML-DSA-44/65/87. new() stamps the
 * keydata with PKCS11_PROV_ALGO_ML_DSA; the remaining lifecycle callbacks are
 * the generic ones from pkcs11_provider_core.c.
 */
const OSSL_DISPATCH pkcs11_mldsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                    (void (*)(void))pkcs11_keymgmt_new_mldsa },
    { OSSL_FUNC_KEYMGMT_FREE,                   (void (*)(void))pkcs11_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS,                    (void (*)(void))pkcs11_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH,                  (void (*)(void))pkcs11_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,             (void (*)(void))pkcs11_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,        (void (*)(void))pkcs11_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,   (void (*)(void))mldsa_query_operation_name },
    { OSSL_FUNC_KEYMGMT_IMPORT,                 (void (*)(void))pqc_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,           (void (*)(void))pqc_import_types },
    { 0, NULL }
};

/*
 * SLH-DSA keymgmt dispatch table, shared by all twelve SLH-DSA parameter sets.
 * Identical to the ML-DSA table except for new() (which stamps
 * PKCS11_PROV_ALGO_SLH_DSA) and query_operation_name().
 */
const OSSL_DISPATCH pkcs11_slhdsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                    (void (*)(void))pkcs11_keymgmt_new_slhdsa },
    { OSSL_FUNC_KEYMGMT_FREE,                   (void (*)(void))pkcs11_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS,                    (void (*)(void))pkcs11_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH,                  (void (*)(void))pkcs11_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,             (void (*)(void))pkcs11_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,        (void (*)(void))pkcs11_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,   (void (*)(void))slhdsa_query_operation_name },
    { OSSL_FUNC_KEYMGMT_IMPORT,                 (void (*)(void))pqc_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,           (void (*)(void))pqc_import_types },
    { 0, NULL }
};


/* ------------------------------------------------------------------------- */
/* SIGNATURE                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * Per-operation signature context. As with EdDSA there is no streaming digest
 * stage and no parameters to negotiate; the AID is cached on the keydata, so
 * this struct only needs to remember which key the operation is bound to.
 */
typedef struct {
    pkcs11_provctx *provctx;
    pkcs11_keydata *key;        /* not owned, lifetime tied to EVP_PKEY */
} pqc_sigctx;

/*
 * signature newctx() callback: allocate an empty pqc_sigctx. propq is unused
 * since we never fetch a digest.
 */
static void *pqc_sig_newctx(void *vprovctx, const char *propq)
{
    pqc_sigctx *ctx;
    (void)propq;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if(ctx == NULL) {
	return NULL;
    }
    ctx->provctx = (pkcs11_provctx *)vprovctx;
    return ctx;
}

/*
 * signature freectx() callback: nothing inside the context is owned.
 */
static void pqc_sig_freectx(void *vctx)
{
    if(vctx) {
	OPENSSL_free(vctx);
    }
}

/*
 * signature dupctx() callback: shallow byte-copy is sufficient since the
 * struct holds only non-owning pointers. EVP_DigestSignFinal dups before the
 * final pass, so this must exist even though there is no streaming state.
 */
static void *pqc_sig_dupctx(void *vctx)
{
    pqc_sigctx *src = (pqc_sigctx *)vctx;
    pqc_sigctx *dup;
    if(src == NULL) {
	return NULL;
    }
    dup = OPENSSL_zalloc(sizeof(*dup));
    if(dup == NULL) {
	return NULL;
    }
    *dup = *src;
    return dup;
}

/*
 * signature digest_sign_init() callback: bind the per-operation ctx to a
 * keydata. ML-DSA and SLH-DSA are pure signatures, so - exactly like EdDSA -
 * OpenSSL passes mdname == NULL and any non-empty digest name is a usage error.
 */
static int pqc_digest_sign_init(void *vctx, const char *mdname,
				void *vkey, const OSSL_PARAM params[])
{
    pqc_sigctx *ctx = (pqc_sigctx *)vctx;
    pkcs11_keydata *key = (pkcs11_keydata *)vkey;

    (void)params;

    if(ctx == NULL || key == NULL) {
	return 0;
    }

    if(mdname != NULL && mdname[0] != '\0') {
	fprintf(stderr, "Error: pkcs11tools PQC: digest '%s' not supported (pure signature only)\n", mdname);
	return 0;
    }

    if(key->algo != PKCS11_PROV_ALGO_ML_DSA && key->algo != PKCS11_PROV_ALGO_SLH_DSA) {
	fprintf(stderr, "Error: pkcs11tools PQC: key algo mismatch\n");
	return 0;
    }

    ctx->key = key;
    return 1;
}

/*
 * signature digest_sign() callback: the one-shot variant invoked by
 * EVP_DigestSign(). Both families register this (no update/final) because the
 * message cannot be streamed: it is presented in a single C_Sign call with
 * mechanism CKM_ML_DSA or CKM_SLH_DSA.
 *
 * Two-pass invocation contract:
 *   - sig == NULL: report the maximum signature size (EVP_PKEY_get_size()).
 *   - sig != NULL: actual signing pass (or fake_sign() when key->fake).
 */
static int pqc_digest_sign(void *vctx,
			   unsigned char *sig, size_t *siglen, size_t sigsize,
			   const unsigned char *tbs, size_t tbslen)
{
    pqc_sigctx *ctx = (pqc_sigctx *)vctx;
    pkcs11_keydata *key;
    CK_MECHANISM mechanism = { 0, NULL_PTR, 0 };
    CK_RV rv;
    size_t needed;
    CK_ULONG p11_siglen;

    if(ctx == NULL || ctx->key == NULL || siglen == NULL) {
	fprintf(stderr, "Error: pkcs11tools PQC digest_sign: invalid arguments\n");
	return 0;
    }
    key = ctx->key;

    /* Largest possible signature for this parameter set. */
    needed = (size_t)EVP_PKEY_get_size(key->pubkey);
    if(needed == 0) {
	fprintf(stderr, "Error: pkcs11tools PQC: cannot determine signature size\n");
	return 0;
    }

    if(sig == NULL) {
	*siglen = needed;
	return 1;
    }

    if(sigsize < needed) {
	fprintf(stderr, "Error: pkcs11tools PQC: output buffer too small (need %zu, got %zu)\n",
		needed, sigsize);
	return 0;
    }

    if(key->fake) {
	fake_sign(sig, needed);
	*siglen = needed;
	return 1;
    }

    if(key->p11ctx == NULL || key->hkey == CK_INVALID_HANDLE) {
	fprintf(stderr, "Error: pkcs11tools PQC: missing PKCS#11 binding\n");
	return 0;
    }

    mechanism.mechanism = (key->algo == PKCS11_PROV_ALGO_ML_DSA) ? CKM_ML_DSA : CKM_SLH_DSA;

    rv = key->p11ctx->FunctionList.C_SignInit(key->p11ctx->Session,
					      &mechanism,
					      key->hkey);
    if(rv != CKR_OK) {
	pkcs11_error(rv, "C_SignInit");
	return 0;
    }

    p11_siglen = (CK_ULONG)needed;
    rv = key->p11ctx->FunctionList.C_Sign(key->p11ctx->Session,
					  (CK_BYTE_PTR)tbs, (CK_ULONG)tbslen,
					  sig, &p11_siglen);
    if(rv != CKR_OK) {
	pkcs11_error(rv, "C_Sign");
	return 0;
    }

    *siglen = (size_t)p11_siglen;
    return 1;
}

/*
 * signature get_ctx_params() callback: serve OSSL_SIGNATURE_PARAM_ALGORITHM_ID
 * with the DER blob cached on the keydata. Unlike EdDSA there is no compact
 * literal: the AID depends on the parameter set and was computed once from the
 * public key in pkcs11_provider_make_pkey().
 */
static int pqc_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    pqc_sigctx *ctx = (pqc_sigctx *)vctx;
    OSSL_PARAM *p;

    if(ctx == NULL || ctx->key == NULL) {
	return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if(p != NULL) {
	if(ctx->key->aidlen == 0) {
	    fprintf(stderr, "Error: pkcs11tools PQC: AlgorithmIdentifier unavailable\n");
	    return 0;
	}
	if(!OSSL_PARAM_set_octet_string(p, ctx->key->aid, ctx->key->aidlen)) {
	    return 0;
	}
    }
    return 1;
}

static const OSSL_PARAM pqc_gettable_ctx_params_arr[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

/*
 * signature gettable_ctx_params() callback: advertise OSSL_SIGNATURE_PARAM_ALGORITHM_ID
 * as the only key we serve.
 */
static const OSSL_PARAM *pqc_gettable_ctx_params(void *vctx, void *vprovctx)
{
    (void)vctx;
    (void)vprovctx;
    return pqc_gettable_ctx_params_arr;
}

/*
 * Shared ML-DSA / SLH-DSA signature dispatch table. Registered under the
 * "ML-DSA" and "SLH-DSA" names in pkcs11_provider_core.c; the per-operation
 * code reads the family (mechanism) and AID from key->algo / key->aid, so a
 * single table covers both algorithms and all their parameter sets.
 */
const OSSL_DISPATCH pkcs11_pqc_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))pqc_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))pqc_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))pqc_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))pqc_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,         (void (*)(void))pqc_digest_sign },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))pqc_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))pqc_gettable_ctx_params },
    { 0, NULL }
};

#endif /* HAVE_PQC_OPENSSL */

/* EOF */
