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
 * Ed25519 / Ed448 KEYMGMT and SIGNATURE for the pkcs11tools provider.
 *
 * EdDSA in OpenSSL is one-shot only (PureEdDSA, mdname must be NULL).
 * The PKCS#11 mechanism used is CKM_EDDSA.
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


/* ------------------------------------------------------------------------- */
/* KEYMGMT                                                                    */
/* ------------------------------------------------------------------------- */

/* Custom OSSL_PARAM key used by pkcs11_provider_make_pkey() to inject a
 * pre-built pkcs11_keydata template into our import() callback. */
#define PKCS11_KEYDATA_PARAM "pkcs11-keydata-ptr"

/*
 * keymgmt query_operation_name() callback (Ed25519): return the canonical
 * algorithm name OpenSSL uses to look up the matching SIGNATURE.
 */
static const char *eddsa_query_operation_name_ed25519(int operation_id)
{
    (void)operation_id;
    return "ED25519";
}

/*
 * keymgmt query_operation_name() callback (Ed448): return the canonical
 * algorithm name OpenSSL uses to look up the matching SIGNATURE.
 */
static const char *eddsa_query_operation_name_ed448(int operation_id)
{
    (void)operation_id;
    return "ED448";
}

/* Single-entry import_types table: only our private keydata pointer is
 * accepted (no standard pub-key bytes import is supported). */
static const OSSL_PARAM eddsa_import_types_arr[] = {
    OSSL_PARAM_octet_string(PKCS11_KEYDATA_PARAM, NULL, 0),
    OSSL_PARAM_END
};

/*
 * keymgmt import_types() callback: advertise the OSSL_PARAM keys our
 * import() understands. Key-pair selection only.
 */
static const OSSL_PARAM *eddsa_import_types(int selection)
{
    if((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
	return NULL;
    }
    return eddsa_import_types_arr;
}

/*
 * keymgmt import() callback: shared between Ed25519 and Ed448. Receives the
 * custom "pkcs11-keydata-ptr" parameter and moves its fields into the
 * framework-allocated keydata. The algo tag (set by
 * pkcs11_keymgmt_new_ed25519/ed448) is used to detect template mismatches.
 */
static int eddsa_import(void *vkey, int selection, const OSSL_PARAM params[])
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
	fprintf(stderr, "Error: pkcs11tools EdDSA import: missing or malformed %s\n",
		PKCS11_KEYDATA_PARAM);
	return 0;
    }

    src = *(pkcs11_keydata **)p->data;
    if(src == NULL || src->algo != target->algo) {
	fprintf(stderr, "Error: pkcs11tools EdDSA import: keydata template mismatch\n");
	return 0;
    }

    /* Move fields out of src into target. The caller owns and frees src. */
    target->pubkey = src->pubkey;   src->pubkey = NULL;
    target->p11ctx = src->p11ctx;
    target->hkey   = src->hkey;
    target->fake   = src->fake;
    return 1;
}

/*
 * Ed25519 keymgmt dispatch table. Most callbacks are shared with the rest
 * of the provider (free/has/match/get_params/gettable_params live in
 * pkcs11_provider_core.c); only new() and query_operation_name() are
 * algorithm-specific. The keymgmt new() pkcs11_keymgmt_new_ed25519 tags the
 * fresh keydata with PKCS11_PROV_ALGO_ED25519.
 */
const OSSL_DISPATCH pkcs11_eddsa_keymgmt_ed25519_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                    (void (*)(void))pkcs11_keymgmt_new_ed25519 },
    { OSSL_FUNC_KEYMGMT_FREE,                   (void (*)(void))pkcs11_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS,                    (void (*)(void))pkcs11_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH,                  (void (*)(void))pkcs11_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,             (void (*)(void))pkcs11_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,        (void (*)(void))pkcs11_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,   (void (*)(void))eddsa_query_operation_name_ed25519 },
    { OSSL_FUNC_KEYMGMT_IMPORT,                 (void (*)(void))eddsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,           (void (*)(void))eddsa_import_types },
    { 0, NULL }
};

/*
 * Ed448 keymgmt dispatch table. Identical shape to the Ed25519 table; only
 * the new() and query_operation_name() entries differ so the keydata gets
 * tagged with the correct algorithm and OpenSSL fetches the matching
 * Ed448 signature implementation.
 */
const OSSL_DISPATCH pkcs11_eddsa_keymgmt_ed448_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                    (void (*)(void))pkcs11_keymgmt_new_ed448 },
    { OSSL_FUNC_KEYMGMT_FREE,                   (void (*)(void))pkcs11_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS,                    (void (*)(void))pkcs11_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH,                  (void (*)(void))pkcs11_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,             (void (*)(void))pkcs11_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,        (void (*)(void))pkcs11_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,   (void (*)(void))eddsa_query_operation_name_ed448 },
    { OSSL_FUNC_KEYMGMT_IMPORT,                 (void (*)(void))eddsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,           (void (*)(void))eddsa_import_types },
    { 0, NULL }
};


/* ------------------------------------------------------------------------- */
/* SIGNATURE                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * Per-operation signature context. EdDSA has no streaming digest stage
 * (PureEdDSA hashes the message internally during sign), no AID cache
 * (the AID is a 7-byte literal), and no parameters to negotiate, so this
 * struct stays minimal.
 */
typedef struct {
    pkcs11_provctx *provctx;
    pkcs11_keydata *key;        /* not owned, lifetime tied to EVP_PKEY */
} eddsa_sigctx;

/*
 * signature newctx() callback: allocate an empty eddsa_sigctx. The propq
 * argument is unused since we never fetch a digest for EdDSA.
 */
static void *eddsa_sig_newctx(void *vprovctx, const char *propq)
{
    eddsa_sigctx *ctx;
    (void)propq;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if(ctx == NULL) {
	return NULL;
    }
    ctx->provctx = (pkcs11_provctx *)vprovctx;
    return ctx;
}

/*
 * signature freectx() callback: nothing inside the context is owned, so
 * a single OPENSSL_free is sufficient.
 */
static void eddsa_sig_freectx(void *vctx)
{
    if(vctx) {
	OPENSSL_free(vctx);
    }
}

/*
 * signature dupctx() callback: shallow byte-copy is sufficient since the
 * struct holds only non-owning pointers. EVP_DigestSignFinal dups before
 * the final pass, so this must be implemented even though there is no
 * streaming state to preserve.
 */
static void *eddsa_sig_dupctx(void *vctx)
{
    eddsa_sigctx *src = (eddsa_sigctx *)vctx;
    eddsa_sigctx *dup;
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
 * specific keydata. Unlike the other algorithms, EdDSA's init enforces
 * mdname == NULL: PureEdDSA hashes the message internally inside the HSM,
 * so passing any digest name from the caller is a usage error.
 */
static int eddsa_digest_sign_init(void *vctx, const char *mdname,
				  void *vkey, const OSSL_PARAM params[])
{
    eddsa_sigctx *ctx = (eddsa_sigctx *)vctx;
    pkcs11_keydata *key = (pkcs11_keydata *)vkey;

    (void)params;

    if(ctx == NULL || key == NULL) {
	return 0;
    }

    /* PureEdDSA only. OpenSSL's digest-sign init for EdDSA passes mdname=NULL.
     * Reject any non-NULL/empty md name, matching the legacy behavior. */
    if(mdname != NULL && mdname[0] != '\0') {
	fprintf(stderr, "Error: pkcs11tools EdDSA: digest '%s' not supported (PureEdDSA only)\n", mdname);
	return 0;
    }

    if(key->algo != PKCS11_PROV_ALGO_ED25519 && key->algo != PKCS11_PROV_ALGO_ED448) {
	fprintf(stderr, "Error: pkcs11tools EdDSA: key algo mismatch\n");
	return 0;
    }

    ctx->key = key;
    return 1;
}

/*
 * signature digest_sign() callback: the one-shot variant invoked by
 * EVP_DigestSign() when no update/final pair is required. EdDSA registers
 * this instead of digest_sign_update / digest_sign_final because PureEdDSA
 * cannot be streamed: the entire to-be-signed message must be presented
 * in one call to C_Sign with mechanism CKM_EDDSA.
 *
 * Two-pass invocation contract:
 *   - sig == NULL: caller is querying the maximum buffer size; we return
 *     EVP_PKEY_get_size() (64 for Ed25519, 114 for Ed448).
 *   - sig != NULL: actual signing pass; runs C_SignInit + C_Sign (or
 *     fake_sign() when key->fake is set, see pkcs11_ossl_fake_sign.c).
 */
static int eddsa_digest_sign(void *vctx,
			     unsigned char *sig, size_t *siglen, size_t sigsize,
			     const unsigned char *tbs, size_t tbslen)
{
    eddsa_sigctx *ctx = (eddsa_sigctx *)vctx;
    pkcs11_keydata *key;
    CK_MECHANISM mechanism = { CKM_EDDSA, NULL_PTR, 0 };
    CK_RV rv;
    size_t needed;
    CK_ULONG p11_siglen;

    if(ctx == NULL || ctx->key == NULL || siglen == NULL) {
	fprintf(stderr, "Error: pkcs11tools EdDSA digest_sign: invalid arguments\n");
	return 0;
    }
    key = ctx->key;

    /* Required signature size from the public key (Ed25519=64, Ed448=114). */
    needed = (size_t)EVP_PKEY_get_size(key->pubkey);
    if(needed == 0) {
	fprintf(stderr, "Error: pkcs11tools EdDSA: cannot determine signature size\n");
	return 0;
    }

    if(sig == NULL) {
	*siglen = needed;
	return 1;
    }

    if(sigsize < needed) {
	fprintf(stderr, "Error: pkcs11tools EdDSA: output buffer too small (need %zu, got %zu)\n",
		needed, sigsize);
	return 0;
    }

    if(key->fake) {
	fake_sign(sig, needed);
	*siglen = needed;
	return 1;
    }

    if(key->p11ctx == NULL || key->hkey == CK_INVALID_HANDLE) {
	fprintf(stderr, "Error: pkcs11tools EdDSA: missing PKCS#11 binding\n");
	return 0;
    }

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
 * DER-encoded AlgorithmIdentifier returned via OSSL_SIGNATURE_PARAM_ALGORITHM_ID.
 *
 * For EdDSA the AlgorithmIdentifier is just the OID with no parameters,
 * per RFC 8410:
 *   AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm   OBJECT IDENTIFIER,
 *       parameters  ABSENT
 *   }
 *
 * Ed25519 OID: 1.3.101.112  -> SEQUENCE { OID 03 2B 65 70 } -> 30 05 06 03 2B 65 70
 * Ed448   OID: 1.3.101.113  -> SEQUENCE { OID 03 2B 65 71 } -> 30 05 06 03 2B 65 71
 */
static const unsigned char ed25519_aid_der[] = {
    0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70
};
static const unsigned char ed448_aid_der[] = {
    0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71
};

/*
 * signature get_ctx_params() callback: serve OSSL_SIGNATURE_PARAM_ALGORITHM_ID
 * with the constant DER blob matching the bound key's curve. No lazy
 * computation needed since the AID is fully determined by the key type.
 */
static int eddsa_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    eddsa_sigctx *ctx = (eddsa_sigctx *)vctx;
    OSSL_PARAM *p;
    const unsigned char *aid = NULL;
    size_t aid_len = 0;

    if(ctx == NULL || ctx->key == NULL) {
	return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if(p != NULL) {
	if(ctx->key->algo == PKCS11_PROV_ALGO_ED25519) {
	    aid = ed25519_aid_der;
	    aid_len = sizeof(ed25519_aid_der);
	} else if(ctx->key->algo == PKCS11_PROV_ALGO_ED448) {
	    aid = ed448_aid_der;
	    aid_len = sizeof(ed448_aid_der);
	} else {
	    return 0;
	}
	if(!OSSL_PARAM_set_octet_string(p, aid, aid_len)) {
	    return 0;
	}
    }
    return 1;
}

static const OSSL_PARAM eddsa_gettable_ctx_params_arr[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

/*
 * signature gettable_ctx_params() callback: advertise OSSL_SIGNATURE_PARAM_ALGORITHM_ID
 * as the only key we serve.
 */
static const OSSL_PARAM *eddsa_gettable_ctx_params(void *vctx, void *vprovctx)
{
    (void)vctx;
    (void)vprovctx;
    return eddsa_gettable_ctx_params_arr;
}

/*
 * Ed25519 signature dispatch table. EdDSA registers DIGEST_SIGN (one-shot),
 * not DIGEST_SIGN_UPDATE/FINAL, because PureEdDSA cannot stream. There are
 * no settable params (no digest, no padding mode, no salt length) so the
 * SET_CTX_PARAMS / SETTABLE_CTX_PARAMS slots are intentionally absent.
 */
const OSSL_DISPATCH pkcs11_eddsa_signature_ed25519_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))eddsa_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))eddsa_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))eddsa_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))eddsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,         (void (*)(void))eddsa_digest_sign },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))eddsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))eddsa_gettable_ctx_params },
    { 0, NULL }
};

/*
 * Ed448 signature dispatch table. Same callbacks as Ed25519 (the per-op
 * code is variant-agnostic and reads the variant from key->algo); a
 * separate table is required so OpenSSL's algorithm registration can map
 * the "ED448" name to a distinct OSSL_DISPATCH array.
 */
const OSSL_DISPATCH pkcs11_eddsa_signature_ed448_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))eddsa_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))eddsa_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))eddsa_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))eddsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,         (void (*)(void))eddsa_digest_sign },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))eddsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))eddsa_gettable_ctx_params },
    { 0, NULL }
};
