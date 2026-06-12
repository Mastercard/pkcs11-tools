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
 * EC KEYMGMT and ECDSA SIGNATURE for the pkcs11tools provider.
 *
 * The PKCS#11 mechanism CKM_ECDSA returns the raw r||s components; this file
 * wraps them in an ECDSA_SIG and DER-encodes the result, as the standard
 * X.509 / PKCS#10 signature representation expects.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

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
 * keymgmt new() callback: allocate an empty pkcs11_keydata tagged for EC.
 * OpenSSL will subsequently call import() to fill it in.
 */
static void *ecdsa_keymgmt_new(void *vprovctx)
{
    pkcs11_provctx *provctx = (pkcs11_provctx *)vprovctx;
    return pkcs11_keydata_new(provctx, PKCS11_PROV_ALGO_EC);
}

/*
 * keymgmt query_operation_name() callback: return the canonical algorithm
 * name OpenSSL uses to look up matching SIGNATURE implementations.
 * Note: keymgmt name is "EC" (key type) but signature operation is "ECDSA".
 */
static const char *ecdsa_query_operation_name(int operation_id)
{
    (void)operation_id;
    return "ECDSA";
}

/* Single-entry import_types table: we only accept our private keydata
 * pointer parameter (no standard group/pub_point import is supported,
 * since the actual private key lives inside a PKCS#11 token). */
static const OSSL_PARAM ecdsa_import_types_arr[] = {
    OSSL_PARAM_octet_string(PKCS11_KEYDATA_PARAM, NULL, 0),
    OSSL_PARAM_END
};

/*
 * keymgmt import_types() callback: advertise the OSSL_PARAM keys our
 * import() understands. Key-pair selection only.
 */
static const OSSL_PARAM *ecdsa_import_types(int selection)
{
    if((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
	return NULL;
    }
    return ecdsa_import_types_arr;
}

/*
 * keymgmt import() callback: receive the custom "pkcs11-keydata-ptr"
 * parameter prepared by pkcs11_provider_make_pkey() and move its fields
 * into the framework-allocated keydata.
 */
static int ecdsa_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    pkcs11_keydata *target = (pkcs11_keydata *)vkey;
    const OSSL_PARAM *p;
    pkcs11_keydata *src;

    if(target == NULL || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
	return 0;
    }
    p = OSSL_PARAM_locate_const(params, PKCS11_KEYDATA_PARAM);
    if(p == NULL || p->data == NULL || p->data_size != sizeof(pkcs11_keydata *)) {
	fprintf(stderr, "Error: pkcs11tools ECDSA import: missing or malformed %s\n",
		PKCS11_KEYDATA_PARAM);
	return 0;
    }
    src = *(pkcs11_keydata **)p->data;
    if(src == NULL || src->algo != target->algo) {
	fprintf(stderr, "Error: pkcs11tools ECDSA import: keydata template mismatch\n");
	return 0;
    }
    /* Move fields out of src into target. The wrapped pubkey ownership
     * transfers; PKCS#11 session/handle/fake-flag are simple values. */
    target->pubkey = src->pubkey;   src->pubkey = NULL;
    target->p11ctx = src->p11ctx;
    target->hkey   = src->hkey;
    target->fake   = src->fake;
    return 1;
}

/*
 * EC keymgmt dispatch table. The free/has/match/get_params/gettable_params
 * callbacks live in pkcs11_provider_core.c (shared across algorithms);
 * only new(), query_operation_name(), import() and import_types() are
 * algorithm-specific.
 */
const OSSL_DISPATCH pkcs11_ecdsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                    (void (*)(void))ecdsa_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE,                   (void (*)(void))pkcs11_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS,                    (void (*)(void))pkcs11_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH,                  (void (*)(void))pkcs11_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,             (void (*)(void))pkcs11_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,        (void (*)(void))pkcs11_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,   (void (*)(void))ecdsa_query_operation_name },
    { OSSL_FUNC_KEYMGMT_IMPORT,                 (void (*)(void))ecdsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,           (void (*)(void))ecdsa_import_types },
    { 0, NULL }
};


/* ------------------------------------------------------------------------- */
/* SIGNATURE                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * Per-operation signature context. Carries the digest stream state and a
 * cached AlgorithmIdentifier, plus a non-owning pointer to the pkcs11_keydata
 * (whose lifetime is tied to the EVP_PKEY passed to digest_sign_init).
 */
typedef struct {
    pkcs11_provctx *provctx;
    pkcs11_keydata *key;        /* not owned, lifetime tied to EVP_PKEY */
    char *propq;                /* owned, may be NULL */
    EVP_MD *md;                 /* owned */
    EVP_MD_CTX *mdctx;          /* owned, accumulates the to-be-signed message */
    unsigned char *aid_der;     /* cached AlgorithmIdentifier DER */
    size_t aid_der_len;
} ecdsa_sigctx;

/* Forward declaration: digest_sign_init forwards init-time params here. */
static int ecdsa_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

/*
 * signature newctx() callback: allocate an empty ecdsa_sigctx. The optional
 * property query string is duplicated for later EVP_MD_fetch calls.
 */
static void *ecdsa_sig_newctx(void *vprovctx, const char *propq)
{
    ecdsa_sigctx *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if(ctx == NULL) {
	return NULL;
    }
    ctx->provctx = (pkcs11_provctx *)vprovctx;
    if(propq) {
	ctx->propq = OPENSSL_strdup(propq);
	if(ctx->propq == NULL) {
	    OPENSSL_free(ctx);
	    return NULL;
	}
    }
    return ctx;
}

/*
 * signature freectx() callback: release every owned field, then the ctx.
 * Safe to call on NULL.
 */
static void ecdsa_sig_freectx(void *vctx)
{
    ecdsa_sigctx *ctx = (ecdsa_sigctx *)vctx;
    if(ctx == NULL) {
	return;
    }
    OPENSSL_free(ctx->propq);
    EVP_MD_free(ctx->md);
    EVP_MD_CTX_free(ctx->mdctx);
    OPENSSL_free(ctx->aid_der);
    OPENSSL_free(ctx);
}

/*
 * signature dupctx() callback: deep-copy the context so the caller can keep
 * the original alive while we run the actual sign on the dup. Required by
 * EVP_DigestSignFinal which dups the sigctx before final.
 */
static void *ecdsa_sig_dupctx(void *vctx)
{
    ecdsa_sigctx *src = (ecdsa_sigctx *)vctx;
    ecdsa_sigctx *dup;
    if(src == NULL) {
	return NULL;
    }
    dup = OPENSSL_zalloc(sizeof(*dup));
    if(dup == NULL) {
	return NULL;
    }
    dup->provctx = src->provctx;
    dup->key = src->key;
    if(src->propq) {
	dup->propq = OPENSSL_strdup(src->propq);
	if(dup->propq == NULL) goto err;
    }
    if(src->md) {
	dup->md = src->md;
	EVP_MD_up_ref(dup->md);
    }
    /* Duplicate the streaming digest state — required so that
     * EVP_DigestSignFinal can dup the pctx and run the actual final on the
     * dup. */
    if(src->mdctx) {
	dup->mdctx = EVP_MD_CTX_new();
	if(dup->mdctx == NULL) goto err;
	if(EVP_MD_CTX_copy_ex(dup->mdctx, src->mdctx) <= 0) goto err;
    }
    return dup;
err:
    ecdsa_sig_freectx(dup);
    return NULL;
}

/*
 * Internal helper: fetch the EVP_MD object identified by `mdname` from our
 * provider's libctx and replace ctx->md with the freshly fetched one.
 */
static int ecdsa_sig_setup_md(ecdsa_sigctx *ctx, const char *mdname)
{
    OSSL_LIB_CTX *libctx = ctx->provctx ? ctx->provctx->libctx : NULL;
    EVP_MD *md;

    if(mdname == NULL || mdname[0] == '\0') {
	fprintf(stderr, "Error: pkcs11tools ECDSA: missing digest name\n");
	return 0;
    }
    md = EVP_MD_fetch(libctx, mdname, ctx->propq);
    if(md == NULL) {
	fprintf(stderr, "Error: pkcs11tools ECDSA: cannot fetch digest '%s'\n", mdname);
	return 0;
    }
    EVP_MD_free(ctx->md);
    ctx->md = md;
    return 1;
}

/*
 * signature digest_sign_init() callback: bind the per-operation ctx to a
 * specific keydata, optionally configure the digest by name, and accept
 * any standard OSSL_PARAM tweaks (forwarded to set_ctx_params).
 */
static int ecdsa_digest_sign_init(void *vctx, const char *mdname,
				  void *vkey, const OSSL_PARAM params[])
{
    ecdsa_sigctx *ctx = (ecdsa_sigctx *)vctx;
    pkcs11_keydata *key = (pkcs11_keydata *)vkey;

    if(ctx == NULL || key == NULL || key->algo != PKCS11_PROV_ALGO_EC) {
	return 0;
    }
    ctx->key = key;
    if(mdname != NULL && !ecdsa_sig_setup_md(ctx, mdname)) {
	return 0;
    }
    OPENSSL_free(ctx->aid_der);
    ctx->aid_der = NULL;
    ctx->aid_der_len = 0;

    EVP_MD_CTX_free(ctx->mdctx);
    ctx->mdctx = EVP_MD_CTX_new();
    if(ctx->mdctx == NULL) {
	return 0;
    }
    if(ctx->md && EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL) <= 0) {
	return 0;
    }
    if(params != NULL && !ecdsa_set_ctx_params(ctx, params)) {
	return 0;
    }
    return 1;
}

/*
 * signature digest_sign_update() callback: feed `data`/`datalen` into the
 * streaming digest. Pure forwarding to EVP_DigestUpdate.
 */
static int ecdsa_digest_sign_update(void *vctx, const unsigned char *data, size_t datalen)
{
    ecdsa_sigctx *ctx = (ecdsa_sigctx *)vctx;
    if(ctx == NULL || ctx->mdctx == NULL) {
	return 0;
    }
    return EVP_DigestUpdate(ctx->mdctx, data, datalen) > 0 ? 1 : 0;
}

/*
 * Convert a raw PKCS#11 ECDSA signature (r||s, two big-endian halves of
 * the same length, each equal to the curve order's byte length) into a
 * DER-encoded ECDSA-Sig-Value (SEQUENCE { INTEGER r, INTEGER s }).
 *
 * PKCS#11 returns the raw concatenation; X.509 / PKCS#10 expect the DER
 * form. Writes the encoding into `sig` (capacity `sigsize`) and stores
 * the actual length in `*siglen`.
 */
static int ecdsa_p11_sig_to_der(const unsigned char *raw, size_t rawlen,
				unsigned char *sig, size_t sigsize, size_t *siglen)
{
    ECDSA_SIG *ecsig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    int rc = 0;
    int enclen;
    unsigned char *p = sig;

    if((rawlen & 1) != 0) {
	fprintf(stderr, "Error: pkcs11tools ECDSA: raw signature has odd length %zu\n", rawlen);
	return 0;
    }
    r = BN_bin2bn(raw, (int)(rawlen / 2), NULL);
    s = BN_bin2bn(raw + rawlen / 2, (int)(rawlen / 2), NULL);
    if(r == NULL || s == NULL) {
	goto err;
    }
    ecsig = ECDSA_SIG_new();
    if(ecsig == NULL) {
	goto err;
    }
    if(!ECDSA_SIG_set0(ecsig, r, s)) {
	goto err;
    }
    r = s = NULL;       /* now owned by ecsig */

    enclen = i2d_ECDSA_SIG(ecsig, NULL);
    if(enclen <= 0 || (size_t)enclen > sigsize) {
	fprintf(stderr, "Error: pkcs11tools ECDSA: encoded sig %d > buffer %zu\n", enclen, sigsize);
	goto err;
    }
    enclen = i2d_ECDSA_SIG(ecsig, &p);
    if(enclen <= 0) {
	goto err;
    }
    *siglen = (size_t)enclen;
    rc = 1;

err:
    ECDSA_SIG_free(ecsig);
    BN_free(r);
    BN_free(s);
    return rc;
}

/*
 * signature digest_sign_final() callback: finalize the digest, send it to
 * PKCS#11 via CKM_ECDSA, then convert the raw r||s output into DER.
 *
 * Two-pass invocation contract:
 *   - sig == NULL: caller is querying the maximum buffer size; we return
 *     EVP_PKEY_get_size() (DER upper bound) and leave the operation in place.
 *   - sig != NULL: actual signing pass; runs C_SignInit + C_Sign (or
 *     fake_sign() when key->fake is set, see pkcs11_ossl_fake_sign.c).
 */
static int ecdsa_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    ecdsa_sigctx *ctx = (ecdsa_sigctx *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    unsigned char *p11sig = NULL;
    size_t p11_capacity;
    CK_ULONG p11_siglen;
    size_t needed;
    pkcs11_keydata *key;
    CK_MECHANISM mech = { CKM_ECDSA, NULL_PTR, 0 };
    CK_RV rv;
    int rc = 0;

    if(ctx == NULL || ctx->key == NULL || ctx->mdctx == NULL || siglen == NULL) {
	return 0;
    }
    key = ctx->key;

    /* Reasonable upper bound for the DER-encoded ECDSA-Sig-Value:
     * EVP_PKEY_get_size returns this. */
    needed = (size_t)EVP_PKEY_get_size(key->pubkey);
    if(needed == 0) {
	return 0;
    }
    if(sig == NULL) {
	*siglen = needed;
	return 1;
    }
    if(sigsize < needed) {
	fprintf(stderr, "Error: pkcs11tools ECDSA: sig buffer too small (need %zu, got %zu)\n",
		needed, sigsize);
	return 0;
    }
    if(EVP_DigestFinal_ex(ctx->mdctx, digest, &digest_len) <= 0) {
	return 0;
    }

    /* PKCS#11 produces raw r||s. Allocate a buffer at least as large as the
     * DER-encoded sig (it is strictly larger). */
    p11_capacity = needed;
    p11sig = OPENSSL_zalloc(p11_capacity);
    if(p11sig == NULL) {
	return 0;
    }

    if(key->fake) {
	/* p11req -F path: skip the HSM and emit the +(+FAKE++) marker. The
	 * raw signature width is 2 * |order_bytes|. */
	BIGNUM *order = NULL;
	if(EVP_PKEY_get_bn_param(key->pubkey, OSSL_PKEY_PARAM_EC_ORDER, &order) == 1 && order != NULL) {
	    p11_capacity = (size_t)BN_num_bytes(order) * 2;
	}
	if(order) BN_free(order);
	fake_sign(p11sig, p11_capacity);
	p11_siglen = (CK_ULONG)p11_capacity;
    } else {
	rv = key->p11ctx->FunctionList.C_SignInit(key->p11ctx->Session, &mech, key->hkey);
	if(rv != CKR_OK) {
	    pkcs11_error(rv, "C_SignInit");
	    goto err;
	}
	p11_siglen = (CK_ULONG)p11_capacity;
	rv = key->p11ctx->FunctionList.C_Sign(key->p11ctx->Session,
					      digest, (CK_ULONG)digest_len,
					      p11sig, &p11_siglen);
	if(rv != CKR_OK) {
	    pkcs11_error(rv, "C_Sign");
	    goto err;
	}
    }

    if(!ecdsa_p11_sig_to_der(p11sig, (size_t)p11_siglen, sig, sigsize, siglen)) {
	goto err;
    }
    rc = 1;

err:
    OPENSSL_free(p11sig);
    return rc;
}


/* ------------------------------------------------------------------------- */
/* AlgorithmIdentifier encoding                                               */
/* ------------------------------------------------------------------------- */

/* ECDSA AID: SEQUENCE { OID ecdsa-with-SHA<x>, parameters ABSENT } per
 * RFC 5754. The composite signature OID is resolved from the (digest_nid,
 * NID_X9_62_id_ecPublicKey) pair via the OBJ subsystem; result is cached. */
static int ecdsa_compute_aid(ecdsa_sigctx *ctx, unsigned char **out, size_t *out_len)
{
    int sigid = NID_undef;
    int md_nid;
    X509_ALGOR *alg = NULL;
    int derlen;
    unsigned char *der = NULL;

    if(ctx->md == NULL) {
	return 0;
    }
    md_nid = EVP_MD_type(ctx->md);
    if(!OBJ_find_sigid_by_algs(&sigid, md_nid, NID_X9_62_id_ecPublicKey)) {
	fprintf(stderr, "Error: pkcs11tools ECDSA: no sigid for md %d\n", md_nid);
	return 0;
    }
    alg = X509_ALGOR_new();
    if(alg == NULL) {
	return 0;
    }
    if(!X509_ALGOR_set0(alg, OBJ_nid2obj(sigid), V_ASN1_UNDEF, NULL)) {
	X509_ALGOR_free(alg);
	return 0;
    }
    derlen = i2d_X509_ALGOR(alg, &der);
    X509_ALGOR_free(alg);
    if(derlen <= 0) {
	return 0;
    }
    *out = der;
    *out_len = (size_t)derlen;
    return 1;
}


/* ------------------------------------------------------------------------- */
/* SIGNATURE params                                                           */
/* ------------------------------------------------------------------------- */

/*
 * signature get_ctx_params() callback: serve OSSL_SIGNATURE_PARAM_ALGORITHM_ID
 * (consulted by X509_sign_ctx() / X509_REQ_sign_ctx() to populate the
 * outer signatureAlgorithm field). Computed lazily and cached.
 */
static int ecdsa_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    ecdsa_sigctx *ctx = (ecdsa_sigctx *)vctx;
    OSSL_PARAM *p;

    if(ctx == NULL) {
	return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if(p != NULL) {
	if(ctx->aid_der == NULL) {
	    if(!ecdsa_compute_aid(ctx, &ctx->aid_der, &ctx->aid_der_len)) {
		return 0;
	    }
	}
	if(!OSSL_PARAM_set_octet_string(p, ctx->aid_der, ctx->aid_der_len)) {
	    return 0;
	}
    }
    return 1;
}

static const OSSL_PARAM ecdsa_gettable_ctx_params_arr[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

/*
 * signature gettable_ctx_params() callback: advertise the OSSL_PARAM keys
 * we serve in get_ctx_params.
 */
static const OSSL_PARAM *ecdsa_gettable_ctx_params(void *vctx, void *vprovctx)
{
    (void)vctx; (void)vprovctx;
    return ecdsa_gettable_ctx_params_arr;
}

static int ecdsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    ecdsa_sigctx *ctx = (ecdsa_sigctx *)vctx;
    const OSSL_PARAM *p;

    if(ctx == NULL || params == NULL) {
	return 1;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if(p != NULL && p->data_type == OSSL_PARAM_UTF8_STRING) {
	if(!ecdsa_sig_setup_md(ctx, (const char *)p->data)) {
	    return 0;
	}
	OPENSSL_free(ctx->aid_der); ctx->aid_der = NULL; ctx->aid_der_len = 0;
    }
    return 1;
}

static const OSSL_PARAM ecdsa_settable_ctx_params_arr[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

/*
 * signature settable_ctx_params() callback: advertise the OSSL_PARAM keys
 * accepted by set_ctx_params.
 */
static const OSSL_PARAM *ecdsa_settable_ctx_params(void *vctx, void *vprovctx)
{
    (void)vctx; (void)vprovctx;
    return ecdsa_settable_ctx_params_arr;
}

/*
 * ECDSA signature dispatch table. Standard digest-sign streaming pattern
 * (init/update/final) plus get/set/gettable/settable_ctx_params for the
 * AlgorithmIdentifier and digest-name negotiation.
 */
const OSSL_DISPATCH pkcs11_ecdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))ecdsa_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))ecdsa_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))ecdsa_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))ecdsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,  (void (*)(void))ecdsa_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,   (void (*)(void))ecdsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))ecdsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))ecdsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,      (void (*)(void))ecdsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))ecdsa_settable_ctx_params },
    { 0, NULL }
};
