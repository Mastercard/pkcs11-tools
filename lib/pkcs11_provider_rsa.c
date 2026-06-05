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
 * RSA KEYMGMT and SIGNATURE for the pkcs11tools provider.
 *
 * Supports PKCS#1 v1.5 (CKM_RSA_PKCS, with DigestInfo prefix built in this
 * file) and RSA-PSS (CKM_RSA_PKCS_PSS, with PSS params translated to
 * CK_RSA_PKCS_PSS_PARAMS).
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
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

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
 * keymgmt new() callback: allocate an empty pkcs11_keydata tagged for RSA.
 * OpenSSL will subsequently call import() to fill it in.
 */
static void *rsa_keymgmt_new(void *vprovctx)
{
    pkcs11_provctx *provctx = (pkcs11_provctx *)vprovctx;
    return pkcs11_keydata_new(provctx, PKCS11_PROV_ALGO_RSA);
}

/*
 * keymgmt query_operation_name() callback: return the canonical algorithm
 * name OpenSSL uses to look up matching SIGNATURE implementations. The
 * same "RSA" name covers both PKCS#1 v1.5 and PSS modes; the choice between
 * them is made via OSSL_SIGNATURE_PARAM_PAD_MODE in set_ctx_params().
 */
static const char *rsa_query_operation_name(int operation_id)
{
    (void)operation_id;
    return "RSA";
}

/* Single-entry import_types table: only our private keydata pointer is
 * accepted (no standard n/e/d import is supported, since the actual
 * private key lives inside a PKCS#11 token). */
static const OSSL_PARAM rsa_import_types_arr[] = {
    OSSL_PARAM_octet_string(PKCS11_KEYDATA_PARAM, NULL, 0),
    OSSL_PARAM_END
};

/*
 * keymgmt import_types() callback: advertise the OSSL_PARAM keys our
 * import() understands. Key-pair selection only.
 */
static const OSSL_PARAM *rsa_import_types(int selection)
{
    if((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
	return NULL;
    }
    return rsa_import_types_arr;
}

/*
 * keymgmt import() callback: receive the custom "pkcs11-keydata-ptr"
 * parameter prepared by pkcs11_provider_make_pkey() and move its fields
 * into the framework-allocated keydata.
 */
static int rsa_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    pkcs11_keydata *target = (pkcs11_keydata *)vkey;
    const OSSL_PARAM *p;
    pkcs11_keydata *src;

    if(target == NULL || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
	return 0;
    }
    p = OSSL_PARAM_locate_const(params, PKCS11_KEYDATA_PARAM);
    if(p == NULL || p->data == NULL || p->data_size != sizeof(pkcs11_keydata *)) {
	fprintf(stderr, "Error: pkcs11tools RSA import: missing or malformed %s\n",
		PKCS11_KEYDATA_PARAM);
	return 0;
    }
    src = *(pkcs11_keydata **)p->data;
    if(src == NULL || src->algo != target->algo) {
	fprintf(stderr, "Error: pkcs11tools RSA import: keydata template mismatch\n");
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
 * RSA keymgmt dispatch table. The free/has/match/get_params/gettable_params
 * callbacks live in pkcs11_provider_core.c; only new(), query_operation_name(),
 * import() and import_types() are algorithm-specific. The same keymgmt
 * serves both PKCS#1 v1.5 and PSS signatures (the padding choice is made
 * later via OSSL_SIGNATURE_PARAM_PAD_MODE).
 */
const OSSL_DISPATCH pkcs11_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                    (void (*)(void))rsa_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE,                   (void (*)(void))pkcs11_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS,                    (void (*)(void))pkcs11_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH,                  (void (*)(void))pkcs11_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,             (void (*)(void))pkcs11_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,        (void (*)(void))pkcs11_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,   (void (*)(void))rsa_query_operation_name },
    { OSSL_FUNC_KEYMGMT_IMPORT,                 (void (*)(void))rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,           (void (*)(void))rsa_import_types },
    { 0, NULL }
};


/* ------------------------------------------------------------------------- */
/* DigestInfo prefixes for CKM_RSA_PKCS                                        */
/* ------------------------------------------------------------------------- */

/*
 * CKM_RSA_PKCS expects the input buffer to already be a DER-encoded
 * DigestInfo (per RFC 8017 EMSA-PKCS1-v1_5 step 2): the token only adds
 * the EMSA padding around it. We therefore precompute the DigestInfo prefix
 * bytes for each supported hash so digest_sign_final can prepend them to
 * the raw digest before invoking C_Sign.
 *
 * (CKM_SHAxxx_RSA_PKCS would handle hashing+DigestInfo+sign in the token,
 * but using CKM_RSA_PKCS keeps the digest computation under OpenSSL
 * control, matching the streaming model EVP_DigestSign expects.)
 */
typedef struct {
    int nid;                    /* OpenSSL digest NID (EVP_MD_type) */
    const unsigned char *prefix;
    size_t prefix_len;
    size_t digest_len;          /* expected raw digest length, sanity-checked */
} digest_prefix_t;

static const unsigned char di_sha1[]   = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};
static const unsigned char di_sha224[] = {
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c
};
static const unsigned char di_sha256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};
static const unsigned char di_sha384[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30
};
static const unsigned char di_sha512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
};

static const digest_prefix_t digest_prefixes[] = {
    { NID_sha1,   di_sha1,   sizeof(di_sha1),   20 },
    { NID_sha224, di_sha224, sizeof(di_sha224), 28 },
    { NID_sha256, di_sha256, sizeof(di_sha256), 32 },
    { NID_sha384, di_sha384, sizeof(di_sha384), 48 },
    { NID_sha512, di_sha512, sizeof(di_sha512), 64 }
};

/* Look up a precomputed DigestInfo prefix by digest NID. Returns NULL when
 * the requested digest is not supported by CKM_RSA_PKCS in this code. */
static const digest_prefix_t *find_digest_prefix(int nid)
{
    size_t i;
    for(i = 0; i < sizeof(digest_prefixes)/sizeof(digest_prefixes[0]); i++) {
	if(digest_prefixes[i].nid == nid) {
	    return &digest_prefixes[i];
	}
    }
    return NULL;
}


/* ------------------------------------------------------------------------- */
/* PSS digest -> PKCS#11 PSS parameters                                       */
/* ------------------------------------------------------------------------- */

/*
 * For CKM_RSA_PKCS_PSS, the token needs a CK_RSA_PKCS_PSS_PARAMS structure
 * carrying:
 *   - hashAlg : the hash mechanism applied to the message (CKM_SHAxxx)
 *   - mgf     : the mask-generation function variant (CKG_MGF1_SHAxxx)
 *   - sLen    : salt length in bytes
 *
 * This table maps OpenSSL digest NIDs to their PKCS#11 mech/MGF1 pair so
 * the signing path can build the params from the EVP_MD set on the sigctx.
 */
typedef struct {
    int nid;                          /* OpenSSL digest NID */
    CK_MECHANISM_TYPE hash_mech;      /* CKM_SHAxxx */
    CK_RSA_PKCS_MGF_TYPE mgf;         /* CKG_MGF1_SHAxxx */
} pss_mech_t;

static const pss_mech_t pss_mechs[] = {
    { NID_sha1,   CKM_SHA_1,  CKG_MGF1_SHA1 },
    { NID_sha224, CKM_SHA224, CKG_MGF1_SHA224 },
    { NID_sha256, CKM_SHA256, CKG_MGF1_SHA256 },
    { NID_sha384, CKM_SHA384, CKG_MGF1_SHA384 },
    { NID_sha512, CKM_SHA512, CKG_MGF1_SHA512 }
};

/* Look up the PSS hash/MGF1 pair for a given digest NID. Returns NULL when
 * the digest is not supported by this PSS implementation. */
static const pss_mech_t *find_pss_mech(int nid)
{
    size_t i;
    for(i = 0; i < sizeof(pss_mechs)/sizeof(pss_mechs[0]); i++) {
	if(pss_mechs[i].nid == nid) {
	    return &pss_mechs[i];
	}
    }
    return NULL;
}


/* ------------------------------------------------------------------------- */
/* SIGNATURE                                                                  */
/* ------------------------------------------------------------------------- */

/* RSA padding mode bound to the per-operation context. Selected by the
 * caller via OSSL_SIGNATURE_PARAM_PAD_MODE in set_ctx_params(). */
typedef enum {
    RSA_PAD_PKCS1 = 0,
    RSA_PAD_PSS
} rsa_pad_mode_t;

/*
 * Per-operation signature context. Carries the digest stream state, the
 * padding mode and PSS parameters, and a cached AlgorithmIdentifier. The
 * pkcs11_keydata pointer is non-owning (its lifetime is tied to the
 * EVP_PKEY passed to digest_sign_init).
 */
typedef struct {
    pkcs11_provctx *provctx;
    pkcs11_keydata *key;        /* not owned */
    char *propq;
    EVP_MD *md;                 /* owned */
    EVP_MD *mgf1_md;            /* owned, for PSS */
    EVP_MD_CTX *mdctx;          /* owned, used during digest_sign_update */
    rsa_pad_mode_t pad_mode;
    int saltlen;                /* PSS salt length, or -1 for "max" */
    unsigned char *aid_der;     /* cached AlgorithmIdentifier DER */
    size_t aid_der_len;
} rsa_sigctx;

/* Forward declaration: init forwards params to set_ctx_params, defined below. */
static int rsa_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

/*
 * signature newctx() callback: allocate a fresh rsa_sigctx with default
 * padding (PKCS#1 v1.5) and saltlen=-1 ("max"). The optional propq is
 * duplicated so subsequent EVP_MD_fetch calls can scope to the same
 * provider as the rest of the operation.
 */
static void *rsa_sig_newctx(void *vprovctx, const char *propq)
{
    rsa_sigctx *ctx = OPENSSL_zalloc(sizeof(*ctx));
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
    ctx->pad_mode = RSA_PAD_PKCS1;
    ctx->saltlen = -1;
    return ctx;
}

/*
 * signature freectx() callback: release every owned field, then the ctx.
 * Safe to call on NULL.
 */
static void rsa_sig_freectx(void *vctx)
{
    rsa_sigctx *ctx = (rsa_sigctx *)vctx;
    if(ctx == NULL) {
	return;
    }
    OPENSSL_free(ctx->propq);
    EVP_MD_free(ctx->md);
    EVP_MD_free(ctx->mgf1_md);
    EVP_MD_CTX_free(ctx->mdctx);
    OPENSSL_free(ctx->aid_der);
    OPENSSL_free(ctx);
}

/*
 * signature dupctx() callback: deep-copy the context including the
 * streaming digest state. Required because EVP_DigestSignFinal dups the
 * provider context before the final sign call so the caller can keep the
 * original alive; we must mirror the mdctx state for the dup to produce
 * the correct signature.
 */
static void *rsa_sig_dupctx(void *vctx)
{
    rsa_sigctx *src = (rsa_sigctx *)vctx;
    rsa_sigctx *dup;
    if(src == NULL) {
	return NULL;
    }
    dup = OPENSSL_zalloc(sizeof(*dup));
    if(dup == NULL) {
	return NULL;
    }
    dup->provctx = src->provctx;
    dup->key = src->key;
    dup->pad_mode = src->pad_mode;
    dup->saltlen = src->saltlen;
    if(src->propq) {
	dup->propq = OPENSSL_strdup(src->propq);
	if(dup->propq == NULL) goto err;
    }
    if(src->md) {
	dup->md = src->md;
	EVP_MD_up_ref(dup->md);
    }
    if(src->mgf1_md) {
	dup->mgf1_md = src->mgf1_md;
	EVP_MD_up_ref(dup->mgf1_md);
    }
    /*
     * Duplicate the streaming digest state. EVP_DigestSignFinal dupes the
     * provider context before the final sign call so the caller can keep
     * the original alive; we must mirror the mdctx state for the dup to be
     * usable, otherwise the final call sees no accumulated data.
     */
    if(src->mdctx) {
	dup->mdctx = EVP_MD_CTX_new();
	if(dup->mdctx == NULL) goto err;
	if(EVP_MD_CTX_copy_ex(dup->mdctx, src->mdctx) <= 0) goto err;
    }
    return dup;
err:
    rsa_sig_freectx(dup);
    return NULL;
}

/*
 * Internal helper: fetch the EVP_MD object identified by `mdname` from our
 * provider's libctx and replace ctx->md with the freshly fetched one.
 */
static int rsa_sig_setup_md(rsa_sigctx *ctx, const char *mdname)
{
    OSSL_LIB_CTX *libctx = ctx->provctx ? ctx->provctx->libctx : NULL;
    EVP_MD *md;

    if(mdname == NULL || mdname[0] == '\0') {
	fprintf(stderr, "Error: pkcs11tools RSA: missing digest name\n");
	return 0;
    }
    md = EVP_MD_fetch(libctx, mdname, ctx->propq);
    if(md == NULL) {
	fprintf(stderr, "Error: pkcs11tools RSA: cannot fetch digest '%s'\n", mdname);
	return 0;
    }
    EVP_MD_free(ctx->md);
    ctx->md = md;
    return 1;
}

/*
 * signature digest_sign_init() callback: bind the per-operation ctx to a
 * specific keydata, optionally configure the digest by name, and accept
 * any standard OSSL_PARAM tweaks (padding mode, MGF1 digest, salt length)
 * by forwarding them to set_ctx_params.
 *
 * Re-allocates the streaming EVP_MD_CTX so calling digest_sign_init twice
 * on the same sigctx is safe.
 */
static int rsa_digest_sign_init(void *vctx, const char *mdname,
				void *vkey, const OSSL_PARAM params[])
{
    rsa_sigctx *ctx = (rsa_sigctx *)vctx;
    pkcs11_keydata *key = (pkcs11_keydata *)vkey;

    if(ctx == NULL || key == NULL || key->algo != PKCS11_PROV_ALGO_RSA) {
	return 0;
    }
    ctx->key = key;
    if(mdname != NULL && !rsa_sig_setup_md(ctx, mdname)) {
	return 0;
    }
    /* Reset cached AID; will be regenerated when queried. */
    OPENSSL_free(ctx->aid_der);
    ctx->aid_der = NULL;
    ctx->aid_der_len = 0;

    /* Re-create the streaming digest context. */
    EVP_MD_CTX_free(ctx->mdctx);
    ctx->mdctx = EVP_MD_CTX_new();
    if(ctx->mdctx == NULL) {
	return 0;
    }
    if(ctx->md && EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL) <= 0) {
	return 0;
    }
    /* Apply caller-supplied parameters (padding, mgf, saltlen, ...) by
     * forwarding them through our standard set_ctx_params handler. */
    if(params != NULL && !rsa_set_ctx_params(ctx, params)) {
	return 0;
    }
    return 1;
}

/*
 * signature digest_sign_update() callback: feed `data`/`datalen` into the
 * streaming digest. Pure forwarding to EVP_DigestUpdate.
 */
static int rsa_digest_sign_update(void *vctx, const unsigned char *data, size_t datalen)
{
    rsa_sigctx *ctx = (rsa_sigctx *)vctx;
    if(ctx == NULL || ctx->mdctx == NULL) {
	return 0;
    }
    return EVP_DigestUpdate(ctx->mdctx, data, datalen) > 0 ? 1 : 0;
}

/* Modulus size in bytes for the bound key, used both as the C_Sign output
 * buffer size and as the upper bound for the PSS "max" salt length. */
static size_t rsa_modulus_bytes(pkcs11_keydata *key)
{
    if(key == NULL || key->pubkey == NULL) {
	return 0;
    }
    return (size_t)EVP_PKEY_get_size(key->pubkey);
}

/*
 * PKCS#1 v1.5 sign helper: prepend the precomputed DigestInfo prefix to
 * the raw digest, then submit the resulting buffer to the token via
 * CKM_RSA_PKCS. The token applies EMSA-PKCS1-v1_5 padding and the modular
 * exponentiation; we do the EMSA preimage construction here.
 *
 * Returns 1 on success with *siglen updated. When key->fake is set the HSM
 * call is skipped and a synthetic +(+FAKE++) marker is written instead
 * (see pkcs11_ossl_fake_sign.c).
 */
static int rsa_do_sign_pkcs1(rsa_sigctx *ctx,
			     const unsigned char *digest, size_t digest_len,
			     unsigned char *sig, size_t *siglen)
{
    const digest_prefix_t *dp;
    unsigned char buf[128];     /* prefix (≤19) + digest (≤64) */
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL_PTR, 0 };
    CK_RV rv;
    CK_ULONG p11_siglen;
    pkcs11_keydata *key = ctx->key;
    int md_nid;

    if(ctx->md == NULL) {
	fprintf(stderr, "Error: pkcs11tools RSA PKCS#1: digest not set\n");
	return 0;
    }
    md_nid = EVP_MD_type(ctx->md);
    dp = find_digest_prefix(md_nid);
    if(dp == NULL) {
	fprintf(stderr, "Error: pkcs11tools RSA PKCS#1: unsupported digest nid=%d\n", md_nid);
	return 0;
    }
    if(digest_len != dp->digest_len) {
	fprintf(stderr, "Error: pkcs11tools RSA PKCS#1: digest length mismatch %zu != %zu\n",
		digest_len, dp->digest_len);
	return 0;
    }
    if(dp->prefix_len + digest_len > sizeof(buf)) {
	fprintf(stderr, "Error: pkcs11tools RSA PKCS#1: DigestInfo too large\n");
	return 0;
    }
    memcpy(buf, dp->prefix, dp->prefix_len);
    memcpy(buf + dp->prefix_len, digest, digest_len);

    if(key->fake) {
	fake_sign(sig, *siglen);
	return 1;
    }
    rv = key->p11ctx->FunctionList.C_SignInit(key->p11ctx->Session, &mech, key->hkey);
    if(rv != CKR_OK) {
	pkcs11_error(rv, "C_SignInit");
	return 0;
    }
    p11_siglen = (CK_ULONG)*siglen;
    rv = key->p11ctx->FunctionList.C_Sign(key->p11ctx->Session,
					  buf, (CK_ULONG)(dp->prefix_len + digest_len),
					  sig, &p11_siglen);
    if(rv != CKR_OK) {
	pkcs11_error(rv, "C_Sign");
	return 0;
    }
    *siglen = (size_t)p11_siglen;
    return 1;
}

/*
 * RSA-PSS sign helper: build CK_RSA_PKCS_PSS_PARAMS from the sigctx, then
 * submit the raw digest (no DigestInfo wrapping for PSS) to the token via
 * CKM_RSA_PKCS_PSS. The token performs EMSA-PSS encoding and the modular
 * exponentiation.
 *
 * Salt length resolution:
 *   -1 ("max") -> modulus_len - hash_len - 2
 *   any other  -> used verbatim
 *
 * Constraint: the legacy implementation requires mgf1_digest == digest;
 * any other combination is rejected to avoid producing signatures the
 * verifier (which infers MGF1 from the AID encoding below) cannot validate.
 */
static int rsa_do_sign_pss(rsa_sigctx *ctx,
			   const unsigned char *digest, size_t digest_len,
			   unsigned char *sig, size_t *siglen)
{
    const pss_mech_t *pm;
    CK_RSA_PKCS_PSS_PARAMS pss_params;
    CK_MECHANISM mech;
    CK_RV rv;
    CK_ULONG p11_siglen;
    pkcs11_keydata *key = ctx->key;
    int md_nid;
    int saltlen;
    size_t modulus_len;
    const EVP_MD *mgf1 = ctx->mgf1_md ? ctx->mgf1_md : ctx->md;

    if(ctx->md == NULL) {
	fprintf(stderr, "Error: pkcs11tools RSA-PSS: digest not set\n");
	return 0;
    }
    md_nid = EVP_MD_type(ctx->md);
    pm = find_pss_mech(md_nid);
    if(pm == NULL) {
	fprintf(stderr, "Error: pkcs11tools RSA-PSS: unsupported digest nid=%d\n", md_nid);
	return 0;
    }
    if(EVP_MD_type(mgf1) != md_nid) {
	/* The legacy implementation assumes mgf1 == digest. */
	fprintf(stderr, "Error: pkcs11tools RSA-PSS: mgf1 digest must equal signing digest\n");
	return 0;
    }
    if(digest_len != (size_t)EVP_MD_size(ctx->md)) {
	fprintf(stderr, "Error: pkcs11tools RSA-PSS: digest length mismatch\n");
	return 0;
    }

    modulus_len = rsa_modulus_bytes(key);
    if(modulus_len == 0) {
	fprintf(stderr, "Error: pkcs11tools RSA-PSS: cannot determine modulus size\n");
	return 0;
    }

    /* Resolve saltlen: -1 (MAX) → modulus - hash - 2 */
    if(ctx->saltlen == -1) {
	if(modulus_len <= digest_len + 2) {
	    fprintf(stderr, "Error: pkcs11tools RSA-PSS: modulus too small for digest\n");
	    return 0;
	}
	saltlen = (int)(modulus_len - digest_len - 2);
    } else {
	saltlen = ctx->saltlen;
    }

    pss_params.hashAlg = pm->hash_mech;
    pss_params.mgf     = pm->mgf;
    pss_params.sLen    = (CK_ULONG)saltlen;
    mech.mechanism      = CKM_RSA_PKCS_PSS;
    mech.pParameter     = &pss_params;
    mech.ulParameterLen = sizeof(pss_params);

    if(key->fake) {
	*siglen = modulus_len;
	fake_sign(sig, modulus_len);
	return 1;
    }
    rv = key->p11ctx->FunctionList.C_SignInit(key->p11ctx->Session, &mech, key->hkey);
    if(rv != CKR_OK) {
	pkcs11_error(rv, "C_SignInit");
	return 0;
    }
    p11_siglen = (CK_ULONG)*siglen;
    rv = key->p11ctx->FunctionList.C_Sign(key->p11ctx->Session,
					  (CK_BYTE_PTR)digest, (CK_ULONG)digest_len,
					  sig, &p11_siglen);
    if(rv != CKR_OK) {
	pkcs11_error(rv, "C_Sign");
	return 0;
    }
    *siglen = (size_t)p11_siglen;
    return 1;
}

/*
 * signature digest_sign_final() callback: finalize the streaming digest,
 * then dispatch to either rsa_do_sign_pkcs1 or rsa_do_sign_pss based on
 * the configured padding mode.
 *
 * Two-pass invocation contract:
 *   - sig == NULL: caller is querying the signature size; we return the
 *     RSA modulus size and leave the digest state intact.
 *   - sig != NULL: actual signing pass; the digest is finalized and the
 *     result fed to the per-padding helper.
 */
static int rsa_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    rsa_sigctx *ctx = (rsa_sigctx *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    size_t needed;

    if(ctx == NULL || ctx->key == NULL || ctx->mdctx == NULL || siglen == NULL) {
	return 0;
    }
    needed = rsa_modulus_bytes(ctx->key);
    if(needed == 0) {
	return 0;
    }
    if(sig == NULL) {
	*siglen = needed;
	return 1;
    }
    if(sigsize < needed) {
	fprintf(stderr, "Error: pkcs11tools RSA: sig buffer too small (need %zu, got %zu)\n",
		needed, sigsize);
	return 0;
    }
    if(EVP_DigestFinal_ex(ctx->mdctx, digest, &digest_len) <= 0) {
	return 0;
    }
    *siglen = needed;
    switch(ctx->pad_mode) {
    case RSA_PAD_PKCS1:
	return rsa_do_sign_pkcs1(ctx, digest, digest_len, sig, siglen);
    case RSA_PAD_PSS:
	return rsa_do_sign_pss(ctx, digest, digest_len, sig, siglen);
    default:
	return 0;
    }
}


/* ------------------------------------------------------------------------- */
/* AlgorithmIdentifier encoding                                               */
/* ------------------------------------------------------------------------- */

/*
 * The OSSL_SIGNATURE_PARAM_ALGORITHM_ID parameter feeds the outer
 * signatureAlgorithm field of X.509 certificates and PKCS#10 CSRs.
 *
 * For PKCS#1 v1.5 the AID is a SEQUENCE { algorithm = sha<x>WithRSAEncryption,
 *                                          parameters = NULL }.
 *
 * For PSS (RFC 4055) the AID is a SEQUENCE { algorithm = id-RSASSA-PSS,
 *                                             parameters = RSASSA-PSS-params },
 * where RSASSA-PSS-params is itself a SEQUENCE of [0] hashAlgorithm,
 * [1] maskGenAlgorithm, [2] saltLength, [3] trailerField (each tagged
 * EXPLICIT and OMITTED if equal to its default).
 */

/*
 * Build the PKCS#1 v1.5 AlgorithmIdentifier DER encoding from the digest
 * configured on `ctx`. The composite signature OID (sha<x>WithRSAEncryption)
 * is resolved from (digest_nid, NID_rsaEncryption) via the OBJ subsystem.
 * On success returns 1 and stores a heap-allocated DER blob in *out (caller
 * frees with OPENSSL_free).
 */
static int rsa_compute_aid_pkcs1(rsa_sigctx *ctx, unsigned char **out, size_t *out_len)
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
    if(!OBJ_find_sigid_by_algs(&sigid, md_nid, NID_rsaEncryption)) {
	fprintf(stderr, "Error: pkcs11tools RSA PKCS#1: no sigid for md %d\n", md_nid);
	return 0;
    }
    alg = X509_ALGOR_new();
    if(alg == NULL) {
	return 0;
    }
    if(!X509_ALGOR_set0(alg, OBJ_nid2obj(sigid), V_ASN1_NULL, NULL)) {
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

/*
 * Build the RSASSA-PSS AlgorithmIdentifier DER encoding from the digest,
 * MGF1 digest and salt length configured on `ctx`. Implementation steps:
 *   1. Allocate an RSA_PSS_PARAMS structure and populate its three
 *      OPTIONAL fields (hashAlgorithm, maskGenAlgorithm, saltLength).
 *      Default values per RFC 4055 (SHA-1 / MGF1+SHA-1 / 20) are OMITTED
 *      so the generated DER is canonical.
 *   2. The maskGenAlgorithm itself wraps an inner AlgorithmIdentifier(mgf1_md)
 *      as its OCTET-STRING parameter; we serialise that inner AlgId first
 *      and embed the bytes as an ASN.1 SEQUENCE inside the outer mgf1 AlgId.
 *   3. Serialise RSASSA-PSS-params, then wrap the bytes in an outer
 *      AlgorithmIdentifier whose algorithm field is id-RSASSA-PSS.
 *
 * On success returns 1 and stores a heap-allocated DER blob in *out
 * (caller frees with OPENSSL_free).
 */
static int rsa_compute_aid_pss(rsa_sigctx *ctx, unsigned char **out, size_t *out_len)
{
    /*
     * Build:
     *   AlgorithmIdentifier {
     *       algorithm  = id-RSASSA-PSS,
     *       parameters = SEQUENCE OF RSASSA-PSS-params {
     *           [0] hashAlgorithm    = AlgId(md),
     *           [1] maskGenAlgorithm = AlgId(id-mgf1, params=AlgId(mgf1_md)),
     *           [2] saltLength       = saltlen,
     *           [3] trailerField     = 1 (default)
     *       }
     *   }
     */
    RSA_PSS_PARAMS *pss = NULL;
    X509_ALGOR *mgf1_inner = NULL;
    X509_ALGOR *outer = NULL;
    unsigned char *mgf1_der = NULL;
    int mgf1_derlen = 0;
    unsigned char *pss_der = NULL;
    int pss_derlen = 0;
    unsigned char *out_der = NULL;
    int out_derlen = 0;
    ASN1_STRING *seq_str = NULL;
    ASN1_TYPE *param_type = NULL;
    int rc = 0;
    size_t modulus_len;
    int saltlen;
    const EVP_MD *mgf1 = ctx->mgf1_md ? ctx->mgf1_md : ctx->md;

    if(ctx->md == NULL) {
	return 0;
    }
    modulus_len = rsa_modulus_bytes(ctx->key);
    if(modulus_len == 0) {
	return 0;
    }
    if(ctx->saltlen == -1) {
	if(modulus_len <= (size_t)EVP_MD_size(ctx->md) + 2) {
	    return 0;
	}
	saltlen = (int)(modulus_len - EVP_MD_size(ctx->md) - 2);
    } else {
	saltlen = ctx->saltlen;
    }

    pss = RSA_PSS_PARAMS_new();
    if(pss == NULL) {
	goto err;
    }

    /* hashAlgorithm (omit if SHA-1) */
    if(EVP_MD_type(ctx->md) != NID_sha1) {
	pss->hashAlgorithm = X509_ALGOR_new();
	if(pss->hashAlgorithm == NULL ||
	   !X509_ALGOR_set0(pss->hashAlgorithm, OBJ_nid2obj(EVP_MD_type(ctx->md)),
			    V_ASN1_NULL, NULL)) {
	    goto err;
	}
    }

    /* maskGenAlgorithm */
    mgf1_inner = X509_ALGOR_new();
    if(mgf1_inner == NULL ||
       !X509_ALGOR_set0(mgf1_inner, OBJ_nid2obj(EVP_MD_type(mgf1)),
			V_ASN1_NULL, NULL)) {
	goto err;
    }
    mgf1_derlen = i2d_X509_ALGOR(mgf1_inner, &mgf1_der);
    if(mgf1_derlen <= 0) {
	goto err;
    }
    pss->maskGenAlgorithm = X509_ALGOR_new();
    if(pss->maskGenAlgorithm == NULL) {
	goto err;
    }
    {
	ASN1_STRING *mgf1_seq = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
	ASN1_TYPE   *mgf1_param = ASN1_TYPE_new();
	if(mgf1_seq == NULL || mgf1_param == NULL ||
	   !ASN1_STRING_set(mgf1_seq, mgf1_der, mgf1_derlen)) {
	    ASN1_STRING_free(mgf1_seq);
	    ASN1_TYPE_free(mgf1_param);
	    goto err;
	}
	ASN1_TYPE_set(mgf1_param, V_ASN1_SEQUENCE, mgf1_seq);
	pss->maskGenAlgorithm->algorithm = OBJ_nid2obj(NID_mgf1);
	pss->maskGenAlgorithm->parameter = mgf1_param;
    }

    /* saltLength (omit if 20, the default) */
    if(saltlen != 20) {
	pss->saltLength = ASN1_INTEGER_new();
	if(pss->saltLength == NULL || !ASN1_INTEGER_set(pss->saltLength, saltlen)) {
	    goto err;
	}
    }

    pss_derlen = i2d_RSA_PSS_PARAMS(pss, &pss_der);
    if(pss_derlen <= 0) {
	goto err;
    }

    /* Outer AlgorithmIdentifier { rsassaPss, SEQUENCE (PSS-params) } */
    outer = X509_ALGOR_new();
    seq_str = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
    param_type = ASN1_TYPE_new();
    if(outer == NULL || seq_str == NULL || param_type == NULL) {
	goto err;
    }
    if(!ASN1_STRING_set(seq_str, pss_der, pss_derlen)) {
	goto err;
    }
    ASN1_TYPE_set(param_type, V_ASN1_SEQUENCE, seq_str);
    seq_str = NULL;
    outer->algorithm = OBJ_nid2obj(NID_rsassaPss);
    outer->parameter = param_type;
    param_type = NULL;

    out_derlen = i2d_X509_ALGOR(outer, &out_der);
    if(out_derlen <= 0) {
	goto err;
    }
    *out = out_der;
    *out_len = (size_t)out_derlen;
    out_der = NULL;
    rc = 1;

err:
    OPENSSL_free(out_der);
    OPENSSL_free(pss_der);
    OPENSSL_free(mgf1_der);
    X509_ALGOR_free(outer);
    X509_ALGOR_free(mgf1_inner);
    RSA_PSS_PARAMS_free(pss);
    ASN1_STRING_free(seq_str);
    ASN1_TYPE_free(param_type);
    return rc;
}


/* ------------------------------------------------------------------------- */
/* SIGNATURE params                                                           */
/* ------------------------------------------------------------------------- */

/*
 * signature get_ctx_params() callback: serve OSSL_SIGNATURE_PARAM_ALGORITHM_ID
 * (consulted by X509_sign_ctx() / X509_REQ_sign_ctx()). The encoded AID is
 * computed lazily on first request and cached on the sigctx; any subsequent
 * change to digest / padding / mgf1 / saltlen invalidates the cache.
 */
static int rsa_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    rsa_sigctx *ctx = (rsa_sigctx *)vctx;
    OSSL_PARAM *p;

    if(ctx == NULL) {
	return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if(p != NULL) {
	if(ctx->aid_der == NULL) {
	    int ok = (ctx->pad_mode == RSA_PAD_PSS)
		? rsa_compute_aid_pss(ctx, &ctx->aid_der, &ctx->aid_der_len)
		: rsa_compute_aid_pkcs1(ctx, &ctx->aid_der, &ctx->aid_der_len);
	    if(!ok) {
		return 0;
	    }
	}
	if(!OSSL_PARAM_set_octet_string(p, ctx->aid_der, ctx->aid_der_len)) {
	    return 0;
	}
    }
    return 1;
}

static const OSSL_PARAM rsa_gettable_ctx_params_arr[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

/*
 * signature gettable_ctx_params() callback: advertise OSSL_SIGNATURE_PARAM_ALGORITHM_ID
 * as the only key we serve.
 */
static const OSSL_PARAM *rsa_gettable_ctx_params(void *vctx, void *vprovctx)
{
    (void)vctx; (void)vprovctx;
    return rsa_gettable_ctx_params_arr;
}

static int rsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    rsa_sigctx *ctx = (rsa_sigctx *)vctx;
    const OSSL_PARAM *p;

    if(ctx == NULL || params == NULL) {
	return 1;
    }

    /* Padding mode */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if(p != NULL) {
	const char *name = NULL;
	int mode = 0;
	if(p->data_type == OSSL_PARAM_UTF8_STRING) {
	    name = (const char *)p->data;
	    if(name) {
		if(strcmp(name, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0) mode = RSA_PKCS1_PADDING;
		else if(strcmp(name, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0) mode = RSA_PKCS1_PSS_PADDING;
		else {
		    fprintf(stderr, "Error: pkcs11tools RSA: unsupported pad mode '%s'\n", name);
		    return 0;
		}
	    }
	} else if(p->data_type == OSSL_PARAM_INTEGER) {
	    if(!OSSL_PARAM_get_int(p, &mode)) return 0;
	} else {
	    return 0;
	}
	if(mode == RSA_PKCS1_PADDING) ctx->pad_mode = RSA_PAD_PKCS1;
	else if(mode == RSA_PKCS1_PSS_PADDING) ctx->pad_mode = RSA_PAD_PSS;
	else {
	    fprintf(stderr, "Error: pkcs11tools RSA: unsupported pad mode %d\n", mode);
	    return 0;
	}
	OPENSSL_free(ctx->aid_der); ctx->aid_der = NULL; ctx->aid_der_len = 0;
    }

    /* Digest */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if(p != NULL && p->data_type == OSSL_PARAM_UTF8_STRING) {
	if(!rsa_sig_setup_md(ctx, (const char *)p->data)) return 0;
	OPENSSL_free(ctx->aid_der); ctx->aid_der = NULL; ctx->aid_der_len = 0;
    }

    /* PSS MGF1 digest */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if(p != NULL && p->data_type == OSSL_PARAM_UTF8_STRING) {
	OSSL_LIB_CTX *libctx = ctx->provctx ? ctx->provctx->libctx : NULL;
	EVP_MD *m = EVP_MD_fetch(libctx, (const char *)p->data, ctx->propq);
	if(m == NULL) {
	    fprintf(stderr, "Error: pkcs11tools RSA: cannot fetch mgf1 digest '%s'\n",
		    (const char *)p->data);
	    return 0;
	}
	EVP_MD_free(ctx->mgf1_md);
	ctx->mgf1_md = m;
	OPENSSL_free(ctx->aid_der); ctx->aid_der = NULL; ctx->aid_der_len = 0;
    }

    /* PSS salt length */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if(p != NULL) {
	int saltlen = 0;
	if(p->data_type == OSSL_PARAM_INTEGER) {
	    if(!OSSL_PARAM_get_int(p, &saltlen)) return 0;
	} else if(p->data_type == OSSL_PARAM_UTF8_STRING) {
	    const char *s = (const char *)p->data;
	    if(strcmp(s, "max") == 0 || strcmp(s, "auto") == 0)
		saltlen = -1;
	    else if(strcmp(s, "digest") == 0)
		saltlen = ctx->md ? EVP_MD_size(ctx->md) : -1;
	    else
		saltlen = atoi(s);
	} else {
	    return 0;
	}
	ctx->saltlen = saltlen;
	OPENSSL_free(ctx->aid_der); ctx->aid_der = NULL; ctx->aid_der_len = 0;
    }

    return 1;
}

static const OSSL_PARAM rsa_settable_ctx_params_arr[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
    OSSL_PARAM_END
};

/*
 * signature settable_ctx_params() callback: advertise the OSSL_PARAM keys
 * accepted by set_ctx_params (padding mode, digest, MGF1 digest, saltlen).
 */
static const OSSL_PARAM *rsa_settable_ctx_params(void *vctx, void *vprovctx)
{
    (void)vctx; (void)vprovctx;
    return rsa_settable_ctx_params_arr;
}

/*
 * signature get_ctx_md_params() callback: forward digest-context parameter
 * queries to the underlying EVP_MD_CTX so callers (e.g. X509_get0_signature)
 * can introspect the running digest.
 */
static int rsa_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    rsa_sigctx *ctx = (rsa_sigctx *)vctx;
    if(ctx == NULL || ctx->mdctx == NULL) return 0;
    return EVP_MD_CTX_get_params(ctx->mdctx, params);
}

/*
 * signature gettable_ctx_md_params() callback: advertise the parameters
 * gettable from the underlying digest, scoped to the EVP_MD on the sigctx.
 */
static const OSSL_PARAM *rsa_gettable_ctx_md_params(void *vctx)
{
    rsa_sigctx *ctx = (rsa_sigctx *)vctx;
    if(ctx == NULL || ctx->md == NULL) return NULL;
    return EVP_MD_gettable_ctx_params(ctx->md);
}

/*
 * RSA signature dispatch table. Standard digest-sign streaming pattern
 * (init/update/final), plus get/set/gettable/settable_ctx_params for the
 * AlgorithmIdentifier, digest, padding mode, MGF1 digest and salt length.
 * The optional get/gettable_ctx_md_params slots forward to the underlying
 * EVP_MD_CTX so callers can introspect the running digest.
 */
const OSSL_DISPATCH pkcs11_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))rsa_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))rsa_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))rsa_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))rsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,  (void (*)(void))rsa_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,   (void (*)(void))rsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))rsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))rsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,      (void (*)(void))rsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))rsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,   (void (*)(void))rsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))rsa_gettable_ctx_md_params },
    { 0, NULL }
};
