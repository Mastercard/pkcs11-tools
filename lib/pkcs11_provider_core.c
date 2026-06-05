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
 * Core of the in-process "pkcs11tools" OpenSSL 3 provider.
 *
 * Responsibilities:
 *  - Provide the entry point OSSL_provider_init.
 *  - Expose per-operation OSSL_ALGORITHM tables that point to per-algorithm
 *    dispatch tables defined in lib/pkcs11_provider_<algo>.c.
 *  - Provide the public helpers pkcs11_provider_install() and
 *    pkcs11_provider_make_pkey() used by the rest of pkcs11-tools.
 *  - Provide a generic keymgmt skeleton (new/free/has/match/get_params)
 *    shared by all algorithms.
 * 
 * Note that only key types that support signing (RSA, DSA, ECDSA, Ed25519, Ed448)
 * are implemented by the provider, to support signing of certificates and CSRs.
 * Other key types (DH, X25519, X448) are not supported by the provider and remain
 * the responsibility of the default provider.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "pkcs11lib.h"
#include "pkcs11_provider.h"
#include "pkcs11_provider_internal.h"


/* ------------------------------------------------------------------------- */
/* keydata helpers                                                            */
/* ------------------------------------------------------------------------- */

/*
 * Allocate a fresh pkcs11_keydata, the per-key state object carried around
 * by the provider's keymgmt. It bundles:
 *  - a back-pointer to the provider context (`provctx`),
 *  - the algorithm tag (`algo`) so dispatch can route generic callbacks,
 *  - a pubkey slot (filled later by the caller),
 *  - a PKCS#11 object handle slot (`hkey`, initialised to invalid).
 *
 * Returns NULL on allocation failure.
 */
pkcs11_keydata *pkcs11_keydata_new(pkcs11_provctx *provctx, pkcs11_prov_algo_t algo)
{
    pkcs11_keydata *kd = OPENSSL_zalloc(sizeof(*kd));
    if(kd == NULL) {
	return NULL;
    }
    kd->provctx = provctx;
    kd->algo = algo;
    kd->hkey = CK_INVALID_HANDLE;
    return kd;
}

/*
 * Release a pkcs11_keydata together with the wrapped public key (if any).
 * The PKCS#11 session/handle (`p11ctx`/`hkey`) are *not* owned by the
 * keydata and remain the caller's responsibility.
 *
 * Safe to call on NULL.
 */
void pkcs11_keydata_free(pkcs11_keydata *kd)
{
    if(kd == NULL) {
	return;
    }
    if(kd->pubkey) {
	EVP_PKEY_free(kd->pubkey);
    }
    OPENSSL_free(kd);
}


/* ------------------------------------------------------------------------- */
/* Generic keymgmt skeleton                                                   */
/* ------------------------------------------------------------------------- */

/*
 * One trivial new() per algorithm so the keymgmt knows which algo tag to
 * stamp on the keydata it produces. The provider-bound EVP_PKEY pipeline
 * always goes through pkcs11_provider_make_pkey() and EVP_PKEY_new_raw_*
 * is not used, so these are mostly placeholders for the OpenSSL framework.
 */
static void *pkcs11_keymgmt_new_generic(void *vprovctx, pkcs11_prov_algo_t algo)
{
    pkcs11_provctx *provctx = (pkcs11_provctx *)vprovctx;
    return pkcs11_keydata_new(provctx, algo);
}

/*
 * Algorithm-tagged keymgmt new() helpers exported in the per-algorithm
 * dispatch tables. OpenSSL calls them when it needs to allocate empty
 * keydata before importing parameters or comparing keys.
 */
void *pkcs11_keymgmt_new_ed25519(void *vprovctx)
{
    return pkcs11_keymgmt_new_generic(vprovctx, PKCS11_PROV_ALGO_ED25519);
}

void *pkcs11_keymgmt_new_ed448(void *vprovctx)
{
    return pkcs11_keymgmt_new_generic(vprovctx, PKCS11_PROV_ALGO_ED448);
}

/*
 * Generic keymgmt free() callback. OpenSSL passes back whatever a `new`
 * callback returned; we just route it through pkcs11_keydata_free.
 */
void pkcs11_keymgmt_free(void *vkey)
{
    pkcs11_keydata_free((pkcs11_keydata *)vkey);
}

/*
 * keymgmt has() callback: report whether the key carries the requested
 * components (`selection` is a bitmask of OSSL_KEYMGMT_SELECT_*).
 *
 * In our model the public part is held as a wrapped EVP_PKEY (`pubkey`)
 * and the "private" part is a PKCS#11 object handle (`hkey`). Either may
 * be missing depending on how the keydata was assembled.
 */
int pkcs11_keymgmt_has(const void *vkey, int selection)
{
    const pkcs11_keydata *kd = (const pkcs11_keydata *)vkey;

    if(kd == NULL) {
	return 0;
    }

    /* We always carry the public part (as a wrapped pubkey), and we
     * pretend to carry the "private" part as a PKCS#11 handle reference. */
    if((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && kd->pubkey == NULL) {
	return 0;
    }
    if((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && kd->hkey == CK_INVALID_HANDLE) {
	return 0;
    }
    return 1;
}

/*
 * keymgmt match() callback: decide whether two keydata objects describe
 * the same key, restricted to the components designated by `selection`.
 *
 *  - PUBLIC_KEY:  both wrapped pubkeys must be present and EVP_PKEY_eq().
 *  - PRIVATE_KEY: both must point to the same PKCS#11 session/handle
 *                 pair (we have no way to compare opaque tokens otherwise).
 *
 * Algorithm tag must always match.
 */
int pkcs11_keymgmt_match(const void *vkey1, const void *vkey2, int selection)
{
    const pkcs11_keydata *k1 = (const pkcs11_keydata *)vkey1;
    const pkcs11_keydata *k2 = (const pkcs11_keydata *)vkey2;

    if(k1 == NULL || k2 == NULL) {
	return 0;
    }
    if(k1->algo != k2->algo) {
	return 0;
    }
    if((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
	if(k1->pubkey == NULL || k2->pubkey == NULL) {
	    return 0;
	}
	if(EVP_PKEY_eq(k1->pubkey, k2->pubkey) != 1) {
	    return 0;
	}
    }
    if((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
	if(k1->hkey != k2->hkey || k1->p11ctx != k2->p11ctx) {
	    return 0;
	}
    }
    return 1;
}

/*
 * keymgmt get_params() callback: forward the request to the wrapped
 * public key. EVP_PKEY_get_params already knows how to populate bits,
 * security_bits, max_size, etc. for the underlying algorithm, so callers
 * get correct sizes without us reimplementing them per algorithm.
 */
int pkcs11_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
    pkcs11_keydata *kd = (pkcs11_keydata *)vkey;

    if(kd == NULL || kd->pubkey == NULL) {
	return 0;
    }
    /* Forward to the wrapped public key so callers retrieve correct
     * bits / security_bits / max_size / etc. */
    return EVP_PKEY_get_params(kd->pubkey, params) == 1 ? 1 : 0;
}

/*
 * keymgmt gettable_params() callback: advertise the OSSL_PARAM keys we
 * answer in get_params(). The libctx pointer is unused; OpenSSL just
 * needs a stable, NULL-terminated table.
 */
const OSSL_PARAM *pkcs11_keymgmt_gettable_params(void *vprovctx)
{
    /* Static superset that covers what callers typically ask for. */
    static const OSSL_PARAM gettable[] = {
	OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
	OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
	OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
	OSSL_PARAM_END
    };
    (void)vprovctx;
    return gettable;
}


/* ------------------------------------------------------------------------- */
/* OSSL_ALGORITHM tables                                                      */
/* ------------------------------------------------------------------------- */

/*
 * Per-operation algorithm tables returned by the provider's QUERY_OPERATION
 * dispatch. OpenSSL walks these tables to find a (name, properties) match
 * when callers ask for a keymgmt or signature implementation.
 *
 * Each entry maps an algorithm name to its dispatch table (defined in the
 * matching lib/pkcs11_provider_<algo>.c file). All tables must be terminated
 * by a {NULL,NULL,NULL,NULL} sentinel.
 */

static const OSSL_ALGORITHM pkcs11_keymgmt_algs[] = {
    { "RSA",     PKCS11_PROVIDER_PROPS, pkcs11_rsa_keymgmt_functions,           "PKCS#11 RSA keymgmt" },
    { "EC",      PKCS11_PROVIDER_PROPS, pkcs11_ecdsa_keymgmt_functions,         "PKCS#11 EC keymgmt" },
    { "DSA",     PKCS11_PROVIDER_PROPS, pkcs11_dsa_keymgmt_functions,           "PKCS#11 DSA keymgmt" },
    { "ED25519", PKCS11_PROVIDER_PROPS, pkcs11_eddsa_keymgmt_ed25519_functions, "PKCS#11 Ed25519 keymgmt" },
    { "ED448",   PKCS11_PROVIDER_PROPS, pkcs11_eddsa_keymgmt_ed448_functions,   "PKCS#11 Ed448 keymgmt" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pkcs11_signature_algs[] = {
    { "RSA",     PKCS11_PROVIDER_PROPS, pkcs11_rsa_signature_functions,           "PKCS#11 RSA signature" },
    { "ECDSA",   PKCS11_PROVIDER_PROPS, pkcs11_ecdsa_signature_functions,         "PKCS#11 ECDSA signature" },
    { "DSA",     PKCS11_PROVIDER_PROPS, pkcs11_dsa_signature_functions,           "PKCS#11 DSA signature" },
    { "ED25519", PKCS11_PROVIDER_PROPS, pkcs11_eddsa_signature_ed25519_functions, "PKCS#11 Ed25519 signature" },
    { "ED448",   PKCS11_PROVIDER_PROPS, pkcs11_eddsa_signature_ed448_functions,   "PKCS#11 Ed448 signature" },
    { NULL, NULL, NULL, NULL }
};


/* ------------------------------------------------------------------------- */
/* Provider dispatch                                                          */
/* ------------------------------------------------------------------------- */

/*
 * Provider QUERY_OPERATION callback: return the OSSL_ALGORITHM table that
 * answers the requested operation, or NULL when we do not implement it.
 * `*no_cache = 0` lets OpenSSL cache lookups for performance.
 */
static const OSSL_ALGORITHM *pkcs11_prov_query(void *vprovctx, int operation_id, int *no_cache)
{
    (void)vprovctx;
    *no_cache = 0;
    switch(operation_id) {
    case OSSL_OP_KEYMGMT:
	return pkcs11_keymgmt_algs;
    case OSSL_OP_SIGNATURE:
	return pkcs11_signature_algs;
    default:
	return NULL;
    }
}

/*
 * Provider TEARDOWN callback: free the per-provider context allocated in
 * pkcs11_prov_init. Called when OSSL_PROVIDER_unload runs the last
 * reference down to zero (typically via OSSL_LIB_CTX_free).
 */
static void pkcs11_prov_teardown(void *vprovctx)
{
    pkcs11_provctx *provctx = (pkcs11_provctx *)vprovctx;
    if(provctx) {
	OPENSSL_free(provctx);
    }
}

static const OSSL_DISPATCH pkcs11_prov_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))pkcs11_prov_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN,        (void (*)(void))pkcs11_prov_teardown },
    { 0, NULL }
};

/*
 * Provider entry point: standard OSSL_provider_init signature.
 *
 * Allocates a per-provider context, locates the libctx exported by the
 * core, publishes our dispatch table to OpenSSL, and hands the context
 * back. Returns 1 on success, 0 on failure.
 */
static int pkcs11_prov_init(const OSSL_CORE_HANDLE *handle,
			    const OSSL_DISPATCH *in,
			    const OSSL_DISPATCH **out,
			    void **provctx)
{
    pkcs11_provctx *ctx;

    /*
     * Locate the libctx exposed by the core via the OSSL_FUNC_CORE_GET_LIBCTX
     * dispatch, so our internal EVP_* calls run in the same context as the
     * caller and remain isolated from the global default libctx.
     */
    OSSL_LIB_CTX *(*core_get_libctx_fn)(const OSSL_CORE_HANDLE *) = NULL;
    for(; in->function_id != 0; in++) {
	if(in->function_id == OSSL_FUNC_CORE_GET_LIBCTX) {
	    core_get_libctx_fn = (OSSL_LIB_CTX *(*)(const OSSL_CORE_HANDLE *))in->function;
	    break;
	}
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if(ctx == NULL) {
	return 0;
    }
    ctx->core = handle;
    ctx->libctx = core_get_libctx_fn ? core_get_libctx_fn(handle) : NULL;

    *provctx = ctx;
    *out = pkcs11_prov_dispatch;
    return 1;
}


/* ------------------------------------------------------------------------- */
/* Public installer                                                           */
/* ------------------------------------------------------------------------- */

/*
 * Allocate a private OSSL_LIB_CTX and load both the OpenSSL `default`
 * provider (for digests and helper algorithms) and our built-in
 * `pkcs11tools` provider into it.
 *
 * Using a private libctx keeps our PKCS#11-routed signing operations
 * isolated from the global default context: callers can safely run
 * standard OpenSSL elsewhere in the process without contention or
 * side-effects.
 *
 * On success, *out_libctx receives the freshly created libctx (caller
 * must OSSL_LIB_CTX_free it once finished with the provider-bound keys)
 * and the function returns 1. On failure all partial allocations are
 * unwound and the function returns 0.
 */
int pkcs11_provider_install(OSSL_LIB_CTX **out_libctx)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *prov_default = NULL;
    OSSL_PROVIDER *prov_pkcs11  = NULL;

    if(out_libctx == NULL) {
	return 0;
    }
    *out_libctx = NULL;

    libctx = OSSL_LIB_CTX_new();
    if(libctx == NULL) {
	fprintf(stderr, "Error: OSSL_LIB_CTX_new failed\n");
	goto err;
    }

    /* Load the default provider into our private libctx so digests, default
     * keymgmts, etc. are available. */
    prov_default = OSSL_PROVIDER_load(libctx, "default");
    if(prov_default == NULL) {
	fprintf(stderr, "Error: failed to load 'default' provider into private libctx\n");
	goto err;
    }

    /* Register and load our built-in provider. */
    if(!OSSL_PROVIDER_add_builtin(libctx, PKCS11_PROVIDER_NAME, pkcs11_prov_init)) {
	fprintf(stderr, "Error: OSSL_PROVIDER_add_builtin failed for %s\n", PKCS11_PROVIDER_NAME);
	goto err;
    }
    prov_pkcs11 = OSSL_PROVIDER_load(libctx, PKCS11_PROVIDER_NAME);
    if(prov_pkcs11 == NULL) {
	fprintf(stderr, "Error: failed to load '%s' provider\n", PKCS11_PROVIDER_NAME);
	goto err;
    }

    *out_libctx = libctx;
    return 1;

err:
    if(prov_pkcs11)  { OSSL_PROVIDER_unload(prov_pkcs11); }
    if(prov_default) { OSSL_PROVIDER_unload(prov_default); }
    if(libctx)       { OSSL_LIB_CTX_free(libctx); }
    return 0;
}


/* ------------------------------------------------------------------------- */
/* Public key constructor                                                     */
/* ------------------------------------------------------------------------- */

/*
 * Map a (key_type, pubkey) pair to the corresponding pkcs11_prov_algo_t and
 * the OpenSSL algorithm name we expose to EVP_PKEY_new_from_name().
 */
static int resolve_algo(key_type_t key_type, EVP_PKEY *pubkey,
			pkcs11_prov_algo_t *algo, const char **algname)
{
    switch(key_type) {
    case ed: {
	int id = EVP_PKEY_id(pubkey);
	if(id == EVP_PKEY_ED25519) {
	    *algo = PKCS11_PROV_ALGO_ED25519;
	    *algname = "ED25519";
	    return 1;
	}
	if(id == EVP_PKEY_ED448) {
	    *algo = PKCS11_PROV_ALGO_ED448;
	    *algname = "ED448";
	    return 1;
	}
	fprintf(stderr, "Error: unsupported EdDSA variant (EVP_PKEY id=%d)\n", id);
	return 0;
    }
    case rsa:
	*algo = PKCS11_PROV_ALGO_RSA;
	*algname = "RSA";
	return 1;
    case ec:
	*algo = PKCS11_PROV_ALGO_EC;
	*algname = "EC";
	return 1;
    case dsa:
	*algo = PKCS11_PROV_ALGO_DSA;
	*algname = "DSA";
	return 1;
    default:
	fprintf(stderr, "Error: pkcs11tools provider: unsupported key type %d\n", (int)key_type);
	return 0;
    }
}

/*
 * Build a provider-bound EVP_PKEY for signing.
 *
 * Inputs:
 *   - libctx:    private libctx returned by pkcs11_provider_install().
 *   - key_type:  pkcs11-tools key family (rsa / dsa / ec / ed).
 *   - pubkey:    EVP_PKEY carrying the public key components - used by
 *                EVP layers for sizing, max_size, security_bits, etc.
 *                The function takes its own reference; caller keeps
 *                ownership of its own.
 *   - p11ctx:    PKCS#11 session/library context the signer will dispatch
 *                C_Sign calls against.
 *   - hkey:      PKCS#11 object handle of the private key.
 *   - fake:      when true, the signer skips C_Sign and emits the marker
 *                buffer (see pkcs11_ossl_fake_sign.c). Used for the `-F`
 *                option of p11req to produce a CSR template without
 *                exercising the HSM.
 *
 * Returns a freshly allocated EVP_PKEY routed through this provider, or
 * NULL on failure. Caller frees with EVP_PKEY_free().
 */
EVP_PKEY *pkcs11_provider_make_pkey(OSSL_LIB_CTX *libctx,
				    key_type_t key_type,
				    EVP_PKEY *pubkey,
				    pkcs11Context *p11ctx,
				    CK_OBJECT_HANDLE hkey,
				    bool fake)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    pkcs11_keydata *kd = NULL;
    pkcs11_provctx *provctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    pkcs11_prov_algo_t algo;
    const char *algname = NULL;

    if(libctx == NULL || pubkey == NULL) {
	fprintf(stderr, "Error: pkcs11_provider_make_pkey: NULL libctx or pubkey\n");
	return NULL;
    }

    if(!resolve_algo(key_type, pubkey, &algo, &algname)) {
	return NULL;
    }

    /* Recover our provider context from the libctx so the keydata can carry
     * a reference to it. */
    prov = OSSL_PROVIDER_load(libctx, PKCS11_PROVIDER_NAME);
    if(prov == NULL) {
	fprintf(stderr, "Error: pkcs11tools provider not loaded in libctx\n");
	goto err;
    }
    provctx = (pkcs11_provctx *)OSSL_PROVIDER_get0_provider_ctx(prov);
    /* OSSL_PROVIDER_load increments a ref count; keep the ref alive for the
     * lifetime of the key by leaking the additional load. The provider is
     * freed when OSSL_LIB_CTX_free runs. */

    kd = pkcs11_keydata_new(provctx, algo);
    if(kd == NULL) {
	fprintf(stderr, "Error: out of memory allocating pkcs11_keydata\n");
	goto err;
    }
    if(!EVP_PKEY_up_ref(pubkey)) {
	fprintf(stderr, "Error: EVP_PKEY_up_ref failed\n");
	goto err;
    }
    kd->pubkey = pubkey;
    kd->p11ctx = p11ctx;
    kd->hkey = hkey;
    kd->fake = fake;

    /*
     * Build the EVP_PKEY by routing through EVP_PKEY_fromdata: OpenSSL allocates
     * a fresh empty keydata via our keymgmt's `new`, then calls our `import`
     * with our custom OSSL_PARAM "pkcs11-keydata-ptr" carrying the pre-built
     * keydata template. The import moves the relevant fields into the
     * framework-allocated keydata, after which we discard the template.
     */
    {
	OSSL_PARAM params[2];
	pkcs11_keydata *kd_param = kd;

	params[0] = OSSL_PARAM_construct_octet_string("pkcs11-keydata-ptr",
						      &kd_param, sizeof(kd_param));
	params[1] = OSSL_PARAM_construct_end();

	pctx = EVP_PKEY_CTX_new_from_name(libctx, algname, PKCS11_PROVIDER_PROPS);
	if(pctx == NULL) {
	    fprintf(stderr, "Error: EVP_PKEY_CTX_new_from_name(%s) failed\n", algname);
	    goto err;
	}
	if(EVP_PKEY_fromdata_init(pctx) <= 0) {
	    fprintf(stderr, "Error: EVP_PKEY_fromdata_init failed for %s\n", algname);
	    goto err;
	}
	if(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
	    fprintf(stderr, "Error: EVP_PKEY_fromdata failed for %s\n", algname);
	    goto err;
	}
    }

    /* The framework's import moved fields out of `kd`. Discard the template. */
    pkcs11_keydata_free(kd);
    kd = NULL;

    EVP_PKEY_CTX_free(pctx);
    return pkey;

err:
    if(pkey) { EVP_PKEY_free(pkey); }
    if(pctx) { EVP_PKEY_CTX_free(pctx); }
    if(kd)   { pkcs11_keydata_free(kd); }
    return NULL;
}
