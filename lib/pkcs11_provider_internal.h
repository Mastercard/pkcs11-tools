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

#ifndef __PKCS11_PROVIDER_INTERNAL_H__
#define __PKCS11_PROVIDER_INTERNAL_H__

#include <stdbool.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/types.h>
#include <openssl/evp.h>

#include "pkcs11lib.h"

/* Provider name and property string used to fetch our algorithms. */
#define PKCS11_PROVIDER_NAME    "pkcs11tools"
#define PKCS11_PROVIDER_PROPS   "provider=" PKCS11_PROVIDER_NAME

/* Algorithm tags for the generic keymgmt/signature dispatch. */
typedef enum {
    PKCS11_PROV_ALGO_RSA = 1,
    PKCS11_PROV_ALGO_DSA,
    PKCS11_PROV_ALGO_EC,        /* ECDSA */
    PKCS11_PROV_ALGO_ED25519,
    PKCS11_PROV_ALGO_ED448
#if defined(HAVE_PQC_OPENSSL)
    ,
    PKCS11_PROV_ALGO_ML_DSA,    /* ML-DSA (FIPS 204), every parameter set */
    PKCS11_PROV_ALGO_SLH_DSA    /* SLH-DSA (FIPS 205), every parameter set */
#endif
} pkcs11_prov_algo_t;

/* Provider context. One instance per loaded provider. */
typedef struct pkcs11_provctx_st {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;       /* libctx exposed by the core */
} pkcs11_provctx;

/*
 * Per-key data carried by an EVP_PKEY whose KEYMGMT belongs to our provider.
 *
 * Holds the public key (as a default-provider EVP_PKEY, used for size/params
 * forwarding) plus the PKCS#11 binding used by the SIGNATURE operation.
 */
typedef struct pkcs11_keydata_st {
    pkcs11_provctx *provctx;
    pkcs11_prov_algo_t algo;
    EVP_PKEY *pubkey;           /* default-provider public key */
    pkcs11Context *p11ctx;
    CK_OBJECT_HANDLE hkey;
    bool fake;
#if defined(HAVE_PQC_OPENSSL)
    /* DER-encoded AlgorithmIdentifier for ML-DSA / SLH-DSA signatures,
     * computed once at make_pkey() time from the public key. The same value
     * is served back through OSSL_SIGNATURE_PARAM_ALGORITHM_ID. Left empty
     * (aidlen == 0) for the classic key types. */
    unsigned char aid[32];
    size_t aidlen;
#endif
} pkcs11_keydata;

/* Allocate a zero-initialized keydata bound to provctx. */
pkcs11_keydata *pkcs11_keydata_new(pkcs11_provctx *provctx, pkcs11_prov_algo_t algo);

/* Free a keydata (releases pubkey too). */
void pkcs11_keydata_free(pkcs11_keydata *kd);

/* Per-algorithm dispatch tables exported by per-algo files. */
extern const OSSL_DISPATCH pkcs11_eddsa_keymgmt_ed25519_functions[];
extern const OSSL_DISPATCH pkcs11_eddsa_keymgmt_ed448_functions[];
extern const OSSL_DISPATCH pkcs11_eddsa_signature_ed25519_functions[];
extern const OSSL_DISPATCH pkcs11_eddsa_signature_ed448_functions[];

extern const OSSL_DISPATCH pkcs11_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH pkcs11_rsa_signature_functions[];

extern const OSSL_DISPATCH pkcs11_ecdsa_keymgmt_functions[];
extern const OSSL_DISPATCH pkcs11_ecdsa_signature_functions[];

extern const OSSL_DISPATCH pkcs11_dsa_keymgmt_functions[];
extern const OSSL_DISPATCH pkcs11_dsa_signature_functions[];

#if defined(HAVE_PQC_OPENSSL)
/*
 * Post-Quantum dispatch tables (ML-DSA / SLH-DSA). The keymgmt tables are
 * shared by every parameter set of their family (ML-DSA-44/65/87, the twelve
 * SLH-DSA sets) and registered under each parameter-set name in
 * pkcs11_provider_core.c. A single signature table serves both families: the
 * mechanism (CKM_ML_DSA / CKM_SLH_DSA) and AlgorithmIdentifier are read from
 * the per-key pkcs11_keydata at signing time.
 */
extern const OSSL_DISPATCH pkcs11_mldsa_keymgmt_functions[];
extern const OSSL_DISPATCH pkcs11_slhdsa_keymgmt_functions[];
extern const OSSL_DISPATCH pkcs11_pqc_signature_functions[];
#endif

/*
 * Generic keymgmt helpers used by per-algorithm files.
 *
 * They centralize the "minimum viable" keymgmt: new/free/has/match/get_params.
 * Per-algorithm files only need to provide the OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME.
 */
OSSL_FUNC_keymgmt_new_fn        pkcs11_keymgmt_new_ed25519;
OSSL_FUNC_keymgmt_new_fn        pkcs11_keymgmt_new_ed448;
#if defined(HAVE_PQC_OPENSSL)
OSSL_FUNC_keymgmt_new_fn        pkcs11_keymgmt_new_mldsa;
OSSL_FUNC_keymgmt_new_fn        pkcs11_keymgmt_new_slhdsa;
#endif
OSSL_FUNC_keymgmt_free_fn       pkcs11_keymgmt_free;
OSSL_FUNC_keymgmt_has_fn        pkcs11_keymgmt_has;
OSSL_FUNC_keymgmt_match_fn      pkcs11_keymgmt_match;
OSSL_FUNC_keymgmt_get_params_fn pkcs11_keymgmt_get_params;
OSSL_FUNC_keymgmt_gettable_params_fn pkcs11_keymgmt_gettable_params;

#endif /* __PKCS11_PROVIDER_INTERNAL_H__ */
