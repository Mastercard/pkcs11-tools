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

#ifndef __PKCS11_PROVIDER_H__
#define __PKCS11_PROVIDER_H__

#include <stdbool.h>
#include <openssl/types.h>

#include "pkcs11lib.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Public API for the in-process "pkcs11tools" OpenSSL 3 provider.
 *
 * The provider intercepts SIGNATURE operations for RSA, DSA, ECDSA, Ed25519,
 * Ed448 and routes them to the underlying PKCS#11 token via C_SignInit / C_Sign.
 * It is loaded into a private OSSL_LIB_CTX so it cannot disturb other OpenSSL
 * users in the same process.
 */

/*
 * Install the provider into a freshly created private OSSL_LIB_CTX.
 *
 * The default provider is also loaded into that libctx so non-pkcs11tools
 * algorithms (digests, etc.) keep working through it.
 *
 * On success, *out_libctx receives a libctx that the caller must release with
 * OSSL_LIB_CTX_free() once all derived objects have been freed.
 *
 * Returns 1 on success, 0 on failure.
 */
int pkcs11_provider_install(OSSL_LIB_CTX **out_libctx);

/*
 * Build an EVP_PKEY belonging to the pkcs11tools provider, wrapping a
 * default-provider public-key EVP_PKEY plus the PKCS#11 binding required
 * for signing (private-key handle, session context, fake-sign flag).
 *
 * `pubkey` must be a public-key EVP_PKEY of the matching type:
 *   - key_type == rsa  : RSA public key
 *   - key_type == dsa  : DSA public key
 *   - key_type == ec   : EC public key (P-256/P-384/P-521/...)
 *   - key_type == ed   : Ed25519 or Ed448 public key
 *
 * On success the function takes its own reference on `pubkey` (via
 * EVP_PKEY_up_ref) so the caller retains ownership of its original
 * reference and must still free it. On failure the caller's reference
 * is untouched.
 *
 * Returns a new EVP_PKEY on success (free with EVP_PKEY_free), NULL on failure.
 */
EVP_PKEY *pkcs11_provider_make_pkey(OSSL_LIB_CTX *libctx,
				    key_type_t key_type,
				    EVP_PKEY *pubkey,
				    pkcs11Context *p11ctx,
				    CK_OBJECT_HANDLE hkey,
				    bool fake);

#ifdef __cplusplus
}
#endif

#endif /* __PKCS11_PROVIDER_H__ */
