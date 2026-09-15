/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2025 Mastercard
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
 * test_ec.c: unit tests for the EC curve-name <-> OID helpers. These are pure
 * (OpenSSL-only, no PKCS#11 token) and therefore run everywhere.
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "pkcs11lib.h"
#include "test_harness.h"

/*
 * curvename -> DER OID -> curvename must round-trip back to the canonical
 * short name for a well-known ANSI X9.62 curve.
 */
static void test_ec_curve_roundtrip(void)
{
    CK_BYTE *oid = NULL;
    CK_ULONG oidlen = 0;

    bool ok = pkcs11_ec_curvename2oid("prime256v1", &oid, &oidlen);
    TH_CHECK(ok, "prime256v1 recognised as an EC curve");
    TH_CHECK(oid != NULL && oidlen > 0, "OID DER allocated");

    if (ok && oid) {
        char name[80];
        pkcs11_ec_oid2curvename(oid, oidlen, name, sizeof name);
        TH_CHECK(strcmp(name, "prime256v1") == 0,
                 "OID decodes back to prime256v1");
        OPENSSL_free(oid);
    }
}

/* A curve given by its OID (rather than its name) is also accepted. */
static void test_ec_curve_by_oid(void)
{
    CK_BYTE *oid = NULL;
    CK_ULONG oidlen = 0;

    /* 1.3.132.0.34 == secp384r1 (Certicom arc) */
    bool ok = pkcs11_ec_curvename2oid("1.3.132.0.34", &oid, &oidlen);
    TH_CHECK(ok, "secp384r1 OID recognised as an EC curve");

    if (ok && oid) {
        char name[80];
        pkcs11_ec_oid2curvename(oid, oidlen, name, sizeof name);
        TH_CHECK(strcmp(name, "secp384r1") == 0,
                 "OID decodes to secp384r1 short name");
        OPENSSL_free(oid);
    }
}

/* A name that is not an OID at all is rejected without allocating. */
static void test_ec_curve_unknown(void)
{
    CK_BYTE *oid = NULL;
    CK_ULONG oidlen = 0;

    bool ok = pkcs11_ec_curvename2oid("definitely-not-a-curve", &oid, &oidlen);
    TH_CHECK(!ok, "bogus curve name rejected");
    TH_CHECK(oid == NULL && oidlen == 0, "nothing allocated on failure");
}

/* A valid OID that is not in an EC-curve arc is rejected. */
static void test_ec_curve_non_ec_oid(void)
{
    CK_BYTE *oid = NULL;
    CK_ULONG oidlen = 0;

    /* sha256 (2.16.840.1.101.3.4.2.1) is a valid OID but not an EC curve. */
    bool ok = pkcs11_ec_curvename2oid("sha256", &oid, &oidlen);
    TH_CHECK(!ok, "non-curve OID rejected");
    TH_CHECK(oid == NULL && oidlen == 0, "nothing allocated on failure");
}

static void test_montgomery_parameter_names(void)
{
    static const CK_BYTE oid_x25519[] = { 0x06, 0x03, 0x2b, 0x65, 0x6e };
    static const CK_BYTE oid_x448[] = { 0x06, 0x03, 0x2b, 0x65, 0x6f };
    static const CK_BYTE curve25519[] = {
        0x13, 0x0a, 'c', 'u', 'r', 'v', 'e', '2', '5', '5', '1', '9'
    };
    static const CK_BYTE curve448[] = {
        0x13, 0x08, 'c', 'u', 'r', 'v', 'e', '4', '4', '8'
    };
    static const CK_BYTE unknown_oid[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };
    static const CK_BYTE trailing_data[] = { 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x00 };
    const char *name;

    name = pkcs11_montgomery_params2name(oid_x25519, sizeof oid_x25519);
    TH_CHECK(name != NULL && strcmp(name, "X25519") == 0,
             "X25519 RFC 8410 OID is recognized");
    name = pkcs11_montgomery_params2name(oid_x448, sizeof oid_x448);
    TH_CHECK(name != NULL && strcmp(name, "X448") == 0,
             "X448 RFC 8410 OID is recognized");
    name = pkcs11_montgomery_params2name(curve25519, sizeof curve25519);
    TH_CHECK(name != NULL && strcmp(name, "X25519") == 0,
             "curve25519 PrintableString is recognized");
    name = pkcs11_montgomery_params2name(curve448, sizeof curve448);
    TH_CHECK(name != NULL && strcmp(name, "X448") == 0,
             "curve448 PrintableString is recognized");
    TH_CHECK(pkcs11_montgomery_params2name(unknown_oid,
                                            sizeof unknown_oid) == NULL,
             "non-Montgomery OID is rejected");
    TH_CHECK(pkcs11_montgomery_params2name(trailing_data,
                                            sizeof trailing_data) == NULL,
             "DER parameters with trailing data are rejected");
    TH_CHECK(pkcs11_montgomery_params2name(NULL, 0) == NULL,
             "empty Montgomery parameters are rejected");
}

static void test_montgomery_curve_generation_parameters(void)
{
    static const CK_BYTE curve25519[] = {
        0x13, 0x0a, 'c', 'u', 'r', 'v', 'e', '2', '5', '5', '1', '9'
    };
    static const CK_BYTE curve448[] = {
        0x13, 0x08, 'c', 'u', 'r', 'v', 'e', '4', '4', '8'
    };
    CK_BYTE *params = NULL;
    CK_ULONG params_len = 0;
    bool ok;

    ok = pkcs11_ex_curvename2oid("X25519", &params, &params_len, mont);
    TH_CHECK(ok && params_len == sizeof curve25519 &&
             memcmp(params, curve25519, sizeof curve25519) == 0,
             "X25519 generation uses the curve25519 PrintableString");
    OPENSSL_free(params);

    params = NULL;
    params_len = 0;
    ok = pkcs11_ex_curvename2oid("X448", &params, &params_len, mont);
    TH_CHECK(ok && params_len == sizeof curve448 &&
             memcmp(params, curve448, sizeof curve448) == 0,
             "X448 generation uses the curve448 PrintableString");
    OPENSSL_free(params);

    params = NULL;
    params_len = 0;
    ok = pkcs11_ex_curvename2oid("prime256v1", &params, &params_len, mont);
    TH_CHECK(!ok && params == NULL && params_len == 0,
             "a non-Montgomery curve is rejected for Montgomery generation");
}

static void test_montgomery_public_key_builder(void)
{
    static const unsigned char oid_x25519[] = { 0x06, 0x03, 0x2b, 0x65, 0x6e };
    static const unsigned char oid_x448[] = { 0x06, 0x03, 0x2b, 0x65, 0x6f };
    static const unsigned char x25519_public[32] = {
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
    };
    unsigned char wrapped_x25519[34] = { 0x04, 0x20 };
    unsigned char x448_public[56] = { 0x05 };
    unsigned char exported[56];
    size_t exported_len;
    EVP_PKEY *pk;

    pk = pkcs11_pkey_from_montgomery_public(oid_x25519,
                                             sizeof oid_x25519,
                                             x25519_public,
                                             sizeof x25519_public);
    TH_CHECK(pk != NULL && EVP_PKEY_is_a(pk, "X25519") == 1,
             "raw X25519 public key is constructed");
    exported_len = sizeof exported;
    TH_CHECK(pk != NULL &&
             EVP_PKEY_get_raw_public_key(pk, exported, &exported_len) == 1 &&
             exported_len == sizeof x25519_public &&
             memcmp(exported, x25519_public, exported_len) == 0,
             "constructed X25519 key preserves public bytes");
    EVP_PKEY_free(pk);

    memcpy(wrapped_x25519 + 2, x25519_public, sizeof x25519_public);
    pk = pkcs11_pkey_from_montgomery_public(oid_x25519,
                                             sizeof oid_x25519,
                                             wrapped_x25519,
                                             sizeof wrapped_x25519);
    TH_CHECK(pk != NULL && EVP_PKEY_is_a(pk, "X25519") == 1,
             "DER-wrapped X25519 public key is accepted for compatibility");
    EVP_PKEY_free(pk);

    pk = pkcs11_pkey_from_montgomery_public(oid_x448, sizeof oid_x448,
                                             x448_public, sizeof x448_public);
    TH_CHECK(pk != NULL && EVP_PKEY_is_a(pk, "X448") == 1,
             "raw X448 public key is constructed");
    EVP_PKEY_free(pk);

    pk = pkcs11_pkey_from_montgomery_public(oid_x25519,
                                             sizeof oid_x25519,
                                             x25519_public,
                                             sizeof x25519_public - 1);
    TH_CHECK(pk == NULL, "incorrect X25519 public-key length is rejected");
    EVP_PKEY_free(pk);
}

int main(void)
{
    TH_RUN(test_ec_curve_roundtrip);
    TH_RUN(test_ec_curve_by_oid);
    TH_RUN(test_ec_curve_unknown);
    TH_RUN(test_ec_curve_non_ec_oid);
    TH_RUN(test_montgomery_parameter_names);
    TH_RUN(test_montgomery_curve_generation_parameters);
    TH_RUN(test_montgomery_public_key_builder);

    return TH_SUMMARY();
}
