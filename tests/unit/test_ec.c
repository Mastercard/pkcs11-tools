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

int main(void)
{
    TH_RUN(test_ec_curve_roundtrip);
    TH_RUN(test_ec_curve_by_oid);
    TH_RUN(test_ec_curve_unknown);
    TH_RUN(test_ec_curve_non_ec_oid);

    return TH_SUMMARY();
}
