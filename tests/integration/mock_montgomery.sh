#!/bin/sh
# Copyright (c) 2026 Mastercard
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Verify PKCS#11 v3 Montgomery public-key inspection and RFC 8410 export.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_MOCK_COMMON:?PKCS11_TESTS_MOCK_COMMON must be set by the test harness}"

command -v openssl >/dev/null 2>&1 || skip "openssl not found in PATH"

P11LS=$(p11bin p11ls)
P11OD=$(p11bin p11od)
P11CAT=$(p11bin p11cat)
P11MORE=$(p11bin p11more)
P11KEYGEN=$(p11bin p11keygen)
P11IMPORTPUBK=$(p11bin p11importpubk)

check_montgomery_keygen() {
    alg=$1
    "$P11KEYGEN" -p :::nologin -k mont -q "$alg" -i "generated-$alg" \
        >/dev/null 2>&1 || die "p11keygen failed for $alg"
}

check_montgomery_import() {
    alg=$1
    src="$WORKDIR/$alg-src.pub"

    openssl genpkey -algorithm "$alg" -out "$WORKDIR/$alg.key" \
        >/dev/null 2>&1 || die "openssl genpkey failed for $alg"
    openssl pkey -in "$WORKDIR/$alg.key" -pubout -out "$src" \
        >/dev/null 2>&1 || die "openssl pubout failed for $alg"

    # The mock validates the Montgomery template (recognized curve in
    # CKA_EC_PARAMS, raw RFC 7748 bytes in CKA_EC_POINT), so a successful
    # import proves p11importpubk produced the standards-shaped object.
    # Objects live in mock memory only, so no cross-process read-back here.
    "$P11IMPORTPUBK" -p :::nologin -f "$src" -i "imported-$alg" \
        >/dev/null 2>&1 || die "p11importpubk failed for $alg"
}

check_montgomery_public_key() {
    alg=$1
    label="mock-$alg"
    pem="$WORKDIR/$alg.pem"

    MOCK_P11_MONTGOMERY_PUBLIC=$label
    MOCK_P11_MONTGOMERY_ALG=$alg
    export MOCK_P11_MONTGOMERY_PUBLIC MOCK_P11_MONTGOMERY_ALG

    list=$("$P11LS" -p :::nologin 2>/dev/null) \
        || die "p11ls failed for $alg"
    printf '%s\n' "$list" | grep -Fqi "mont($alg)" \
        || die "p11ls did not identify $alg as a Montgomery key"

    dump=$("$P11OD" -p :::nologin "pubk/$label" 2>/dev/null) \
        || die "p11od failed for $alg"
    printf '%s\n' "$dump" | grep -q 'CKK_EC_MONTGOMERY' \
        || die "p11od did not decode CKK_EC_MONTGOMERY for $alg"
    for attr in CKA_EC_PARAMS CKA_EC_POINT CKA_DERIVE; do
        printf '%s\n' "$dump" | grep -q "$attr" \
            || die "p11od output for $alg is missing $attr"
    done

    "$P11CAT" -p :::nologin "pubk/$label" >"$pem" 2>/dev/null \
        || die "p11cat failed to export $alg"
    grep -q 'BEGIN PUBLIC KEY' "$pem" \
        || die "p11cat did not emit an SPKI PEM for $alg"
    openssl pkey -pubin -in "$pem" -noout -text 2>/dev/null \
        | grep -qi "$alg" \
        || die "OpenSSL could not parse the exported $alg SPKI"

    "$P11MORE" -p :::nologin "pubk/$label" 2>/dev/null \
        | grep -qi "$alg" \
        || die "p11more did not render $alg"
}

check_montgomery_public_key X25519
check_montgomery_public_key X448

check_montgomery_keygen X25519
check_montgomery_keygen X448
"$P11KEYGEN" -p :::nologin -k montgomery -i generated-default \
    >/dev/null 2>&1 || die "p11keygen montgomery alias/default X25519 failed"

check_montgomery_import X25519
check_montgomery_import X448

if "$P11KEYGEN" -p :::nologin -k mont -q prime256v1 -i bad-curve \
    >/dev/null 2>&1; then
    die "p11keygen accepted a non-Montgomery curve"
fi

MOCK_P11_MONTGOMERY_PUBLIC=mock-invalid
MOCK_P11_MONTGOMERY_ALG=X25519
export MOCK_P11_MONTGOMERY_PUBLIC MOCK_P11_MONTGOMERY_ALG

for missing in point params; do
    if MOCK_P11_MONTGOMERY_MISSING=$missing \
        "$P11CAT" -p :::nologin pubk/mock-invalid \
        >"$WORKDIR/missing-$missing.pem" 2>/dev/null; then
        die "p11cat succeeded with missing CKA_EC_${missing}"
    fi
    if MOCK_P11_MONTGOMERY_MISSING=$missing \
        "$P11MORE" -p :::nologin pubk/mock-invalid \
        >"$WORKDIR/missing-$missing.txt" 2>/dev/null; then
        die "p11more succeeded with missing CKA_EC_${missing}"
    fi
done

for malformed in point params; do
    if MOCK_P11_MONTGOMERY_MALFORMED=$malformed \
        "$P11CAT" -p :::nologin pubk/mock-invalid \
        >"$WORKDIR/malformed-$malformed.pem" 2>/dev/null; then
        die "p11cat succeeded with malformed CKA_EC_${malformed}"
    fi
    if MOCK_P11_MONTGOMERY_MALFORMED=$malformed \
        "$P11MORE" -p :::nologin pubk/mock-invalid \
        >"$WORKDIR/malformed-$malformed.txt" 2>/dev/null; then
        die "p11more succeeded with malformed CKA_EC_${malformed}"
    fi
done

echo "PASS: X25519/X448 keygen, import, rendering, export and malformed-object errors"
