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

echo "PASS: X25519/X448 listing, attribute decoding, SPKI export and rendering"
