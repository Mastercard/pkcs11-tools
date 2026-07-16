#!/bin/sh
# Copyright (c) 2025 Mastercard
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

# Integration test: full happy path against a fresh SoftHSM2 token.
#   1. generate an RSA and an EC signing key pair (p11keygen)
#   2. list the token content and check the objects are there (p11ls)
#   3. produce a CSR and validate its self-signature with OpenSSL (p11req)

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11LS=$(p11bin p11ls)
P11REQ=$(p11bin p11req)

# --- 1. key generation ------------------------------------------------------
# SoftHSM enforces CKA_SIGN, so request signing capability explicitly.
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i test-rsa sign=true verify=true \
    >/dev/null 2>&1 || die "p11keygen (RSA) failed"

"$KEYGEN" -l "$PKCS11LIB" -k ec -q prime256v1 -i test-ec sign=true verify=true \
    >/dev/null 2>&1 || die "p11keygen (EC) failed"

# --- 2. listing -------------------------------------------------------------
out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"

echo "$out" | grep -q 'prvk/test-rsa' || die "p11ls: RSA private key missing"
echo "$out" | grep -q 'pubk/test-rsa' || die "p11ls: RSA public key missing"
echo "$out" | grep -q 'prvk/test-ec'  || die "p11ls: EC private key missing"
echo "$out" | grep -q 'pubk/test-ec'  || die "p11ls: EC public key missing"

# --- 3. CSR generation + OpenSSL verification -------------------------------
if command -v openssl >/dev/null 2>&1; then
    "$P11REQ" -l "$PKCS11LIB" -i test-rsa -d '/CN=p11test-rsa' 2>/dev/null \
        | openssl req -verify -noout >/dev/null 2>&1 \
        || die "p11req (RSA) CSR failed OpenSSL self-signature verification"

    "$P11REQ" -l "$PKCS11LIB" -i test-ec -d '/CN=p11test-ec' 2>/dev/null \
        | openssl req -verify -noout >/dev/null 2>&1 \
        || die "p11req (EC) CSR failed OpenSSL self-signature verification"
else
    echo "openssl not found: skipping CSR verification step" >&2
fi

echo "keygen/ls/req: OK"
