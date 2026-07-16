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

# Integration test: p11mkcert (self-signed certificate from a token key).
#   1. generate an RSA and an EC signing key (p11keygen)
#   2. emit a self-signed certificate to stdout and validate it with OpenSSL
#   3. generate + import a certificate onto the token (-j) and confirm it lands

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

command -v openssl >/dev/null 2>&1 || skip "openssl not found in PATH"

KEYGEN=$(p11bin p11keygen)
P11MKCERT=$(p11bin p11mkcert)
P11LS=$(p11bin p11ls)

# --- 1. signing keys --------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i mk-rsa \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (RSA) failed"
"$KEYGEN" -l "$PKCS11LIB" -k ec -q prime256v1 -i mk-ec \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (EC) failed"

# --- 2. self-signed certificate to stdout, validated by OpenSSL -------------
# RSA: OpenSSL must parse the DER/PEM and read back our subject.
"$P11MKCERT" -l "$PKCS11LIB" -i mk-rsa -d '/CN=p11mkcert-rsa' 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null \
    | grep -q 'p11mkcert-rsa' \
    || die "p11mkcert (RSA): OpenSSL could not read the expected subject"

# EC: same, with a SHA-384 digest to exercise a non-default hash.
"$P11MKCERT" -l "$PKCS11LIB" -i mk-ec -H sha384 -d '/CN=p11mkcert-ec' 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null \
    | grep -q 'p11mkcert-ec' \
    || die "p11mkcert (EC): OpenSSL could not read the expected subject"

# --- 3. import onto the token (-j) ------------------------------------------
"$P11MKCERT" -l "$PKCS11LIB" -i mk-rsa -d '/CN=p11mkcert-imported' -j \
    >/dev/null 2>&1 || die "p11mkcert (-j import) failed"

"$P11LS" -l "$PKCS11LIB" 2>/dev/null | grep -q 'cert/mk-rsa' \
    || die "p11mkcert: imported certificate not found on token"

echo "mkcert: OK"
