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

# Integration test: p11more (human-readable dump of token objects).
#   1. generate an RSA key pair (p11keygen)
#   2. self-sign a certificate and import it onto the token (p11mkcert -j)
#   3. run p11more on the certificate and on the public key, checking that the
#      human-readable rendering contains the expected fields.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11MKCERT=$(p11bin p11mkcert)
P11MORE=$(p11bin p11more)

# --- 1. key + certificate ---------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i more-key \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (RSA) failed"

"$P11MKCERT" -l "$PKCS11LIB" -i more-key -d '/CN=p11more-test' -j \
    >/dev/null 2>&1 || die "p11mkcert (-j import) failed"

# --- 2. p11more on the certificate ------------------------------------------
cert_out=$("$P11MORE" -l "$PKCS11LIB" cert/more-key 2>/dev/null) \
    || die "p11more (certificate) returned non-zero"

echo "$cert_out" | grep -q 'Certificate:' \
    || die "p11more: certificate rendering missing 'Certificate:' header"
echo "$cert_out" | grep -q 'p11more-test' \
    || die "p11more: certificate subject/issuer not shown"

# --- 3. p11more on the public key -------------------------------------------
pub_out=$("$P11MORE" -l "$PKCS11LIB" pubk/more-key 2>/dev/null) \
    || die "p11more (public key) returned non-zero"

echo "$pub_out" | grep -qiE 'public.?key|modulus|RSA' \
    || die "p11more: public-key rendering missing expected fields"

echo "more: OK"
