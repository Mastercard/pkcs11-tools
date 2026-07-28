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

# Integration test: JOSE Web Key (JWK, RFC 7517) wrapping output.
#   p11wrap -J emits the wrapped key as a JWK JSON object instead of the native
#   pkcs11-tools format. This exercises the JWK serialization path in
#   pkcs11_wrapoutput.c.
#
#   1. RSA wrapping key (wrap/unwrap + encrypt/decrypt for RSA transport)
#   2. extractable AES target key
#   3. p11wrap -a oaep -J <wrapping_key_id> -o file
#   4. check the output is a JWK object with the expected members

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11WRAP=$(p11bin p11wrap)

# --- key material -----------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i jwk-wrap \
    wrap=true unwrap=true encrypt=true decrypt=true >/dev/null 2>&1 \
    || die "p11keygen (RSA wrapping key) failed"

"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i jwk-target \
    encrypt=true decrypt=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (target key) failed"

# --- JWK wrap ---------------------------------------------------------------
jwkfile="$WORKDIR/wrapped.jwk"
"$P11WRAP" -l "$PKCS11LIB" -i jwk-target -w jwk-wrap -a oaep \
    -J jwk-wrapper-id -o "$jwkfile" >/dev/null 2>&1 \
    || die "p11wrap -J (JWK) failed"
[ -s "$jwkfile" ] || die "p11wrap -J produced an empty file"

# --- JWK structure checks ---------------------------------------------------
# The wrapped key is a symmetric (AES) key, so the JWK key type is "oct".
grep -q '"kty"[[:space:]]*:[[:space:]]*"oct"' "$jwkfile" \
    || die "JWK: missing or unexpected \"kty\" (expected \"oct\")"

# RSA-OAEP key management algorithm.
grep -q '"alg"[[:space:]]*:[[:space:]]*"RSA-OAEP"' "$jwkfile" \
    || die "JWK: missing or unexpected \"alg\" (expected \"RSA-OAEP\")"

# Key id echoes the target label.
grep -q '"kid"[[:space:]]*:[[:space:]]*"jwk-target"' "$jwkfile" \
    || die "JWK: missing or unexpected \"kid\" (expected \"jwk-target\")"

# The wrapping key id passed through -J must be reflected in the output.
grep -q 'jwk-wrapper-id' "$jwkfile" \
    || die "JWK: wrapping_key_id (-J value) not present in output"

# A non-empty base64url-encoded wrapped key value.
grep -qE '"k"[[:space:]]*:[[:space:]]*"[A-Za-z0-9_-]+"' "$jwkfile" \
    || die "JWK: missing or empty \"k\" (wrapped key material)"

echo "jwk output (RSA-OAEP wrapped oct key): OK"
