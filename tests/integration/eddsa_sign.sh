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

# Integration test: EdDSA signing through the OpenSSL provider.
#   Producing a CSR (p11req) or a self-signed certificate (p11mkcert) with an
#   EdDSA key stored on the token drives the OpenSSL provider glue that signs
#   with the on-token key (pkcs11_provider_eddsa.c). This is distinct from
#   EdDSA key *generation*, which is covered by keytypes.sh.
#
#   1. Ed25519 key -> p11req CSR, verified by OpenSSL
#   2. Ed25519 key -> p11mkcert self-signed certificate, subject checked
#   3. Ed448 key   -> p11req CSR, verified by OpenSSL
#
# Requires openssl (for signature verification and certificate parsing).

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

OPENSSL=$(command -v openssl 2>/dev/null) || skip "openssl not found in PATH"

KEYGEN=$(p11bin p11keygen)
P11REQ=$(p11bin p11req)
P11MKCERT=$(p11bin p11mkcert)
have_ed448=0

# --- key material -----------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k ed -q ED25519 -i eddsa-25519 \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (Ed25519) failed"
if supports_ed448_keygen; then
    have_ed448=1
    "$KEYGEN" -l "$PKCS11LIB" -k ed -q ED448 -i eddsa-448 \
        sign=true verify=true >/dev/null 2>&1 \
        || die "p11keygen (Ed448) failed"
fi

# --- 1. Ed25519 CSR ---------------------------------------------------------
"$P11REQ" -l "$PKCS11LIB" -i eddsa-25519 -d '/CN=ed25519.example' 2>/dev/null \
    | "$OPENSSL" req -noout -verify >/dev/null 2>&1 \
    || die "Ed25519 CSR failed OpenSSL self-signature verification"

# --- 2. Ed25519 self-signed certificate -------------------------------------
cert_subject=$("$P11MKCERT" -l "$PKCS11LIB" -i eddsa-25519 \
    -d '/CN=ed25519-cert' 2>/dev/null \
    | "$OPENSSL" x509 -noout -subject 2>/dev/null) \
    || die "p11mkcert (Ed25519) produced an unparseable certificate"
echo "$cert_subject" | grep -q 'ed25519-cert' \
    || die "p11mkcert (Ed25519): unexpected certificate subject"

if [ "$have_ed448" -eq 1 ]; then
    # --- 3. Ed448 CSR -------------------------------------------------------
    "$P11REQ" -l "$PKCS11LIB" -i eddsa-448 -d '/CN=ed448.example' 2>/dev/null \
        | "$OPENSSL" req -noout -verify >/dev/null 2>&1 \
        || die "Ed448 CSR failed OpenSSL self-signature verification"
fi

echo "eddsa signing (Ed25519 req+cert, Ed448 req): OK"
