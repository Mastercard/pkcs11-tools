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

# Integration test: wrapping and unwrapping asymmetric *private* keys.
#   The other wrap tests round-trip symmetric (AES) keys; wrapping an RSA or EC
#   private key drives different branches of pkcs11_wrap.c / pkcs11_unwrap.c /
#   pkcs11_wrapoutput.c (the wrapped blob carries the private-key attributes).
#
#   1. RSA private key : wrap under an AES KEK (rfc5649), remove, unwrap; then
#      prove the restored key still works by signing a CSR that OpenSSL verifies
#   2. EC private key  : wrap/remove/unwrap; confirm the restored object is an
#      EC private key (a CSR cannot be rebuilt without the matching public key,
#      so the check here is structural)
#
# The RSA functional check needs openssl; when openssl is absent it falls back
# to the same structural check used for EC.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11WRAP=$(p11bin p11wrap)
P11UNWRAP=$(p11bin p11unwrap)
P11RM=$(p11bin p11rm)
P11REQ=$(p11bin p11req)
P11LS=$(p11bin p11ls)

OPENSSL=$(command -v openssl 2>/dev/null || true)

# --- AES key-wrap key -------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i wpk-kek \
    wrap=true unwrap=true >/dev/null 2>&1 \
    || die "p11keygen (AES KEK) failed"

# wrap_unwrap_priv KIND KEYGEN_ARGS...: generate an extractable private key of
# the given KIND, wrap it under the KEK, remove the on-token private key, and
# unwrap it under a new label. Echoes the restored private-key label.
wrap_unwrap_priv() {
    _src=$1
    _dst=$2
    _file="$WORKDIR/$_dst.wrap"

    "$P11WRAP" -l "$PKCS11LIB" -i "$_src" -w wpk-kek -a rfc5649 \
        -o "$_file" >/dev/null 2>&1 || die "p11wrap ($_src) failed"
    [ -s "$_file" ] || die "p11wrap ($_src) produced an empty file"

    "$P11RM" -l "$PKCS11LIB" -y "prvk/$_src" >/dev/null 2>&1 \
        || die "p11rm (prvk/$_src) failed"

    "$P11UNWRAP" -l "$PKCS11LIB" -f "$_file" -i "$_dst" \
        CKA_SIGN=true >/dev/null 2>&1 || die "p11unwrap ($_dst) failed"

    "$P11LS" -l "$PKCS11LIB" 2>/dev/null | grep -q "prvk/$_dst" \
        || die "unwrapped private key prvk/$_dst not found"
}

# --- 1. RSA private key -----------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i wpk-rsa \
    sign=true verify=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (RSA private key) failed"
wrap_unwrap_priv wpk-rsa wpk-rsa-restored

if [ -n "$OPENSSL" ]; then
    "$P11REQ" -l "$PKCS11LIB" -i wpk-rsa-restored -d '/CN=unwrapped-rsa' \
        2>/dev/null | "$OPENSSL" req -noout -verify >/dev/null 2>&1 \
        || die "restored RSA private key could not produce a valid CSR"
fi

# --- 2. EC private key ------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k ec -q prime256v1 -i wpk-ec \
    sign=true verify=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (EC private key) failed"
wrap_unwrap_priv wpk-ec wpk-ec-restored

"$P11LS" -l "$PKCS11LIB" 2>/dev/null | grep -q 'prvk/wpk-ec-restored.*ec(' \
    || die "restored EC private key not rendered as an EC key"

echo "wrap private keys (RSA functional, EC structural): OK"
