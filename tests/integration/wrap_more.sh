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

# Integration test: key-wrapping algorithm / target-type combinations not yet
# exercised by wrap_unwrap / wrap_algos / wrap_privkey / envelope / jwk. These
# reach the remaining inner/outer envelope-algorithm dispatch arms and the
# private-key / DES3 target branches of pkcs11_wrap.c, pkcs11_unwrap.c and
# pkcs11_wrapoutput.c:
#
#   1. envelope(inner=rfc5649,outer=pkcs1)  round-trip (pkcs1 outer, AES target)
#   2. envelope(inner=rfc3394,outer=oaep)   round-trip (rfc3394 inner)
#   3. envelope(inner=rfc3394,outer=pkcs1)  round-trip (rfc3394 inner + pkcs1)
#   4. DES3 secret key wrapped under an AES KEK (rfc5649) round-trip
#   5. RSA private key enveloped under RSA transport, then unwrapped
#   6. EC  private key enveloped under RSA transport, then unwrapped
#   7. JWK (-J) output of a DES3 key wrapped with rfc5649 (non-OAEP JWK arm)
#
# Symmetric round-trips are verified by comparing the ECB key check value
# before wrapping and after unwrapping. Private-key round-trips are confirmed
# by the unwrapped object reappearing on the token with the expected key type.
# Token-only (no openssl dependency).

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11WRAP=$(p11bin p11wrap)
P11UNWRAP=$(p11bin p11unwrap)
P11RM=$(p11bin p11rm)
P11KCV=$(p11bin p11kcv)
P11LS=$(p11bin p11ls)

kcv_ecb() {  # $1 = seck/<label> ; echoes the ECB KCV hex
    "$P11KCV" -l "$PKCS11LIB" -f ecb "$1" 2>/dev/null \
        | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p'
}

# --- wrapping keys ----------------------------------------------------------
# RSA transport key used as the outer/asymmetric wrapper.
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i wm-rsa \
    wrap=true unwrap=true encrypt=true decrypt=true >/dev/null 2>&1 \
    || die "p11keygen (RSA transport key) failed"
# AES KEK used as a symmetric wrapper.
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i wm-aeskek \
    wrap=true unwrap=true encrypt=true decrypt=true >/dev/null 2>&1 \
    || die "p11keygen (AES KEK) failed"

# --- 1..3 envelope algorithm variants (AES target, KCV round-trip) ----------
n=0
for algo in \
    'envelope(inner=rfc5649,outer=pkcs1)' \
    'envelope(inner=rfc3394,outer=oaep)' \
    'envelope(inner=rfc3394,outer=pkcs1)'
do
    n=$((n + 1))
    tgt="wm-env$n"
    wf="$WORKDIR/env$n.wrap"

    "$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i "$tgt" \
        encrypt=true decrypt=true extractable=true >/dev/null 2>&1 \
        || die "p11keygen ($tgt) failed"
    kref=$(kcv_ecb "seck/$tgt")
    [ -n "$kref" ] || die "could not read reference KCV of $tgt"

    "$P11WRAP" -l "$PKCS11LIB" -i "$tgt" -w wm-rsa -a "$algo" -o "$wf" \
        >/dev/null 2>&1 || die "p11wrap '$algo' failed"
    [ -s "$wf" ] || die "p11wrap '$algo' produced an empty file"

    "$P11RM" -l "$PKCS11LIB" -y "seck/$tgt" >/dev/null 2>&1 \
        || die "p11rm ($tgt) failed"
    "$P11UNWRAP" -l "$PKCS11LIB" -f "$wf" -i "${tgt}r" \
        CKA_ENCRYPT=true CKA_DECRYPT=true >/dev/null 2>&1 \
        || die "p11unwrap '$algo' failed"

    knew=$(kcv_ecb "seck/${tgt}r")
    [ "$knew" = "$kref" ] || die "'$algo': KCV mismatch after round-trip"
done

# --- 4. DES3 secret key wrapped under an AES KEK (rfc5649) -------------------
"$KEYGEN" -l "$PKCS11LIB" -k des -b 192 -i wm-des3 \
    encrypt=true decrypt=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (DES3 target) failed"
des3ref=$(kcv_ecb "seck/wm-des3")
[ -n "$des3ref" ] || die "could not read reference KCV of DES3 key"

"$P11WRAP" -l "$PKCS11LIB" -i wm-des3 -w wm-aeskek -a rfc5649 \
    -o "$WORKDIR/des3.wrap" >/dev/null 2>&1 || die "p11wrap (DES3) failed"
"$P11RM" -l "$PKCS11LIB" -y seck/wm-des3 >/dev/null 2>&1 \
    || die "p11rm (DES3) failed"
# The wrapped file already carries CKA_CLASS / CKA_KEY_TYPE (DES3); no overrides.
"$P11UNWRAP" -l "$PKCS11LIB" -f "$WORKDIR/des3.wrap" -i wm-des3r \
    >/dev/null 2>&1 || die "p11unwrap (DES3) failed"
[ "$(kcv_ecb seck/wm-des3r)" = "$des3ref" ] \
    || die "DES3: KCV mismatch after wrap/unwrap round-trip"

# --- 5. RSA private key enveloped under RSA transport -----------------------
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i wm-rprv \
    sign=true verify=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (RSA private target) failed"
"$P11WRAP" -l "$PKCS11LIB" -i wm-rprv -w wm-rsa \
    -a 'envelope(inner=rfc5649,outer=oaep)' -o "$WORKDIR/rprv.wrap" \
    >/dev/null 2>&1 || die "p11wrap (RSA private envelope) failed"
"$P11RM" -l "$PKCS11LIB" -y prvk/wm-rprv >/dev/null 2>&1 \
    || die "p11rm (RSA private) failed"
"$P11UNWRAP" -l "$PKCS11LIB" -f "$WORKDIR/rprv.wrap" -i wm-rprvr \
    >/dev/null 2>&1 || die "p11unwrap (RSA private envelope) failed"
"$P11LS" -l "$PKCS11LIB" 2>/dev/null | grep -q 'prvk/wm-rprvr.*rsa' \
    || die "unwrapped RSA private key not present as an RSA private key"

# --- 6. EC private key enveloped under RSA transport ------------------------
"$KEYGEN" -l "$PKCS11LIB" -k ec -q prime256v1 -i wm-ecprv \
    sign=true verify=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (EC private target) failed"
"$P11WRAP" -l "$PKCS11LIB" -i wm-ecprv -w wm-rsa \
    -a 'envelope(inner=rfc5649,outer=oaep)' -o "$WORKDIR/ecprv.wrap" \
    >/dev/null 2>&1 || die "p11wrap (EC private envelope) failed"
"$P11RM" -l "$PKCS11LIB" -y prvk/wm-ecprv >/dev/null 2>&1 \
    || die "p11rm (EC private) failed"
"$P11UNWRAP" -l "$PKCS11LIB" -f "$WORKDIR/ecprv.wrap" -i wm-ecprvr \
    >/dev/null 2>&1 || die "p11unwrap (EC private envelope) failed"
"$P11LS" -l "$PKCS11LIB" 2>/dev/null | grep -q 'prvk/wm-ecprvr.*ec' \
    || die "unwrapped EC private key not present as an EC private key"

# --- 7. JWK output of a DES3 key wrapped with rfc5649 -----------------------
# This is the non-OAEP JWK serialization arm (key_ops, no "alg": "RSA-OAEP").
"$KEYGEN" -l "$PKCS11LIB" -k des -b 192 -i wm-jdes \
    encrypt=true decrypt=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (JWK DES3 target) failed"
jwkfile="$WORKDIR/des3.jwk"
"$P11WRAP" -l "$PKCS11LIB" -i wm-jdes -w wm-aeskek -a rfc5649 \
    -J wm-aeskek -o "$jwkfile" >/dev/null 2>&1 \
    || die "p11wrap -J (DES3/rfc5649 JWK) failed"
grep -q '"kty"[[:space:]]*:[[:space:]]*"oct"' "$jwkfile" \
    || die "JWK (DES3): missing or unexpected \"kty\""
grep -qE '"k"[[:space:]]*:[[:space:]]*"[A-Za-z0-9_-]+"' "$jwkfile" \
    || die "JWK (DES3): missing or empty wrapped key material \"k\""

echo "envelope variants / DES3 / private-key wrap / rfc5649 JWK: OK"
