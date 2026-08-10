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

# Integration test: variety of key-wrapping algorithms.
#   - RSA wrapping key   -> pkcs1, oaep        (asymmetric key-transport)
#   - AES wrapping key   -> rfc3394            (symmetric key-wrap)
#   (rfc5649 is already covered by wrap_unwrap.sh; cbcpad is not supported by
#    SoftHSM2 and is therefore left out here.)
# For each algorithm the target AES key is wrapped to a file and unwrapped back
# under a fresh label, and the key check value must survive the round-trip.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11WRAP=$(p11bin p11wrap)
P11UNWRAP=$(p11bin p11unwrap)
P11KCV=$(p11bin p11kcv)

# --- key material -----------------------------------------------------------
# RSA transport key: needs wrap/unwrap AND encrypt/decrypt for RSA key transport.
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i rsawrap \
    wrap=true unwrap=true encrypt=true decrypt=true >/dev/null 2>&1 \
    || die "p11keygen (RSA wrapping key) failed"

# AES key-wrap key.
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i aeswrap \
    wrap=true unwrap=true >/dev/null 2>&1 \
    || die "p11keygen (AES wrapping key) failed"

# Extractable AES target to be wrapped and restored.
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i wtarget \
    encrypt=true decrypt=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (target key) failed"

kcv_ref=$("$P11KCV" -l "$PKCS11LIB" -f ecb seck/wtarget 2>/dev/null \
    | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p')
[ -n "$kcv_ref" ] || die "could not read reference KCV of target key"

# roundtrip ALGO WRAPKEY LABEL: wrap the target under WRAPKEY with ALGO, unwrap
# it back under LABEL, and confirm the restored KCV matches the reference.
roundtrip() {
    _algo=$1
    _wrapkey=$2
    _label=$3
    _file="$WORKDIR/$_label.wrap"

    "$P11WRAP" -l "$PKCS11LIB" -i wtarget -w "$_wrapkey" -a "$_algo" \
        -o "$_file" >/dev/null 2>&1 \
        || die "p11wrap ($_algo) failed"
    [ -s "$_file" ] || die "p11wrap ($_algo) produced an empty file"

    "$P11UNWRAP" -l "$PKCS11LIB" -f "$_file" -i "$_label" \
        CKA_ENCRYPT=true CKA_DECRYPT=true >/dev/null 2>&1 \
        || die "p11unwrap ($_algo) failed"

    _kcv=$("$P11KCV" -l "$PKCS11LIB" -f ecb "seck/$_label" 2>/dev/null \
        | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p')
    [ "$_kcv" = "$kcv_ref" ] \
        || die "$_algo: KCV mismatch after wrap/unwrap round-trip"
}

# --- round-trips ------------------------------------------------------------
roundtrip pkcs1   rsawrap restored_pkcs1
roundtrip oaep    rsawrap restored_oaep
roundtrip rfc3394 aeswrap restored_rfc3394

echo "wrap algorithms (pkcs1/oaep/rfc3394): OK"
