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

# Integration test: symmetric key wrap / unwrap round-trip.
#   1. generate an AES wrapping key (wrap/unwrap) and an extractable AES target
#   2. wrap the target under the wrapping key with RFC5649 (p11wrap)
#   3. unwrap it back under a new label (p11unwrap)
#   4. confirm the restored key is present and usable (p11ls / p11kcv)

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11LS=$(p11bin p11ls)
P11WRAP=$(p11bin p11wrap)
P11UNWRAP=$(p11bin p11unwrap)
P11KCV=$(p11bin p11kcv)

WRAPFILE="$WORKDIR/target.wrap"

# --- 1. key generation ------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i wrapper \
    wrap=true unwrap=true >/dev/null 2>&1 \
    || die "p11keygen (wrapping key) failed"

# the target must be extractable so it can be wrapped out of the token.
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i target \
    encrypt=true decrypt=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (target key) failed"

# reference KCV of the original target key, to compare after the round-trip.
kcv_before=$("$P11KCV" -l "$PKCS11LIB" -f ecb seck/target 2>/dev/null \
    | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p') \
    || die "p11kcv (target, before) failed"

# --- 2. wrap ----------------------------------------------------------------
"$P11WRAP" -l "$PKCS11LIB" -i target -w wrapper -a rfc5649 -o "$WRAPFILE" \
    >/dev/null 2>&1 || die "p11wrap (rfc5649) failed"

[ -s "$WRAPFILE" ] || die "p11wrap produced an empty wrapped-key file"

# --- 3. unwrap --------------------------------------------------------------
"$P11UNWRAP" -l "$PKCS11LIB" -f "$WRAPFILE" -i restored \
    CKA_ENCRYPT=true CKA_DECRYPT=true >/dev/null 2>&1 \
    || die "p11unwrap failed"

# --- 4. verification --------------------------------------------------------
out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"
echo "$out" | grep -q 'seck/restored' || die "p11ls: restored key missing"

kcv_after=$("$P11KCV" -l "$PKCS11LIB" -f ecb seck/restored 2>/dev/null \
    | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p') \
    || die "p11kcv (restored) failed"

if [ -z "$kcv_before" ] || [ "$kcv_before" != "$kcv_after" ]; then
    die "KCV mismatch: wrap/unwrap did not preserve the key material"
fi

echo "wrap/unwrap: OK"
