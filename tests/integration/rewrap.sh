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

# Integration test: p11rewrap (unwrap + rewrap under a different key).
#   1. generate two AES key-wrap keys (KEK-A, KEK-B) and an extractable target
#   2. wrap the target under KEK-A to a file (p11wrap)
#   3. remove the target from the token (rewrap re-creates it transiently)
#   4. rewrap the file from KEK-A to KEK-B (p11rewrap -W)
#   5. unwrap the KEK-B file and confirm the key material survived (KCV match)

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11WRAP=$(p11bin p11wrap)
P11REWRAP=$(p11bin p11rewrap)
P11UNWRAP=$(p11bin p11unwrap)
P11RM=$(p11bin p11rm)
P11KCV=$(p11bin p11kcv)

FILE_A="$WORKDIR/rewrap_a.wrap"
FILE_B="$WORKDIR/rewrap_b.wrap"

# --- 1. key material --------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i kek-a \
    wrap=true unwrap=true >/dev/null 2>&1 \
    || die "p11keygen (KEK-A) failed"
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i kek-b \
    wrap=true unwrap=true >/dev/null 2>&1 \
    || die "p11keygen (KEK-B) failed"
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i rwtarget \
    encrypt=true decrypt=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (target) failed"

kcv_ref=$("$P11KCV" -l "$PKCS11LIB" -f ecb seck/rwtarget 2>/dev/null \
    | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p')
[ -n "$kcv_ref" ] || die "could not read reference KCV of target key"

# --- 2. wrap under KEK-A ----------------------------------------------------
"$P11WRAP" -l "$PKCS11LIB" -i rwtarget -w kek-a -a rfc5649 -o "$FILE_A" \
    >/dev/null 2>&1 || die "p11wrap (KEK-A) failed"
[ -s "$FILE_A" ] || die "p11wrap produced an empty file"

# --- 3. remove the on-token copy so rewrap can re-create it -----------------
# p11rewrap unwraps the key back onto the token (under its embedded label)
# before rewrapping, so the original object must not already be present.
"$P11RM" -l "$PKCS11LIB" -y seck/rwtarget >/dev/null 2>&1 \
    || die "p11rm (target) failed"

# --- 4. rewrap KEK-A -> KEK-B -----------------------------------------------
"$P11REWRAP" -l "$PKCS11LIB" -f "$FILE_A" \
    -W 'wrappingkey="kek-b",algorithm=rfc5649,filename="'"$FILE_B"'"' \
    >/dev/null 2>&1 || die "p11rewrap (KEK-A -> KEK-B) failed"
[ -s "$FILE_B" ] || die "p11rewrap produced an empty file"

# rewrap left a transient copy of the target on the token; drop it so the
# unwrap below lands on a clean label.
"$P11RM" -l "$PKCS11LIB" -y seck/rwtarget >/dev/null 2>&1 || true

# --- 5. unwrap the KEK-B file and compare -----------------------------------
"$P11UNWRAP" -l "$PKCS11LIB" -f "$FILE_B" -i rwrestored \
    CKA_ENCRYPT=true CKA_DECRYPT=true >/dev/null 2>&1 \
    || die "p11unwrap (KEK-B file) failed"

kcv_after=$("$P11KCV" -l "$PKCS11LIB" -f ecb seck/rwrestored 2>/dev/null \
    | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p')
[ "$kcv_after" = "$kcv_ref" ] \
    || die "KCV mismatch: rewrap did not preserve the key material"

echo "rewrap: OK"
