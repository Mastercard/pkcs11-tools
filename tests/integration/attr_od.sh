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

# Integration test: attribute inspection and modification.
#   1. generate an AES key with encrypt enabled (p11keygen)
#   2. dump its attributes (p11od) and confirm CKA_ENCRYPT is reported
#   3. flip CKA_ENCRYPT to false (p11setattr) and confirm the change (p11od)

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11OD=$(p11bin p11od)
P11SETATTR=$(p11bin p11setattr)

# --- 1. key generation ------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i test-attr \
    encrypt=true decrypt=true >/dev/null 2>&1 \
    || die "p11keygen (AES) failed"

# --- 2. dump attributes -----------------------------------------------------
od_before=$("$P11OD" -l "$PKCS11LIB" seck/test-attr) \
    || die "p11od returned non-zero"

echo "$od_before" | grep -q 'CKA_ENCRYPT' \
    || die "p11od: CKA_ENCRYPT not present in dump"

# --- 3. modify an attribute -------------------------------------------------
"$P11SETATTR" -l "$PKCS11LIB" -y seck/test-attr CKA_ENCRYPT=false \
    >/dev/null 2>&1 || die "p11setattr (CKA_ENCRYPT=false) failed"

# CKA_ENCRYPT should now read as CK_FALSE in the dump.
od_after=$("$P11OD" -l "$PKCS11LIB" seck/test-attr) \
    || die "p11od (after) returned non-zero"

echo "$od_after" | grep -A1 'CKA_ENCRYPT' | grep -q 'CK_FALSE' \
    || die "p11setattr: CKA_ENCRYPT was not cleared"

echo "attr/od: OK"
