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

# Integration test: symmetric key generation and key check values.
#   1. generate AES, 3DES (des/192) and generic-secret (HMAC) keys (p11keygen)
#   2. list them and confirm they are secret keys of the right type (p11ls)
#   3. compute key check values several ways (p11kcv)

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11LS=$(p11bin p11ls)
P11KCV=$(p11bin p11kcv)

# --- 1. key generation ------------------------------------------------------
# encrypt/decrypt are needed for the ECB-based KCV flavours; sign/verify for CMAC.
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i test-aes \
    encrypt=true decrypt=true sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (AES) failed"

"$KEYGEN" -l "$PKCS11LIB" -k des -b 192 -i test-des3 \
    encrypt=true decrypt=true sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (DES3) failed"

"$KEYGEN" -l "$PKCS11LIB" -k generic -b 256 -i test-hmac \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (generic/HMAC) failed"

# --- 2. listing -------------------------------------------------------------
out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"

echo "$out" | grep -q 'seck/test-aes'  || die "p11ls: AES key missing"
echo "$out" | grep -q 'seck/test-des3' || die "p11ls: DES3 key missing"
echo "$out" | grep -q 'seck/test-hmac' || die "p11ls: HMAC key missing"

# the AES object should advertise its key length
echo "$out" | grep 'seck/test-aes' | grep -q 'aes(256)' \
    || die "p11ls: AES key does not report aes(256)"

# --- 3. key check values ----------------------------------------------------
# ECB flavour: encrypt a block of zeros (requires CKA_ENCRYPT).
"$P11KCV" -l "$PKCS11LIB" -f ecb seck/test-aes >/dev/null 2>&1 \
    || die "p11kcv (AES, ecb) failed"

"$P11KCV" -l "$PKCS11LIB" -f cmac seck/test-aes >/dev/null 2>&1 \
    || die "p11kcv (AES, cmac) failed"

# Remaining AES flavours exercise the distinct MAC code paths in pkcs11_kcv.c.
for flavour in kcv mac aes-xcbc-mac aes-xcbc-mac-96; do
    "$P11KCV" -l "$PKCS11LIB" -f "$flavour" seck/test-aes >/dev/null 2>&1 \
        || die "p11kcv (AES, $flavour) failed"
done

# A non-default KCV length (-n) drives the truncation path.
"$P11KCV" -l "$PKCS11LIB" -n 4 -f cmac seck/test-aes >/dev/null 2>&1 \
    || die "p11kcv (AES, cmac, -n 4) failed"

# 3DES supports ecb, mac and cmac.
for flavour in ecb mac cmac; do
    "$P11KCV" -l "$PKCS11LIB" -f "$flavour" seck/test-des3 >/dev/null 2>&1 \
        || die "p11kcv (DES3, $flavour) failed"
done

# HMAC keys: the KCV flavour is ignored; a buffer length is supplied.
"$P11KCV" -l "$PKCS11LIB" -b 32 seck/test-hmac >/dev/null 2>&1 \
    || die "p11kcv (HMAC) failed"

echo "symkeys/kcv: OK"
