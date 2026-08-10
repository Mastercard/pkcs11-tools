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

# Integration test: rendering of DSA and EdDSA public keys through p11od /
# p11more / p11cat. These key types take dedicated attribute-printing branches
# in pkcs11_od.c, pkcs11_more.c and pkcs11_cat.c that the RSA/EC tests miss:
#
#   - DSA public key : CKA_PRIME / CKA_SUBPRIME / CKA_BASE / CKA_VALUE
#   - Ed25519 key    : CKA_EC_PARAMS / CKA_EC_POINT with an Edwards curve
#
# openssl is used to generate the DSA public key to import.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

command -v openssl >/dev/null 2>&1 || skip "openssl not found in PATH"

KEYGEN=$(p11bin p11keygen)
P11IMPORTPUBK=$(p11bin p11importpubk)
P11OD=$(p11bin p11od)
P11MORE=$(p11bin p11more)
P11CAT=$(p11bin p11cat)

# --- DSA public key (imported) ---------------------------------------------
openssl dsaparam -genkey -out "$WORKDIR/dsa.pem" 2048 >/dev/null 2>&1 \
    || skip "openssl cannot generate DSA parameters"
openssl dsa -in "$WORKDIR/dsa.pem" -pubout -out "$WORKDIR/dsapub.pem" \
    >/dev/null 2>&1 || die "openssl could not extract the DSA public key"

"$P11IMPORTPUBK" -l "$PKCS11LIB" -f "$WORKDIR/dsapub.pem" -i pr-dsa \
    >/dev/null 2>&1 || die "p11importpubk (DSA) failed"

dsaod=$("$P11OD" -l "$PKCS11LIB" pubk/pr-dsa 2>/dev/null) \
    || die "p11od (DSA public key) returned non-zero"
for attr in CKA_PRIME CKA_SUBPRIME CKA_BASE CKA_VALUE; do
    printf '%s\n' "$dsaod" | grep -q "$attr" \
        || die "p11od: DSA public key missing $attr"
done

"$P11MORE" -l "$PKCS11LIB" pubk/pr-dsa >/dev/null 2>&1 \
    || die "p11more (DSA public key) returned non-zero"

"$P11CAT" -l "$PKCS11LIB" pubk/pr-dsa 2>/dev/null \
    | grep -q 'BEGIN PUBLIC KEY' \
    || die "p11cat: DSA public key not exported as SubjectPublicKeyInfo"

# --- Ed25519 public key (generated) ----------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k ed -q ed25519 -i pr-ed \
    sign=true verify=true >/dev/null 2>&1 || die "p11keygen (Ed25519) failed"

edod=$("$P11OD" -l "$PKCS11LIB" pubk/pr-ed 2>/dev/null) \
    || die "p11od (Ed25519 public key) returned non-zero"
printf '%s\n' "$edod" | grep -q 'CKA_EC_PARAMS' \
    || die "p11od: Ed25519 public key missing CKA_EC_PARAMS"
printf '%s\n' "$edod" | grep -q 'CKA_EC_POINT' \
    || die "p11od: Ed25519 public key missing CKA_EC_POINT"

"$P11MORE" -l "$PKCS11LIB" pubk/pr-ed >/dev/null 2>&1 \
    || die "p11more (Ed25519 public key) returned non-zero"

"$P11CAT" -l "$PKCS11LIB" pubk/pr-ed 2>/dev/null \
    | grep -q 'BEGIN PUBLIC KEY' \
    || die "p11cat: Ed25519 public key not exported as SubjectPublicKeyInfo"

echo "DSA / EdDSA public-key rendering (od/more/cat): OK"
