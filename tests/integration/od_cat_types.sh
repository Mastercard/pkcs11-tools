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

# Integration test: broaden the object classes fed to p11od / p11cat / p11more
# so that the class-specific attribute rendering in pkcs11_od.c, pkcs11_cat.c
# and pkcs11_more.c is exercised beyond what od_more.sh / cat_extended.sh cover:
#
#   1. certificate  : p11od shows the certificate-only attributes
#      (CKA_SUBJECT / CKA_ISSUER / CKA_SERIAL_NUMBER / CKA_CERTIFICATE_TYPE)
#   2. certificate  : p11cat exports it as a PEM certificate
#   3. RSA private key : p11od shows the RSA key material attributes
#      (CKA_MODULUS / CKA_PUBLIC_EXPONENT) and p11more renders it
#   4. data object  : p11importdata round-trips through p11cat
#
# p11mkcert (step 1-2) needs no openssl; the whole test is token-only.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11MKCERT=$(p11bin p11mkcert)
P11OD=$(p11bin p11od)
P11CAT=$(p11bin p11cat)
P11MORE=$(p11bin p11more)
P11IMPORTDATA=$(p11bin p11importdata)

"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i oct-rsa \
    sign=true verify=true >/dev/null 2>&1 || die "p11keygen (RSA) failed"
"$P11MKCERT" -l "$PKCS11LIB" -i oct-rsa -d '/CN=oct-cert/O=TestOrg' -j \
    >/dev/null 2>&1 || die "p11mkcert (-j import) failed"

# --- 1. p11od on the certificate --------------------------------------------
certod=$("$P11OD" -l "$PKCS11LIB" cert/oct-rsa 2>/dev/null) \
    || die "p11od (certificate) returned non-zero"
for attr in CKA_SUBJECT CKA_ISSUER CKA_SERIAL_NUMBER CKA_CERTIFICATE_TYPE CKA_VALUE; do
    printf '%s\n' "$certod" | grep -q "$attr" \
        || die "p11od: certificate missing $attr"
done

# --- 2. p11cat on the certificate -------------------------------------------
"$P11CAT" -l "$PKCS11LIB" cert/oct-rsa 2>/dev/null \
    | grep -q 'BEGIN CERTIFICATE' \
    || die "p11cat: certificate not exported as PEM"

# --- 3. p11od + p11more on the RSA private key ------------------------------
rsaod=$("$P11OD" -l "$PKCS11LIB" prvk/oct-rsa 2>/dev/null) \
    || die "p11od (RSA private key) returned non-zero"
printf '%s\n' "$rsaod" | grep -q 'CKA_MODULUS' \
    || die "p11od: RSA private key missing CKA_MODULUS"
printf '%s\n' "$rsaod" | grep -q 'CKA_PUBLIC_EXPONENT' \
    || die "p11od: RSA private key missing CKA_PUBLIC_EXPONENT"

"$P11MORE" -l "$PKCS11LIB" prvk/oct-rsa >/dev/null 2>&1 \
    || die "p11more (RSA private key) returned non-zero"

# --- 4. data object round-trip through p11importdata + p11cat ---------------
printf 'p11-oct-data-payload' > "$WORKDIR/oct-data.bin"
"$P11IMPORTDATA" -l "$PKCS11LIB" -f "$WORKDIR/oct-data.bin" -i oct-data \
    >/dev/null 2>&1 || die "p11importdata failed"

back=$("$P11CAT" -l "$PKCS11LIB" data/oct-data 2>/dev/null) \
    || die "p11cat (data object) returned non-zero"
[ "$back" = "p11-oct-data-payload" ] \
    || die "p11cat: data object content did not round-trip (got: $back)"

echo "p11od/p11cat/p11more across cert, RSA key and data: OK"
