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

# Integration test: attribute dump (p11od) and human-readable rendering
# (p11more) across several object classes.
#   - EC public key  : p11more shows the public point / curve size
#   - EC private key : p11od shows CKA_EC_PARAMS and CKA_KEY_TYPE
#   - AES secret key : p11od shows CKA_CLASS / CKA_KEY_TYPE
#   - data object    : p11od shows CKA_CLASS and CKA_VALUE
# This exercises the class-specific branches of pkcs11_od.c, pkcs11_more.c and
# the EC public-key rendering in pkcs11_pubk.c.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11OD=$(p11bin p11od)
P11MORE=$(p11bin p11more)
P11IMPORTDATA=$(p11bin p11importdata)

# --- object material --------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k ec -q prime256v1 -i od-ec \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (EC) failed"

"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i od-aes \
    encrypt=true decrypt=true >/dev/null 2>&1 \
    || die "p11keygen (AES) failed"

printf 'p11od-data-object' > "$WORKDIR/od-data.bin"
"$P11IMPORTDATA" -l "$PKCS11LIB" -f "$WORKDIR/od-data.bin" -i od-data \
    >/dev/null 2>&1 || die "p11importdata failed"

# --- 1. p11more on the EC public key ----------------------------------------
ecpub=$("$P11MORE" -l "$PKCS11LIB" pubk/od-ec 2>/dev/null) \
    || die "p11more (EC public key) returned non-zero"
echo "$ecpub" | grep -qiE 'public.?key|pub:' \
    || die "p11more: EC public-key rendering missing expected fields"

# --- 2. p11od on the EC private key -----------------------------------------
ecpriv=$("$P11OD" -l "$PKCS11LIB" prvk/od-ec 2>/dev/null) \
    || die "p11od (EC private key) returned non-zero"
echo "$ecpriv" | grep -q 'CKA_EC_PARAMS' \
    || die "p11od: EC private key missing CKA_EC_PARAMS"
echo "$ecpriv" | grep -q 'CKA_KEY_TYPE' \
    || die "p11od: EC private key missing CKA_KEY_TYPE"

# --- 3. p11od on the AES secret key -----------------------------------------
aesod=$("$P11OD" -l "$PKCS11LIB" seck/od-aes 2>/dev/null) \
    || die "p11od (AES secret key) returned non-zero"
echo "$aesod" | grep -q 'CKA_CLASS' \
    || die "p11od: AES secret key missing CKA_CLASS"
echo "$aesod" | grep -q 'CKA_KEY_TYPE' \
    || die "p11od: AES secret key missing CKA_KEY_TYPE"

# --- 4. p11od on the data object --------------------------------------------
dataod=$("$P11OD" -l "$PKCS11LIB" data/od-data 2>/dev/null) \
    || die "p11od (data object) returned non-zero"
echo "$dataod" | grep -q 'CKA_CLASS' \
    || die "p11od: data object missing CKA_CLASS"
echo "$dataod" | grep -q 'CKA_VALUE' \
    || die "p11od: data object missing CKA_VALUE"

echo "od/more (EC pub, EC prv, AES, data): OK"
