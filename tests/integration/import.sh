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

# Integration test: importing external material and reading it back.
#   1. build an RSA key, its public key and a self-signed cert with OpenSSL
#   2. import the public key, certificate and a raw data blob (p11import*)
#   3. list them (p11ls) and read them back (p11cat), comparing to the source

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

command -v openssl >/dev/null 2>&1 || skip "openssl not found in PATH"

IMPORTPUBK=$(p11bin p11importpubk)
IMPORTCERT=$(p11bin p11importcert)
IMPORTDATA=$(p11bin p11importdata)
P11LS=$(p11bin p11ls)
P11CAT=$(p11bin p11cat)

KEY="$WORKDIR/ext.key"
PUB="$WORKDIR/ext.pub"
CRT="$WORKDIR/ext.crt"
DATA="$WORKDIR/data.bin"
SUBJECT="/CN=p11-import-test"

# --- 1. generate external material ------------------------------------------
openssl genrsa -out "$KEY" 2048 >/dev/null 2>&1 \
    || die "openssl genrsa failed"
openssl rsa -in "$KEY" -pubout -out "$PUB" >/dev/null 2>&1 \
    || die "openssl rsa -pubout failed"
openssl req -new -x509 -key "$KEY" -subj "$SUBJECT" -days 1 -out "$CRT" \
    >/dev/null 2>&1 || die "openssl req -x509 failed"
printf 'pkcs11-tools-import-test-payload' > "$DATA"

# --- 2. import --------------------------------------------------------------
"$IMPORTPUBK" -l "$PKCS11LIB" -f "$PUB" -i extpub >/dev/null 2>&1 \
    || die "p11importpubk failed"
"$IMPORTCERT" -l "$PKCS11LIB" -f "$CRT" -i extcert >/dev/null 2>&1 \
    || die "p11importcert failed"
"$IMPORTDATA" -l "$PKCS11LIB" -f "$DATA" -i mydata >/dev/null 2>&1 \
    || die "p11importdata failed"

# --- 3. listing -------------------------------------------------------------
out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"
echo "$out" | grep -q 'pubk/extpub'  || die "p11ls: imported public key missing"
echo "$out" | grep -q 'cert/extcert' || die "p11ls: imported certificate missing"
echo "$out" | grep -q 'data/mydata'  || die "p11ls: imported data object missing"

# --- 4. read back -----------------------------------------------------------
# certificate: p11cat emits PEM; OpenSSL must parse it and see our subject.
"$P11CAT" -l "$PKCS11LIB" cert/extcert 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null \
    | grep -q 'p11-import-test' \
    || die "p11cat/openssl: certificate subject mismatch"

# data object: the extracted bytes must match what we imported.
"$P11CAT" -l "$PKCS11LIB" data/mydata 2>/dev/null > "$WORKDIR/data.out" \
    || die "p11cat (data) failed"
cmp -s "$DATA" "$WORKDIR/data.out" \
    || die "p11cat: extracted data differs from the imported blob"

echo "import: OK"
