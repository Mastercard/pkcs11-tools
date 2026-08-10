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

# Integration test: import of externally-generated X.509 certificates
# (p11importcert), in both PEM and DER encodings.
#   1. OpenSSL creates a self-signed certificate (PEM + DER)
#   2. p11importcert imports the PEM certificate onto the token
#   3. p11importcert imports the DER certificate onto the token
#   4. both are listed by p11ls, and the PEM one is exported again with p11cat
#      and its subject compared with the original
#
# This exercises the certificate import/parse paths (pkcs11_cert.c and the
# certificate helpers). Requires openssl to synthesise the certificate.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

OPENSSL=$(command -v openssl 2>/dev/null) || skip "openssl not found in PATH"

P11IMPORTCERT=$(p11bin p11importcert)
P11CAT=$(p11bin p11cat)
P11LS=$(p11bin p11ls)

SUBJECT='/CN=Imported Test Cert/O=Test/C=BE'

# --- 0. synthesise a self-signed certificate (PEM + DER) --------------------
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes \
    -keyout "$WORKDIR/cert.key" -out "$WORKDIR/cert.pem" \
    -days 1 -subj "$SUBJECT" >/dev/null 2>&1 \
    || die "openssl could not create the test certificate"
"$OPENSSL" x509 -in "$WORKDIR/cert.pem" -outform DER \
    -out "$WORKDIR/cert.der" >/dev/null 2>&1 \
    || die "openssl could not convert the certificate to DER"

# --- 1. import the PEM certificate ------------------------------------------
"$P11IMPORTCERT" -l "$PKCS11LIB" -f "$WORKDIR/cert.pem" -i cert-pem \
    >/dev/null 2>&1 || die "p11importcert (PEM) failed"

# --- 2. import the DER certificate ------------------------------------------
"$P11IMPORTCERT" -l "$PKCS11LIB" -f "$WORKDIR/cert.der" -i cert-der \
    >/dev/null 2>&1 || die "p11importcert (DER) failed"

# --- 3. both must be listed -------------------------------------------------
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null) || die "p11ls returned non-zero"
echo "$ls_out" | grep -q 'cert/cert-pem' \
    || die "p11ls: imported PEM certificate not found"
echo "$ls_out" | grep -q 'cert/cert-der' \
    || die "p11ls: imported DER certificate not found"

# --- 4. export the PEM certificate again and compare subjects ---------------
subj_ref=$("$OPENSSL" x509 -in "$WORKDIR/cert.pem" -noout -subject 2>/dev/null)
subj_tok=$("$P11CAT" -l "$PKCS11LIB" cert/cert-pem 2>/dev/null \
    | "$OPENSSL" x509 -noout -subject 2>/dev/null) \
    || die "p11cat could not export the imported certificate"
[ -n "$subj_tok" ] || die "exported certificate subject is empty"
[ "$subj_ref" = "$subj_tok" ] \
    || die "subject mismatch between original and imported certificate"

echo "import certificates (PEM + DER, subject round-trip): OK"
