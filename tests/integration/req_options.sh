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

# Integration test: p11req option coverage beyond the basic happy path.
#   - RSA-PSS signature (-a pss) with SHA-384 (-H sha384)
#   - Subject Alternative Names (-e DNS:/email:/IP:) and a Subject Key
#     Identifier extension (-X), written to an output file (-o)
#   - EC CSR with SHA-512 (-H sha512), emitted to stdout
#   - fake signing (-F): a syntactically valid but not-really-signed CSR
#
# Each real CSR is verified with OpenSSL (self-signature) and the SAN content is
# checked. This exercises the signature-algorithm, digest, extension and output
# branches of p11req.c / pkcs11_cert_common.c. Requires openssl.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

OPENSSL=$(command -v openssl 2>/dev/null) || skip "openssl not found in PATH"

KEYGEN=$(p11bin p11keygen)
P11REQ=$(p11bin p11req)

# --- key material -----------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i req-rsa \
    sign=true verify=true >/dev/null 2>&1 || die "p11keygen (RSA) failed"
"$KEYGEN" -l "$PKCS11LIB" -k ec -q prime256v1 -i req-ec \
    sign=true verify=true >/dev/null 2>&1 || die "p11keygen (EC) failed"

# --- 1. RSA-PSS + SHA-384 + SANs + SKI, to a file ---------------------------
pss_csr="$WORKDIR/pss.csr"
"$P11REQ" -l "$PKCS11LIB" -i req-rsa -d '/CN=pss.example/O=Test/C=BE' \
    -a pss -H sha384 \
    -e DNS:pss.example -e email:admin@pss.example -e IP:192.0.2.10 \
    -X -o "$pss_csr" >/dev/null 2>&1 \
    || die "p11req (RSA-PSS/sha384/SAN/SKI) failed"
[ -s "$pss_csr" ] || die "p11req (RSA-PSS) produced an empty file"

"$OPENSSL" req -in "$pss_csr" -noout -verify >/dev/null 2>&1 \
    || die "RSA-PSS CSR failed OpenSSL self-signature verification"

req_text=$("$OPENSSL" req -in "$pss_csr" -noout -text 2>/dev/null)
echo "$req_text" | grep -qi 'rsassaPss' \
    || die "RSA-PSS CSR: signature algorithm is not rsassaPss"
echo "$req_text" | grep -q 'DNS:pss.example' \
    || die "RSA-PSS CSR: DNS SAN missing"
echo "$req_text" | grep -q 'admin@pss.example' \
    || die "RSA-PSS CSR: email SAN missing"
echo "$req_text" | grep -q '192.0.2.10' \
    || die "RSA-PSS CSR: IP SAN missing"

# --- 2. EC CSR + SHA-512, to stdout -----------------------------------------
"$P11REQ" -l "$PKCS11LIB" -i req-ec -d '/CN=ec.example' -H sha512 2>/dev/null \
    | "$OPENSSL" req -noout -verify >/dev/null 2>&1 \
    || die "EC CSR (sha512) failed OpenSSL self-signature verification"

# --- 3. fake-signed CSR (-F): parseable, subject preserved ------------------
fake_subject=$("$P11REQ" -l "$PKCS11LIB" -i req-rsa -d '/CN=fake.example' -F \
    2>/dev/null | "$OPENSSL" req -noout -subject 2>/dev/null) \
    || die "p11req -F (fake signing) produced an unparseable CSR"
echo "$fake_subject" | grep -q 'fake.example' \
    || die "p11req -F: subject not preserved in fake-signed CSR"

echo "req options (PSS/sha384/SAN/SKI, EC sha512, fake): OK"
