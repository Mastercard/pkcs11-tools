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

# Integration test: p11mkcert option coverage beyond the basic self-signed
# path exercised by mkcert.sh. Drives the extension / signature / validity
# branches of pkcs11_cert_common.c and pkcs11_cert.c:
#
#   1. RSA-PSS + custom validity (-u) + SAN (-e, x3) + SKI (-X)
#      -> OpenSSL confirms the PSS algorithm, both extensions and the SAN values
#   2. reverse subject DN (-r)      -> CN appears first in the parsed subject
#   3. verbose certificate dump (-v) -> the human-readable "Certificate:" render
#
# openssl is required to parse and validate the generated certificates.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

command -v openssl >/dev/null 2>&1 || skip "openssl not found in PATH"

KEYGEN=$(p11bin p11keygen)
P11MKCERT=$(p11bin p11mkcert)

"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i mko-rsa \
    sign=true verify=true >/dev/null 2>&1 || die "p11keygen (RSA) failed"

# --- 1. PSS + validity + SAN + SKI ------------------------------------------
cert="$WORKDIR/mko.pem"
"$P11MKCERT" -l "$PKCS11LIB" -i mko-rsa -a pss -H sha256 -u 3650 -X \
    -e DNS:example.com -e email:admin@example.com -e IP:10.0.0.1 \
    -d '/CN=p11mkcert-opt/O=TestOrg' >"$cert" 2>/dev/null \
    || die "p11mkcert (PSS+SAN+SKI) failed"

text=$(openssl x509 -in "$cert" -noout -text 2>/dev/null) \
    || die "OpenSSL could not parse the PSS certificate"

printf '%s\n' "$text" | grep -qi 'rsassaPss' \
    || die "expected an RSA-PSS signature algorithm"
printf '%s\n' "$text" | grep -q 'Subject Alternative Name' \
    || die "SAN extension missing"
printf '%s\n' "$text" | grep -q 'example.com' \
    || die "SAN DNS value missing"
printf '%s\n' "$text" | grep -q 'Subject Key Identifier' \
    || die "SKI extension missing"

# -u 3650 => certificate must not already be expired
openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 \
    || die "certificate unexpectedly reported as expired"

# --- 2. reverse subject DN --------------------------------------------------
subject=$("$P11MKCERT" -l "$PKCS11LIB" -i mko-rsa -r \
    -d '/CN=rev-cn/O=RevOrg/C=BE' 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null) \
    || die "p11mkcert (-r) failed"
# With -r the CN is emitted first; without it C would lead.
printf '%s\n' "$subject" | grep -qE 'subject=[^,]*CN[[:space:]]*=[[:space:]]*rev-cn' \
    || die "reverse DN did not place CN first (got: $subject)"

# --- 3. verbose certificate dump --------------------------------------------
"$P11MKCERT" -l "$PKCS11LIB" -i mko-rsa -v -d '/CN=verbose-dump' 2>/dev/null \
    | grep -q 'Certificate:' \
    || die "verbose (-v) did not print a human-readable certificate"

echo "p11mkcert options (PSS/SAN/SKI/validity/reverse/verbose): OK"
