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

# Integration test: DSA signing through the OpenSSL provider.
#   Producing a CSR (p11req) or a self-signed certificate (p11mkcert) with a DSA
#   key stored on the token drives the OpenSSL provider glue that signs with the
#   on-token key. PKCS#11 CKM_DSA returns a raw r||s pair which the provider
#   wraps into a DSA_SIG and DER-encodes for X.509 / PKCS#10
#   (pkcs11_provider_dsa.c). This is distinct from DSA key *generation*, which
#   is covered by keygen_all_types.sh.
#
#   1. DSA-2048 key -> p11req CSR (default sha256), verified by OpenSSL
#   2. same key     -> p11req CSR with explicit sha256, verified by OpenSSL
#   3. same key     -> p11req CSR with sha224, verified by OpenSSL
#   4. same key     -> p11mkcert self-signed certificate, subject checked
#   5. sha384 is rejected: DSA has no signature OID for it (error path)
#
# Requires openssl (for signature verification and certificate parsing).

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

OPENSSL=$(command -v openssl 2>/dev/null) || skip "openssl not found in PATH"

KEYGEN=$(p11bin p11keygen)
P11REQ=$(p11bin p11req)
P11MKCERT=$(p11bin p11mkcert)

# --- DSA domain parameters (fixed 2048-bit, so we do not pay for slow openssl
#     dsaparam generation and the test stays deterministic) -------------------
dsa_params="$WORKDIR/dsa2048.pem"
cat > "$dsa_params" <<'EOF'
-----BEGIN DSA PARAMETERS-----
MIICKAKCAQEAnC6KjaLcbEyXHgoj414nH/tr3F4eruF4krZAjqkFoWerXD1u1yVB
3Y7tdFQ8NyVl2QU5aleZf+qQhlp5mj/Ne2jVOfdZpdJCg6cOEF7nzaH1JrDE6dYN
hdt7QWEZLj404+qpdlVhQC2RERplO892bC+TPITBuHhGdeAfHilB1j1ElDIE0JEU
2HKaUItmRDBhiOliasKDJfMdUFYwffMFksm/01Vy2UUbI1lKiTiU8mc/5i5Yj3Y0
dXRlxWR6wT37c6g+OxkTkoTLWDB+V7FpVMZgrodNZttmuLDTlH0T3JpKEWg2zcuL
EoG7OmRF3ZcTsjRLFIq76gVL3sJFdj3xOwIdALft2dMyXf6uCzHsVFvbjMWKd8GV
aSEW3amgzWUCggEAJ7Rlr8TF4aDPIoJHK771Fk26vKNTGzLq1aUoJIZcc0kvPaNE
YQqbLo15aRtk0c2zl+7XI/fkuVi0doTl+7hi/SSWKZsW9mzt1gpwSiAkKkDxGabc
EzILTjOswnGJs3wD71AhLMc/9umpEIs9iwHTf2Dawi+Qzm+GZWQVM1lcI8v+yjOe
L84dOoNBXWZHs6wlACztacXT4ujCT21TV525H31QcCOZPe/fKh788DSXilTzGBzp
gZ2WgU6tGjCR4KRtQmDjVactcGBMuTbZiktmUNs72HJGsBOSEGjG/KfWUeOwa3F2
gNegu5PP7Qm4E9Vrd4MBa4Kj5C3iqTms73ecFA==
-----END DSA PARAMETERS-----
EOF

# --- key material -----------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k dsa -d "$dsa_params" -i dsa-sign \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (DSA 2048) failed"

# --- 1. CSR with the default hash (sha256) ----------------------------------
"$P11REQ" -l "$PKCS11LIB" -i dsa-sign -d '/CN=dsa.example' 2>/dev/null \
    | "$OPENSSL" req -noout -verify >/dev/null 2>&1 \
    || die "DSA CSR (sha256) failed OpenSSL self-signature verification"

# --- 2. CSR with explicit sha256 --------------------------------------------
"$P11REQ" -l "$PKCS11LIB" -i dsa-sign -H sha256 -d '/CN=dsa-sha256.example' 2>/dev/null \
    | "$OPENSSL" req -noout -verify >/dev/null 2>&1 \
    || die "DSA CSR (explicit sha256) failed OpenSSL self-signature verification"

# --- 3. CSR with sha224 -----------------------------------------------------
"$P11REQ" -l "$PKCS11LIB" -i dsa-sign -H sha224 -d '/CN=dsa-sha224.example' 2>/dev/null \
    | "$OPENSSL" req -noout -verify >/dev/null 2>&1 \
    || die "DSA CSR (sha224) failed OpenSSL self-signature verification"

# --- 4. self-signed certificate ---------------------------------------------
cert_subject=$("$P11MKCERT" -l "$PKCS11LIB" -i dsa-sign \
    -d '/CN=dsa-cert' 2>/dev/null \
    | "$OPENSSL" x509 -noout -subject 2>/dev/null) \
    || die "p11mkcert (DSA) produced an unparseable certificate"
echo "$cert_subject" | grep -q 'dsa-cert' \
    || die "p11mkcert (DSA): unexpected certificate subject"

# --- 5. sha384 is rejected (DSA provider has no signature OID for it) --------
# This exercises the provider's "no sigid for md" error branch. The command
# must fail; OpenSSL must not receive a valid CSR.
set +e
"$P11REQ" -l "$PKCS11LIB" -i dsa-sign -H sha384 -d '/CN=dsa-sha384.example' \
    >"$WORKDIR/sha384.out" 2>"$WORKDIR/sha384.err"
rc=$?
set -e
[ "$rc" -ne 0 ] \
    || die "DSA CSR with sha384 unexpectedly succeeded (expected rejection)"

echo "dsa signing (req sha256/sha224 + cert, sha384 rejected): OK"
