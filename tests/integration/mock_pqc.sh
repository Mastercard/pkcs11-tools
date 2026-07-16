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

# Integration test: post-quantum (ML-DSA / SLH-DSA / ML-KEM) end-to-end,
# mock-backed.
#
# SoftHSM2 2.6 rejects the PQC keygen mechanisms (CKR_MECHANISM_INVALID), so the
# whole PQC surface -- keygen, key rendering (p11ls/p11od/p11cat), and above all
# the OpenSSL signing provider (lib/pkcs11_provider_pqc.c) used by p11req and
# p11mkcert -- is UNTESTABLE against SoftHSM2. The programmable mock advertises
# the PQC mechanisms and, crucially, generates *real* OpenSSL PQC keys: it
# exports the raw public key into CKA_VALUE (so the tools rebuild the SPKI) and
# C_Sign produces a genuine ML-DSA/SLH-DSA signature. That lets OpenSSL verify
# the CSR / certificate self-signature the tool produces -- a true end-to-end
# check of the token signing path, with fake crypto nowhere in the loop.
#
# Requires OpenSSL >= 3.5 (native ML-DSA/SLH-DSA); both the tools and the mock
# are built against the same libcrypto, so a probe keygen decides whether to run
# or skip. The CSR/cert verification additionally needs the `openssl` CLI.
#
# Covers: pkcs11_provider_pqc.c (signing), pkcs11_cert_common.c PQC SPKI,
# pkcs11_req.c / pkcs11_cert.c PQC arms, pkcs11_keygen.c PQC keygen, the
# ls/od/cat PQC rendering arms, and src/p11keygen.c / p11req.c / p11mkcert.c.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_MOCK_COMMON:?PKCS11_TESTS_MOCK_COMMON must be set by the test harness}"

P11KEYGEN=$(p11bin p11keygen)
P11LS=$(p11bin p11ls)
P11OD=$(p11bin p11od)
P11CAT=$(p11bin p11cat)
P11REQ=$(p11bin p11req)
P11MKCERT=$(p11bin p11mkcert)

# ---------------------------------------------------------------------------
# 0. Probe: is PQC available in this build? (OpenSSL >= 3.5 on both sides.)
if ! "$P11KEYGEN" -k mldsa -b 65 -i pqcprobe >/dev/null 2>&1; then
    skip "PQC not supported by this build (OpenSSL < 3.5?)"
fi

have_openssl=0
if command -v openssl >/dev/null 2>&1; then
    have_openssl=1
fi

# ---------------------------------------------------------------------------
# 1. Keygen driver path: every supported family must generate cleanly. This
#    exercises the p11keygen CLI + lib/pkcs11_keygen.c PQC keypair templates +
#    parameter-set selection (pkcs11_pqc.c) with no token persistence required.
"$P11KEYGEN" -k mldsa  -b 44  -i kg-mldsa44  >/dev/null 2>&1 || die "p11keygen mldsa-44 failed"
"$P11KEYGEN" -k mldsa  -b 65  -i kg-mldsa65  >/dev/null 2>&1 || die "p11keygen mldsa-65 failed"
"$P11KEYGEN" -k mldsa  -b 87  -i kg-mldsa87  >/dev/null 2>&1 || die "p11keygen mldsa-87 failed"
"$P11KEYGEN" -k slhdsa -b 1   -i kg-slhdsa   >/dev/null 2>&1 || die "p11keygen slhdsa failed"
"$P11KEYGEN" -k mlkem  -b 768 -i kg-mlkem768 >/dev/null 2>&1 || die "p11keygen mlkem-768 failed"

# ---------------------------------------------------------------------------
# 2. Seeded ML-DSA-65 key pair: rendering + signing.
#    The mock seeds a persistent ML-DSA key under this label at C_Initialize so
#    that separate tool processes (p11ls, p11od, p11cat, p11req, p11mkcert) all
#    operate on the same real key.
MOCK_P11_PQC_KEYPAIR=pqcml
MOCK_P11_PQC_ALG=ML-DSA-65
export MOCK_P11_PQC_KEYPAIR MOCK_P11_PQC_ALG

# 2a. p11ls must render it as an ML-DSA public+private key pair.
ls_out=$("$P11LS" 2>/dev/null) || die "p11ls (ML-DSA) failed"
echo "$ls_out" | grep -Eq 'pubk/pqcml .*mldsa\(65\)' \
    || die "p11ls did not render the ML-DSA public key:
$ls_out"
echo "$ls_out" | grep -Eq 'prvk/pqcml .*mldsa\(65\)' \
    || die "p11ls did not render the ML-DSA private key:
$ls_out"

# 2b. p11od must dump the public object with its raw CKA_VALUE.
od_out=$("$P11OD" pubk/pqcml 2>/dev/null) || die "p11od (ML-DSA) failed"
echo "$od_out" | grep -q 'CKA_VALUE' \
    || die "p11od did not show CKA_VALUE for the ML-DSA public key:
$od_out"

# 2c. p11cat must emit a PEM SubjectPublicKeyInfo that OpenSSL can parse.
cat_out=$("$P11CAT" pubk/pqcml 2>/dev/null) || die "p11cat (ML-DSA) failed"
echo "$cat_out" | grep -q 'BEGIN PUBLIC KEY' \
    || die "p11cat did not emit a PEM public key:
$cat_out"
if [ "$have_openssl" -eq 1 ]; then
    echo "$cat_out" | openssl pkey -pubin -noout 2>/dev/null \
        || die "openssl could not parse the ML-DSA public key from p11cat"
fi

# 2d. p11req: produce a CSR and have OpenSSL verify the ML-DSA self-signature.
"$P11REQ" -l "$PKCS11LIB" -i pqcml -d '/CN=mldsa.example/O=mock' \
    -o "$WORKDIR/mldsa.csr" 2>/dev/null \
    || die "p11req (ML-DSA) failed to produce a CSR"
[ -s "$WORKDIR/mldsa.csr" ] || die "p11req (ML-DSA) produced an empty CSR"
if [ "$have_openssl" -eq 1 ]; then
    vout=$(openssl req -in "$WORKDIR/mldsa.csr" -noout -verify 2>&1) \
        || die "openssl failed on the ML-DSA CSR:
$vout"
    echo "$vout" | grep -qi 'verify OK' \
        || die "OpenSSL did not confirm the ML-DSA CSR self-signature:
$vout"
    openssl req -in "$WORKDIR/mldsa.csr" -noout -text 2>/dev/null \
        | grep -qi 'ML-DSA-65' \
        || die "ML-DSA CSR does not advertise ML-DSA-65"
fi

# 2e. p11mkcert: self-signed ML-DSA certificate, parseable by OpenSSL.
"$P11MKCERT" -l "$PKCS11LIB" -i pqcml -d '/CN=mldsa.cert' \
    -o "$WORKDIR/mldsa.crt" 2>/dev/null \
    || die "p11mkcert (ML-DSA) failed to produce a certificate"
[ -s "$WORKDIR/mldsa.crt" ] || die "p11mkcert (ML-DSA) produced an empty certificate"
if [ "$have_openssl" -eq 1 ]; then
    subj=$(openssl x509 -in "$WORKDIR/mldsa.crt" -noout -subject 2>/dev/null) \
        || die "openssl could not parse the ML-DSA certificate"
    echo "$subj" | grep -q 'mldsa.cert' \
        || die "ML-DSA certificate has an unexpected subject: $subj"
    openssl x509 -in "$WORKDIR/mldsa.crt" -noout -text 2>/dev/null \
        | grep -qi 'ML-DSA-65' \
        || die "ML-DSA certificate does not advertise ML-DSA-65"
fi

# ---------------------------------------------------------------------------
# 3. Seeded SLH-DSA key pair: exercises the slh_dsa signing arm of the provider.
#    SHA2-128f is the fast variant (signature in a few ms), keeping the test
#    quick while still crossing the CKM_SLH_DSA C_Sign path.
MOCK_P11_PQC_KEYPAIR=pqcslh
MOCK_P11_PQC_ALG=SLH-DSA-SHA2-128f
export MOCK_P11_PQC_KEYPAIR MOCK_P11_PQC_ALG

ls_out=$("$P11LS" 2>/dev/null) || die "p11ls (SLH-DSA) failed"
echo "$ls_out" | grep -Eq 'prvk/pqcslh .*slhdsa' \
    || die "p11ls did not render the SLH-DSA private key:
$ls_out"

"$P11REQ" -l "$PKCS11LIB" -i pqcslh -d '/CN=slhdsa.example' \
    -o "$WORKDIR/slhdsa.csr" 2>/dev/null \
    || die "p11req (SLH-DSA) failed to produce a CSR"
[ -s "$WORKDIR/slhdsa.csr" ] || die "p11req (SLH-DSA) produced an empty CSR"
if [ "$have_openssl" -eq 1 ]; then
    vout=$(openssl req -in "$WORKDIR/slhdsa.csr" -noout -verify 2>&1) \
        || die "openssl failed on the SLH-DSA CSR:
$vout"
    echo "$vout" | grep -qi 'verify OK' \
        || die "OpenSSL did not confirm the SLH-DSA CSR self-signature:
$vout"
    openssl req -in "$WORKDIR/slhdsa.csr" -noout -text 2>/dev/null \
        | grep -qi 'SLH-DSA-SHA2-128F' \
        || die "SLH-DSA CSR does not advertise SLH-DSA-SHA2-128f"
fi

echo "PASS: mock-backed PQC keygen, rendering and ML-DSA/SLH-DSA signing"
exit 0
