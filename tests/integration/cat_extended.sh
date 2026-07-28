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

# Integration test: p11cat public-key export, plain and extended (-x).
#   1. generate an RSA and an EC key pair (p11keygen)
#   2. p11cat pubk/<rsa>       -> SubjectPublicKeyInfo   (-----BEGIN PUBLIC KEY-)
#   3. p11cat -x pubk/<rsa>    -> PKCS#1 RSAPublicKey     (-----BEGIN RSA PUBLIC-)
#   4. p11cat pubk/<ec>        -> SubjectPublicKeyInfo    (-----BEGIN PUBLIC KEY-)
#   5. p11cat -x pubk/<ec>     -> EC parameters           (-----BEGIN EC PARAM--)
# When openssl is available the exported material is parsed back to confirm it
# is well-formed and describes the expected key. This exercises the extended
# public-key rendering paths (pkcs11_pubk.c / pkcs11_cat.c).

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11CAT=$(p11bin p11cat)

OPENSSL=$(command -v openssl 2>/dev/null || true)

# --- key material -----------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i cat-rsa \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (RSA) failed"

"$KEYGEN" -l "$PKCS11LIB" -k ec -q prime256v1 -i cat-ec \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (EC) failed"

# --- 1. RSA public key, SubjectPublicKeyInfo (plain) ------------------------
rsa_spki="$WORKDIR/cat-rsa.spki.pem"
"$P11CAT" -l "$PKCS11LIB" pubk/cat-rsa >"$rsa_spki" 2>/dev/null \
    || die "p11cat (RSA, plain) returned non-zero"
grep -q 'BEGIN PUBLIC KEY' "$rsa_spki" \
    || die "p11cat (RSA, plain): missing SubjectPublicKeyInfo PEM header"
if [ -n "$OPENSSL" ]; then
    "$OPENSSL" pkey -pubin -in "$rsa_spki" -noout -text >/dev/null 2>&1 \
        || die "openssl could not parse the RSA SubjectPublicKeyInfo"
fi

# --- 2. RSA public key, PKCS#1 RSAPublicKey (extended, -x) -------------------
rsa_pkcs1="$WORKDIR/cat-rsa.pkcs1.pem"
"$P11CAT" -l "$PKCS11LIB" -x pubk/cat-rsa >"$rsa_pkcs1" 2>/dev/null \
    || die "p11cat -x (RSA) returned non-zero"
grep -q 'BEGIN RSA PUBLIC KEY' "$rsa_pkcs1" \
    || die "p11cat -x (RSA): missing PKCS#1 RSAPublicKey PEM header"
if [ -n "$OPENSSL" ]; then
    "$OPENSSL" rsa -RSAPublicKey_in -in "$rsa_pkcs1" -noout -text >/dev/null 2>&1 \
        || die "openssl could not parse the PKCS#1 RSAPublicKey"
fi

# --- 3. EC public key, SubjectPublicKeyInfo (plain) -------------------------
ec_spki="$WORKDIR/cat-ec.spki.pem"
"$P11CAT" -l "$PKCS11LIB" pubk/cat-ec >"$ec_spki" 2>/dev/null \
    || die "p11cat (EC, plain) returned non-zero"
grep -q 'BEGIN PUBLIC KEY' "$ec_spki" \
    || die "p11cat (EC, plain): missing SubjectPublicKeyInfo PEM header"
if [ -n "$OPENSSL" ]; then
    "$OPENSSL" pkey -pubin -in "$ec_spki" -noout -text 2>/dev/null \
        | grep -qi 'prime256v1' \
        || die "openssl did not report prime256v1 for the EC public key"
fi

# --- 4. EC public key, EC parameters (extended, -x) -------------------------
ec_params="$WORKDIR/cat-ec.params.pem"
"$P11CAT" -l "$PKCS11LIB" -x pubk/cat-ec >"$ec_params" 2>/dev/null \
    || die "p11cat -x (EC) returned non-zero"
grep -q 'BEGIN EC PARAMETERS' "$ec_params" \
    || die "p11cat -x (EC): missing EC PARAMETERS PEM header"

echo "cat extended (RSA SPKI/PKCS#1, EC SPKI/params): OK"
