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

# Integration test: rendering of the object types that the other display tests
# (attr_od / cat_extended / od_more / od_cat_types / more / pubk_render) do not
# yet reach. It exercises the dedicated per-type branches of pkcs11_cat.c,
# pkcs11_more.c and pkcs11_od.c:
#
#   - DH public key      : SubjectPublicKeyInfo (p11cat), native DH PARAMETERS
#                          (p11cat -x), human-readable dump (p11more) and the
#                          CKA_PRIME / CKA_BASE / CKA_VALUE + CKK_DH attribute
#                          rendering (p11od).            [pkcs11_*.c CKK_DH case]
#   - Ed448 public key   : SPKI (p11cat), the "no usable curve parameters"
#                          warning (p11cat -x), human-readable dump (p11more)
#                          and CKK_EC_EDWARDS rendering (p11od).  [ed448 branch]
#   - secret/private key : the "***WARNING: ... can't be disclosed" branch of
#                          both p11cat and p11more (CKO_SECRET_KEY/PRIVATE_KEY).
#   - DES / DES2 / DES3 / generic-secret : the CKK_DES / CKK_DES2 / CKK_DES3 /
#                          CKK_GENERIC_SECRET arms of the p11od key-type switch.
#
# Everything is generated on the token by p11keygen (DH uses hard-coded 2048-bit
# domain parameters to avoid slow runtime generation and any openssl dependency),
# so this test needs only SoftHSM2.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11OD=$(p11bin p11od)
P11MORE=$(p11bin p11more)
P11CAT=$(p11bin p11cat)
have_ed448=0

# Fixed 2048-bit DH domain parameters (same as keygen_all_types.sh) so DH key
# generation is instant and reproducible, with no openssl CLI dependency.
dh_params="$WORKDIR/dhparam.pem"
cat > "$dh_params" <<'EOF'
-----BEGIN DH PARAMETERS-----
MIIBDAKCAQEAo4vXgqSVXpOg8d/XbgElhsQtRG+jdwDCrEKSklS9EfJkk6ftMuHy
wx4mQgC+ObPE2w0m1VotW/zj+Tz+cg5zl5C+zIHGa9tCUOjZbN4avQAqVQ9+6QFi
OFXU3gHG6XiPSlZm57QOBxKTGVB1QMW7pqFuc0TPg1JbTGZ8JZnp0/gqObbD9XQf
+vjrx0TupynSpqiqqVmqde6V+NOgZwzBZGMCmFzlpjCxo9b/QkKT3wqqOOYpRxqn
c/qozI+wuvpvlHcPTU8et4fDL0lz6oho2GqcH9ch5jWIVV+36BTsuIPYPvhTpwu1
E6w5hw5wBZMc2XiDKaiz75Vct06e7hxJNwIBAgICAOE=
-----END DH PARAMETERS-----
EOF

# --- DH keypair -------------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k dh -d "$dh_params" -i rt-dh derive=true \
    >/dev/null 2>&1 || die "p11keygen (DH) failed"

# p11cat: encapsulated SubjectPublicKeyInfo
"$P11CAT" -l "$PKCS11LIB" pubk/rt-dh 2>/dev/null \
    | grep -q 'BEGIN PUBLIC KEY' \
    || die "p11cat: DH public key not exported as SubjectPublicKeyInfo"

# p11cat -x: native openssl DH PARAMETERS block
"$P11CAT" -x -l "$PKCS11LIB" pubk/rt-dh 2>/dev/null \
    | grep -q 'BEGIN DH PARAMETERS' \
    || die "p11cat -x: DH public key did not emit native DH PARAMETERS"

# p11more: human-readable dump
"$P11MORE" -l "$PKCS11LIB" pubk/rt-dh 2>/dev/null \
    | grep -qi 'DH Public-Key' \
    || die "p11more: DH public key not rendered"

# p11od: the DH-specific attributes and key-type name
dhod=$("$P11OD" -l "$PKCS11LIB" pubk/rt-dh 2>/dev/null) \
    || die "p11od (DH public key) returned non-zero"
for attr in CKA_PRIME CKA_BASE CKA_VALUE CKK_DH; do
    printf '%s\n' "$dhod" | grep -q "$attr" \
        || die "p11od: DH public key output missing $attr"
done

# secret/private-key non-disclosure warning (private half of the DH pair)
"$P11CAT" -l "$PKCS11LIB" prvk/rt-dh 2>&1 \
    | grep -q "can't be disclosed" \
    || die "p11cat: missing non-disclosure warning for a private key"
"$P11MORE" -l "$PKCS11LIB" prvk/rt-dh 2>&1 \
    | grep -q "can't be disclosed" \
    || die "p11more: missing non-disclosure warning for a private key"

# --- Ed448 keypair ----------------------------------------------------------
if supports_ed448_keygen; then
    have_ed448=1

    "$KEYGEN" -l "$PKCS11LIB" -k ed -q ed448 -i rt-ed448 \
        sign=true verify=true >/dev/null 2>&1 || die "p11keygen (Ed448) failed"

    "$P11CAT" -l "$PKCS11LIB" pubk/rt-ed448 2>/dev/null \
        | grep -q 'BEGIN PUBLIC KEY' \
        || die "p11cat: Ed448 public key not exported as SubjectPublicKeyInfo"

    # -x on an Edwards curve prints a warning (no usable curve parameters)
    "$P11CAT" -x -l "$PKCS11LIB" pubk/rt-ed448 2>&1 >/dev/null \
        | grep -qi 'Edwards 448' \
        || die "p11cat -x: expected the Edwards-448 no-parameters warning"

    "$P11MORE" -l "$PKCS11LIB" pubk/rt-ed448 2>/dev/null \
        | grep -qi 'ED448 Public-Key' \
        || die "p11more: Ed448 public key not rendered"

    "$P11OD" -l "$PKCS11LIB" pubk/rt-ed448 2>/dev/null \
        | grep -q 'CKK_EC_EDWARDS' \
        || die "p11od: Ed448 public key not reported as CKK_EC_EDWARDS"
fi

# --- symmetric key types (p11od key-type switch arms) -----------------------
# DES(64) -> CKK_DES, DES2(128) -> CKK_DES2, DES3(192) -> CKK_DES3
for pair in 64:CKK_DES 128:CKK_DES2 192:CKK_DES3; do
    bits=${pair%%:*}; want=${pair##*:}
    lbl="rt-des$bits"
    "$KEYGEN" -l "$PKCS11LIB" -k des -b "$bits" -i "$lbl" \
        encrypt=true decrypt=true >/dev/null 2>&1 \
        || die "p11keygen des/$bits failed"
    "$P11OD" -l "$PKCS11LIB" "seck/$lbl" 2>/dev/null \
        | grep -q "$want" \
        || die "p11od: $lbl not reported as $want"
done

# generic secret -> CKK_GENERIC_SECRET
"$KEYGEN" -l "$PKCS11LIB" -k generic -b 160 -i rt-gen \
    sign=true verify=true >/dev/null 2>&1 || die "p11keygen generic/160 failed"
"$P11OD" -l "$PKCS11LIB" seck/rt-gen 2>/dev/null \
    | grep -q 'CKK_GENERIC_SECRET' \
    || die "p11od: generic secret not reported as CKK_GENERIC_SECRET"

# non-disclosure warning on a secret key too
"$P11CAT" -l "$PKCS11LIB" seck/rt-gen 2>&1 \
    | grep -q "can't be disclosed" \
    || die "p11cat: missing non-disclosure warning for a secret key"

echo "DH / optional Ed448 / DES* / generic rendering (od/more/cat) + non-disclosure: OK"
