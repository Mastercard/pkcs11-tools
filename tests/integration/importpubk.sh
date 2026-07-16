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

# Integration test: import of externally-generated public keys (p11importpubk).
#   OpenSSL generates public keys of several types and encodings; each is
#   imported onto the token and, where practical, read back with p11cat and
#   compared to the original. This exercises the public-key parsing/creation
#   paths in pkcs11_pubk.c for RSA, EC and DSA, in both PEM and DER encodings.
#
#   1. RSA public key, PEM   -> import + modulus round-trip via p11cat
#   2. RSA public key, DER   -> import (DER decoding path)
#   3. EC prime256v1, PEM    -> import + public-point round-trip via p11cat
#   4. EC secp384r1, DER     -> import (second curve, DER decoding path)
#   5. DSA public key, PEM   -> import (DSA branch); p11ls confirms dsa(2048)
#   6. DH public key, PEM    -> import (DH branch); p11ls confirms dh(2048)
#   7. Ed25519 public key    -> import (Edwards branch); p11ls confirms ed
#   8. Ed448 public key      -> import (Edwards branch, second curve)
#
# The whole test depends on openssl to synthesise the key material, so it skips
# cleanly when openssl is not available. DH uses hard-coded 2048-bit domain
# parameters (openssl only generates the key, not the slow parameters).

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

OPENSSL=$(command -v openssl 2>/dev/null) || skip "openssl not found in PATH"

P11IMPORTPUBK=$(p11bin p11importpubk)
P11CAT=$(p11bin p11cat)
P11LS=$(p11bin p11ls)

# --- 1. RSA public key, PEM, with modulus round-trip ------------------------
"$OPENSSL" genrsa -out "$WORKDIR/rsa.key" 2048 >/dev/null 2>&1 \
    || die "openssl genrsa failed"
"$OPENSSL" rsa -in "$WORKDIR/rsa.key" -pubout -out "$WORKDIR/rsa.pub.pem" \
    >/dev/null 2>&1 || die "openssl rsa -pubout (PEM) failed"

"$P11IMPORTPUBK" -l "$PKCS11LIB" -f "$WORKDIR/rsa.pub.pem" -i imp-rsa-pem \
    >/dev/null 2>&1 || die "p11importpubk (RSA PEM) failed"

mod_ref=$("$OPENSSL" rsa -pubin -in "$WORKDIR/rsa.pub.pem" -modulus -noout \
    2>/dev/null)
mod_tok=$("$P11CAT" -l "$PKCS11LIB" pubk/imp-rsa-pem 2>/dev/null \
    | "$OPENSSL" rsa -pubin -modulus -noout 2>/dev/null)
[ -n "$mod_ref" ] || die "could not compute reference RSA modulus"
[ "$mod_ref" = "$mod_tok" ] \
    || die "RSA modulus mismatch after import/export round-trip"

# --- 2. RSA public key, DER -------------------------------------------------
"$OPENSSL" rsa -in "$WORKDIR/rsa.key" -pubout -outform DER \
    -out "$WORKDIR/rsa.pub.der" >/dev/null 2>&1 \
    || die "openssl rsa -pubout (DER) failed"
"$P11IMPORTPUBK" -l "$PKCS11LIB" -f "$WORKDIR/rsa.pub.der" -i imp-rsa-der \
    >/dev/null 2>&1 || die "p11importpubk (RSA DER) failed"

# --- 3. EC prime256v1, PEM, with public-point round-trip --------------------
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$WORKDIR/ec.key" \
    >/dev/null 2>&1 || die "openssl ecparam (prime256v1) failed"
"$OPENSSL" ec -in "$WORKDIR/ec.key" -pubout -out "$WORKDIR/ec.pub.pem" \
    >/dev/null 2>&1 || die "openssl ec -pubout (PEM) failed"

"$P11IMPORTPUBK" -l "$PKCS11LIB" -f "$WORKDIR/ec.pub.pem" -i imp-ec-pem \
    >/dev/null 2>&1 || die "p11importpubk (EC PEM) failed"

pt_ref=$("$OPENSSL" ec -pubin -in "$WORKDIR/ec.pub.pem" -text -noout 2>/dev/null \
    | tr -d ' \n:')
pt_tok=$("$P11CAT" -l "$PKCS11LIB" pubk/imp-ec-pem 2>/dev/null \
    | "$OPENSSL" ec -pubin -text -noout 2>/dev/null | tr -d ' \n:')
[ -n "$pt_ref" ] || die "could not compute reference EC public point"
[ "$pt_ref" = "$pt_tok" ] \
    || die "EC public point mismatch after import/export round-trip"

# --- 4. EC secp384r1, DER ---------------------------------------------------
"$OPENSSL" ecparam -name secp384r1 -genkey -noout -out "$WORKDIR/ec384.key" \
    >/dev/null 2>&1 || die "openssl ecparam (secp384r1) failed"
"$OPENSSL" ec -in "$WORKDIR/ec384.key" -pubout -outform DER \
    -out "$WORKDIR/ec384.pub.der" >/dev/null 2>&1 \
    || die "openssl ec -pubout (DER) failed"
"$P11IMPORTPUBK" -l "$PKCS11LIB" -f "$WORKDIR/ec384.pub.der" -i imp-ec-der \
    >/dev/null 2>&1 || die "p11importpubk (EC DER) failed"

# --- 5. DSA public key, PEM -------------------------------------------------
"$OPENSSL" dsaparam -out "$WORKDIR/dsa.par" 2048 >/dev/null 2>&1 \
    || die "openssl dsaparam failed"
"$OPENSSL" gendsa -out "$WORKDIR/dsa.key" "$WORKDIR/dsa.par" >/dev/null 2>&1 \
    || die "openssl gendsa failed"
"$OPENSSL" dsa -in "$WORKDIR/dsa.key" -pubout -out "$WORKDIR/dsa.pub.pem" \
    >/dev/null 2>&1 || die "openssl dsa -pubout failed"
"$P11IMPORTPUBK" -l "$PKCS11LIB" -f "$WORKDIR/dsa.pub.pem" -i imp-dsa-pem \
    >/dev/null 2>&1 || die "p11importpubk (DSA PEM) failed"

# --- 6. DH public key, PEM --------------------------------------------------
# Hard-coded 2048-bit DH parameters (same as keygen_all_types.sh): openssl only
# has to derive a key from them, which is instant, avoiding slow dhparam gen.
cat > "$WORKDIR/dh.par" <<'EOF'
-----BEGIN DH PARAMETERS-----
MIIBDAKCAQEAo4vXgqSVXpOg8d/XbgElhsQtRG+jdwDCrEKSklS9EfJkk6ftMuHy
wx4mQgC+ObPE2w0m1VotW/zj+Tz+cg5zl5C+zIHGa9tCUOjZbN4avQAqVQ9+6QFi
OFXU3gHG6XiPSlZm57QOBxKTGVB1QMW7pqFuc0TPg1JbTGZ8JZnp0/gqObbD9XQf
+vjrx0TupynSpqiqqVmqde6V+NOgZwzBZGMCmFzlpjCxo9b/QkKT3wqqOOYpRxqn
c/qozI+wuvpvlHcPTU8et4fDL0lz6oho2GqcH9ch5jWIVV+36BTsuIPYPvhTpwu1
E6w5hw5wBZMc2XiDKaiz75Vct06e7hxJNwIBAgICAOE=
-----END DH PARAMETERS-----
EOF
"$OPENSSL" genpkey -paramfile "$WORKDIR/dh.par" -out "$WORKDIR/dh.key" \
    >/dev/null 2>&1 || die "openssl genpkey (DH) failed"
"$OPENSSL" pkey -in "$WORKDIR/dh.key" -pubout -out "$WORKDIR/dh.pub.pem" \
    >/dev/null 2>&1 || die "openssl pkey -pubout (DH) failed"
"$P11IMPORTPUBK" -l "$PKCS11LIB" -f "$WORKDIR/dh.pub.pem" -i imp-dh-pem \
    >/dev/null 2>&1 || die "p11importpubk (DH PEM) failed"

# --- 7. Ed25519 public key --------------------------------------------------
"$OPENSSL" genpkey -algorithm ed25519 -out "$WORKDIR/ed25519.key" \
    >/dev/null 2>&1 || skip "openssl cannot generate Ed25519 keys"
"$OPENSSL" pkey -in "$WORKDIR/ed25519.key" -pubout \
    -out "$WORKDIR/ed25519.pub.pem" >/dev/null 2>&1 \
    || die "openssl pkey -pubout (Ed25519) failed"
"$P11IMPORTPUBK" -l "$PKCS11LIB" -f "$WORKDIR/ed25519.pub.pem" -i imp-ed25519 \
    >/dev/null 2>&1 || die "p11importpubk (Ed25519) failed"

# --- 8. Ed448 public key ----------------------------------------------------
"$OPENSSL" genpkey -algorithm ed448 -out "$WORKDIR/ed448.key" \
    >/dev/null 2>&1 || skip "openssl cannot generate Ed448 keys"
"$OPENSSL" pkey -in "$WORKDIR/ed448.key" -pubout \
    -out "$WORKDIR/ed448.pub.pem" >/dev/null 2>&1 \
    || die "openssl pkey -pubout (Ed448) failed"
"$P11IMPORTPUBK" -l "$PKCS11LIB" -f "$WORKDIR/ed448.pub.pem" -i imp-ed448 \
    >/dev/null 2>&1 || die "p11importpubk (Ed448) failed"

# --- confirm every imported public key is present on the token --------------
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null) || die "p11ls returned non-zero"
for _lbl in imp-rsa-pem imp-rsa-der imp-ec-pem imp-ec-der imp-dsa-pem \
            imp-dh-pem imp-ed25519 imp-ed448; do
    echo "$ls_out" | grep -q "pubk/$_lbl" \
        || die "imported public key pubk/$_lbl not listed by p11ls"
done
echo "$ls_out" | grep -q 'imp-dsa-pem.*dsa' \
    || die "p11ls did not report the DSA public key as a DSA key"
echo "$ls_out" | grep -q 'imp-dh-pem.*dh' \
    || die "p11ls did not report the DH public key as a DH key"
echo "$ls_out" | grep -q 'imp-ed25519.*ed' \
    || die "p11ls did not report the Ed25519 public key as an Edwards key"

echo "import public keys (RSA/EC/DSA/DH/Ed25519/Ed448, PEM+DER): OK"
