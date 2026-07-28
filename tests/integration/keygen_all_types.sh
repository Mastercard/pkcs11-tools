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

# Integration test: exhaustively generate every key type/size that SoftHSM2
# supports through p11keygen, and confirm each key is created with the expected
# rendering in p11ls. This exercises the per-mechanism generation branches of
# pkcs11_keygen.c and the per-key-type rendering in pkcs11_ls.c:
#
#   AES     : 128 / 192 / 256
#   DES     : 64 (single) / 128 (DES2) / 192 (DES3)
#   RSA     : 1024 / 2048 / 3072 / 4096
#   EC      : prime256v1 / secp384r1 / secp521r1
#   ED      : Ed25519 / Ed448
#   generic : HMAC-style generic secret (160 / 256)
#   DSA     : 2048 (domain parameters supplied below)
#   DH      : 2048 (domain parameters supplied below)
#
# DSA and DH require a domain-parameter file. Rather than depend on the openssl
# CLI (and pay for slow dhparam generation), fixed 2048-bit parameters are
# embedded below, keeping the test fully token-only and deterministic.
#
# Mechanisms SoftHSM2 does NOT support (ML-KEM / ML-DSA / SLH-DSA -> keygen
# returns CKR_MECHANISM_INVALID) are intentionally out of scope here.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11LS=$(p11bin p11ls)
have_ed448=0

# --- embedded DSA / DH domain parameters ------------------------------------
dsa_params="$WORKDIR/dsa2048.pem"
dh_params="$WORKDIR/dh2048.pem"

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

# --- symmetric keys ---------------------------------------------------------
for bits in 128 192 256; do
    "$KEYGEN" -l "$PKCS11LIB" -k aes -b "$bits" -i "kat-aes$bits" \
        encrypt=true decrypt=true >/dev/null 2>&1 \
        || die "p11keygen aes/$bits failed"
done

# DES: 64 = single DES, 128 = DES2, 192 = DES3
for bits in 64 128 192; do
    "$KEYGEN" -l "$PKCS11LIB" -k des -b "$bits" -i "kat-des$bits" \
        encrypt=true decrypt=true >/dev/null 2>&1 \
        || die "p11keygen des/$bits failed"
done

# generic secret (HMAC-style); also exercise the 'hmac' alias for one size
"$KEYGEN" -l "$PKCS11LIB" -k generic -b 160 -i kat-gen160 \
    sign=true verify=true >/dev/null 2>&1 || die "p11keygen generic/160 failed"
"$KEYGEN" -l "$PKCS11LIB" -k hmac -b 256 -i kat-gen256 \
    sign=true verify=true >/dev/null 2>&1 || die "p11keygen hmac/256 failed"

# --- RSA --------------------------------------------------------------------
for bits in 1024 2048 3072 4096; do
    "$KEYGEN" -l "$PKCS11LIB" -k rsa -b "$bits" -i "kat-rsa$bits" \
        sign=true verify=true >/dev/null 2>&1 \
        || die "p11keygen rsa/$bits failed"
done

# --- EC ---------------------------------------------------------------------
for curve in prime256v1 secp384r1 secp521r1; do
    "$KEYGEN" -l "$PKCS11LIB" -k ec -q "$curve" -i "kat-ec-$curve" \
        sign=true verify=true >/dev/null 2>&1 \
        || die "p11keygen ec/$curve failed"
done

# --- EdDSA ------------------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k ed -q ed25519 -i kat-ed25519 \
    sign=true verify=true >/dev/null 2>&1 || die "p11keygen ed/ed25519 failed"
if supports_ed448_keygen; then
    have_ed448=1
    "$KEYGEN" -l "$PKCS11LIB" -k ed -q ed448 -i kat-ed448 \
        sign=true verify=true >/dev/null 2>&1 || die "p11keygen ed/ed448 failed"
fi

# --- DSA / DH (with embedded domain parameters) -----------------------------
"$KEYGEN" -l "$PKCS11LIB" -k dsa -d "$dsa_params" -i kat-dsa \
    sign=true verify=true >/dev/null 2>&1 || die "p11keygen dsa (2048 params) failed"
"$KEYGEN" -l "$PKCS11LIB" -k dh -d "$dh_params" -i kat-dh \
    derive=true >/dev/null 2>&1 || die "p11keygen dh (2048 params) failed"

# --- verify renderings in a single p11ls listing ----------------------------
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null) || die "p11ls returned non-zero"

# check_render LABEL PREFIX RENDER: assert p11ls shows PREFIX/LABEL with RENDER.
check_render() {
    printf '%s\n' "$ls_out" \
        | grep -E "${2}/${1}[[:space:]]" \
        | grep -q "$3" \
        || die "p11ls: ${2}/${1} not rendered as '${3}'"
}

# symmetric keys are secret keys (seck)
check_render kat-aes128 seck 'aes(128)'
check_render kat-aes192 seck 'aes(192)'
check_render kat-aes256 seck 'aes(256)'
check_render kat-des64  seck 'des(64)'
check_render kat-des128 seck 'des(128)'
check_render kat-des192 seck 'des(192)'
check_render kat-gen160 seck 'generic'
check_render kat-gen256 seck 'generic'

# asymmetric keys expose both a private (prvk) and a public (pubk) object
for bits in 1024 2048 3072 4096; do
    check_render "kat-rsa$bits" prvk "rsa($bits)"
    check_render "kat-rsa$bits" pubk "rsa($bits)"
done
for curve in prime256v1 secp384r1 secp521r1; do
    check_render "kat-ec-$curve" prvk "ec($curve)"
    check_render "kat-ec-$curve" pubk "ec($curve)"
done
check_render kat-ed25519 prvk 'ed(ED25519)'
check_render kat-ed25519 pubk 'ed(ED25519)'
if [ "$have_ed448" -eq 1 ]; then
    check_render kat-ed448   prvk 'ed(ED448)'
    check_render kat-ed448   pubk 'ed(ED448)'
fi
check_render kat-dsa     prvk 'dsa(2048)'
check_render kat-dsa     pubk 'dsa(2048)'
check_render kat-dh      prvk 'dh(2048)'
check_render kat-dh      pubk 'dh(2048)'

echo "p11keygen all SoftHSM-supported key types: OK"
