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

# Integration test: driving the tools against the Mozilla NSS software token
# (libsoftokn3.so) instead of SoftHSM2.
#
# NSS is a second, independent PKCS#11 implementation. Exercising it covers code
# that SoftHSM2 never reaches, in particular the NSS initialisation branch of
# lib/pkcs11_context.c (the tools hand the database location to softoken through
# the NSS-specific CK_NSS_C_INITIALIZE_ARGS.LibraryParameters member) and the
# `-m' / PKCS11NSSDIR option shared by every tool.
#
# Two phases, matching the two ways softoken can be configured (see
# nss_common.sh for the rationale):
#   1. read-only queries via the tool's own `-m <configdir>' option;
#   2. read-write operations (key generation, listing) via NSS_LIB_PARAMS,
#      wrapped by the nss_rw helper.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_NSS_COMMON:?PKCS11_TESTS_NSS_COMMON must be set by the test harness}"

P11SLOTINFO=$(p11bin p11slotinfo)
P11KEYGEN=$(p11bin p11keygen)
P11LS=$(p11bin p11ls)
P11OD=$(p11bin p11od)

# ---------------------------------------------------------------------------
# Phase 1: read-only slot / token / mechanism enumeration through `-m'.
#
# The generic ("NSS Generic Crypto Services") slot needs no login, so these
# checks exercise the tool's NSS_InitArgs branch and p11slotinfo's mechanism
# rendering without depending on the (finicky) NSS login path.

si_out=$("$P11SLOTINFO" -m "$PKCS11NSSDIR" -l "$PKCS11LIB" -s "$NSS_GENERIC_SLOT" 2>&1) \
    || die "p11slotinfo (-m, NSS) failed: $si_out"
echo "$si_out" | grep -q 'NSS Generic Crypto Services' \
    || die "p11slotinfo (-m, NSS): expected NSS token label not found"
# softoken advertises a large software mechanism set; require a healthy count so
# the test fails loudly if enumeration silently returns nothing.
mech_count=$(echo "$si_out" | grep -c 'CKM_')
[ "$mech_count" -ge 50 ] \
    || die "p11slotinfo (-m, NSS): only $mech_count mechanisms listed (expected >= 50)"
echo "$si_out" | grep -q 'CKM_RSA_PKCS' \
    || die "p11slotinfo (-m, NSS): CKM_RSA_PKCS not advertised"
echo "$si_out" | grep -q 'CKM_AES_' \
    || die "p11slotinfo (-m, NSS): no AES mechanism advertised"

# The -e switch adds elliptic-curve details to the mechanism table.
sie_out=$("$P11SLOTINFO" -m "$PKCS11NSSDIR" -l "$PKCS11LIB" -s "$NSS_GENERIC_SLOT" -e 2>&1) \
    || die "p11slotinfo (-m -e, NSS) failed: $sie_out"
echo "$sie_out" | grep -q 'CKM_ECDSA' \
    || die "p11slotinfo (-m -e, NSS): CKM_ECDSA not advertised"
echo "$sie_out" | grep -q 'ec:' \
    || die "p11slotinfo (-m -e, NSS): elliptic-curve details missing"

# ---------------------------------------------------------------------------
# Phase 2: read-write operations on the persistent "NSS Certificate DB" token.
#
# These go through nss_rw so softoken opens *our* database read-write and the
# login with PKCS11PASSWORD succeeds. RSA, EC and AES generation cover the
# public-key, private-key and secret-key object paths against a second backend.

nss_rw "$P11KEYGEN" -l "$PKCS11LIB" -s "$PKCS11SLOT" -p "$PKCS11PASSWORD" \
    -k rsa -b 2048 -i nsskey sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (RSA, NSS) failed"
nss_rw "$P11KEYGEN" -l "$PKCS11LIB" -s "$PKCS11SLOT" -p "$PKCS11PASSWORD" \
    -k ec -d prime256v1 -i nssec sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (EC, NSS) failed"
nss_rw "$P11KEYGEN" -l "$PKCS11LIB" -s "$PKCS11SLOT" -p "$PKCS11PASSWORD" \
    -k aes -b 256 -i nssaes encrypt=true decrypt=true >/dev/null 2>&1 \
    || die "p11keygen (AES, NSS) failed"

ls_out=$(nss_rw "$P11LS" -l "$PKCS11LIB" -s "$PKCS11SLOT" -p "$PKCS11PASSWORD" 2>&1) \
    || die "p11ls (NSS) failed: $ls_out"
echo "$ls_out" | grep -q 'pubk/nsskey' \
    || die "p11ls (NSS): RSA public key not found"
echo "$ls_out" | grep -q 'prvk/nsskey' \
    || die "p11ls (NSS): RSA private key not found"
echo "$ls_out" | grep -q 'pubk/nssec' \
    || die "p11ls (NSS): EC public key not found"
echo "$ls_out" | grep -q 'seck/nssaes' \
    || die "p11ls (NSS): AES secret key not found"

# p11od against NSS renders the object's attributes; confirm it succeeds and
# shows the expected class/type for the AES key.
od_out=$(nss_rw "$P11OD" -l "$PKCS11LIB" -s "$PKCS11SLOT" -p "$PKCS11PASSWORD" seck/nssaes 2>&1) \
    || die "p11od (NSS) failed: $od_out"
echo "$od_out" | grep -q 'CKO_SECRET_KEY' \
    || die "p11od (NSS): CKA_CLASS not rendered for the AES key"
echo "$od_out" | grep -q 'CKK_AES' \
    || die "p11od (NSS): CKA_KEY_TYPE not rendered for the AES key"

echo "NSS softoken backend (slotinfo -m/-e read-only, keygen/ls/od read-write): OK"
