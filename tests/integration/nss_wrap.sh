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

# Integration test: CBC-PAD key wrapping against the NSS software token.
#
# CBC-PAD wrapping (the CKM_<cipher>_CBC_PAD mechanisms) is deliberately NOT
# exercised by the SoftHSM2 tests: SoftHSM2 does not offer those mechanisms for
# wrapping, so its C_WrapKey call fails before the tool's success path runs.
# NSS softoken *does* support CKM_AES_CBC_PAD, which lets this test drive the
# whole cbcpad wrap/unwrap round-trip -- the size-query + real C_WrapKey calls
# in lib/pkcs11_wrap.c _wrap_cbcpad() and the matching C_UnwrapKey path in
# lib/pkcs11_unwrap.c _unwrap_cbcpad() -- that no other backend reaches.
#
# Three round-trips, all read-write and therefore driven through nss_rw (see
# nss_common.sh): a symmetric key wrapped with plain cbcpad, the same key
# wrapped with an envelope whose inner algorithm is cbcpad (RSA-OAEP outer), and
# an RSA private key wrapped with cbcpad.
#
# NSS caveat honoured throughout: NSS softoken keys its internal object store by
# CKA_ID, so two objects sharing a CKA_ID collide (the later silently displaces
# the earlier). p11keygen derives the CKA_ID as "<type><bits>-<unix-time>", so
# two keys of the *same* type and size generated within the same second would
# clash. The key inventory below therefore uses distinct type/size combinations
# (aes-256, aes-128, rsa-2048, rsa-3072) so every generated CKA_ID is unique,
# and each unwrapped key is given an explicit, distinct CKA_ID.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_NSS_COMMON:?PKCS11_TESTS_NSS_COMMON must be set by the test harness}"

P11KEYGEN=$(p11bin p11keygen)
P11WRAP=$(p11bin p11wrap)
P11UNWRAP=$(p11bin p11unwrap)
P11KCV=$(p11bin p11kcv)
P11LS=$(p11bin p11ls)

L="$PKCS11LIB"
S="$PKCS11SLOT"
P="$PKCS11PASSWORD"

# kcv_of LABEL: echo the ECB key check value of secret key seck/LABEL.
kcv_of() {
    nss_rw "$P11KCV" -l "$L" -s "$S" -p "$P" -f ecb "seck/$1" 2>/dev/null \
        | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p'
}

# --- key material -----------------------------------------------------------
# Distinct type/size combinations keep every auto-generated CKA_ID unique so
# NSS' CKA_ID-keyed store never clobbers a previously generated key.
nss_rw "$P11KEYGEN" -l "$L" -s "$S" -p "$P" -k aes -b 256 -i aeswrap \
    wrap=true unwrap=true >/dev/null 2>&1 \
    || die "p11keygen (AES-256 cbcpad wrapping key) failed"

nss_rw "$P11KEYGEN" -l "$L" -s "$S" -p "$P" -k aes -b 128 -i wtarget \
    encrypt=true decrypt=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (AES-128 target key) failed"

nss_rw "$P11KEYGEN" -l "$L" -s "$S" -p "$P" -k rsa -b 2048 -i rsawrap \
    wrap=true unwrap=true encrypt=true decrypt=true >/dev/null 2>&1 \
    || die "p11keygen (RSA-2048 envelope wrapping key) failed"

nss_rw "$P11KEYGEN" -l "$L" -s "$S" -p "$P" -k rsa -b 3072 -i rsatarget \
    sign=true verify=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (RSA-3072 target private key) failed"

kcv_ref=$(kcv_of wtarget)
[ -n "$kcv_ref" ] || die "could not read reference KCV of the target key"

# --- round-trip 1: plain cbcpad on a symmetric key --------------------------
nss_rw "$P11WRAP" -l "$L" -s "$S" -p "$P" -i wtarget -w aeswrap -a cbcpad \
    -o "$WORKDIR/cbcpad.wrap" >/dev/null 2>&1 \
    || die "p11wrap (cbcpad) failed"
[ -s "$WORKDIR/cbcpad.wrap" ] || die "p11wrap (cbcpad) produced an empty file"

nss_rw "$P11UNWRAP" -l "$L" -s "$S" -p "$P" -f "$WORKDIR/cbcpad.wrap" \
    -i restored_cbcpad CKA_ID=0xA1 CKA_ENCRYPT=true CKA_DECRYPT=true >/dev/null 2>&1 \
    || die "p11unwrap (cbcpad) failed"

kcv1=$(kcv_of restored_cbcpad)
[ "$kcv1" = "$kcv_ref" ] || die "cbcpad: KCV mismatch after wrap/unwrap round-trip"

# --- round-trip 2: envelope with a cbcpad inner algorithm -------------------
# envelope(inner=cbcpad,outer=oaep): the inner cbcpad wrap of the target key is
# itself wrapped with RSA-OAEP. This exercises the cbcpad path as part of the
# envelope machinery, which SoftHSM2 also cannot reach (its inner cbcpad fails).
nss_rw "$P11WRAP" -l "$L" -s "$S" -p "$P" -i wtarget -w rsawrap \
    -a 'envelope(inner=cbcpad,outer=oaep)' -o "$WORKDIR/env.wrap" >/dev/null 2>&1 \
    || die "p11wrap (envelope inner=cbcpad) failed"
[ -s "$WORKDIR/env.wrap" ] || die "p11wrap (envelope) produced an empty file"

nss_rw "$P11UNWRAP" -l "$L" -s "$S" -p "$P" -f "$WORKDIR/env.wrap" \
    -i restored_env CKA_ID=0xA2 CKA_ENCRYPT=true CKA_DECRYPT=true >/dev/null 2>&1 \
    || die "p11unwrap (envelope inner=cbcpad) failed"

kcv2=$(kcv_of restored_env)
[ "$kcv2" = "$kcv_ref" ] || die "envelope(cbcpad): KCV mismatch after round-trip"

# --- round-trip 3: cbcpad wrapping of an RSA private key --------------------
# Wrapping an asymmetric private key with a symmetric cbcpad mechanism is a
# common real-world use; verify the wrapped private key can be unwrapped back
# into a usable private-key object.
nss_rw "$P11WRAP" -l "$L" -s "$S" -p "$P" -i rsatarget -w aeswrap -a cbcpad \
    -o "$WORKDIR/rsa.wrap" >/dev/null 2>&1 \
    || die "p11wrap (cbcpad, RSA private key) failed"
[ -s "$WORKDIR/rsa.wrap" ] || die "p11wrap (cbcpad, RSA private key) produced an empty file"

nss_rw "$P11UNWRAP" -l "$L" -s "$S" -p "$P" -f "$WORKDIR/rsa.wrap" \
    -i restored_rsa CKA_ID=0xA3 CKA_SIGN=true >/dev/null 2>&1 \
    || die "p11unwrap (cbcpad, RSA private key) failed"

# Confirm the restored object is present as a private key.
nss_rw "$P11LS" -l "$L" -s "$S" -p "$P" 2>/dev/null | grep -q 'prvk/restored_rsa' \
    || die "restored RSA private key not found after cbcpad unwrap"

echo "NSS cbcpad wrapping (symmetric, envelope inner=cbcpad, RSA private key): OK"
