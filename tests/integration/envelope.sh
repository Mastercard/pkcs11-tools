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

# Integration test: two-layer "envelope" key wrapping.
#   An envelope wraps the target key under a symmetric inner algorithm
#   (rfc5649) and then wraps that inner key under an asymmetric outer algorithm
#   (oaep, RSA key transport). This exercises the envelope code paths in
#   pkcs11_wrap.c / pkcs11_unwrap.c / pkcs11_wrapoutput.c.
#
#   1. RSA outer wrapping key (wrap/unwrap + encrypt/decrypt for RSA transport)
#   2. extractable AES target key
#   3. p11wrap -a 'envelope(inner=rfc5649,outer=oaep)' -> file
#   4. remove the on-token target, then p11unwrap the envelope back
#   5. the key check value must survive the round-trip

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11WRAP=$(p11bin p11wrap)
P11UNWRAP=$(p11bin p11unwrap)
P11RM=$(p11bin p11rm)
P11KCV=$(p11bin p11kcv)

# --- key material -----------------------------------------------------------
# RSA outer/transport key: wrap+unwrap AND encrypt+decrypt.
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i env-outer \
    wrap=true unwrap=true encrypt=true decrypt=true >/dev/null 2>&1 \
    || die "p11keygen (RSA outer key) failed"

# Extractable AES target to be enveloped and restored.
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i env-target \
    encrypt=true decrypt=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (target key) failed"

kcv_ref=$("$P11KCV" -l "$PKCS11LIB" -f ecb seck/env-target 2>/dev/null \
    | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p')
[ -n "$kcv_ref" ] || die "could not read reference KCV of target key"

# --- envelope wrap ----------------------------------------------------------
envfile="$WORKDIR/envelope.wrap"
"$P11WRAP" -l "$PKCS11LIB" -i env-target -w env-outer \
    -a 'envelope(inner=rfc5649,outer=oaep)' -o "$envfile" >/dev/null 2>&1 \
    || die "p11wrap (envelope) failed"
[ -s "$envfile" ] || die "p11wrap (envelope) produced an empty file"

# --- remove target, then unwrap the envelope back ---------------------------
"$P11RM" -l "$PKCS11LIB" -y seck/env-target >/dev/null 2>&1 \
    || die "p11rm (target) failed"

"$P11UNWRAP" -l "$PKCS11LIB" -f "$envfile" -i env-restored \
    CKA_ENCRYPT=true CKA_DECRYPT=true >/dev/null 2>&1 \
    || die "p11unwrap (envelope) failed"

kcv_new=$("$P11KCV" -l "$PKCS11LIB" -f ecb seck/env-restored 2>/dev/null \
    | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p')
[ "$kcv_new" = "$kcv_ref" ] \
    || die "envelope: KCV mismatch after wrap/unwrap round-trip"

echo "envelope wrap (inner=rfc5649,outer=oaep): OK"
