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

# Integration test: p11keycomp end-to-end key-component import (mock-backed).
#
# p11keycomp splits a symmetric key into N components that are entered by hand
# and XOR-combined on the token: the first component is loaded via an RSA PKCS#1
# unwrap (CKM_RSA_PKCS), the rest via CKM_XOR_BASE_AND_DATA derivations, then a
# final identity XOR + C_CopyObject persists it and a KCV is computed. SoftHSM2
# implements neither CKM_XOR_BASE_AND_DATA nor this exact flow, so this whole
# command is UNTESTABLE against SoftHSM2. The programmable mock provides a real
# RSA unwrapping key (so the PKCS#1 round-trip actually works) plus the XOR
# derive and DES3-ECB KCV paths, unlocking p11keycomp coverage.
#
# The component prompt (prompt_for_hex) reads hex straight from stdin with
# getline(), without toggling tty echo, so a plain pipe drives it -- no PTY and
# no LD_PRELOAD needed.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_MOCK_COMMON:?PKCS11_TESTS_MOCK_COMMON must be set by the test harness}"

P11KEYCOMP=$(p11bin p11keycomp)

# Ask the mock to seed a real RSA-2048 key pair under this label; p11keycomp
# reads its modulus/exponent to PKCS#1-encrypt the first component and unwraps
# it with the matching private key.
MOCK_P11_RSA_KEYPAIR=mockrsa
export MOCK_P11_RSA_KEYPAIR

# Two 16-byte (CKK_DES2) components, entered as 32 hex digits each.
COMP1=0123456789abcdef0123456789abcdef
COMP2=fedcba9876543210fedcba9876543210

# ---------------------------------------------------------------------------
# 1. Two-component import: exercises RSA unwrap + one XOR derive + final derive
#    + C_CopyObject + KCV via DES3-ECB encrypt.
out=$(printf '%s\n%s\n' "$COMP1" "$COMP2" | \
      "$P11KEYCOMP" -i mockdes2 -c 2 -w mockrsa 2>&1) \
    || die "p11keycomp (2 components) failed: $out"

echo "$out" | grep -q "Key with label 'mockdes2' successfully imported" \
    || die "2-component import did not report success:
$out"
echo "$out" | grep -Eq '^KCV = [0-9a-f]{6}$' \
    || die "2-component import did not print a 6-hex-digit KCV:
$out"

# ---------------------------------------------------------------------------
# 2. Single-component import: exercises the RSA-unwrap-only path (cnt==1, no
#    intermediate XOR derive) plus the final derive/copy/KCV.
out=$(printf '%s\n' "$COMP1" | \
      "$P11KEYCOMP" -i mockdes1 -c 1 -w mockrsa 2>&1) \
    || die "p11keycomp (1 component) failed: $out"

echo "$out" | grep -q "Key with label 'mockdes1' successfully imported" \
    || die "1-component import did not report success:
$out"
echo "$out" | grep -Eq '^KCV = [0-9a-f]{6}$' \
    || die "1-component import did not print a KCV:
$out"

# ---------------------------------------------------------------------------
# 3. Error path: an unknown wrapping-key label must be reported (the tool
#    prints the diagnostic and skips the import; its exit status is not a
#    reliable signal here, so assert on the message and the absence of an
#    import instead).
out=$(printf '%s\n' "$COMP1" | \
      "$P11KEYCOMP" -i mockdesX -c 1 -w nosuchkey 2>&1) || true
echo "$out" | grep -qi "could not find a private key with label 'nosuchkey'" \
    || die "missing wrapping key not reported as expected:
$out"
echo "$out" | grep -q "successfully imported" \
    && die "import unexpectedly reported success with a missing wrapping key:
$out"

echo "PASS: p11keycomp end-to-end key-component import (mock)"
exit 0
