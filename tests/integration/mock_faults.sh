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

# Integration test: PKCS#11 driver-error paths via the mock's fault injection.
#
# A real token almost never returns errors on demand, so the tools' error
# branches (pkcs11_error() reporting + the callers' cleanup/return paths) stay
# uncovered. The mock reads MOCK_P11_FAIL="C_Name@N=CKR_CODE[;...]" and makes the
# Nth call to C_Name return CKR_CODE, letting us drive those branches
# deterministically. This covers pkcs11_error.c formatting on live codes plus
# the failure handling in pkcs11_session.c / pkcs11_keygen.c drivers.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_MOCK_COMMON:?PKCS11_TESTS_MOCK_COMMON must be set by the test harness}"

P11LS=$(p11bin p11ls)
P11KEYGEN=$(p11bin p11keygen)
P11RM=$(p11bin p11rm)
P11SETATTR=$(p11bin p11setattr)

# expect_fail DESC MSG -- ENV=... TOOL ARGS...
# Runs the tool with a fault armed (env passed after `--'), requires a non-zero
# exit and that the expected CKR message appears on the merged output.
expect_fail() {
    _desc=$1; _msg=$2; shift 2
    [ "$1" = "--" ] || die "expect_fail: malformed call ($_desc)"
    shift
    out=$(env "$@" 2>&1) && rc=0 || rc=$?
    [ "$rc" -ne 0 ] \
        || die "$_desc: expected non-zero exit, got 0
$out"
    echo "$out" | grep -q "$_msg" \
        || die "$_desc: expected message '$_msg' not found
$out"
    echo "  ok: $_desc (rc=$rc)"
}

# expect_msg DESC MSG -- ENV=... TOOL ARGS...
# Like expect_fail but only asserts the diagnostic is printed. Several object
# tools report a PKCS#11 error yet still exit 0, so the message (not the exit
# code) is the reliable signal that the error branch was taken.
expect_msg() {
    _desc=$1; _msg=$2; shift 2
    [ "$1" = "--" ] || die "expect_msg: malformed call ($_desc)"
    shift
    out=$(env "$@" 2>&1) || true
    echo "$out" | grep -q "$_msg" \
        || die "$_desc: expected message '$_msg' not found
$out"
    echo "  ok: $_desc"
}

# ---------------------------------------------------------------------------
# 1. Slot enumeration failure (C_GetSlotList) -> fatal, reported by p11ls.
expect_fail "C_GetSlotList -> CKR_DEVICE_ERROR" \
    "C_GetSlotList() returned CKR_DEVICE_ERROR" \
    -- MOCK_P11_FAIL='C_GetSlotList@1=CKR_DEVICE_ERROR' "$P11LS"

# ---------------------------------------------------------------------------
# 2. Login failure (C_Login) -> fatal, reported by p11ls. Uses a symbolic code
#    that the mock resolves through its CKR_* name table.
expect_fail "C_Login -> CKR_PIN_LOCKED" \
    "C_Login() returned CKR_PIN_LOCKED" \
    -- MOCK_P11_FAIL='C_Login@1=CKR_PIN_LOCKED' "$P11LS"

# ---------------------------------------------------------------------------
# 3. Asymmetric key generation failure (C_GenerateKeyPair) -> p11keygen aborts.
expect_fail "C_GenerateKeyPair -> CKR_DEVICE_ERROR" \
    "C_GenerateKeyPair() returned CKR_DEVICE_ERROR" \
    -- MOCK_P11_FAIL='C_GenerateKeyPair@1=CKR_DEVICE_ERROR' \
       "$P11KEYGEN" -k rsa -b 2048 -i failrsa

# ---------------------------------------------------------------------------
# 4. Symmetric key generation failure (C_GenerateKey) -> p11keygen aborts.
expect_fail "C_GenerateKey -> CKR_DEVICE_ERROR" \
    "C_GenerateKey() returned CKR_DEVICE_ERROR" \
    -- MOCK_P11_FAIL='C_GenerateKey@1=CKR_DEVICE_ERROR' \
       "$P11KEYGEN" -k aes -b 256 -i failaes

# ---------------------------------------------------------------------------
# 5. A numeric (hex) code is honored just like a symbolic one. 0x30 ==
#    CKR_DEVICE_ERROR; this proves the strtoul() fallback path in the parser.
expect_fail "C_Login -> 0x30 (numeric)" \
    "C_Login() returned CKR_DEVICE_ERROR" \
    -- MOCK_P11_FAIL='C_Login@1=0x30' "$P11LS"

# ---------------------------------------------------------------------------
# 6. Nth-call gating: a fault armed for a call number that is never reached must
#    NOT fire -- p11ls succeeds and lists the default key.
out=$(env MOCK_P11_FAIL='C_GetSlotList@99=CKR_DEVICE_ERROR' "$P11LS" 2>&1) \
    || die "unreached-count fault should not fire, but p11ls failed:
$out"
echo "$out" | grep -q "seck/mockaes" \
    || die "expected default key not listed when fault is not reached:
$out"
echo "  ok: unreached-count fault does not fire"

# ---------------------------------------------------------------------------
# Object-operation error branches. These tools report the PKCS#11 error but
# still return 0, so assert on the diagnostic only. Each drives a distinct
# driver's failure path against the mock's default seck/mockaes key.

# 7. Deletion failure (C_DestroyObject) -> p11rm error branch.
expect_msg "C_DestroyObject -> CKR_DEVICE_ERROR (p11rm)" \
    "C_DestroyObject() returned CKR_DEVICE_ERROR" \
    -- MOCK_P11_FAIL='C_DestroyObject@1=CKR_DEVICE_ERROR' \
       "$P11RM" -y seck/mockaes

# 8. Attribute-set failure (C_SetAttributeValue) -> p11setattr error branch.
expect_msg "C_SetAttributeValue -> CKR_ATTRIBUTE_VALUE_INVALID (p11setattr)" \
    "C_SetAttributeValue() returned CKR_ATTRIBUTE_VALUE_INVALID" \
    -- MOCK_P11_FAIL='C_SetAttributeValue@1=CKR_ATTRIBUTE_VALUE_INVALID' \
       "$P11SETATTR" -y seck/mockaes CKA_LABEL=renamed

# 9. Search-setup failure (C_FindObjectsInit) -> object lookup error branch.
expect_msg "C_FindObjectsInit -> CKR_DEVICE_ERROR (p11rm)" \
    "C_FindObjectsInit() returned CKR_DEVICE_ERROR" \
    -- MOCK_P11_FAIL='C_FindObjectsInit@1=CKR_DEVICE_ERROR' \
       "$P11RM" -y seck/mockaes

echo "PASS: mock fault-injection driver-error paths"
exit 0
