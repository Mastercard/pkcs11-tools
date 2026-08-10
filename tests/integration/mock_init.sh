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

# Integration test: p11init driver-error paths via the mock's fault injection.
#
# p11init is the toolset's one DESTRUCTIVE command (C_InitToken erases a token).
# init.sh / init_validation.sh / init_interactive.sh cover its argument checks,
# guards and happy path on real backends, but two branches remain unreachable
# from a real token:
#
#   - lib/pkcs11_init.c pkcs11_init_token(): C_InitToken() itself returning an
#     error (SoftHSM2 succeeds, and forcing a real failure would be destructive);
#   - lib/pkcs11_init.c pkcs11_init_pin():   C_InitPIN() itself returning an error.
#
# The mock makes both safe and deterministic: its C_InitToken/C_InitPIN are
# no-ops (nothing is erased), and MOCK_P11_FAIL lets us make the Nth call return
# any CKR_ code. We drive each operation once to FAIL (assert the error branch)
# and once to SUCCEED (assert the success branch), so the whole init/init-PIN
# code path is exercised without ever touching a real token.
#
# The SO PIN handed to a standalone -U must match the mock's login PIN (1234,
# what C_Login checks) since -U opens an SO session before C_InitPIN.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_MOCK_COMMON:?PKCS11_TESTS_MOCK_COMMON must be set by the test harness}"

P11INIT=$(p11bin p11init)

# run_init EXPECT DESC MSG MOCK_P11_FAIL-spec -- <p11init args...>
#   EXPECT is "fail" (require non-zero exit) or "ok" (require zero exit).
#   MSG must appear on the merged output in both cases.
#   The fault spec may be empty ('') to arm no fault.
run_init() {
    _expect=$1; _desc=$2; _msg=$3; _fail=$4; shift 4
    [ "$1" = "--" ] || die "run_init: malformed call ($_desc)"
    shift
    set +e
    out=$(MOCK_P11_FAIL="$_fail" "$P11INIT" -l "$PKCS11LIB" "$@" 2>&1)
    rc=$?
    set -e
    if [ "$_expect" = "fail" ]; then
        [ "$rc" -ne 0 ] || die "$_desc: expected non-zero exit, got 0
$out"
    else
        [ "$rc" -eq 0 ] || die "$_desc: expected success, got rc=$rc
$out"
    fi
    printf '%s\n' "$out" | grep -q "$_msg" \
        || die "$_desc: expected message '$_msg' not found
$out"
    echo "  ok: $_desc (rc=$rc)"
}

# ---------------------------------------------------------------------------
# 1. C_InitToken failure -> pkcs11_init_token() reports it and p11init aborts.
#    -R authorizes the reset so the guard lets us reach C_InitToken on the
#    mock's (reported-initialized) slot 0; the mock erases nothing.
run_init fail "C_InitToken -> CKR_TOKEN_WRITE_PROTECTED" \
    "C_InitToken() returned CKR_TOKEN_WRITE_PROTECTED" \
    'C_InitToken@1=CKR_TOKEN_WRITE_PROTECTED' \
    -- -B -I -R -s 0 -O 1234 -T mocklabel

# 2. C_InitToken success -> pkcs11_init_token() success branch.
run_init ok "C_InitToken success" \
    "Token at slot index 0 initialized successfully" \
    '' \
    -- -B -I -R -s 0 -O 1234 -T mocklabel

# ---------------------------------------------------------------------------
# 3. C_InitPIN failure -> pkcs11_init_pin() reports it and p11init aborts.
#    Standalone -U opens an SO session (C_Login with the mock PIN 1234) then
#    calls C_InitPIN to set the user PIN.
run_init fail "C_InitPIN -> CKR_PIN_INVALID" \
    "C_InitPIN() returned CKR_PIN_INVALID" \
    'C_InitPIN@1=CKR_PIN_INVALID' \
    -- -B -U -s 0 -O 1234 -P newuserpin

# 4. C_InitPIN success -> pkcs11_init_pin() success branch.
run_init ok "C_InitPIN success" \
    "User (crypto officer) PIN initialized successfully" \
    '' \
    -- -B -U -s 0 -O 1234 -P newuserpin

echo "PASS: mock p11init driver-error paths (C_InitToken / C_InitPIN)"
exit 0
