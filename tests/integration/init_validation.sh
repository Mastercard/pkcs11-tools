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

# Integration test: p11init safe-fail validation (batch mode, no prompts).
#
# p11init is the one DESTRUCTIVE command in the toolset (C_InitToken erases a
# token), so its guard rails matter as much as its happy path. init.sh covers
# the successful batch flow and init_interactive.sh the interactive prompts;
# this test hammers the *refusals* -- every argument-validation and safe-fail
# branch that must stop p11init BEFORE it touches (let alone erases) a token:
#
#   - the operation / option combination checks (p11init.c: -I/-U required, -R
#     needs -I, -t incompatible with -I, and each batch-mode "missing required
#     argument" error);
#   - slot-index syntax validation (non-numeric and negative -s values);
#   - PIN-source handling (':::nologin' rejected for -O and -P; ':::exec:' PIN
#     retrieval accepted);
#   - the library / slot / token resolution failures (bad library path, slot
#     index out of range, unknown token label, over-long token label);
#   - and, crucially, the reinitialization guard: p11init must REFUSE to
#     reinitialize an already initialized token unless -R is given, without
#     destroying it. We point it at the shared token (slot 0) WITHOUT -R and
#     confirm both the refusal and that the token is left intact.
#
# Everything here runs in batch mode (-B) or fails before any interactive
# prompt, so no terminal/preload machinery is needed: this test is portable to
# every platform that has SoftHSM2 (Windows/MinGW included).

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

P11INIT=$(p11bin p11init)
P11LS=$(p11bin p11ls)

# expect_fail "<diagnostic substring>" <p11init args...>
# Run p11init, require a NON-zero exit, and require the given substring on its
# combined output. A destructive command must both fail AND say why.
expect_fail() {
    _want=$1
    shift
    set +e
    _out=$("$P11INIT" -l "$PKCS11LIB" "$@" 2>&1)
    _rc=$?
    set -e
    [ "$_rc" -ne 0 ] \
        || die "p11init $* unexpectedly succeeded (should have failed: $_want)"
    printf '%s\n' "$_out" | grep -qi "$_want" \
        || die "p11init $*: expected diagnostic '$_want', got: $_out"
}

# --- 1. operation / option combination checks -------------------------------
# no operation requested (neither -I nor -U); also drives the -m (NSS config
# directory) option parsing on the way to the error.
expect_fail 'at least one operation'                 -B -m sql:.
# -R (reset) without -I
expect_fail 'reset) requires'                        -B -R -U -O 1 -t x -P 2
# a token label (-t) cannot address a token for -I
expect_fail 'cannot be used to address'              -B -I -t x -O 1 -T y

# --- 2. batch-mode "missing required argument" checks -----------------------
# -I / -U in batch mode demand every value up front (no prompting allowed)
expect_fail 'SO PIN .* is required'                  -B -I -s 1 -T x
expect_fail 'requires a slot index'                  -B -I -O 1 -T x
expect_fail 'requires a token label'                 -B -I -s 1 -O 1
expect_fail 'requires a new user PIN'                -B -U -t x -O 1
expect_fail 'requires a slot index .* or a token label' -B -U -O 1 -P 2

# --- 3. slot-index syntax validation ----------------------------------------
# non-numeric and negative slot indexes are rejected during option parsing
expect_fail 'invalid slot index'                     -I -s abc -O 1 -T x
expect_fail 'invalid slot index'                     -I -s-5 -O 1 -T x

# --- 4. PIN-source handling -------------------------------------------------
# ':::nologin' is explicitly unsupported for both the SO and the user PIN
expect_fail 'nologin.* is not supported'             -B -I -s 1 -O :::nologin -T x
expect_fail 'nologin.* is not supported'             -B -U -t x -O 1234 -P :::nologin
# ':::exec:' PIN retrieval IS supported: both PINs are pulled from a command;
# the request then fails only because the target token label does not exist
# (so no token is touched), which proves the exec PINs were resolved.
expect_fail 'not found' \
    -B -U -t no-such-token-xyz -O ':::exec:echo 5678' -P ':::exec:echo 4321'

# --- 5. library / slot / token resolution failures --------------------------
# a bad library path is reported before anything else happens
set +e
out=$("$P11INIT" -l /nonexistent/does-not-exist.so -B -I -s 1 -O 1 -T x 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ] || die "p11init accepted a nonexistent library path"
printf '%s\n' "$out" | grep -qi 'does not exist\|could not\|library' \
    || die "p11init: bad library path produced no diagnostic: $out"

# a slot index past the end of the slot list is rejected safely
expect_fail 'not within range'                       -B -I -s 999 -O 5678 -T x
# an unknown token label (-U) is reported and nothing is changed
expect_fail 'not found'                              -B -U -t no-such-token-xyz -O 5678 -P 4321
# a token label longer than the PKCS#11 field (32 chars) is rejected
expect_fail 'longer than'  -B -I -s 1 -O 5678 -T 'label-far-too-long-for-a-pkcs11-token-field'

# a wrong SO PIN makes the Security Officer login fail when opening the session
# for a standalone -U: the operation is refused (C_Login error) and the token's
# user PIN is left untouched. A single failed SO login stays well within
# SoftHSM's retry budget, and the throwaway token is discarded afterwards.
expect_fail 'C_Login\|PIN_INCORRECT\|incorrect' \
    -B -U -t "$TOKEN_LABEL" -O definitely-the-wrong-so-pin -P 43214321

# --- 6. the reinitialization guard (the destructive one) --------------------
# Slot 0 holds the initialized shared token. Without -R, p11init MUST refuse to
# reinitialize it -- and must do so WITHOUT erasing it. This is the single most
# important safety property of the command.
set +e
guard_out=$("$P11INIT" -l "$PKCS11LIB" -B -I -s 0 -O 5678 -T should-not-apply 2>&1)
guard_rc=$?
set -e
[ "$guard_rc" -ne 0 ] || die "p11init reinitialized slot 0 without -R (DESTRUCTIVE!)"
printf '%s\n' "$guard_out" | grep -qi 'already initialized' \
    || die "reinit guard: expected an 'already initialized' refusal, got: $guard_out"

# prove the token was NOT touched: it is still usable with its original user PIN
# (PKCS11PASSWORD, exported by common.sh for the shared token).
"$P11LS" -l "$PKCS11LIB" -s 0 -p "$PKCS11PASSWORD" >/dev/null 2>&1 \
    || die "reinit guard: the shared token appears damaged after the refusal"

echo "p11init validation (arg checks, PIN sources, resolution, reinit guard): OK"
