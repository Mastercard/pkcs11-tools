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

# Integration test: interactive token initialization (p11init without -B).
#
# The batch-mode init test (init.sh) reaches C_InitToken / C_InitPIN but skips
# every interactive branch of lib/pkcs11_init.c: the slot enumeration
# (print_slot_entry), the "Enter slot index:" prompt with its out-of-range retry
# (parse_slot_index_input / pkcs11_get_slotindex), the twice-entered SO/user PIN
# prompts, the standalone -U confirmation, and the destructive reset guard
# (pkcs11_inittoken_guard + its (y/N) confirmation). This test drives all of
# them by feeding the prompts from a pipe with the notty preload.
#
#   1. interactive -I : slot list + out-of-range index (99) rejected, then a
#                       valid index (1), a new label, and the SO PIN entered
#                       twice -> the spare token is initialized.
#   2. interactive -U : standalone user-PIN (re)set on that token, requiring the
#                       (y/N) confirmation, the SO PIN, and the user PIN twice;
#                       a keygen with the new user PIN proves the token is usable.
#   3. interactive -I -R : reset (reinitialize) the same slot; the guard detects
#                          the initialized token and asks for confirmation before
#                          the SO PIN (the existing one) re-initializes it.
#   4. reset refusal   : answering 'n' to the reset guard aborts with a non-zero
#                        status and leaves the token untouched.
#
# The prompts read from a terminal, so we feed them via the notty preload
# (LD_PRELOAD/DYLD, Unix-only) -> the whole test self-skips elsewhere.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

require_pin_prompt_preload

P11INIT=$(p11bin p11init)
KEYGEN=$(p11bin p11keygen)
P11LS=$(p11bin p11ls)
P11SLOTINFO=$(p11bin p11slotinfo)

# List every slot's token label. p11slotinfo only enumerates all slots when no
# specific slot is selected, so PKCS11SLOT / PKCS11PASSWORD (exported by the
# harness) must be cleared; stdin is closed so the trailing prompt cannot hang.
all_slot_labels() {
    ( unset PKCS11SLOT PKCS11PASSWORD
      "$P11SLOTINFO" -l "$PKCS11LIB" </dev/null 2>&1 )
}

# Resolve the current slot INDEX holding a given token label. SoftHSM assigns a
# fresh, random slot ID whenever a token is (re)initialized, so the index of a
# just-created token is not stable and must be looked up before addressing it by
# index (the destructive -I/-R operations only accept a slot index, not a label).
slot_index_of_label() {
    all_slot_labels | awk -v want="$1" '
        /^Slot index:/  { idx = $3 }
        /^Token Label :/ {
            lbl = $0; sub(/^Token Label : /, "", lbl); sub(/[ \t]+$/, "", lbl)
            if (lbl == want) { print idx; exit }
        }'
}

# SoftHSM exposes the initialized shared token at slot index 0 and one spare,
# uninitialized slot right after it (index 1). We operate on the spare only.
SPARE_SLOT=1
SO_PIN=90909090
USER_PIN=43214321
LABEL1=ii-first
LABEL2=ii-reset

# --- 0. non-destructive interactive input validation ------------------------
# These run while the spare slot is still pristine: each one aborts BEFORE any
# C_InitToken / C_InitPIN, so they exercise the interactive error branches of
# lib/pkcs11_init.c and src/p11init.c without touching a token.

# 0a. slot prompt: rejects every malformed index (non-numeric, overflow,
#     trailing junk) and an out-of-range value, then aborts cleanly at EOF
#     (parse_slot_index_input + the retry loop + the NULL-prompt exit).
set +e
out=$(printf 'abc\n99999999999999999999\n7x\n99\n' \
      | notty_run "$P11INIT" -l "$PKCS11LIB" -I 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ] || die "interactive -I: malformed slot input then EOF should fail"
echo "$out" | grep -q 'invalid slot index' \
    || die "interactive -I: a malformed slot index was not rejected"
echo "$out" | grep -q 'not within range' \
    || die "interactive -I: an out-of-range slot index was not rejected"

# 0b. an empty token label is refused (label prompt returns "").
set +e
out=$(printf '%s\n\n' "$SPARE_SLOT" \
      | notty_run "$P11INIT" -l "$PKCS11LIB" -I 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ] || die "interactive -I: an empty token label should be refused"
echo "$out" | grep -qi 'token label is required' \
    || die "interactive -I: empty label did not produce the expected diagnostic"

# 0c. aborting at the SO-PIN prompt (EOF) fails without initializing anything.
set +e
out=$(printf '%s\nlbl\n' "$SPARE_SLOT" \
      | notty_run "$P11INIT" -l "$PKCS11LIB" -I 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ] || die "interactive -I: EOF at the SO PIN prompt should fail"

# 0d. standalone -U with a 'n' answer to the confirmation must abort and leave
#     the token's user PIN unchanged (guards against an accidental lock-out).
set +e
out=$(printf 'n\n' \
      | notty_run "$P11INIT" -l "$PKCS11LIB" -U -t "$TOKEN_LABEL" 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ] || die "interactive -U: refusing the confirmation should abort"
echo "$out" | grep -qi 'NOT been changed' \
    || die "interactive -U: the refusal did not report the PIN as unchanged"
# the shared token must still accept its original user PIN (nothing changed).
"$P11LS" -l "$PKCS11LIB" -s 0 -p "$PKCS11PASSWORD" >/dev/null 2>&1 \
    || die "interactive -U refusal: the shared token appears to have changed"

# --- 1. interactive -I: slot list + out-of-range retry + PIN-twice -----------
set +e
out=$(printf '99\n%s\n%s\n%s\n%s\n' "$SPARE_SLOT" "$LABEL1" "$SO_PIN" "$SO_PIN" \
      | notty_run "$P11INIT" -l "$PKCS11LIB" -I 2>&1)
rc=$?
set -e
[ "$rc" -eq 0 ] || die "interactive p11init -I failed (rc=$rc): $out"
echo "$out" | grep -q 'not within range' \
    || die "interactive -I: out-of-range slot index was not rejected"
echo "$out" | grep -q 'initialized successfully' \
    || die "interactive -I: token was not reported as initialized"

# --- 2. interactive -U: confirmation + SO PIN + user PIN twice ---------------
set +e
out=$(printf 'y\n%s\n%s\n%s\n' "$SO_PIN" "$USER_PIN" "$USER_PIN" \
      | notty_run "$P11INIT" -l "$PKCS11LIB" -U -t "$LABEL1" 2>&1)
rc=$?
set -e
[ "$rc" -eq 0 ] || die "interactive p11init -U failed (rc=$rc): $out"
echo "$out" | grep -qi 'user .*PIN initialized successfully' \
    || die "interactive -U: user PIN was not reported as set"

# the freshly PIN'd token must be usable with the new user PIN
"$KEYGEN" -l "$PKCS11LIB" -t "$LABEL1" -p "$USER_PIN" \
    -k aes -b 128 -i ii-probe encrypt=true >/dev/null 2>&1 \
    || die "keygen into interactively initialized token failed"
"$P11LS" -l "$PKCS11LIB" -t "$LABEL1" -p "$USER_PIN" 2>/dev/null \
    | grep -q 'seck/ii-probe' \
    || die "probe key not found in interactively initialized token"

# --- 3. interactive -I -R: reset guard confirmation + relabel ----------------
# Reinitialization re-authenticates with the token's EXISTING SO PIN (which is
# preserved) and applies a new label. The just-initialized token's slot index is
# not stable, so resolve it by label first.
reset_slot=$(slot_index_of_label "$LABEL1")
[ -n "$reset_slot" ] || die "could not locate slot index of token '$LABEL1'"
set +e
out=$(printf 'y\n%s\n%s\n%s\n' "$LABEL2" "$SO_PIN" "$SO_PIN" \
      | notty_run "$P11INIT" -l "$PKCS11LIB" -I -R -s "$reset_slot" 2>&1)
rc=$?
set -e
[ "$rc" -eq 0 ] || die "interactive p11init -I -R (reset) failed (rc=$rc): $out"
echo "$out" | grep -qi 'reinitiali' \
    || die "reset: the reinitialization guard prompt did not appear"
echo "$out" | grep -q 'initialized successfully' \
    || die "reset: token was not reported as reinitialized"
all_slot_labels | grep -q "$LABEL2" \
    || die "reset: the new token label is not visible after reinitialization"

# --- 4. reset refusal: answering 'n' must abort and change nothing -----------
refuse_slot=$(slot_index_of_label "$LABEL2")
[ -n "$refuse_slot" ] || die "could not locate slot index of token '$LABEL2'"
set +e
out=$(printf 'n\n' \
      | notty_run "$P11INIT" -l "$PKCS11LIB" -I -R -s "$refuse_slot" 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ] || die "reset refusal unexpectedly returned success"
echo "$out" | grep -qi 'NOT been reinitialized' \
    || die "reset refusal did not report the token as left untouched"
all_slot_labels | grep -q "$LABEL2" \
    || die "reset refusal must leave the previous token (label) in place"

echo "interactive p11init (-I slot prompt+retry, -U confirm, -R reset+refusal): OK"
