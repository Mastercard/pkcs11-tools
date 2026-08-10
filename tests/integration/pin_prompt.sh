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

# Integration test: interactive terminal password/PIN (and slot) prompts.
#
# The pkcs11-tools binaries read secrets from a real terminal: before reading
# they turn the tty echo off (tcgetattr/tcsetattr on stdin), which aborts when
# stdin is a pipe. We preload tests/preload/notty.so to neutralize those two
# termios calls so the prompt path can be driven deterministically from stdin,
# without a PTY. This exercises prompt_core()/pkcs11_prompt() and the
# interactive branches of pkcs11_open_session() (lib/pkcs11_session.c) that the
# other tests, which pass credentials via the environment, never reach.
#
# LD_PRELOAD is Unix-only, so this test self-skips off Linux/FreeBSD.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

require_pin_prompt_preload

P11LS=$(p11bin p11ls)
P11KEYGEN=$(p11bin p11keygen)

# Remember the real token PIN before we start unsetting it from the child env.
PIN="$PKCS11PASSWORD"
PROBE_KEY=pinprobe

# Plant a key non-interactively (credentials come from the exported env), so the
# interactive listings below have something stable to assert on.
"$P11KEYGEN" -k aes -b 128 -i "$PROBE_KEY" >/dev/null 2>&1 \
    || die "could not plant probe key"

# --- 1) correct PIN typed at the prompt (slot supplied via env) -------------
# PKCS11SLOT stays exported (non-interactive slot selection), only the PIN is
# prompted for. Feeding the right PIN must authenticate and list the key.
set +e
out=$(unset PKCS11PASSWORD
      printf '%s\n' "$PIN" | notty_run "$P11LS" -l "$PKCS11LIB" 2>&1)
rc=$?
set -e
[ "$rc" -eq 0 ] || die "prompted login with correct PIN failed (rc=$rc): $out"
echo "$out" | grep -q "seck/$PROBE_KEY" \
    || die "prompted login did not list the probe key"

# --- 2) wrong PIN typed at the prompt --------------------------------------
# The prompt must be reached and the bad PIN rejected by the token.
set +e
out=$(unset PKCS11PASSWORD
      printf '%s\n' "0000wrong" | notty_run "$P11LS" -l "$PKCS11LIB" 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ] || die "prompted login with wrong PIN unexpectedly succeeded"
echo "$out" | grep -q 'CKR_PIN_INCORRECT' \
    || die "wrong PIN did not yield CKR_PIN_INCORRECT: $out"

# --- 3) fully interactive: slot prompt THEN PIN prompt ----------------------
# With neither PKCS11SLOT nor PKCS11PASSWORD in the env and no -s option, the
# tool prompts for the slot index first, then for the PIN. Feed both on stdin.
set +e
out=$(unset PKCS11PASSWORD PKCS11SLOT
      printf '0\n%s\n' "$PIN" | notty_run "$P11LS" -l "$PKCS11LIB" 2>&1)
rc=$?
set -e
[ "$rc" -eq 0 ] || die "fully-interactive slot+PIN login failed (rc=$rc): $out"
echo "$out" | grep -q "seck/$PROBE_KEY" \
    || die "fully-interactive login did not list the probe key"

echo "pin_prompt (interactive PIN/slot prompts via preload): OK"
