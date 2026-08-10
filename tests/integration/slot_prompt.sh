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

# Integration test: interactive slot selection when no slot is specified.
#
# When neither -s, -t, PKCS11SLOT nor PKCS11TOKENLABEL is provided, the tools
# enter interactive mode: pkcs11_open_session() (lib/pkcs11_session.c) prints
# the slot list ("PKCS#11 module slot list:" / "Slot index: N") and prompts
# "Enter slot index:" in a loop, re-prompting with
# "*** Error: slot index value N not within range [...]" until a valid index is
# entered; it then prompts for the PIN. This drives the slot-enumeration output
# and the out-of-range retry branch that the credential-via-env tests skip.
#
# The prompts read from a terminal, so we feed them from a pipe with the notty
# preload (see common.sh). LD_PRELOAD/DYLD is Unix-only -> self-skips elsewhere.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

require_pin_prompt_preload

P11LS=$(p11bin p11ls)
P11KEYGEN=$(p11bin p11keygen)

PIN="$PKCS11PASSWORD"
PROBE_KEY=slotprobe

# Plant a key non-interactively so the interactive listing has a stable anchor.
"$P11KEYGEN" -k aes -b 128 -i "$PROBE_KEY" >/dev/null 2>&1 \
    || die "could not plant probe key"

# --- 1) interactive slot selection: enumeration + valid index + PIN ---------
# No slot and no PIN in the environment: expect the slot list to be printed,
# then a valid slot index (0) and the PIN authenticate and list the key.
set +e
out=$(unset PKCS11PASSWORD PKCS11SLOT
      printf '0\n%s\n' "$PIN" | notty_run "$P11LS" -l "$PKCS11LIB" 2>&1)
rc=$?
set -e
[ "$rc" -eq 0 ] || die "interactive slot selection failed (rc=$rc): $out"
echo "$out" | grep -q 'PKCS#11 module slot list:' \
    || die "interactive mode did not print the slot list header"
echo "$out" | grep -q 'Slot index:' \
    || die "interactive mode did not enumerate slot indexes"
echo "$out" | grep -q "seck/$PROBE_KEY" \
    || die "interactive slot selection did not list the probe key"

# --- 2) out-of-range index is rejected, then a valid one is accepted --------
# Feed an impossible slot index first: the tool must complain that it is out of
# range and re-prompt; supplying a valid index (0) then the PIN must succeed.
set +e
out=$(unset PKCS11PASSWORD PKCS11SLOT
      printf '99\n0\n%s\n' "$PIN" | notty_run "$P11LS" -l "$PKCS11LIB" 2>&1)
rc=$?
set -e
[ "$rc" -eq 0 ] || die "slot retry loop did not recover to success (rc=$rc): $out"
echo "$out" | grep -q 'not within range' \
    || die "out-of-range slot index did not produce a range error"
echo "$out" | grep -q "seck/$PROBE_KEY" \
    || die "slot retry loop did not eventually list the probe key"

echo "slot_prompt (interactive slot selection via preload): OK"
