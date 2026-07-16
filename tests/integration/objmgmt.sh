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

# Integration test: object management (copy / rename / delete).
#   1. generate an AES key (p11keygen)
#   2. copy it to a new label (p11cp)
#   3. rename the copy (p11mv)
#   4. delete the renamed object (p11rm) and confirm it is gone (p11ls)
#
# Note: p11cp / p11mv require the source and destination to share the same
# object-class prefix (here: seck/).

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11LS=$(p11bin p11ls)
P11CP=$(p11bin p11cp)
P11MV=$(p11bin p11mv)
P11RM=$(p11bin p11rm)
P11IMPORTDATA=$(p11bin p11importdata)

# --- 1. key generation ------------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i orig \
    encrypt=true decrypt=true >/dev/null 2>&1 \
    || die "p11keygen (AES) failed"

# --- 2. copy ----------------------------------------------------------------
"$P11CP" -l "$PKCS11LIB" -y seck/orig seck/copy >/dev/null 2>&1 \
    || die "p11cp failed"

out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"
echo "$out" | grep -q 'seck/orig' || die "p11cp: original disappeared"
echo "$out" | grep -q 'seck/copy' || die "p11cp: copy not created"

# --- 3. rename --------------------------------------------------------------
"$P11MV" -l "$PKCS11LIB" -y seck/copy seck/renamed >/dev/null 2>&1 \
    || die "p11mv failed"

out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"
echo "$out" | grep -q 'seck/renamed' || die "p11mv: renamed object missing"
echo "$out" | grep -q 'seck/copy'    && die "p11mv: old label still present"

# --- 4. delete --------------------------------------------------------------
"$P11RM" -l "$PKCS11LIB" -y seck/renamed >/dev/null 2>&1 \
    || die "p11rm failed"

out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"
echo "$out" | grep -q 'seck/renamed' && die "p11rm: object not deleted"

# the original must still be there.
echo "$out" | grep -q 'seck/orig' || die "p11rm: deleted the wrong object"

# --- 5. interactive delete (no -y): answer n (keep) then y (delete) ---------
# Without -y, p11rm prompts "delete ... ? (y/N)" and reads the answer with
# getchar() from stdin; feeding a pipe drives the interactive branch.
printf 'n\n' | "$P11RM" -l "$PKCS11LIB" seck/orig >/dev/null 2>&1 \
    || die "p11rm (interactive, n) returned an error"
out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"
echo "$out" | grep -q 'seck/orig' \
    || die "p11rm (interactive, n): object was deleted despite declining"

"$P11CP" -l "$PKCS11LIB" -y seck/orig seck/victim >/dev/null 2>&1 \
    || die "p11cp (setup for interactive rm) failed"
printf 'y\n' | "$P11RM" -l "$PKCS11LIB" seck/victim >/dev/null 2>&1 \
    || die "p11rm (interactive, y) failed"
out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"
echo "$out" | grep -q 'seck/victim' \
    && die "p11rm (interactive, y): object was not deleted after confirming"

# --- 6. class-shortcut label: 'p11rm data' removes every data object --------
# A bare class name (cert/pubk/prvk/seck/data, no '/') is a shortcut that
# targets all objects of that class.
printf 'shortcut-1' > "$WORKDIR/one.bin"
printf 'shortcut-2' > "$WORKDIR/two.bin"
"$P11IMPORTDATA" -l "$PKCS11LIB" -f "$WORKDIR/one.bin" -i shortcut-data-1 \
    >/dev/null 2>&1 || die "p11importdata (1) failed"
"$P11IMPORTDATA" -l "$PKCS11LIB" -f "$WORKDIR/two.bin" -i shortcut-data-2 \
    >/dev/null 2>&1 || die "p11importdata (2) failed"
out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"
echo "$out" | grep -q 'data/shortcut-data-1' \
    || die "setup: first data object missing"

"$P11RM" -l "$PKCS11LIB" -y data >/dev/null 2>&1 \
    || die "p11rm (class shortcut 'data') failed"
out=$("$P11LS" -l "$PKCS11LIB") || die "p11ls returned non-zero"
echo "$out" | grep -q 'data/shortcut-data-1' \
    && die "p11rm 'data' shortcut: first data object survived"
echo "$out" | grep -q 'data/shortcut-data-2' \
    && die "p11rm 'data' shortcut: second data object survived"
# the secret key must be untouched by the data-only shortcut.
echo "$out" | grep -q 'seck/orig' \
    || die "p11rm 'data' shortcut: removed a non-data object"

echo "objmgmt: OK"
