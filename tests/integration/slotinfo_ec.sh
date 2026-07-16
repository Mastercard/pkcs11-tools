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

# Integration test: p11slotinfo -e (named elliptic-curve support probing).
#
# With -e, p11slotinfo iterates over every named curve known to the linked
# OpenSSL (EC_get_builtin_curves) and, for each one, actually attempts an EC
# key-pair generation on the token (pkcs11_testgenEC_support in
# lib/pkcs11_slotinfo.c). Curves for which generation succeeds are listed under
# an "EC curves supported by token" section. This drives the EC-support path
# that the plain slotinfo.sh test does not reach.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

SLOTINFO=$(p11bin p11slotinfo)

# --- with -e: the EC-curves section is present ------------------------------
out=$("$SLOTINFO" -l "$PKCS11LIB" -e) || die "p11slotinfo -e returned non-zero"

echo "$out" | grep -q 'EC curves supported by token' \
    || die "p11slotinfo -e did not print the EC curves section"

# The three NIST prime curves are OpenSSL built-ins and are supported by
# SoftHSM2, so each must appear on its own line in the supported list. These
# are the same curves the keygen tests exercise, and are portable across the
# OpenSSL builds on Linux, FreeBSD and MinGW64.
for curve in prime256v1 secp384r1 secp521r1; do
    echo "$out" | grep -Fxq "$curve" \
        || die "p11slotinfo -e did not report '$curve' as supported"
done

# --- without -e: the EC-curves section is absent ----------------------------
# This confirms the section is produced by -e specifically, not printed
# unconditionally.
plain=$("$SLOTINFO" -l "$PKCS11LIB") || die "p11slotinfo returned non-zero"

if echo "$plain" | grep -q 'EC curves supported by token'; then
    die "p11slotinfo without -e unexpectedly printed the EC curves section"
fi

echo "p11slotinfo -e (EC curve support): OK"
