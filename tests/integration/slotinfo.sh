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

# Integration test: p11slotinfo against a fresh SoftHSM2 token.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

SLOTINFO=$(p11bin p11slotinfo)

out=$("$SLOTINFO" -l "$PKCS11LIB") || die "p11slotinfo returned non-zero"

echo "$out" | grep -q 'CKF_TOKEN_PRESENT' \
    || die "expected CKF_TOKEN_PRESENT in slot info output"
echo "$out" | grep -q "$TOKEN_LABEL" \
    || die "expected token label '$TOKEN_LABEL' in slot info output"

echo "p11slotinfo: OK"
