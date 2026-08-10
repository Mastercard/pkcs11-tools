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

# Integration test: token initialization (p11init, batch mode).
#   SoftHSM2 always exposes one spare, uninitialized slot after the initialized
#   ones. common.sh initializes the token at slot index 0, so slot index 1 is a
#   fresh slot we can initialize with p11init without touching the shared token.
#
#   1. p11init -I : initialize the spare slot's token (C_InitToken, SO PIN)
#   2. p11init -U : set the user (crypto officer) PIN (C_InitPIN)
#   3. keygen a key into the freshly initialized token to prove it is usable
#
# This exercises the token/PIN initialization paths (p11init.c / pkcs11_init.c).
#
# Note: the destructive reinitialization path (p11init -I -R) is deliberately
# not tested here. SoftHSM2 assigns a fresh, random slot ID when a token is
# created, so the slot *index* of the just-initialized token is not stable, and
# targeting a reinitialization by index could hit the wrong slot.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

P11INIT=$(p11bin p11init)
KEYGEN=$(p11bin p11keygen)
P11LS=$(p11bin p11ls)

# Spare (uninitialized) slot index and credentials for the new token.
SPARE_SLOT=1
SO_PIN=90909090
USER_PIN=43214321
NEW_LABEL=p11init-new

# --- 1. initialize the spare slot's token -----------------------------------
"$P11INIT" -l "$PKCS11LIB" -B -I -s "$SPARE_SLOT" -O "$SO_PIN" -T "$NEW_LABEL" \
    >/dev/null 2>&1 || die "p11init -I (token initialization) failed"

# --- 2. set the user PIN ----------------------------------------------------
"$P11INIT" -l "$PKCS11LIB" -B -U -t "$NEW_LABEL" -O "$SO_PIN" -P "$USER_PIN" \
    >/dev/null 2>&1 || die "p11init -U (user PIN initialization) failed"

# --- 3. the token must now be usable ----------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -t "$NEW_LABEL" -p "$USER_PIN" \
    -k aes -b 128 -i init-probe encrypt=true >/dev/null 2>&1 \
    || die "p11keygen into freshly initialized token failed"

count=$("$P11LS" -l "$PKCS11LIB" -t "$NEW_LABEL" -p "$USER_PIN" 2>/dev/null \
    | grep -c 'seck/init-probe')
[ "$count" -eq 1 ] || die "probe key not found in freshly initialized token"

echo "token init (init token + user PIN + keygen): OK"
