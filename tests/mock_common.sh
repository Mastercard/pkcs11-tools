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

# mock_common.sh: shared setup for the *mock-backed* integration tests.
#
# Unlike common.sh, this helper does NOT require SoftHSM2: it points the tools
# at the programmable mock PKCS#11 module (tests/mock/mock_pkcs11.so) instead.
# That is the whole point of the mock -- it exercises code paths SoftHSM2 cannot
# (CKM_XOR_BASE_AND_DATA for p11keycomp, exotic wrap mechanisms, and injected
# driver errors) and it runs even where no real PKCS#11 token is installed.
#
# Sourced (not executed) by tests/integration/mock_*.sh. It:
#   - provides skip()/die() helpers (Automake protocol: 77 == SKIP, 1 == FAIL);
#   - skips cleanly when the mock module was not built (e.g. Windows/MinGW, where
#     loadable preload-style modules are not produced by the suite);
#   - exports PKCS11LIB (-> the mock), PKCS11SLOT, PKCS11PASSWORD and sensible
#     MOCK_P11_* defaults that the mock reads at C_Initialize;
#   - creates a throwaway WORKDIR and removes it on exit.
#
# On success the following are available to the sourcing script:
#   PKCS11LIB, PKCS11SLOT, PKCS11PASSWORD, WORKDIR
#   p11bin <tool>   echoes the absolute path of a built tool, or skips.

# ----------------------------------------------------------------------------
# Diagnostics helpers.
skip() { echo "SKIP: $*" >&2; exit 77; }
die()  { echo "FAIL: $*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# Resolve the directory holding the built binaries.
: "${PKCS11_TOOLS_BINDIR:?PKCS11_TOOLS_BINDIR must be set by the test harness}"

p11bin() {
    _tool="$PKCS11_TOOLS_BINDIR/$1"
    if [ ! -x "$_tool" ]; then
        skip "binary not built: $_tool"
    fi
    echo "$_tool"
}

# ----------------------------------------------------------------------------
# Locate the mock module. It is only built off Windows/MinGW (loadable modules
# are produced with `cc -shared -fPIC'); when absent, skip the whole test.
if [ -z "${PKCS11_MOCK:-}" ] || [ ! -e "$PKCS11_MOCK" ]; then
    skip "mock PKCS#11 module not built: ${PKCS11_MOCK:-unset}"
fi

PKCS11LIB="$PKCS11_MOCK"
export PKCS11LIB

# ----------------------------------------------------------------------------
# Credentials + mock defaults. The mock's default PIN matches PKCS11PASSWORD so
# non-interactive tools authenticate without extra configuration.
PKCS11SLOT=0
PKCS11PASSWORD=1234
export PKCS11SLOT PKCS11PASSWORD

MOCK_P11_PIN=1234
export MOCK_P11_PIN

# ----------------------------------------------------------------------------
# Throwaway working directory for any scratch files the test needs.
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/p11mock.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM
