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

# common.sh: shared setup for integration tests.
#
# Sourced (not executed) by every tests/integration/*.sh script. It:
#   - provides skip()/die() helpers following the Automake exit-code protocol
#     (77 == SKIP, 1 == FAIL);
#   - locates softhsm2-util and libsofthsm2.so, skipping the test cleanly when
#     they are absent (so `make check' stays green on build-only machines);
#   - creates a throwaway SoftHSM2 token in a temporary directory and exports
#     the PKCS11LIB / PKCS11SLOT / PKCS11PASSWORD environment variables the
#     pkcs11-tools binaries read directly;
#   - registers a trap to remove the temporary directory on exit.
#
# Expected environment (exported by AM_TESTS_ENVIRONMENT in tests/Makefile.am):
#   PKCS11_TOOLS_BINDIR   directory containing the built p11* binaries
#
# On success the following are available to the sourcing script:
#   PKCS11LIB, PKCS11SLOT, PKCS11PASSWORD, TOKEN_LABEL, WORKDIR
#   p11bin <tool>         echoes the absolute path of a built tool, or skips

# ----------------------------------------------------------------------------
# Diagnostics helpers (Automake protocol: exit 77 = skip, exit 1 = fail)
skip() { echo "SKIP: $*" >&2; exit 77; }
die()  { echo "FAIL: $*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# Resolve the directory holding the built binaries.
: "${PKCS11_TOOLS_BINDIR:?PKCS11_TOOLS_BINDIR must be set by the test harness}"

# p11bin TOOL: echo the absolute path to a built tool, or skip if it is missing
# (e.g. a partial build). Keeps individual tests resilient.
p11bin() {
    _tool="$PKCS11_TOOLS_BINDIR/$1"
    if [ ! -x "$_tool" ]; then
        skip "binary not built: $_tool"
    fi
    echo "$_tool"
}

# Some SoftHSM2 builds advertise CKM_EC_EDWARDS_KEY_PAIR_GEN but still reject
# Ed448 private-key generation at runtime (observed on Alpine 3.21's 2.6.1
# package). Probe the actual operation so tests can keep exercising Ed448 where
# it works without making that token-specific limitation a hard failure.
supports_ed448_keygen() {
    _keygen=$(p11bin p11keygen)
    _label="ed448-probe-$$"

    "$_keygen" -l "$PKCS11LIB" -k ed -q ED448 -i "$_label" \
        sign=true verify=true >/dev/null 2>&1
}

# ----------------------------------------------------------------------------
# Locate softhsm2-util.
SOFTHSM2_UTIL=$(command -v softhsm2-util 2>/dev/null) \
    || skip "softhsm2-util not found in PATH"

# Locate libsofthsm2.so across the usual vendor locations. SOFTHSM2_LIB may be
# set in the environment to point at a specific library.
find_softhsm_lib() {
    for _cand in \
        "${SOFTHSM2_LIB:-}" \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/*/softhsm/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so \
        /usr/local/lib/libsofthsm2.so \
        "${HOMEBREW_PREFIX:-/opt/homebrew}/lib/softhsm/libsofthsm2.so"
    do
        [ -n "$_cand" ] && [ -e "$_cand" ] && { echo "$_cand"; return 0; }
    done
    return 1
}

PKCS11LIB=$(find_softhsm_lib) || skip "libsofthsm2.so not found"
export PKCS11LIB

# ----------------------------------------------------------------------------
# Create a throwaway SoftHSM2 token in a private temp directory.
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/p11test.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM
mkdir -p "$WORKDIR/tokens"

cat > "$WORKDIR/softhsm2.conf" <<EOF
directories.tokendir = $WORKDIR/tokens
objectstore.backend = file
log.level = ERROR
EOF
SOFTHSM2_CONF="$WORKDIR/softhsm2.conf"
export SOFTHSM2_CONF

TOKEN_LABEL=p11test
PKCS11PASSWORD=1234
PKCS11SLOT=0            # slot *index* used by the pkcs11-tools binaries
export PKCS11PASSWORD PKCS11SLOT

"$SOFTHSM2_UTIL" --init-token --slot 0 --label "$TOKEN_LABEL" \
    --pin "$PKCS11PASSWORD" --so-pin 5678 >/dev/null 2>&1 \
    || die "SoftHSM2 token initialization failed"

# ----------------------------------------------------------------------------
# Interactive-prompt support: feed a tool's terminal password/PIN (and slot)
# prompt from a pipe.
#
# The tools switch terminal echo off (tcgetattr/tcsetattr on stdin) before
# reading a secret; on a pipe that aborts before any input is read. Preloading
# tests/preload/notty.so neutralizes those termios calls so the secret can be
# supplied on stdin. Preloading is a Unix mechanism: LD_PRELOAD on ELF systems
# (Linux/*BSD) and DYLD_INSERT_LIBRARIES on macOS (the stub uses dyld
# interposing). It is unavailable on Windows/MinGW.
#
# require_pin_prompt_preload: skip (exit 77) when preloading is unavailable
# (unsupported OS, or the stub was not built), otherwise select the preload
# mechanism. On success it sets NOTTY_PRELOAD (path to the stub) and
# NOTTY_PRELOAD_ENV (the loader variable name) and makes notty_run available.
#
# notty_run CMD [ARGS...]: run CMD with the preload active, in a subshell, so
# the loader variable does not leak into the rest of the test. Feed input via a
# pipe, e.g.:  printf '%s\n' "$PIN" | notty_run "$TOOL" -l "$PKCS11LIB"
require_pin_prompt_preload() {
    case "$(uname -s 2>/dev/null)" in
        Linux | FreeBSD | GNU/kFreeBSD | NetBSD | OpenBSD | DragonFly)
            NOTTY_PRELOAD_ENV=LD_PRELOAD ;;
        Darwin)
            NOTTY_PRELOAD_ENV=DYLD_INSERT_LIBRARIES ;;
        *)
            skip "interactive prompt test needs LD_PRELOAD/DYLD (Unix only)" ;;
    esac
    if [ -z "${PKCS11_PRELOAD_NOTTY:-}" ] || [ ! -e "$PKCS11_PRELOAD_NOTTY" ]; then
        skip "preload stub not built: ${PKCS11_PRELOAD_NOTTY:-unset}"
    fi
    NOTTY_PRELOAD="$PKCS11_PRELOAD_NOTTY"
}

# notty_run: exec a command with the preload loader variable set. Kept in a
# subshell and set explicitly (never through /usr/bin/env, which on macOS is
# SIP-protected and would strip DYLD_* before our binary is reached).
notty_run() {
    case "${NOTTY_PRELOAD_ENV:-}" in
        LD_PRELOAD)
            ( LD_PRELOAD="$NOTTY_PRELOAD"; export LD_PRELOAD; exec "$@" ) ;;
        DYLD_INSERT_LIBRARIES)
            ( DYLD_INSERT_LIBRARIES="$NOTTY_PRELOAD"
              export DYLD_INSERT_LIBRARIES; exec "$@" ) ;;
        *)
            die "notty_run called before require_pin_prompt_preload" ;;
    esac
}
