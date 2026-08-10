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

# nss_common.sh: shared setup for the *NSS-softoken-backed* integration tests.
#
# It points the tools at Mozilla NSS' software token (libsoftokn3.so) instead of
# SoftHSM2. NSS is a second, independent PKCS#11 implementation; running the
# tools against it exercises code that no other backend reaches -- most notably
# the NSS initialisation branch in lib/pkcs11_context.c (the tools pass the DB
# location through the NSS-specific CK_NSS_C_INITIALIZE_ARGS.LibraryParameters
# member) and the `-m' / PKCS11NSSDIR option handling shared by every tool.
#
# NSS is notoriously finicky to embed. Two mechanisms are used deliberately:
#
#   1. `-m <configdir>' (read-only checks). The tool builds the softoken
#      parameter string "configDir='<dir>'" and feeds it via
#      CK_NSS_C_INITIALIZE_ARGS on the C_Initialize retry. This is exactly the
#      tool code path we want to cover. It is reliable for read-only queries
#      (slot / token / mechanism enumeration on the login-free generic slot).
#
#   2. NSS_LIB_PARAMS (read-write operations). softoken also reads its full
#      parameter string from the NSS_LIB_PARAMS environment variable on the
#      *first* C_Initialize. Supplying the complete, canonical parameter string
#      this way is the robust, documented method to drive softoken loaded as a
#      raw PKCS#11 module, and it makes login + token writes (keygen, ...) work
#      deterministically. Read-write cases go through the nss_rw helper below.
#
# The helper self-skips (exit 77) when libsoftokn3.so or certutil is not
# available, so `make check' stays green on machines without NSS.
#
# On success the following are available to the sourcing script:
#   PKCS11LIB        -> libsoftokn3.so
#   PKCS11NSSDIR     -> "sql:<dir>" NSS config directory (for -m)
#   PKCS11PASSWORD   -> NSS DB password
#   PKCS11SLOT       -> 1 (the persistent "NSS Certificate DB" token)
#   NSS_GENERIC_SLOT -> 0 (the login-free "NSS Generic Crypto Services" token)
#   NSS_PARAMS       -> canonical softoken parameter string for NSS_LIB_PARAMS
#   WORKDIR          -> throwaway scratch directory
#   nss_rw CMD ...   -> run CMD with NSS_LIB_PARAMS set (read-write NSS access)
#   p11bin <tool>    -> absolute path of a built tool, or skip.

# ----------------------------------------------------------------------------
# Diagnostics helpers (Automake protocol: exit 77 = skip, exit 1 = fail).
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
# NSS hygiene: NSS is stateful and consults several environment variables. Clear
# any inherited NSS configuration so a developer's or CI's environment cannot
# redirect softoken at a different database. NSS_LIB_PARAMS in particular is set
# per-command (only through nss_rw) and must not leak into the read-only `-m'
# checks, otherwise softoken would satisfy the first C_Initialize from the
# environment and the tool's NSS_InitArgs branch would never run.
unset NSS_LIB_PARAMS SSL_DIR MOZ_NO_REMOTE 2>/dev/null || true
NSS_DEFAULT_DB_TYPE=sql
export NSS_DEFAULT_DB_TYPE

# ----------------------------------------------------------------------------
# Locate libsoftokn3 across the usual vendor locations. NSS_SOFTOKN_LIB may
# be set in the environment to point at a specific library.
# On macOS, Homebrew installs NSS as a keg-only formula under
# $HOMEBREW_PREFIX/opt/nss/ (HOMEBREW_PREFIX may be non-default, e.g.
# /Users/<name>/homebrew for a rootless install).  The library is a .dylib
# on Darwin and a .so on Linux/other.
find_softokn_lib() {
    for _cand in \
        "${NSS_SOFTOKN_LIB:-}" \
        "${HOMEBREW_PREFIX:-/opt/homebrew}/opt/nss/lib/libsoftokn3.dylib" \
        "${HOMEBREW_PREFIX:-/opt/homebrew}/lib/libsoftokn3.dylib" \
        /usr/lib/*/libsoftokn3.so \
        /usr/lib64/libsoftokn3.so \
        /usr/lib/libsoftokn3.so \
        /usr/local/lib/libsoftokn3.so \
        /usr/local/lib/nss/libsoftokn3.so \
        "${HOMEBREW_PREFIX:-/opt/homebrew}/opt/nss/lib/libsoftokn3.so" \
        "${HOMEBREW_PREFIX:-/opt/homebrew}/lib/libsoftokn3.so"
    do
        [ -n "$_cand" ] && [ -e "$_cand" ] && { echo "$_cand"; return 0; }
    done
    return 1
}

PKCS11LIB=$(find_softokn_lib) || skip "libsoftokn3 (NSS softoken) not found"
export PKCS11LIB

# certutil (from NSS' tools) is needed to create and password-protect the DB.
# Homebrew installs NSS as keg-only: certutil lives under
# $HOMEBREW_PREFIX/opt/nss/bin/ and is not added to PATH automatically.
find_certutil() {
    command -v certutil 2>/dev/null && return 0
    for _cand in \
        "${HOMEBREW_PREFIX:-/opt/homebrew}/opt/nss/bin/certutil" \
        /usr/local/opt/nss/bin/certutil
    do
        [ -x "$_cand" ] && { echo "$_cand"; return 0; }
    done
    return 1
}
CERTUTIL=$(find_certutil) || skip "certutil (NSS tools) not found"

# ----------------------------------------------------------------------------
# Create a throwaway NSS database in a private temp directory.
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/p11nss.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM
mkdir -p "$WORKDIR/nssdb"

PKCS11PASSWORD=1234
PKCS11SLOT=1               # persistent "NSS Certificate DB" token
NSS_GENERIC_SLOT=0        # login-free "NSS Generic Crypto Services" token
export PKCS11PASSWORD PKCS11SLOT NSS_GENERIC_SLOT

PKCS11NSSDIR="sql:$WORKDIR/nssdb"
export PKCS11NSSDIR

# The password file must hold exactly the password (no trailing newline).
printf '%s' "$PKCS11PASSWORD" > "$WORKDIR/nsspw.txt"
"$CERTUTIL" -N -d "$PKCS11NSSDIR" -f "$WORKDIR/nsspw.txt" >/dev/null 2>&1 \
    || skip "NSS database initialization (certutil -N) failed"

# Canonical softoken parameter string for NSS_LIB_PARAMS (read-write access).
# The single quotes are literal: softoken's parser expects configdir='<path>'
# with the quotes as delimiters, so they are part of the value on purpose.
# shellcheck disable=SC2089
NSS_PARAMS="configdir='$PKCS11NSSDIR' certPrefix='' keyPrefix='' secmod='secmod.db' flags="
# shellcheck disable=SC2090
export NSS_PARAMS

# nss_rw CMD [ARGS...]: run CMD against the NSS token with read-write access,
# by exposing the full softoken parameter string through NSS_LIB_PARAMS. Run in
# a subshell so the variable never leaks into the read-only `-m' checks.
nss_rw() {
    # shellcheck disable=SC2090
    ( NSS_LIB_PARAMS="$NSS_PARAMS"; export NSS_LIB_PARAMS; exec "$@" )
}
