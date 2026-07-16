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

# Integration test: the -V (version) option of every command.
#
# Each tool wires -V to print_version_info() (src/version.c): it writes a
# banner to stderr ("<tool> belongs to pkcs11-tools v<version> ...", the target
# triple, the OpenSSL version) and exits with RC_ERROR_USAGE (8). This test
# checks that contract for all commands at once.
#
# Unlike the other integration tests, -V touches no PKCS#11 token, so this
# script does NOT source common.sh (which would require SoftHSM2): it only needs
# the built binaries. That keeps the version smoke test running on build-only
# machines with no PKCS#11 module installed.

set -eu

# Automake protocol: 77 = skip, 1 = fail.
skip() { echo "SKIP: $*" >&2; exit 77; }
die()  { echo "FAIL: $*" >&2; exit 1; }

: "${PKCS11_TOOLS_BINDIR:?PKCS11_TOOLS_BINDIR must be set by the test harness}"

# RC_ERROR_USAGE, as returned by print_version_info() (include/pkcs11lib.h).
RC_ERROR_USAGE=8

# Every command built from src/Makefile.am's bin_PROGRAMS. All of them route
# -V through print_version_info().
tools='
p11mkcert p11rewrap p11wrap p11unwrap p11cp p11ls p11cat p11more p11od
p11rm p11mv p11slotinfo p11req p11importcert p11importpubk p11importdata
p11keycomp p11setattr masqreq p11keygen p11kcv p11init
'

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/p11ver.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM
outf="$WORKDIR/out"
errf="$WORKDIR/err"

checked=0
for tool in $tools; do
    bin="$PKCS11_TOOLS_BINDIR/$tool"
    # A partial build should skip cleanly rather than fail the whole suite.
    [ -x "$bin" ] || skip "binary not built: $bin"

    set +e
    "$bin" -V >"$outf" 2>"$errf"
    rc=$?
    set -e

    # 1) exit code must be RC_ERROR_USAGE.
    [ "$rc" -eq "$RC_ERROR_USAGE" ] \
        || die "$tool -V exit code $rc, expected $RC_ERROR_USAGE"

    # 2) the banner is written to stderr, not stdout.
    [ ! -s "$outf" ] \
        || die "$tool -V wrote to stdout (banner must go to stderr)"

    # 3) banner names the tool (basename of argv[0]) and the package/version.
    grep -q "^$tool belongs to pkcs11-tools v" "$errf" \
        || die "$tool -V banner missing '<tool> belongs to pkcs11-tools v...'"

    # 4) banner includes the target triple and the OpenSSL version lines.
    grep -q 'arch/CPU/OS:' "$errf" \
        || die "$tool -V banner missing the target triple line"
    grep -q 'using openssl library:' "$errf" \
        || die "$tool -V banner missing the OpenSSL version line"

    checked=$((checked + 1))
done

[ "$checked" -gt 0 ] || die "no tools were checked"

echo "version_option (-V on $checked commands): OK"
