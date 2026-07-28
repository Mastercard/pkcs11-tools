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

# Integration test: the -h (usage) option, the unknown-option error path, and
# the missing-required-argument error path of every command.
#
# Each tool has a print_usage() that writes a "USAGE: <tool> ..." banner to
# stderr and exits with a non-zero (usage) status. An unrecognised option makes
# getopt complain and the tool fall into its error branch ("Try `<tool> -h'
# ..."), also exiting non-zero. Running a tool with NO arguments trips a third,
# distinct branch: the post-getopt check that a required option/argument is
# missing (e.g. "At least one required option or argument is wrong or missing").
# All three paths are pure option handling: they touch no PKCS#11 token, so this
# smoke test covers every command's print_usage(), getopt error branch, and
# missing-required-argument branch at once.
#
# Like version_option.sh, this script does NOT source common.sh (no SoftHSM2
# needed): it only needs the built binaries, so it also runs on build-only
# machines with no PKCS#11 module installed.

set -eu

# Automake protocol: 77 = skip, 1 = fail.
skip() { echo "SKIP: $*" >&2; exit 77; }
die()  { echo "FAIL: $*" >&2; exit 1; }

: "${PKCS11_TOOLS_BINDIR:?PKCS11_TOOLS_BINDIR must be set by the test harness}"

# Every command built from src/Makefile.am's bin_PROGRAMS.
tools='
p11mkcert p11rewrap p11wrap p11unwrap p11cp p11ls p11cat p11more p11od
p11rm p11mv p11slotinfo p11req p11importcert p11importpubk p11importdata
p11keycomp p11setattr masqreq p11keygen p11kcv p11init
'

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/p11usage.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM
outf="$WORKDIR/out"
errf="$WORKDIR/err"

checked=0
for tool in $tools; do
    bin="$PKCS11_TOOLS_BINDIR/$tool"
    # A partial build should skip cleanly rather than fail the whole suite.
    [ -x "$bin" ] || skip "binary not built: $bin"

    # --- 1) -h prints the usage banner and exits non-zero -----------------
    set +e
    "$bin" -h >"$outf" 2>"$errf"
    rc=$?
    set -e

    [ "$rc" -ne 0 ] \
        || die "$tool -h exited 0, expected a non-zero usage status"
    [ ! -s "$outf" ] \
        || die "$tool -h wrote to stdout (usage must go to stderr)"
    grep -q "^USAGE:.*$tool" "$errf" \
        || die "$tool -h stderr missing 'USAGE: ...$tool' banner"

    # --- 2) an unknown option triggers the getopt error branch ------------
    set +e
    "$bin" -Z >"$outf" 2>"$errf"
    rc=$?
    set -e

    [ "$rc" -ne 0 ] \
        || die "$tool -Z exited 0, expected a non-zero error status"
    [ ! -s "$outf" ] \
        || die "$tool -Z wrote to stdout (diagnostics must go to stderr)"
    [ -s "$errf" ] \
        || die "$tool -Z produced no diagnostic on stderr"

    # --- 3) no arguments trips the missing-required-argument branch --------
    # Distinct from the getopt error above: getopt returns immediately, then
    # the tool's own post-parse validation rejects the missing required
    # option/argument. Token-free (the check runs before any module is loaded).
    set +e
    "$bin" >"$outf" 2>"$errf"
    rc=$?
    set -e

    [ "$rc" -ne 0 ] \
        || die "$tool (no args) exited 0, expected a non-zero error status"
    [ ! -s "$outf" ] \
        || die "$tool (no args) wrote to stdout (diagnostics must go to stderr)"
    [ -s "$errf" ] \
        || die "$tool (no args) produced no diagnostic on stderr"

    checked=$((checked + 1))
done

[ "$checked" -gt 0 ] || die "no tools were checked"

echo "usage_option (-h + bad option + no args on $checked commands): OK"
