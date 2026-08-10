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

# Integration test: p11keygen option coverage beyond the plain keygen paths
# exercised elsewhere. Drives branches of pkcs11_keygen.c / src/p11keygen.c:
#
#   1. generate-and-wrap (-W): a freshly generated AES key is wrapped to a file
#      in the same invocation. The key is confirmed on the token and the wrapped
#      blob is unwrapped back, comparing key check values.
#   2. custom RSA public exponent (-e 3): OpenSSL confirms the exponent (the
#      check is skipped when openssl is unavailable; the keygen itself is not).

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11UNWRAP=$(p11bin p11unwrap)
P11RM=$(p11bin p11rm)
P11KCV=$(p11bin p11kcv)
P11CAT=$(p11bin p11cat)

OPENSSL=$(command -v openssl 2>/dev/null || true)

ecb_kcv() {
    "$P11KCV" -l "$PKCS11LIB" -f ecb "seck/$1" 2>/dev/null \
        | sed -n 's/.*KCV = \([0-9a-fA-F]*\).*/\1/p'
}

# --- 1. generate-and-wrap ---------------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i ko-kek \
    wrap=true unwrap=true >/dev/null 2>&1 || die "p11keygen (AES KEK) failed"

gw_file="$WORKDIR/ko-gw.wrap"
# Options must precede the non-option key-attribute operands. glibc's getopt(3)
# permutes argv so options may follow operands, but POSIX getopt(3) (and thus
# gnulib's getopt on non-glibc platforms such as the *BSDs, macOS and Cygwin)
# stops at the first operand: a trailing -W would then be handed to the
# attribute parser and rejected. See the gnulib manual, "Getopt".
"$KEYGEN" -l "$PKCS11LIB" -k aes -b 128 -i ko-gw \
    -W "wrappingkey=\"ko-kek\",algorithm=rfc5649,filename=\"$gw_file\"" \
    extractable=true encrypt=true \
    >/dev/null 2>&1 || die "p11keygen (generate-and-wrap) failed"
[ -s "$gw_file" ] || die "p11keygen (-W) produced no wrapped file"

orig=$(ecb_kcv ko-gw)
[ -n "$orig" ] || die "generated key ko-gw not found on the token"

"$P11RM" -l "$PKCS11LIB" -y seck/ko-gw >/dev/null 2>&1 \
    || die "p11rm (ko-gw) failed"
"$P11UNWRAP" -l "$PKCS11LIB" -f "$gw_file" -i ko-gw2 \
    encrypt=true >/dev/null 2>&1 || die "p11unwrap (ko-gw2) failed"

got=$(ecb_kcv ko-gw2)
[ "$got" = "$orig" ] \
    || die "generate-and-wrap round-trip KCV mismatch (expected $orig, got $got)"

# --- 2. custom RSA public exponent ------------------------------------------
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -e 3 -i ko-rsa \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (RSA, custom exponent) failed"

if [ -n "$OPENSSL" ]; then
    "$P11CAT" -l "$PKCS11LIB" pubk/ko-rsa 2>/dev/null \
        | "$OPENSSL" rsa -pubin -noout -text 2>/dev/null \
        | grep -qi 'Exponent: 3 ' \
        || die "custom RSA exponent (-e 3) not reflected in the public key"
fi

echo "p11keygen options (generate-and-wrap, custom exponent): OK"
