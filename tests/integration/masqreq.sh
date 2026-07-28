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

# Integration test: masqreq (rewrite the subject/extensions of a PKCS#10 CSR
# WITHOUT re-signing it).
#
# Unlike the other integration tests, masqreq needs no PKCS#11 token: it only
# manipulates a CSR with OpenSSL. It therefore does NOT source common.sh and
# runs on any machine that has OpenSSL, skipping only when OpenSSL is missing.

set -eu

skip() { echo "SKIP: $*" >&2; exit 77; }
die()  { echo "FAIL: $*" >&2; exit 1; }

: "${PKCS11_TOOLS_BINDIR:?PKCS11_TOOLS_BINDIR must be set by the test harness}"

MASQREQ="$PKCS11_TOOLS_BINDIR/masqreq"
[ -x "$MASQREQ" ] || skip "binary not built: $MASQREQ"
command -v openssl >/dev/null 2>&1 || skip "openssl not found in PATH"

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/p11masq.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

KEY="$WORKDIR/k.pem"
ORIG="$WORKDIR/orig.csr"
MASQ="$WORKDIR/masq.csr"

# --- 1. produce an original CSR ---------------------------------------------
openssl req -new -newkey rsa:2048 -nodes -keyout "$KEY" \
    -subj '/CN=original-subject/O=Orig' -out "$ORIG" >/dev/null 2>&1 \
    || die "openssl could not create the original CSR"

# --- 2. masquerade the subject ----------------------------------------------
"$MASQREQ" -c "$ORIG" -d '/CN=masqueraded-subject/O=Masq' -o "$MASQ" \
    >/dev/null 2>&1 || die "masqreq failed"

[ -s "$MASQ" ] || die "masqreq produced an empty CSR"

# --- 3. verify the new subject ----------------------------------------------
subject=$(openssl req -in "$MASQ" -noout -subject 2>/dev/null) \
    || die "OpenSSL could not parse the masqueraded CSR"

echo "$subject" | grep -q 'masqueraded-subject' \
    || die "masqreq: new subject not applied (got: $subject)"

echo "$subject" | grep -q 'original-subject' \
    && die "masqreq: original subject unexpectedly still present"

# The masqueraded public key must be identical to the original (masqreq reuses
# the key and does not re-sign): compare the two public keys.
pub_orig=$(openssl req -in "$ORIG" -noout -pubkey 2>/dev/null) \
    || die "could not extract public key from original CSR"
pub_masq=$(openssl req -in "$MASQ" -noout -pubkey 2>/dev/null) \
    || die "could not extract public key from masqueraded CSR"

[ "$pub_orig" = "$pub_masq" ] \
    || die "masqreq: public key changed (should be preserved verbatim)"

# --- 3b. an RSA-PSS input CSR keeps its PSS signature algorithm -------------
# masqreq re-forges the signature through the pkcs11tools OpenSSL 3 provider
# while preserving the ORIGINAL signature algorithm. For an RSA-PSS request it
# must recover the message digest from the embedded PSS parameters (here
# SHA-384, a non-default digest) and re-emit an rsassaPss signature. This is
# the only test that exercises the PSS branch of pkcs11_masq_X509_REQ.
PSS_ORIG="$WORKDIR/pss-orig.csr"
PSS_MASQ="$WORKDIR/pss-masq.csr"
if openssl req -new -newkey rsa:2048 -nodes -keyout "$WORKDIR/pss.key" \
        -sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
        -subj '/CN=pss-original/O=Orig' -out "$PSS_ORIG" >/dev/null 2>&1; then

    "$MASQREQ" -c "$PSS_ORIG" -d '/CN=pss-masqueraded/O=Masq' -o "$PSS_MASQ" \
        >/dev/null 2>&1 || die "masqreq (RSA-PSS input) failed"
    [ -s "$PSS_MASQ" ] || die "masqreq (RSA-PSS) produced an empty CSR"

    pss_text=$(openssl req -in "$PSS_MASQ" -noout -text 2>/dev/null) \
        || die "OpenSSL could not parse the masqueraded RSA-PSS CSR"
    printf '%s\n' "$pss_text" | grep -qi 'rsassaPss' \
        || die "masqreq: RSA-PSS signature algorithm not preserved"
    printf '%s\n' "$pss_text" | grep -qiE 'Hash Algorithm:[[:space:]]*sha384' \
        || die "masqreq: PSS digest (sha384) not recovered from the input CSR"

    # the new subject must be applied and the public key preserved verbatim,
    # exactly as required for the PKCS#1 v1.5 case above.
    openssl req -in "$PSS_MASQ" -noout -subject 2>/dev/null \
        | grep -q 'pss-masqueraded' \
        || die "masqreq: RSA-PSS new subject not applied"
    pss_pub_orig=$(openssl req -in "$PSS_ORIG" -noout -pubkey 2>/dev/null)
    pss_pub_masq=$(openssl req -in "$PSS_MASQ" -noout -pubkey 2>/dev/null)
    [ "$pss_pub_orig" = "$pss_pub_masq" ] \
        || die "masqreq: RSA-PSS public key changed (should be preserved)"
else
    echo "NOTE: openssl cannot create RSA-PSS CSRs here; skipping PSS masqreq check" >&2
fi

# --- 4. reverse DN + SKI + verbose + many SAN (trips the WARN_SAN warning) ---
# Covers -r, -X, -v, and the -e SAN loop including the "many SAN fields" warning
# branch (fires when the SAN count reaches the warning threshold).
sanargs=""
i=1
while [ "$i" -le 26 ]; do
    sanargs="$sanargs -e DNS:h$i.example"
    i=$((i + 1))
done
FULL="$WORKDIR/full.csr"
# shellcheck disable=SC2086 # sanargs is a list of separate -e <field> tokens
"$MASQREQ" -c "$ORIG" -d '/CN=full/O=FullOrg' -r -X -v $sanargs -o "$FULL" \
    >"$WORKDIR/verbose.out" 2>"$WORKDIR/full.err" \
    || die "masqreq (reverse/SKI/verbose/SAN) failed"

[ -s "$FULL" ] || die "masqreq (full) produced an empty CSR"
grep -q 'Warning: many SAN fields' "$WORKDIR/full.err" \
    || die "masqreq: expected the 'many SAN fields' warning (>= threshold)"
[ -s "$WORKDIR/verbose.out" ] \
    || die "masqreq -v produced no verbose output on stdout"
openssl req -in "$FULL" -noout -text 2>/dev/null | grep -q 'Subject Alternative Name' \
    || die "masqreq: SAN extension missing from the output CSR"
openssl req -in "$FULL" -noout -text 2>/dev/null | grep -q 'Subject Key Identifier' \
    || die "masqreq -X: Subject Key Identifier extension missing"

# --- 5. an invalid subject DN is rejected -----------------------------------
set +e
"$MASQREQ" -c "$ORIG" -d 'not-a-valid-dn' -o "$WORKDIR/bad.csr" \
    >"$WORKDIR/dn.out" 2>"$WORKDIR/dn.err"
rc=$?
set -e
[ "$rc" -ne 0 ] || die "masqreq accepted an invalid DN (expected failure)"
grep -qi 'invalid DN' "$WORKDIR/dn.err" \
    || die "masqreq: invalid DN did not produce the expected diagnostic"

# --- 6. a missing input file is reported ------------------------------------
set +e
"$MASQREQ" -c "$WORKDIR/does-not-exist.csr" -d '/CN=x' -o "$WORKDIR/x.csr" \
    >"$WORKDIR/nf.out" 2>"$WORKDIR/nf.err"
rc=$?
set -e
[ "$rc" -ne 0 ] || die "masqreq accepted a missing input file (expected failure)"
grep -qi 'could not load' "$WORKDIR/nf.err" \
    || die "masqreq: missing input file did not produce the expected diagnostic"

echo "masqreq: OK"
