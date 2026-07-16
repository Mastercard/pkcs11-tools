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

# Integration test: attribute editing (p11setattr) and object copy/rename
# (p11cp / p11mv).
#   1. p11setattr : change CKA_LABEL and CKA_ID on a data object and a key
#   2. p11cp      : copy a secret key to a new label (both must then exist)
#   3. p11mv      : rename the copy (old label gone, new label present)
#
# These exercise the peek/poke attribute paths (pkcs11_peekpoke.c) and the
# object copy/move tools.

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11IMPORTDATA=$(p11bin p11importdata)
P11SETATTR=$(p11bin p11setattr)
P11CP=$(p11bin p11cp)
P11MV=$(p11bin p11mv)
P11LS=$(p11bin p11ls)

# --- object material --------------------------------------------------------
printf 'setattr-payload' > "$WORKDIR/sa.bin"
"$P11IMPORTDATA" -l "$PKCS11LIB" -f "$WORKDIR/sa.bin" -i sa-data \
    >/dev/null 2>&1 || die "p11importdata failed"

"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i sa-key \
    encrypt=true decrypt=true extractable=true >/dev/null 2>&1 \
    || die "p11keygen (AES) failed"

# An RSA keypair gives us public- and private-key objects, so the type-prefixed
# (pubk/, prvk/) copy paths can be exercised too.
"$KEYGEN" -l "$PKCS11LIB" -k rsa -b 2048 -i sa-rsa \
    sign=true verify=true >/dev/null 2>&1 \
    || die "p11keygen (RSA) failed"

# A certificate object lets the interactive setattr path exercise its
# CKO_CERTIFICATE (cert/) prefix arm. Import a static, self-signed cert so no
# runtime openssl dependency is introduced.
P11IMPORTCERT=$(p11bin p11importcert)
cat > "$WORKDIR/sa-cert.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIUSKWeLhdWpltvzV0+LZq6fHNJtHQwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUcDExdGVzdC1zZXRhdHRyLWNlcnQwHhcNMjYwNzE0MTEy
MTM5WhcNMzYwNzExMTEyMTM5WjAfMR0wGwYDVQQDDBRwMTF0ZXN0LXNldGF0dHIt
Y2VydDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANvHOqGZX/gBlIXX
rIyB1qpxqDVS8QoNevcKlGBvqno2azt1rXfSIyAOpVQ6f32orsXTxdfUJfZ+dQHT
L08/RlA05cm+b8Tq/XVL80D+1R33eiHa645IKQTa5tOAWCWQkGnvBLqQG+Yrv/S1
0Hd340HWlGIcW+PC1lu5tI40KoKuOEvLRJyT30Hfe9k5oOkFX+PKIW/kYB94dfZi
SzBZQDVsBj0f1Pp5ZRC2bN1qvWTMCRWigG4GcdVZnBHV/7f6JcSxt+BwAeOv3u8u
nR4HZTglH/QjXex3HXLyuf4oGUXZEyKuQXGHoOSVGfYqdoG5JybKsT508DPCC18T
3UszRpMCAwEAAaNTMFEwHQYDVR0OBBYEFCGb5cLVXZKPihwFSAtSdQAncaUoMB8G
A1UdIwQYMBaAFCGb5cLVXZKPihwFSAtSdQAncaUoMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBAKZ4a3wjulnG//GcYxqvsYHgRsXcgEe+U0wtwp2S
cdusYklu6y1kZsjaiEFHJ0V8/o0HzSy0Eacqv/G+53BkhSWruhhNRf5SIkTW5JTB
XjrY188BpeHNp2zF1A30WOZsAqQLK59hRR+P6yV9FeFv7+vrAYbAqRBdhf5g1ova
SNdXzo/a59hzmDs0svr2PxWZ6r3xGnIyGR/XGpamC4rWXBPy6gIgyf4mbxdZ5yME
8a2O0Mg1gIWha55vFvDqkVDDWKpC9WK56Ji8u5edjO+E+/9zqyaeMqspUF1oU6FX
rdV6VPCwtaEWUp+w9G8IJvLvneBVpk75P3Sfb7jcpP296vo=
-----END CERTIFICATE-----
EOF
"$P11IMPORTCERT" -l "$PKCS11LIB" -f "$WORKDIR/sa-cert.pem" -i sa-cert \
    >/dev/null 2>&1 || die "p11importcert failed"

# --- 1. p11setattr: rename a data object via CKA_LABEL ----------------------
"$P11SETATTR" -l "$PKCS11LIB" -y data/sa-data CKA_LABEL=sa-data2 \
    >/dev/null 2>&1 || die "p11setattr (data CKA_LABEL) failed"
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null)
echo "$ls_out" | grep -qE 'data/sa-data2[[:space:]]' \
    || die "p11setattr: relabelled data object not found"
echo "$ls_out" | grep -qE 'data/sa-data[[:space:]]' \
    && die "p11setattr: old data label still present after relabel"

# --- 1b. p11setattr: set CKA_ID on the secret key ---------------------------
"$P11SETATTR" -l "$PKCS11LIB" -y seck/sa-key CKA_ID='{deadbeef}' \
    >/dev/null 2>&1 || die "p11setattr (seck CKA_ID) failed"

# --- 2. p11cp: copy the secret key to a new label ---------------------------
"$P11CP" -l "$PKCS11LIB" -y seck/sa-key seck/sa-copy >/dev/null 2>&1 \
    || die "p11cp (secret key) failed"
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null)
echo "$ls_out" | grep -q 'seck/sa-key' \
    || die "p11cp: original key disappeared after copy"
echo "$ls_out" | grep -q 'seck/sa-copy' \
    || die "p11cp: copied key not found"

# --- 3. p11mv: rename the copy ----------------------------------------------
"$P11MV" -l "$PKCS11LIB" -y seck/sa-copy seck/sa-moved >/dev/null 2>&1 \
    || die "p11mv (rename) failed"
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null)
echo "$ls_out" | grep -q 'seck/sa-moved' \
    || die "p11mv: renamed key not found"
echo "$ls_out" | grep -q 'seck/sa-copy' \
    && die "p11mv: old label still present after rename"

# --- 4. p11cp with explicit type prefixes (pubk/, prvk/) --------------------
# Exercises the per-class dispatch (whatsrc/whatdest) in pkcs11_cp.c beyond the
# secret-key case above.
"$P11CP" -l "$PKCS11LIB" -y pubk/sa-rsa pubk/sa-rsa-pub >/dev/null 2>&1 \
    || die "p11cp (public key) failed"
"$P11CP" -l "$PKCS11LIB" -y prvk/sa-rsa prvk/sa-rsa-prv >/dev/null 2>&1 \
    || die "p11cp (private key) failed"
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null)
echo "$ls_out" | grep -q 'pubk/sa-rsa-pub' \
    || die "p11cp: copied public key not found"
echo "$ls_out" | grep -q 'prvk/sa-rsa-prv' \
    || die "p11cp: copied private key not found"

# --- 5. error: source and destination of different kinds --------------------
# The tool must refuse and exit non-zero (regression guard: it used to ignore
# pkcs11_cp_objects()'s return value and exit 0).
set +e
"$P11CP" -l "$PKCS11LIB" -y seck/sa-key pubk/wrong-kind \
    >"$WORKDIR/mismatch.out" 2>"$WORKDIR/mismatch.err"
rc=$?
set -e
[ "$rc" -ne 0 ] \
    || die "p11cp accepted mismatched source/destination kinds (expected failure)"
grep -qi 'same kind' "$WORKDIR/mismatch.err" \
    || die "p11cp: mismatched-kind error message missing"

# --- 6. error: destination already exists -----------------------------------
# seck/sa-moved was created in step 3; copying onto it must be refused with a
# non-zero exit (regression guard for the prefixed object-exists check).
set +e
"$P11CP" -l "$PKCS11LIB" -y seck/sa-key seck/sa-moved \
    >"$WORKDIR/exists.out" 2>"$WORKDIR/exists.err"
rc=$?
set -e
[ "$rc" -ne 0 ] \
    || die "p11cp overwrote an existing destination (expected failure)"
grep -qi 'already exists' "$WORKDIR/exists.err" \
    || die "p11cp: destination-exists error message missing"

# --- 7. interactive confirmation (no -y): answer y then n -------------------
# Without -y the tool prompts "copy ... ? (y/N)" and reads the answer with
# getchar() from stdin. Feeding a pipe drives the interactive branch.
printf 'y\n' | "$P11CP" -l "$PKCS11LIB" seck/sa-key seck/sa-viayes \
    >/dev/null 2>&1 || die "p11cp (interactive, y) failed"
printf 'n\n' | "$P11CP" -l "$PKCS11LIB" seck/sa-key seck/sa-viano \
    >/dev/null 2>&1 || die "p11cp (interactive, n) returned an error"
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null)
echo "$ls_out" | grep -q 'seck/sa-viayes' \
    || die "p11cp (interactive, y): the confirmed copy was not created"
echo "$ls_out" | grep -q 'seck/sa-viano' \
    && die "p11cp (interactive, n): a declined copy was created anyway"

# --- 8. p11mv with explicit type prefixes -----------------------------------
# Move (rename) the RSA copies made in step 4 through the prefixed pubk/, prvk/
# dispatch, then a secret-key copy through seck/.
"$P11MV" -l "$PKCS11LIB" -y pubk/sa-rsa-pub pubk/sa-rsa-pub2 >/dev/null 2>&1 \
    || die "p11mv (public key) failed"
"$P11MV" -l "$PKCS11LIB" -y prvk/sa-rsa-prv prvk/sa-rsa-prv2 >/dev/null 2>&1 \
    || die "p11mv (private key) failed"
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null)
echo "$ls_out" | grep -q 'pubk/sa-rsa-pub2' \
    || die "p11mv: renamed public key not found"
echo "$ls_out" | grep -q 'pubk/sa-rsa-pub[[:space:]]' \
    && die "p11mv: old public-key label still present after rename"
echo "$ls_out" | grep -q 'prvk/sa-rsa-prv2' \
    || die "p11mv: renamed private key not found"

# --- 9. p11mv error paths (mismatched kinds, destination exists) ------------
set +e
"$P11MV" -l "$PKCS11LIB" -y seck/sa-key cert/wrong-kind \
    >"$WORKDIR/mvmismatch.out" 2>"$WORKDIR/mvmismatch.err"
rc=$?
set -e
[ "$rc" -ne 0 ] \
    || die "p11mv accepted mismatched source/destination kinds (expected failure)"

# seck/sa-viayes exists (step 7); moving sa-key onto it must be refused.
set +e
"$P11MV" -l "$PKCS11LIB" -y seck/sa-key seck/sa-viayes \
    >"$WORKDIR/mvexists.out" 2>"$WORKDIR/mvexists.err"
rc=$?
set -e
[ "$rc" -ne 0 ] \
    || die "p11mv overwrote an existing destination (expected failure)"
grep -qi 'already exists' "$WORKDIR/mvexists.err" \
    || die "p11mv: destination-exists error message missing"

# --- 10. p11mv interactive confirmation (no -y): answer y then n ------------
# Make two disposable secret-key copies, then move them interactively.
"$P11CP" -l "$PKCS11LIB" -y seck/sa-key seck/sa-mvy >/dev/null 2>&1 \
    || die "p11cp (setup for interactive mv) failed"
"$P11CP" -l "$PKCS11LIB" -y seck/sa-key seck/sa-mvn >/dev/null 2>&1 \
    || die "p11cp (setup for interactive mv) failed"
printf 'y\n' | "$P11MV" -l "$PKCS11LIB" seck/sa-mvy seck/sa-mvy-done \
    >/dev/null 2>&1 || die "p11mv (interactive, y) failed"
printf 'n\n' | "$P11MV" -l "$PKCS11LIB" seck/sa-mvn seck/sa-mvn-done \
    >/dev/null 2>&1 || die "p11mv (interactive, n) returned an error"
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null)
echo "$ls_out" | grep -q 'seck/sa-mvy-done' \
    || die "p11mv (interactive, y): the confirmed rename did not happen"
echo "$ls_out" | grep -q 'seck/sa-mvn-done' \
    && die "p11mv (interactive, n): a declined rename happened anyway"

# --- 11. p11setattr interactive confirmation (no -y): answer y then n -------
# Without -y, p11setattr prompts "set attributes on <prefix><label> ? (y/N)"
# and reads the answer with getchar() from stdin (pkcs11_chattr.c). A plain
# pipe drives the interactive branch -- no PTY needed. 'y' applies the change,
# any other answer (here 'n') leaves the object untouched.
"$P11CP" -l "$PKCS11LIB" -y seck/sa-key seck/sa-say >/dev/null 2>&1 \
    || die "p11cp (setup for interactive setattr) failed"
"$P11CP" -l "$PKCS11LIB" -y seck/sa-key seck/sa-san >/dev/null 2>&1 \
    || die "p11cp (setup for interactive setattr) failed"
printf 'y\n' | "$P11SETATTR" -l "$PKCS11LIB" seck/sa-say CKA_LABEL=sa-say-done \
    >/dev/null 2>&1 || die "p11setattr (interactive, y) failed"
printf 'n\n' | "$P11SETATTR" -l "$PKCS11LIB" seck/sa-san CKA_LABEL=sa-san-done \
    >/dev/null 2>&1 || die "p11setattr (interactive, n) returned an error"
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null)
echo "$ls_out" | grep -q 'seck/sa-say-done' \
    || die "p11setattr (interactive, y): the confirmed change was not applied"
echo "$ls_out" | grep -qE 'seck/sa-say[[:space:]]' \
    && die "p11setattr (interactive, y): the old label is still present"
echo "$ls_out" | grep -q 'seck/sa-san-done' \
    && die "p11setattr (interactive, n): a declined change was applied anyway"
echo "$ls_out" | grep -qE 'seck/sa-san[[:space:]]' \
    || die "p11setattr (interactive, n): the object was altered despite declining"

# --- 12. p11setattr interactive over the other object classes ---------------
# One confirmed ('y') change per remaining class exercises the CKO_DATA /
# CKO_PUBLIC_KEY / CKO_PRIVATE_KEY / CKO_CERTIFICATE arms of the prefix switch
# in the interactive branch (pkcs11_chattr.c). data/sa-data2, the pubk/, prvk/
# copies from steps 1 and 8, and the imported cert/sa-cert are disposable here.
printf 'y\n' | "$P11SETATTR" -l "$PKCS11LIB" data/sa-data2 CKA_LABEL=sa-data-final \
    >/dev/null 2>&1 || die "p11setattr (interactive, data) failed"
printf 'y\n' | "$P11SETATTR" -l "$PKCS11LIB" pubk/sa-rsa-pub2 CKA_LABEL=sa-rsa-pub3 \
    >/dev/null 2>&1 || die "p11setattr (interactive, public key) failed"
printf 'y\n' | "$P11SETATTR" -l "$PKCS11LIB" prvk/sa-rsa-prv2 CKA_LABEL=sa-rsa-prv3 \
    >/dev/null 2>&1 || die "p11setattr (interactive, private key) failed"
printf 'y\n' | "$P11SETATTR" -l "$PKCS11LIB" cert/sa-cert CKA_LABEL=sa-cert-final \
    >/dev/null 2>&1 || die "p11setattr (interactive, certificate) failed"
ls_out=$("$P11LS" -l "$PKCS11LIB" 2>/dev/null)
echo "$ls_out" | grep -q 'data/sa-data-final' \
    || die "p11setattr (interactive, data): relabel not applied"
echo "$ls_out" | grep -q 'pubk/sa-rsa-pub3' \
    || die "p11setattr (interactive, public key): relabel not applied"
echo "$ls_out" | grep -q 'prvk/sa-rsa-prv3' \
    || die "p11setattr (interactive, private key): relabel not applied"
echo "$ls_out" | grep -q 'cert/sa-cert-final' \
    || die "p11setattr (interactive, certificate): relabel not applied"

echo "setattr/cp/mv (relabel, set id, copy, move, prefixes, errors, interactive): OK"
