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

# Integration test: object filter / "URL" parsing (pkcs11_template.c). The CLI
# tools accept filters of the form TYPE[/ATTRIBUTE]/VALUE; this drives the
# parse_object_class / parse_attribute_type / parse_attribute_value paths that
# the other tests hit only via the implicit "label" form:
#
#   - TYPE/label/VALUE  : explicit short attribute name
#   - TYPE/id/{hex}     : hexadecimal value between curly braces
#   - TYPE/CKA_NAME/VAL : full PKCS#11 attribute name
#   - TYPE alone        : whole-class filter
#   - invalid path      : the "invalid path to object" error branch

set -eu

# shellcheck source=/dev/null
. "${PKCS11_TESTS_COMMON:?PKCS11_TESTS_COMMON must be set by the test harness}"

KEYGEN=$(p11bin p11keygen)
P11LS=$(p11bin p11ls)
P11OD=$(p11bin p11od)
P11SETATTR=$(p11bin p11setattr)

"$KEYGEN" -l "$PKCS11LIB" -k aes -b 256 -i flt-key \
    encrypt=true >/dev/null 2>&1 || die "p11keygen (AES) failed"

# Give the key a known CKA_ID so the id/{hex} filter has something to match.
"$P11SETATTR" -l "$PKCS11LIB" -y seck/flt-key 'CKA_ID={cafe}' >/dev/null 2>&1 \
    || die "p11setattr (CKA_ID) failed"

# --- whole-class filter -----------------------------------------------------
"$P11LS" -l "$PKCS11LIB" seck 2>/dev/null | grep -q 'flt-key' \
    || die "type-only filter 'seck' did not list the key"

# --- explicit short attribute name (label) ----------------------------------
"$P11LS" -l "$PKCS11LIB" seck/label/flt-key 2>/dev/null | grep -q 'flt-key' \
    || die "filter 'seck/label/flt-key' did not match"

# --- hexadecimal value filter -----------------------------------------------
"$P11LS" -l "$PKCS11LIB" 'seck/id/{cafe}' 2>/dev/null | grep -q 'flt-key' \
    || die "filter 'seck/id/{cafe}' did not match"

# --- full CKA_ attribute name -----------------------------------------------
"$P11OD" -l "$PKCS11LIB" 'seck/CKA_LABEL/flt-key' 2>/dev/null \
    | grep -q 'CKA_CLASS' \
    || die "filter 'seck/CKA_LABEL/flt-key' did not dump the object"

# --- malformed filter -> the invalid-path error branch ----------------------
"$P11LS" -l "$PKCS11LIB" 'nosuchtype/x' 2>&1 \
    | grep -q 'invalid path to object' \
    || die "malformed filter did not report an invalid path"

# --- extended "+" filter: additional-attribute discrimination ---------------
# A second object sharing the same CKA_ID but with a different capability lets
# us prove that the extra "+CKA_.../{..}" attribute actually narrows the search
# (pkcs11_make_idtemplate_with_extra_attributes / parse_attributes).
"$KEYGEN" -l "$PKCS11LIB" -k generic -b 160 -i flt-key2 \
    sign=true >/dev/null 2>&1 || die "p11keygen (generic) failed"
"$P11SETATTR" -l "$PKCS11LIB" -y seck/flt-key2 'CKA_ID={cafe}' >/dev/null 2>&1 \
    || die "p11setattr (CKA_ID on flt-key2) failed"

# both objects share id/{cafe}; flt-key is a substring of flt-key2, so match
# the full "seck/<label>" path followed by whitespace to disambiguate.
both=$("$P11LS" -l "$PKCS11LIB" 'seck/id/{cafe}' 2>/dev/null)
printf '%s\n' "$both" | grep -Eq 'seck/flt-key[[:space:]]' \
    || die "plain id filter did not list flt-key"
printf '%s\n' "$both" | grep -Eq 'seck/flt-key2[[:space:]]' \
    || die "plain id filter did not list flt-key2"

# id/{cafe}+CKA_ENCRYPT/{01} must match ONLY the encrypting AES key
enc=$("$P11LS" -l "$PKCS11LIB" 'seck/id/{cafe}+CKA_ENCRYPT/{01}' 2>/dev/null)
printf '%s\n' "$enc" | grep -Eq 'seck/flt-key[[:space:]]' \
    || die "extended +CKA_ENCRYPT filter did not match the AES key"
if printf '%s\n' "$enc" | grep -Eq 'seck/flt-key2[[:space:]]'; then
    die "extended +CKA_ENCRYPT filter wrongly matched the signing key"
fi

# id/{cafe}+CKA_SIGN/{01} must match ONLY the signing generic key
sig=$("$P11LS" -l "$PKCS11LIB" 'seck/id/{cafe}+CKA_SIGN/{01}' 2>/dev/null)
printf '%s\n' "$sig" | grep -Eq 'seck/flt-key2[[:space:]]' \
    || die "extended +CKA_SIGN filter did not match the generic key"
if printf '%s\n' "$sig" | grep -Eq 'seck/flt-key[[:space:]]'; then
    die "extended +CKA_SIGN filter wrongly matched the AES key"
fi

echo "object filter parsing (pkcs11_template.c): OK"
