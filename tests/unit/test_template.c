/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2025 Mastercard
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * test_template.c: unit tests for the object-filter / "search template" parser
 * in pkcs11_template.c. These functions turn a textual filter such as
 *
 *     seck/id/{cafe}                 (single filter)
 *     cert/sn/1234+CKA_ENCRYPT/{01}  (extended filter, '+'-concatenated)
 *
 * into a pkcs11IdTemplate ready for a C_FindObjects search. The parser is pure
 * (no PKCS#11 session required), so it runs everywhere - Linux, FreeBSD and
 * MinGW64 - without a token.
 *
 * pkcs11_create_id() dispatches on the presence of a '+':
 *   - no '+'  -> pkcs11_make_idtemplate()                  (regex-based)
 *   - a '+'   -> pkcs11_make_idtemplate_with_extra_attributes()
 */

#include <stdlib.h>
#include <string.h>

#include "pkcs11lib.h"
#include "test_harness.h"

/*
 * Return the first populated attribute of the requested type in the template,
 * or NULL if none is present. Unused template slots have a NULL pValue; the
 * object-class slot carries CKA_CLASS, so searching for any other type never
 * collides with it.
 */
static CK_ATTRIBUTE *find_attr(pkcs11IdTemplate *t, CK_ATTRIBUTE_TYPE type)
{
    int i;
    if (t == NULL || t->template == NULL) {
        return NULL;
    }
    for (i = 0; i < IDTMPL_TEMPLATE_SIZE; i++) {
        if (t->template[i].pValue != NULL && t->template[i].type == type) {
            return &t->template[i];
        }
    }
    return NULL;
}

/* Convenience: does the template hold an attribute of this type/value? */
static int has_attr_value(pkcs11IdTemplate *t, CK_ATTRIBUTE_TYPE type,
                          const void *val, size_t len)
{
    CK_ATTRIBUTE *a = find_attr(t, type);
    return a != NULL && a->ulValueLen == len && memcmp(a->pValue, val, len) == 0;
}

/* --- single-filter path: bare label defaults to CKA_LABEL, no class -------- */
static void test_single_bare_label(void)
{
    pkcs11IdTemplate *t = pkcs11_create_id("mylabel");

    TH_CHECK(t != NULL, "bare label parses");
    if (t) {
        TH_CHECK(t->has_resource == CK_TRUE, "resource present");
        TH_CHECK(t->has_class == CK_FALSE, "no class for bare label");
        TH_CHECK(pkcs11_sizeof_idtemplate(t) == 1, "template length is 1");
        TH_CHECK(has_attr_value(t, CKA_LABEL, "mylabel", 7),
                 "label value verbatim");
        pkcs11_delete_idtemplate(t);
    }
}

/* --- single-filter path: class and straight label name -------- */
static void test_single_class_label(void)
{
    pkcs11IdTemplate *t = pkcs11_create_id("seck/foo");
    TH_CHECK(t != NULL, "seck/foo parses");
    if (t) {
        TH_CHECK(t->has_class == CK_TRUE, "class present");
        TH_CHECK(t->oclass == CKO_SECRET_KEY, "class is secret key");
        TH_CHECK(pkcs11_sizeof_idtemplate(t) == 2, "template length is 2");
        TH_CHECK(has_attr_value(t, CKA_LABEL, "foo", 3), "label value is foo");
        pkcs11_delete_idtemplate(t);
    }
}

/* --- single-filter path: class/label, all possible classes -------- */
static void test_single_class_label_all(void)
{
    struct { const char *url; CK_OBJECT_CLASS cls; } cases[] = {
        { "pubk/foo", CKO_PUBLIC_KEY },
        { "prvk/foo", CKO_PRIVATE_KEY },
        { "seck/foo", CKO_SECRET_KEY },
        { "cert/foo", CKO_CERTIFICATE },
        { "data/foo", CKO_DATA },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pkcs11IdTemplate *t = pkcs11_create_id((char *)cases[i].url);
        TH_CHECK(t != NULL && t->has_class == CK_TRUE
                 && t->oclass == cases[i].cls, cases[i].url);
        if (t) {
            TH_CHECK(has_attr_value(t, CKA_LABEL, "foo", 3), "label value is foo");
            pkcs11_delete_idtemplate(t);
        }
    }
}

/* --- single-filter path: class/attr/value with a short 'label' name -------- */
static void test_single_class_label_value(void)
{
    pkcs11IdTemplate *t = pkcs11_create_id("seck/label/foo");

    TH_CHECK(t != NULL, "seck/label/foo parses");
    if (t) {
        TH_CHECK(t->has_class == CK_TRUE, "class present");
        TH_CHECK(t->oclass == CKO_SECRET_KEY, "class is secret key");
        TH_CHECK(pkcs11_sizeof_idtemplate(t) == 2, "template length is 2");
        TH_CHECK(has_attr_value(t, CKA_LABEL, "foo", 3), "label value is foo");
        pkcs11_delete_idtemplate(t);
    }
}

/* --- single-filter path: hexadecimal id in curly braces -------------------- */
static void test_single_hex_id(void)
{
    pkcs11IdTemplate *t = pkcs11_create_id("id/{cafe}");
    CK_BYTE expect[] = { 0xca, 0xfe };

    TH_CHECK(t != NULL, "id/{cafe} parses");
    if (t) {
        TH_CHECK(t->has_class == CK_FALSE, "no class");
        TH_CHECK(has_attr_value(t, CKA_ID, expect, sizeof(expect)),
                 "id decoded from hex");
        pkcs11_delete_idtemplate(t);
    }
}

/* --- single-filter path: 'sn' short name -> CKA_SERIAL_NUMBER -------------- */
static void test_single_serial(void)
{
    pkcs11IdTemplate *t = pkcs11_create_id("cert/sn/1234");

    TH_CHECK(t != NULL, "cert/sn/1234 parses");
    if (t) {
        TH_CHECK(t->oclass == CKO_CERTIFICATE, "class is certificate");
        TH_CHECK(has_attr_value(t, CKA_SERIAL_NUMBER, "1234", 4),
                 "serial number value");
        pkcs11_delete_idtemplate(t);
    }
}

/* --- single-filter path: full CKA_ attribute name -------------------------- */
static void test_single_full_attrname(void)
{
    pkcs11IdTemplate *t = pkcs11_create_id("data/CKA_VALUE/{deadbeef}");
    CK_BYTE expect[] = { 0xde, 0xad, 0xbe, 0xef };

    TH_CHECK(t != NULL, "data/CKA_VALUE/{deadbeef} parses");
    if (t) {
        TH_CHECK(t->oclass == CKO_DATA, "class is data");
        TH_CHECK(has_attr_value(t, CKA_VALUE, expect, sizeof(expect)),
                 "CKA_VALUE decoded from hex");
        pkcs11_delete_idtemplate(t);
    }
}

/* --- single-filter path: every class prefix maps to its CKO_* value -------- */
static void test_single_all_classes(void)
{
    struct { const char *url; CK_OBJECT_CLASS cls; } cases[] = {
        { "pubk/x", CKO_PUBLIC_KEY },
        { "prvk/x", CKO_PRIVATE_KEY },
        { "seck/x", CKO_SECRET_KEY },
        { "cert/x", CKO_CERTIFICATE },
        { "data/x", CKO_DATA },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pkcs11IdTemplate *t = pkcs11_create_id((char *)cases[i].url);
        TH_CHECK(t != NULL && t->has_class == CK_TRUE
                 && t->oclass == cases[i].cls, cases[i].url);
        if (t) {
            pkcs11_delete_idtemplate(t);
        }
    }
}

/* --- single-filter path: the CKA_CLASS/{hex} whole-class shortcut ----------
 * p11ls builds these strings (CLASS_SECK etc.) to list a whole object class. */
static void test_single_class_shortcut(void)
{
    pkcs11IdTemplate *t = pkcs11_create_id(CLASS_SECK);
    CK_BYTE expect[] = { 0x04, 0, 0, 0, 0, 0, 0, 0 };

    TH_CHECK(t != NULL, "CLASS_SECK parses");
    if (t) {
        TH_CHECK(has_attr_value(t, CKA_CLASS, expect, sizeof(expect)),
                 "CKA_CLASS carries the secret-key class bytes");
        pkcs11_delete_idtemplate(t);
    }
}

/* --- single-filter path: malformed inputs are rejected --------------------- */
static void test_single_errors(void)
{
    /* too many '/' segments: does not match the filter regex */
    TH_CHECK(pkcs11_create_id("foo/bar/baz/qux") == NULL,
             "over-segmented filter rejected");
    /* a syntactically valid but unknown CKA_ attribute name */
    TH_CHECK(pkcs11_create_id("cert/CKA_NOSUCH/{01}") == NULL,
             "unknown CKA_ attribute rejected");
    /* NULL input is rejected up front */
    TH_CHECK(pkcs11_create_id(NULL) == NULL, "NULL url rejected");
}

/* --- extended path: class + concatenated additional attributes ------------
 * Regression test for the '+' template parser (previously produced garbage /
 * matched nothing). Every attribute must appear with the right type/value. */
static void test_extended_two_attrs(void)
{
    pkcs11IdTemplate *t = pkcs11_create_id("cert/CKA_ID/{01}+CKA_ENCRYPT/{01}");
    CK_BYTE one[] = { 0x01 };

    TH_CHECK(t != NULL, "extended cert/CKA_ID/{01}+CKA_ENCRYPT/{01} parses");
    if (t) {
        TH_CHECK(t->has_class == CK_TRUE && t->oclass == CKO_CERTIFICATE,
                 "class is certificate");
        TH_CHECK(has_attr_value(t, CKA_ID, one, 1),
                 "first attribute CKA_ID = 0x01");
        TH_CHECK(has_attr_value(t, CKA_ENCRYPT, one, 1),
                 "additional attribute CKA_ENCRYPT = 0x01");
        pkcs11_delete_idtemplate(t);
    }
}

/* --- extended path: leading label plus two boolean attributes -------------- */
static void test_extended_label_plus_bools(void)
{
    pkcs11IdTemplate *t =
        pkcs11_create_id("seck/label/foo+CKA_ENCRYPT/{01}+CKA_DECRYPT/{01}");
    CK_BYTE one[] = { 0x01 };

    TH_CHECK(t != NULL, "extended label + two bools parses");
    if (t) {
        TH_CHECK(t->oclass == CKO_SECRET_KEY, "class is secret key");
        TH_CHECK(has_attr_value(t, CKA_LABEL, "foo", 3), "label value is foo");
        TH_CHECK(has_attr_value(t, CKA_ENCRYPT, one, 1), "CKA_ENCRYPT present");
        TH_CHECK(has_attr_value(t, CKA_DECRYPT, one, 1), "CKA_DECRYPT present");
        pkcs11_delete_idtemplate(t);
    }
}

int main(void)
{
    TH_RUN(test_single_bare_label);
    TH_RUN(test_single_class_label);
    TH_RUN(test_single_class_label_all);
    TH_RUN(test_single_class_label_value);
    TH_RUN(test_single_hex_id);
    TH_RUN(test_single_serial);
    TH_RUN(test_single_full_attrname);
    TH_RUN(test_single_all_classes);
    TH_RUN(test_single_class_shortcut);
    TH_RUN(test_single_errors);
    TH_RUN(test_extended_two_attrs);
    TH_RUN(test_extended_label_plus_bools);

    return TH_SUMMARY();
}
