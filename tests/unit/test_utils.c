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
 * test_utils.c: unit tests for the pure (token-independent) helpers exposed by
 * pkcs11lib.h. These need no PKCS#11 token and therefore run everywhere.
 */

#include <stdlib.h>
#include <string.h>

#include "pkcs11lib.h"
#include "test_harness.h"

/*
 * These three helpers are defined (non-static) in pkcs11_utils.c, but their
 * prototypes are commented out in pkcs11lib.h. Declare them here so we can
 * exercise them directly.
 */
extern char *   print_keyClass(CK_ULONG keyClass);
extern char *   print_keyType(CK_ULONG keyType);
extern CK_ULONG get_object_class(char *arg);

/* hex2bin_new(): even number of hex digits -> exact byte string. */
static void test_hex2bin_even(void)
{
    size_t outlen = 0;
    char *bin = hex2bin_new("48656C6C6F", 10, &outlen); /* "Hello" */

    TH_CHECK(bin != NULL, "hex2bin_new returned NULL");
    TH_CHECK(outlen == 5, "expected 5 output bytes");
    TH_CHECK(bin != NULL && memcmp(bin, "Hello", 5) == 0, "decoded content mismatch");

    hex2bin_free(bin);
}

/* hex2bin_new(): odd number of digits is left-padded with a leading zero. */
static void test_hex2bin_odd(void)
{
    size_t outlen = 0;
    char *bin = hex2bin_new("F", 1, &outlen); /* -> 0x0F */

    TH_CHECK(bin != NULL, "hex2bin_new returned NULL");
    TH_CHECK(outlen == 1, "expected 1 output byte");
    TH_CHECK(bin != NULL && (unsigned char)bin[0] == 0x0F, "expected 0x0F");

    hex2bin_free(bin);
}

/* hex2bin_new(): non-hex "decoration" characters are ignored. */
static void test_hex2bin_decorated(void)
{
    char in[] = "{ 48 65 }"; /* "He", with braces and spaces as decorations */
    size_t outlen = 0;
    char *bin = hex2bin_new(in, strlen(in), &outlen);

    TH_CHECK(bin != NULL, "hex2bin_new returned NULL");
    TH_CHECK(outlen == 2, "expected 2 output bytes");
    TH_CHECK(bin != NULL && memcmp(bin, "He", 2) == 0, "decoded content mismatch");

    hex2bin_free(bin);
}

/* get_attribute_type(): name (with or without CKA_ prefix, any case) -> type. */
static void test_get_attribute_type(void)
{
    TH_CHECK(get_attribute_type("CKA_SIGN") == CKA_SIGN, "CKA_SIGN resolves");
    TH_CHECK(get_attribute_type("sign") == CKA_SIGN, "lowercase, no-prefix resolves");
    TH_CHECK(get_attribute_type("LABEL") == CKA_LABEL, "LABEL resolves");
    TH_CHECK(get_attribute_type("not-an-attribute") == (CK_ATTRIBUTE_TYPE)0xFFFFFFFF,
             "unknown name -> 0xFFFFFFFF");
}

/* pkcs11_get_attribute_type_from_name(): bsearch over the generated table. */
static void test_attr_from_name(void)
{
    TH_CHECK(pkcs11_get_attribute_type_from_name("CKA_CLASS") == CKA_CLASS,
             "CKA_CLASS resolves via table");
    TH_CHECK(pkcs11_get_attribute_type_from_name("CKA_DOES_NOT_EXIST")
             == (CK_ATTRIBUTE_TYPE)0xFFFFFFFF,
             "unknown name -> 0xFFFFFFFF");
}

/* label_or_id(): a CKA_LABEL value is copied verbatim and NUL-terminated. */
static void test_label_or_id_label(void)
{
    char buf[64];
    CK_BYTE labelval[] = "mylabel";
    CK_ATTRIBUTE label = { CKA_LABEL, labelval, 7 }; /* len excludes the NUL */

    char *out = label_or_id(&label, NULL, buf, (int)sizeof(buf));

    TH_CHECK(out == buf, "label_or_id returns its buffer");
    TH_CHECK(strcmp(buf, "mylabel") == 0, "label copied verbatim");
}

/* label_or_id(): with no label, a CKA_ID is rendered as id/{hex}. */
static void test_label_or_id_id(void)
{
    char buf[64];
    CK_BYTE idval[] = { 0xAB, 0xCD };
    CK_ATTRIBUTE id = { CKA_ID, idval, sizeof(idval) };

    char *out = label_or_id(NULL, &id, buf, (int)sizeof(buf));

    TH_CHECK(out == buf, "label_or_id returns its buffer");
    TH_CHECK(strcmp(buf, "id/{abcd}") == 0, "id rendered as id/{hex}");
}

/* label_or_id(): neither label nor id -> the unlabelled-object placeholder. */
static void test_label_or_id_none(void)
{
    char buf[64];

    label_or_id(NULL, NULL, buf, (int)sizeof(buf));

    TH_CHECK(strstr(buf, "unlabelled") != NULL,
             "empty label/id -> unlabelled placeholder");
}

/* pkcs11_ll_basename(): returns the trailing path component (or the input). */
static void test_basename(void)
{
    char p1[] = "/usr/lib/softhsm/libsofthsm2.so";
    char p2[] = "libp11.so";
    char p3[] = "/trailing/";

    TH_CHECK(strcmp(pkcs11_ll_basename(p1), "libsofthsm2.so") == 0,
             "basename of full path");
    TH_CHECK(strcmp(pkcs11_ll_basename(p2), "libp11.so") == 0,
             "basename of bare name is itself");
    TH_CHECK(strcmp(pkcs11_ll_basename(p3), "") == 0,
             "basename of trailing slash is empty");
}

/* print_keyClass(): each known CKO_* value maps to its spelled-out name, and
 * an unknown class returns NULL (the switch has no default). */
static void test_print_keyclass(void)
{
    TH_CHECK(strcmp(print_keyClass(CKO_DATA), "CKO_DATA") == 0, "CKO_DATA");
    TH_CHECK(strcmp(print_keyClass(CKO_CERTIFICATE), "CKO_CERTIFICATE") == 0,
             "CKO_CERTIFICATE");
    TH_CHECK(strcmp(print_keyClass(CKO_PUBLIC_KEY), "CKO_PUBLIC_KEY") == 0,
             "CKO_PUBLIC_KEY");
    TH_CHECK(strcmp(print_keyClass(CKO_PRIVATE_KEY), "CKO_PRIVATE_KEY") == 0,
             "CKO_PRIVATE_KEY");
    TH_CHECK(strcmp(print_keyClass(CKO_SECRET_KEY), "CKO_SECRET_KEY") == 0,
             "CKO_SECRET_KEY");
    TH_CHECK(strcmp(print_keyClass(CKO_HW_FEATURE), "CKO_HW_FEATURE") == 0,
             "CKO_HW_FEATURE");
    TH_CHECK(strcmp(print_keyClass(CKO_DOMAIN_PARAMETERS),
                    "CKO_DOMAIN_PARAMETERS") == 0, "CKO_DOMAIN_PARAMETERS");
    TH_CHECK(strcmp(print_keyClass(CKO_MECHANISM), "CKO_MECHANISM") == 0,
             "CKO_MECHANISM");
    TH_CHECK(print_keyClass((CK_ULONG)0xdeadbeef) == NULL,
             "unknown class -> NULL");
}

/* print_keyType(): known CKK_* values map to their names; anything else falls
 * back to the CKK_VENDOR_DEFINED default. */
static void test_print_keytype(void)
{
    TH_CHECK(strcmp(print_keyType(CKK_AES), "CKK_AES") == 0, "CKK_AES");
    TH_CHECK(strcmp(print_keyType(CKK_DES), "CKK_DES") == 0, "CKK_DES");
    TH_CHECK(strcmp(print_keyType(CKK_DES3), "CKK_DES3") == 0, "CKK_DES3");
    TH_CHECK(strcmp(print_keyType(CKK_RSA), "CKK_RSA") == 0, "CKK_RSA");
    TH_CHECK(strcmp(print_keyType(CKK_GENERIC_SECRET),
                    "CKK_GENERIC_SECRET") == 0, "CKK_GENERIC_SECRET");
    TH_CHECK(strcmp(print_keyType(CKK_EC), "CKK_VENDOR_DEFINED") == 0,
             "unmapped type -> vendor default");
}

/* get_object_class(): case-insensitive CKO_* name -> value, unknown -> 0. */
static void test_get_object_class(void)
{
    TH_CHECK(get_object_class("CKO_CERTIFICATE") == CKO_CERTIFICATE, "cert");
    TH_CHECK(get_object_class("cko_public_key") == CKO_PUBLIC_KEY,
             "pubkey (case-insensitive)");
    TH_CHECK(get_object_class("CKO_PRIVATE_KEY") == CKO_PRIVATE_KEY, "privkey");
    TH_CHECK(get_object_class("CKO_SECRET_KEY") == CKO_SECRET_KEY, "seckey");
    TH_CHECK(get_object_class("not-a-class") == 0, "unknown -> 0");
}

/* get_attribute_for_type_and_value(): boolean attrs accept true/false spellings,
 * CKA_ID/CKA_LABEL build string/hex attributes, and unsupported inputs yield
 * NULL. */
static void test_attr_for_value(void)
{
    CK_ATTRIBUTE_PTR a;

    a = get_attribute_for_type_and_value(CKA_SIGN, "true");
    TH_CHECK(a != NULL && a->type == CKA_SIGN
             && a->ulValueLen == sizeof(CK_BBOOL)
             && *(CK_BBOOL *)a->pValue == CK_TRUE, "bool true");
    release_attribute(a);

    a = get_attribute_for_type_and_value(CKA_DECRYPT, "no");
    TH_CHECK(a != NULL && *(CK_BBOOL *)a->pValue == CK_FALSE, "bool no -> false");
    release_attribute(a);

    a = get_attribute_for_type_and_value(CKA_WRAP, "1");
    TH_CHECK(a != NULL && *(CK_BBOOL *)a->pValue == CK_TRUE, "bool 1 -> true");
    release_attribute(a);

    a = get_attribute_for_type_and_value(CKA_VERIFY, "maybe");
    TH_CHECK(a == NULL, "invalid boolean value -> NULL");

    a = get_attribute_for_type_and_value(CKA_LABEL, "mylabel");
    TH_CHECK(a != NULL && a->type == CKA_LABEL
             && a->ulValueLen == strlen("mylabel")
             && memcmp(a->pValue, "mylabel", 7) == 0, "label string");
    release_attribute(a);

    a = get_attribute_for_type_and_value(CKA_ID, "{deadbeef}");
    TH_CHECK(a != NULL && a->type == CKA_ID && a->ulValueLen == 4,
             "braced hex id -> 4 raw bytes");
    release_attribute(a);

    a = get_attribute_for_type_and_value(CKA_VALUE, "x");
    TH_CHECK(a == NULL, "unsupported attribute type -> NULL");
}

/* get_attributes_from_argv(): parse "attr=value" / "attr:value" tokens into a
 * heap array. Note it rewrites argv in place (strtok), so use mutable buffers. */
static void test_attributes_from_argv(void)
{
    char a0[] = "CKA_SIGN=true";
    char a1[] = "label:myobj";
    char *argv[] = { a0, a1 };
    CK_ATTRIBUTE *attrs = NULL;
    int n = get_attributes_from_argv(&attrs, 0, 2, argv);

    TH_CHECK(n == 2, "parsed two attribute/value pairs");
    TH_CHECK(attrs != NULL, "attribute array allocated");
    if (attrs != NULL) {
        TH_CHECK(attrs[0].type == CKA_SIGN, "first attribute is CKA_SIGN");
        TH_CHECK(attrs[1].type == CKA_LABEL, "second attribute is CKA_LABEL");
        release_attributes(attrs, 2); /* also frees the array itself */
    }
}

int main(void)
{
    TH_RUN(test_hex2bin_even);
    TH_RUN(test_hex2bin_odd);
    TH_RUN(test_hex2bin_decorated);
    TH_RUN(test_get_attribute_type);
    TH_RUN(test_attr_from_name);
    TH_RUN(test_label_or_id_label);
    TH_RUN(test_label_or_id_id);
    TH_RUN(test_label_or_id_none);
    TH_RUN(test_basename);
    TH_RUN(test_print_keyclass);
    TH_RUN(test_print_keytype);
    TH_RUN(test_get_object_class);
    TH_RUN(test_attr_for_value);
    TH_RUN(test_attributes_from_argv);

    return TH_SUMMARY();
}
