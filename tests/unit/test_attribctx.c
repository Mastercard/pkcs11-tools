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
 * test_attribctx.c: unit tests for the "attribute context" grammar, i.e. the
 * flex/bison parser in lib/attribctx_lexer.l + lib/attribctx_parser.y that
 * turns command-line attribute assignments such as
 *
 *     CKA_LABEL=mykey class=seck token=true CKA_KEY_TYPE=aes
 *     CKA_ID=0xdeadbeef  no sensitive  !extractable
 *     CKA_ALLOWED_MECHANISMS={CKM_RSA_PKCS CKM_AES_CBC}
 *     CKA_WRAP_TEMPLATE={ CKA_ENCRYPT=true CKA_DECRYPT=false }
 *
 * into a CK_ATTRIBUTE array ready for a PKCS#11 call. The parser is pure (no
 * token, no session), so it runs everywhere - Linux, FreeBSD and MinGW64.
 *
 * Public API (include/pkcs11lib.h):
 *   attribCtx *pkcs11_new_attribcontext(void);
 *   func_rc    pkcs11_parse_attribs_from_argv(ctx, pos, argc, argv, additional);
 *   CK_ATTRIBUTE_PTR pkcs11_get_attrlist_from_attribctx(ctx);
 *   size_t           pkcs11_get_attrnum_from_attribctx(ctx);
 *   void       pkcs11_free_attribcontext(ctx);
 *
 * The grammar was measured as the least-covered code in the tree (parser 1.8%,
 * lexer 16.5%), which is what this suite targets.
 */

#include <stdlib.h>
#include <string.h>

#include "pkcs11lib.h"
#include "test_harness.h"

/*
 * Parse a single attribute string into a fresh attribute context. The parser
 * concatenates argv[pos..argc) with spaces, so passing the whole expression as
 * one argv element is equivalent to the shell splitting it into words.
 *
 * Returns the context (caller frees) and stores the parse return code in *rc.
 */
static attribCtx *parse_str(const char *s, func_rc *rc)
{
    attribCtx *ctx = pkcs11_new_attribcontext();
    char *argv[1];
    argv[0] = (char *) s;                 /* the parser never mutates argv */
    func_rc r = pkcs11_parse_attribs_from_argv(ctx, 0, 1, argv, NULL);
    if (rc) {
        *rc = r;
    }
    return ctx;
}

/* Return the first attribute of the requested type, or NULL if absent. */
static CK_ATTRIBUTE_PTR find_attr(attribCtx *ctx, CK_ATTRIBUTE_TYPE type)
{
    CK_ATTRIBUTE_PTR a = pkcs11_get_attrlist_from_attribctx(ctx);
    size_t n = pkcs11_get_attrnum_from_attribctx(ctx);
    size_t i;
    if (a == NULL) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        if (a[i].type == type) {
            return &a[i];
        }
    }
    return NULL;
}

/* --- string / label attributes --------------------------------------- */

static void test_string_label(void)
{
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("CKA_LABEL=\"mykey\"", &rc);

    TH_CHECK(rc == rc_ok, "CKA_LABEL=\"mykey\" parses");
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_LABEL);
    TH_CHECK(a != NULL, "CKA_LABEL attribute is present");
    if (a) {
        TH_CHECK(a->ulValueLen == 5, "CKA_LABEL length is 5");
        TH_CHECK(a->pValue && memcmp(a->pValue, "mykey", 5) == 0,
                 "CKA_LABEL value is 'mykey'");
    }
    pkcs11_free_attribcontext(ctx);
}

static void test_label_shortcut(void)
{
    /* the bare keyword 'label' is an alias for CKA_LABEL */
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("label=\"shortcut\"", &rc);

    TH_CHECK(rc == rc_ok, "label=\"shortcut\" parses");
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_LABEL);
    TH_CHECK(a != NULL, "shortcut resolves to CKA_LABEL");
    if (a) {
        TH_CHECK(a->ulValueLen == 8 && memcmp(a->pValue, "shortcut", 8) == 0,
                 "shortcut value is 'shortcut'");
    }
    pkcs11_free_attribcontext(ctx);
}

static void test_quoted_string(void)
{
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("CKA_LABEL=\"hello world\"", &rc);

    TH_CHECK(rc == rc_ok, "quoted string parses");
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_LABEL);
    TH_CHECK(a != NULL, "quoted CKA_LABEL is present");
    if (a) {
        TH_CHECK(a->ulValueLen == 11 &&
                 memcmp(a->pValue, "hello world", 11) == 0,
                 "quoted value keeps the embedded space");
    }
    pkcs11_free_attribcontext(ctx);
}

static void test_empty_quoted_string(void)
{
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("CKA_LABEL=\"\"", &rc);

    TH_CHECK(rc == rc_ok, "empty quoted string parses");
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_LABEL);
    TH_CHECK(a != NULL, "empty CKA_LABEL is present");
    if (a) {
        TH_CHECK(a->ulValueLen == 0, "empty string has length 0");
    }
    pkcs11_free_attribcontext(ctx);
}

/* --- hex byte strings ------------------------------------------------- */

static void test_id_hex(void)
{
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("CKA_ID=0xdeadbeef", &rc);
    const unsigned char expect[] = { 0xde, 0xad, 0xbe, 0xef };

    TH_CHECK(rc == rc_ok, "CKA_ID=0xdeadbeef parses");
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_ID);
    TH_CHECK(a != NULL, "CKA_ID attribute is present");
    if (a) {
        TH_CHECK(a->ulValueLen == 4, "hex decodes to 4 bytes");
        TH_CHECK(a->pValue && memcmp(a->pValue, expect, 4) == 0,
                 "hex bytes are {de ad be ef}");
    }
    pkcs11_free_attribcontext(ctx);
}

static void test_hex_odd_length_error(void)
{
    /* an odd number of hex digits makes the lexer bail out */
    func_rc rc = rc_ok;
    attribCtx *ctx = parse_str("CKA_ID=0xabc", &rc);

    TH_CHECK(rc != rc_ok, "odd-length hex is rejected");
    pkcs11_free_attribcontext(ctx);
}

/* --- boolean attributes ---------------------------------------------- */

static void test_boolean_true_forms(void)
{
    /* true|CK_TRUE|yes|on|1 all mean CK_TRUE */
    static const char *const forms[] = {
        "CKA_TOKEN=true", "CKA_TOKEN=CK_TRUE", "CKA_TOKEN=yes",
        "CKA_TOKEN=on", "CKA_TOKEN=1"
    };
    size_t i;
    for (i = 0; i < sizeof(forms) / sizeof(forms[0]); i++) {
        func_rc rc = rc_error_other_error;
        attribCtx *ctx = parse_str(forms[i], &rc);
        CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_TOKEN);
        TH_CHECK(rc == rc_ok && a != NULL, "true form parses");
        if (a) {
            TH_CHECK(a->ulValueLen == sizeof(CK_BBOOL) &&
                     *(CK_BBOOL *) a->pValue == CK_TRUE,
                     "true form yields CK_TRUE");
        }
        pkcs11_free_attribcontext(ctx);
    }
}

static void test_boolean_false_forms(void)
{
    /* false|CK_FALSE|off|0 all mean CK_FALSE (note: bare 'no' is negation) */
    static const char *const forms[] = {
        "CKA_TOKEN=false", "CKA_TOKEN=CK_FALSE", "CKA_TOKEN=off",
        "CKA_TOKEN=0"
    };
    size_t i;
    for (i = 0; i < sizeof(forms) / sizeof(forms[0]); i++) {
        func_rc rc = rc_error_other_error;
        attribCtx *ctx = parse_str(forms[i], &rc);
        CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_TOKEN);
        TH_CHECK(rc == rc_ok && a != NULL, "false form parses");
        if (a) {
            TH_CHECK(a->ulValueLen == sizeof(CK_BBOOL) &&
                     *(CK_BBOOL *) a->pValue == CK_FALSE,
                     "false form yields CK_FALSE");
        }
        pkcs11_free_attribcontext(ctx);
    }
}

static void test_boolean_bare_is_true(void)
{
    /* a boolean keyword with no '=value' defaults to CK_TRUE */
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("sensitive", &rc);
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_SENSITIVE);

    TH_CHECK(rc == rc_ok && a != NULL, "bare boolean parses");
    if (a) {
        TH_CHECK(*(CK_BBOOL *) a->pValue == CK_TRUE,
                 "bare 'sensitive' means CK_TRUE");
    }
    pkcs11_free_attribcontext(ctx);
}

static void test_boolean_negation(void)
{
    /* NOT / NO / ! before a boolean keyword mean CK_FALSE */
    struct { const char *expr; CK_ATTRIBUTE_TYPE type; } cases[] = {
        { "no sensitive",  CKA_SENSITIVE   },
        { "!extractable",  CKA_EXTRACTABLE },
        { "NOT token",     CKA_TOKEN       },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        func_rc rc = rc_error_other_error;
        attribCtx *ctx = parse_str(cases[i].expr, &rc);
        CK_ATTRIBUTE_PTR a = find_attr(ctx, cases[i].type);
        TH_CHECK(rc == rc_ok && a != NULL, "negated boolean parses");
        if (a) {
            TH_CHECK(*(CK_BBOOL *) a->pValue == CK_FALSE,
                     "negation yields CK_FALSE");
        }
        pkcs11_free_attribcontext(ctx);
    }
}

/* --- key type -------------------------------------------------------- */

static void test_key_type(void)
{
    struct { const char *expr; CK_KEY_TYPE kt; } cases[] = {
        { "CKA_KEY_TYPE=aes",  CKK_AES            },
        { "key_type=rsa",      CKK_RSA            },
        { "CKA_KEY_TYPE=des3", CKK_DES3           },
        { "CKA_KEY_TYPE=ec",   CKK_EC             },
        { "CKA_KEY_TYPE=generic", CKK_GENERIC_SECRET },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        func_rc rc = rc_error_other_error;
        attribCtx *ctx = parse_str(cases[i].expr, &rc);
        CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_KEY_TYPE);
        TH_CHECK(rc == rc_ok && a != NULL, "key type parses");
        if (a) {
            TH_CHECK(a->ulValueLen == sizeof(CK_KEY_TYPE) &&
                     *(CK_KEY_TYPE *) a->pValue == cases[i].kt,
                     "key type value matches");
        }
        pkcs11_free_attribcontext(ctx);
    }
}

/* --- object class ---------------------------------------------------- */

static void test_object_class(void)
{
    struct { const char *expr; CK_OBJECT_CLASS cls; } cases[] = {
        { "CKA_CLASS=CKO_SECRET_KEY", CKO_SECRET_KEY  },
        { "class=seck",               CKO_SECRET_KEY  },
        { "class=pubk",               CKO_PUBLIC_KEY  },
        { "class=prvk",               CKO_PRIVATE_KEY },
        { "class=cert",               CKO_CERTIFICATE },
        { "class=data",               CKO_DATA        },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        func_rc rc = rc_error_other_error;
        attribCtx *ctx = parse_str(cases[i].expr, &rc);
        CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_CLASS);
        TH_CHECK(rc == rc_ok && a != NULL, "object class parses");
        if (a) {
            TH_CHECK(a->ulValueLen == sizeof(CK_OBJECT_CLASS) &&
                     *(CK_OBJECT_CLASS *) a->pValue == cases[i].cls,
                     "object class value matches");
        }
        pkcs11_free_attribcontext(ctx);
    }
}

/* --- date ------------------------------------------------------------ */

static void test_date(void)
{
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("CKA_START_DATE=20250131", &rc);
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_START_DATE);

    TH_CHECK(rc == rc_ok && a != NULL, "8-digit date parses");
    if (a) {
        TH_CHECK(a->ulValueLen == sizeof(CK_DATE), "date length is sizeof(CK_DATE)");
        TH_CHECK(a->pValue && memcmp(a->pValue, "20250131", 8) == 0,
                 "date bytes are YYYYMMDD");
    }
    pkcs11_free_attribcontext(ctx);
}

/* --- allowed mechanisms list ----------------------------------------- */

static void test_allowed_mechanisms(void)
{
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("CKA_ALLOWED_MECHANISMS={CKM_RSA_PKCS CKM_AES_CBC}", &rc);
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_ALLOWED_MECHANISMS);

    TH_CHECK(rc == rc_ok && a != NULL, "allowed-mechanisms list parses");
    if (a) {
        TH_CHECK(a->ulValueLen == 2 * sizeof(CK_MECHANISM_TYPE),
                 "two mechanisms => two slots");
        if (a->ulValueLen == 2 * sizeof(CK_MECHANISM_TYPE)) {
            CK_MECHANISM_TYPE_PTR m = (CK_MECHANISM_TYPE_PTR) a->pValue;
            TH_CHECK(m[0] == CKM_RSA_PKCS, "first mechanism is CKM_RSA_PKCS");
            TH_CHECK(m[1] == CKM_AES_CBC, "second mechanism is CKM_AES_CBC");
        }
    }
    pkcs11_free_attribcontext(ctx);
}

static void test_unknown_mechanism_error(void)
{
    /* an unknown CKM_ token makes the lexer terminate -> parse error */
    func_rc rc = rc_ok;
    attribCtx *ctx = parse_str("CKA_ALLOWED_MECHANISMS={CKM_NOT_A_REAL_MECH}", &rc);

    TH_CHECK(rc != rc_ok, "unknown mechanism is rejected");
    pkcs11_free_attribcontext(ctx);
}

/* --- one-level template ---------------------------------------------- */

static void test_wrap_template(void)
{
    func_rc rc = rc_error_other_error;
    attribCtx *ctx =
        parse_str("CKA_WRAP_TEMPLATE={ CKA_ENCRYPT=true CKA_DECRYPT=false }", &rc);
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_WRAP_TEMPLATE);

    TH_CHECK(rc == rc_ok, "wrap template parses");
    TH_CHECK(a != NULL, "CKA_WRAP_TEMPLATE is present in the main list");
    if (a) {
        TH_CHECK(a->ulValueLen == 2 * sizeof(CK_ATTRIBUTE),
                 "template holds two nested attributes");
        if (a->pValue && a->ulValueLen == 2 * sizeof(CK_ATTRIBUTE)) {
            CK_ATTRIBUTE_PTR sub = (CK_ATTRIBUTE_PTR) a->pValue;
            CK_ATTRIBUTE_PTR enc = NULL, dec = NULL;
            size_t i;
            for (i = 0; i < 2; i++) {
                if (sub[i].type == CKA_ENCRYPT) { enc = &sub[i]; }
                if (sub[i].type == CKA_DECRYPT) { dec = &sub[i]; }
            }
            TH_CHECK(enc && *(CK_BBOOL *) enc->pValue == CK_TRUE,
                     "nested CKA_ENCRYPT is CK_TRUE");
            TH_CHECK(dec && *(CK_BBOOL *) dec->pValue == CK_FALSE,
                     "nested CKA_DECRYPT is CK_FALSE");
        }
    }
    pkcs11_free_attribcontext(ctx);
}

static void test_nested_template_error(void)
{
    /* a template inside a template is explicitly forbidden by the grammar */
    func_rc rc = rc_ok;
    attribCtx *ctx = parse_str(
        "CKA_WRAP_TEMPLATE={ CKA_UNWRAP_TEMPLATE={ CKA_ENCRYPT=true } }", &rc);

    TH_CHECK(rc != rc_ok, "nested templates are rejected");
    pkcs11_free_attribcontext(ctx);
}

/* --- several attributes at once -------------------------------------- */

static void test_multiple_attributes(void)
{
    /* the shell passes several words; the parser concatenates the argv */
    char *argv[] = { "CKA_LABEL=\"combo\"", "class=seck", "token=true",
                     "CKA_KEY_TYPE=aes" };
    attribCtx *ctx = pkcs11_new_attribcontext();
    func_rc rc = pkcs11_parse_attribs_from_argv(ctx, 0, 4, argv, NULL);

    TH_CHECK(rc == rc_ok, "multi-word attribute line parses");
    TH_CHECK(pkcs11_get_attrnum_from_attribctx(ctx) == 4,
             "four attributes are produced");

    CK_ATTRIBUTE_PTR label = find_attr(ctx, CKA_LABEL);
    CK_ATTRIBUTE_PTR cls   = find_attr(ctx, CKA_CLASS);
    CK_ATTRIBUTE_PTR tok   = find_attr(ctx, CKA_TOKEN);
    CK_ATTRIBUTE_PTR kt    = find_attr(ctx, CKA_KEY_TYPE);

    TH_CHECK(label && label->ulValueLen == 5 &&
             memcmp(label->pValue, "combo", 5) == 0, "label is 'combo'");
    TH_CHECK(cls && *(CK_OBJECT_CLASS *) cls->pValue == CKO_SECRET_KEY,
             "class is secret key");
    TH_CHECK(tok && *(CK_BBOOL *) tok->pValue == CK_TRUE, "token is true");
    TH_CHECK(kt && *(CK_KEY_TYPE *) kt->pValue == CKK_AES, "key type is aes");

    pkcs11_free_attribcontext(ctx);
}

static void test_additional_prefix(void)
{
    /*
     * The 'additional' argument is prepended before argv - the tools use it to
     * force attributes (e.g. an implicit class) ahead of user input.
     */
    char *argv[] = { "token=true" };
    attribCtx *ctx = pkcs11_new_attribcontext();
    func_rc rc = pkcs11_parse_attribs_from_argv(ctx, 0, 1, argv, "class=data");

    TH_CHECK(rc == rc_ok, "additional-prefixed line parses");
    CK_ATTRIBUTE_PTR cls = find_attr(ctx, CKA_CLASS);
    CK_ATTRIBUTE_PTR tok = find_attr(ctx, CKA_TOKEN);
    TH_CHECK(cls && *(CK_OBJECT_CLASS *) cls->pValue == CKO_DATA,
             "additional supplies CKA_CLASS=data");
    TH_CHECK(tok && *(CK_BBOOL *) tok->pValue == CK_TRUE,
             "argv still supplies CKA_TOKEN=true");
    pkcs11_free_attribcontext(ctx);
}

/* --- error paths ----------------------------------------------------- */

static void test_empty_input_error(void)
{
    /* the grammar requires at least one expression */
    char *argv[1];
    argv[0] = (char *) "";
    attribCtx *ctx = pkcs11_new_attribcontext();
    func_rc rc = pkcs11_parse_attribs_from_argv(ctx, 0, 1, argv, NULL);

    TH_CHECK(rc != rc_ok, "empty input is a parse error");
    pkcs11_free_attribcontext(ctx);
}

static void test_garbage_input_error(void)
{
    func_rc rc = rc_ok;
    attribCtx *ctx = parse_str("=====", &rc);

    TH_CHECK(rc != rc_ok, "garbage input is a parse error");
    pkcs11_free_attribcontext(ctx);
}

/* --- exhaustive key types ------------------------------------------- */

static void test_key_type_all(void)
{
    /*
     * Every CKK_ token rule in the lexer, using the canonical CKK_ spelling so
     * each distinct lexer action line is exercised. The value tokens all feed
     * the same CKATTR_KEY ASSIGN KEYTYPE parser rule.
     */
    struct { const char *expr; CK_KEY_TYPE kt; } cases[] = {
        { "CKA_KEY_TYPE=CKK_DES",            CKK_DES            },
        { "CKA_KEY_TYPE=CKK_DES2",           CKK_DES2           },
        { "CKA_KEY_TYPE=CKK_DH",             CKK_DH             },
        { "CKA_KEY_TYPE=CKK_DSA",            CKK_DSA            },
        { "CKA_KEY_TYPE=CKK_EC_EDWARDS",     CKK_EC_EDWARDS     },
        { "CKA_KEY_TYPE=CKK_MD5_HMAC",       CKK_MD5_HMAC       },
        { "CKA_KEY_TYPE=CKK_SHA_1_HMAC",     CKK_SHA_1_HMAC     },
        { "CKA_KEY_TYPE=CKK_RIPEMD128_HMAC", CKK_RIPEMD128_HMAC },
        { "CKA_KEY_TYPE=CKK_SHA224_HMAC",    CKK_SHA224_HMAC    },
        { "CKA_KEY_TYPE=CKK_SHA256_HMAC",    CKK_SHA256_HMAC    },
        { "CKA_KEY_TYPE=CKK_SHA384_HMAC",    CKK_SHA384_HMAC    },
        { "CKA_KEY_TYPE=CKK_SHA512_HMAC",    CKK_SHA512_HMAC    },
        { "CKA_KEY_TYPE=CKK_ML_KEM",         CKK_ML_KEM         },
        { "CKA_KEY_TYPE=CKK_ML_DSA",         CKK_ML_DSA         },
        { "CKA_KEY_TYPE=CKK_SLH_DSA",        CKK_SLH_DSA        },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        func_rc rc = rc_error_other_error;
        attribCtx *ctx = parse_str(cases[i].expr, &rc);
        CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_KEY_TYPE);
        TH_CHECK(rc == rc_ok && a != NULL, "key type parses");
        if (a) {
            TH_CHECK(a->ulValueLen == sizeof(CK_KEY_TYPE) &&
                     *(CK_KEY_TYPE *) a->pValue == cases[i].kt,
                     "key type value matches");
        }
        pkcs11_free_attribcontext(ctx);
    }
}

/* --- remaining object classes --------------------------------------- */

static void test_object_class_all(void)
{
    struct { const char *expr; CK_OBJECT_CLASS cls; } cases[] = {
        { "CKA_CLASS=CKO_HW_FEATURE",        CKO_HW_FEATURE        },
        { "CKA_CLASS=CKO_DOMAIN_PARAMETERS", CKO_DOMAIN_PARAMETERS },
        { "CKA_CLASS=CKO_MECHANISM",         CKO_MECHANISM         },
        { "CKA_CLASS=CKO_OTP_KEY",           CKO_OTP_KEY           },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        func_rc rc = rc_error_other_error;
        attribCtx *ctx = parse_str(cases[i].expr, &rc);
        CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_CLASS);
        TH_CHECK(rc == rc_ok && a != NULL, "object class parses");
        if (a) {
            TH_CHECK(*(CK_OBJECT_CLASS *) a->pValue == cases[i].cls,
                     "object class value matches");
        }
        pkcs11_free_attribcontext(ctx);
    }
}

/* --- other CKATTR_STR attributes (subject, ec_params) ---------------- */

static void test_string_subject(void)
{
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("CKA_SUBJECT=\"CN=test\"", &rc);
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_SUBJECT);

    TH_CHECK(rc == rc_ok && a != NULL, "CKA_SUBJECT parses");
    if (a) {
        TH_CHECK(a->ulValueLen == 7 && memcmp(a->pValue, "CN=test", 7) == 0,
                 "subject string captured");
    }
    pkcs11_free_attribcontext(ctx);
}

static void test_ec_params_hex(void)
{
    /* CKA_EC_PARAMS as a hex DER OID (prime256v1) - the CKATTR_STR hex path */
    func_rc rc = rc_error_other_error;
    const unsigned char expect[] = { 0x06, 0x08, 0x2a, 0x86, 0x48,
                                     0xce, 0x3d, 0x03, 0x01, 0x07 };
    attribCtx *ctx = parse_str("CKA_EC_PARAMS=0x06082a8648ce3d030107", &rc);
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_EC_PARAMS);

    TH_CHECK(rc == rc_ok && a != NULL, "CKA_EC_PARAMS parses");
    if (a) {
        TH_CHECK(a->ulValueLen == sizeof(expect) &&
                 memcmp(a->pValue, expect, sizeof(expect)) == 0,
                 "ec params DER captured from hex");
    }
    pkcs11_free_attribcontext(ctx);
}

/* --- CKA_END_DATE and the date-as-hex-string path -------------------- */

static void test_end_date(void)
{
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("CKA_END_DATE=20261231", &rc);
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_END_DATE);

    TH_CHECK(rc == rc_ok && a != NULL, "CKA_END_DATE parses");
    if (a) {
        TH_CHECK(a->ulValueLen == sizeof(CK_DATE) &&
                 memcmp(a->pValue, "20261231", 8) == 0,
                 "end date bytes are YYYYMMDD");
    }
    pkcs11_free_attribcontext(ctx);
}

static void test_date_as_hex(void)
{
    /*
     * The grammar also accepts a date supplied as a 0x... hex string (the
     * CKATTR_DATE ASSIGN STRING rule). 0x3230323630313031 is the ASCII for
     * "20260101" (8 bytes = sizeof(CK_DATE)).
     */
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str("CKA_START_DATE=0x3230323630313031", &rc);
    CK_ATTRIBUTE_PTR a = find_attr(ctx, CKA_START_DATE);

    TH_CHECK(rc == rc_ok && a != NULL, "hex-encoded date parses");
    if (a) {
        TH_CHECK(a->ulValueLen == sizeof(CK_DATE) &&
                 memcmp(a->pValue, "20260101", 8) == 0,
                 "hex date decodes to YYYYMMDD");
    }
    pkcs11_free_attribcontext(ctx);
}

/* --- every boolean attribute keyword --------------------------------- */

static void test_boolean_attributes_all(void)
{
    /* one test per remaining CKA_ boolean lexer rule (set to true) */
    struct { const char *expr; CK_ATTRIBUTE_TYPE type; } cases[] = {
        { "CKA_ENCRYPT=true",           CKA_ENCRYPT           },
        { "CKA_DECRYPT=true",           CKA_DECRYPT           },
        { "CKA_WRAP=true",              CKA_WRAP              },
        { "CKA_UNWRAP=true",            CKA_UNWRAP            },
        { "CKA_SIGN=true",              CKA_SIGN             },
        { "CKA_SIGN_RECOVER=true",      CKA_SIGN_RECOVER      },
        { "CKA_VERIFY=true",            CKA_VERIFY           },
        { "CKA_VERIFY_RECOVER=true",    CKA_VERIFY_RECOVER    },
        { "CKA_DERIVE=true",            CKA_DERIVE           },
        { "CKA_PRIVATE=true",           CKA_PRIVATE          },
        { "CKA_MODIFIABLE=true",        CKA_MODIFIABLE        },
        { "CKA_COPYABLE=true",          CKA_COPYABLE          },
        { "CKA_TRUSTED=true",           CKA_TRUSTED          },
        { "CKA_WRAP_WITH_TRUSTED=true", CKA_WRAP_WITH_TRUSTED },
        { "CKA_ENCAPSULATE=true",       CKA_ENCAPSULATE       },
        { "CKA_DECAPSULATE=true",       CKA_DECAPSULATE       },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        func_rc rc = rc_error_other_error;
        attribCtx *ctx = parse_str(cases[i].expr, &rc);
        CK_ATTRIBUTE_PTR a = find_attr(ctx, cases[i].type);
        TH_CHECK(rc == rc_ok && a != NULL, "boolean attribute parses");
        if (a) {
            TH_CHECK(*(CK_BBOOL *) a->pValue == CK_TRUE,
                     "boolean attribute is CK_TRUE");
        }
        pkcs11_free_attribcontext(ctx);
    }
}

/* --- all five template kinds, and the too-many-templates guard ------- */

static void test_all_template_kinds(void)
{
    /* the five distinct CKATTR_TEMPLATE tokens, each with one nested attr */
    func_rc rc = rc_error_other_error;
    attribCtx *ctx = parse_str(
        "CKA_WRAP_TEMPLATE={ CKA_ENCRYPT=true } "
        "CKA_UNWRAP_TEMPLATE={ CKA_DECRYPT=true } "
        "CKA_DERIVE_TEMPLATE={ CKA_DERIVE=true } "
        "CKA_ENCAPSULATE_TEMPLATE={ CKA_ENCAPSULATE=true } "
        "CKA_DECAPSULATE_TEMPLATE={ CKA_DECAPSULATE=true }",
        &rc);

    TH_CHECK(rc == rc_ok, "five distinct templates parse");
    TH_CHECK(find_attr(ctx, CKA_WRAP_TEMPLATE) != NULL, "wrap template present");
    TH_CHECK(find_attr(ctx, CKA_UNWRAP_TEMPLATE) != NULL, "unwrap template present");
    TH_CHECK(find_attr(ctx, CKA_DERIVE_TEMPLATE) != NULL, "derive template present");
    TH_CHECK(find_attr(ctx, CKA_ENCAPSULATE_TEMPLATE) != NULL,
             "encapsulate template present");
    TH_CHECK(find_attr(ctx, CKA_DECAPSULATE_TEMPLATE) != NULL,
             "decapsulate template present");
    pkcs11_free_attribcontext(ctx);
}

static void test_too_many_templates_error(void)
{
    /* the grammar allows at most 5 templates; a sixth must be rejected */
    func_rc rc = rc_ok;
    attribCtx *ctx = parse_str(
        "CKA_WRAP_TEMPLATE={ CKA_ENCRYPT=true } "
        "CKA_UNWRAP_TEMPLATE={ CKA_DECRYPT=true } "
        "CKA_DERIVE_TEMPLATE={ CKA_DERIVE=true } "
        "CKA_ENCAPSULATE_TEMPLATE={ CKA_ENCAPSULATE=true } "
        "CKA_DECAPSULATE_TEMPLATE={ CKA_DECAPSULATE=true } "
        "CKA_WRAP_TEMPLATE={ CKA_SIGN=true }",
        &rc);

    TH_CHECK(rc != rc_ok, "a sixth template is rejected");
    pkcs11_free_attribcontext(ctx);
}

/* --- unterminated quoted string error -------------------------------- */

static void test_unterminated_string_error(void)
{
    /* opening quote with no closing quote hits the <STR><<EOF>> lexer rule */
    func_rc rc = rc_ok;
    attribCtx *ctx = parse_str("CKA_LABEL=\"never closed", &rc);

    TH_CHECK(rc != rc_ok, "unterminated quoted string is rejected");
    pkcs11_free_attribcontext(ctx);

    /*
     * The <STR><<EOF>> rule ends the scan without returning to the INITIAL
     * start condition, leaving the shared (non-reentrant) lexer stuck in STR.
     * This is harmless in the real tools (one parse per process) but would
     * corrupt the next parse in this test binary. Feed a lone closing quote:
     * in the STR state it matches the end-quote rule, which runs BEGIN(INITIAL)
     * and restores the lexer for the following tests.
     */
    {
        func_rc rrc = rc_ok;
        attribCtx *rctx = parse_str("\"", &rrc);
        pkcs11_free_attribcontext(rctx);
    }
}

int main(void)
{
    TH_RUN(test_string_label);
    TH_RUN(test_label_shortcut);
    TH_RUN(test_quoted_string);
    TH_RUN(test_empty_quoted_string);
    TH_RUN(test_id_hex);
    TH_RUN(test_hex_odd_length_error);
    TH_RUN(test_boolean_true_forms);
    TH_RUN(test_boolean_false_forms);
    TH_RUN(test_boolean_bare_is_true);
    TH_RUN(test_boolean_negation);
    TH_RUN(test_key_type);
    TH_RUN(test_key_type_all);
    TH_RUN(test_object_class);
    TH_RUN(test_object_class_all);
    TH_RUN(test_string_subject);
    TH_RUN(test_ec_params_hex);
    TH_RUN(test_date);
    TH_RUN(test_end_date);
    TH_RUN(test_date_as_hex);
    TH_RUN(test_allowed_mechanisms);
    TH_RUN(test_unknown_mechanism_error);
    TH_RUN(test_boolean_attributes_all);
    TH_RUN(test_wrap_template);
    TH_RUN(test_all_template_kinds);
    TH_RUN(test_too_many_templates_error);
    TH_RUN(test_nested_template_error);
    TH_RUN(test_unterminated_string_error);
    TH_RUN(test_multiple_attributes);
    TH_RUN(test_additional_prefix);
    TH_RUN(test_empty_input_error);
    TH_RUN(test_garbage_input_error);
    return TH_SUMMARY();
}
