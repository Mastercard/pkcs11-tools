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
 * test_wrappedkey.c: unit tests for the "wrapping job" grammar, i.e. the
 * flex/bison parser in lib/wrappedkey_lexer.l + lib/wrappedkey_parser.y that
 * turns the p11wrap "-W" argument into a wrappedKeyCtx. p11wrap prefixes the
 * argument with '@' and passes it to pkcs11_prepare_wrappingctx(), e.g.
 *
 *     @wrappingkey="kek",algorithm=pkcs1,filename="out.wrapped"
 *     @algorithm=oaep(hash=CKM_SHA256,mgf=CKG_MGF1_SHA256,label="lbl")
 *     @algorithm=cbcpad(iv=0x0011223344556677)
 *     @algorithm=rfc5649(flavour=CKM_AES_KEY_WRAP_PAD)
 *     @algorithm=envelope(inner=cbcpad,outer=oaep)
 *
 * The parse is pure - it only fills a context, no token or session is needed -
 * so it runs everywhere: Linux, FreeBSD and MinGW64.
 *
 * pkcs11_new_wrappedkeycontext() requires a non-NULL pkcs11Context, but only
 * stores the pointer (it is dereferenced later, during the actual wrap). A
 * zeroed pkcs11Context is therefore enough to exercise the grammar.
 *
 * The wrapping method for a lone (non-envelope) job is stored at
 * key[WRAPPEDKEYCTX_LONE_KEY_INDEX].wrapping_meth; envelope jobs populate both
 * OUTER and INNER slots.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pkcs11lib.h"
#include "test_harness.h"

/* Allocate a zeroed pkcs11Context good enough to hold a wrapping context. */
static pkcs11Context *dummy_p11ctx(void)
{
    return (pkcs11Context *) calloc(1, sizeof(pkcs11Context));
}

/*
 * Parse a wrapping-job body (WITHOUT the leading '@', which we add here) into a
 * fresh wrappedKeyCtx. Returns the context (caller frees) and stores the parse
 * return code in *rc.
 */
static wrappedKeyCtx *parse_job(pkcs11Context *p11, const char *body, func_rc *rc)
{
    wrappedKeyCtx *wctx = pkcs11_new_wrappedkeycontext(p11);
    char *job = malloc(strlen(body) + 2);
    func_rc r;

    job[0] = '@';
    memcpy(job + 1, body, strlen(body) + 1);
    r = pkcs11_prepare_wrappingctx(wctx, job);
    free(job);
    if (rc) {
        *rc = r;
    }
    return wctx;
}

static enum wrappingmethod lone_meth(wrappedKeyCtx *wctx)
{
    return wctx->key[WRAPPEDKEYCTX_LONE_KEY_INDEX].wrapping_meth;
}

/* --- full wrapped-key FILE parsing ----------------------------------- */
/*
 * The other half of the grammar - pkcs11_new_wrapped_key_from_file() - parses a
 * complete ".wrapped" file (headers + attribute statements + PEM blocks + an
 * optional public-key section). This drives the wkeyset/headers/metastmts/
 * assignstmts/pubk productions and the OUTERKEYPEM/INNERKEYPEM/PUBKPEM lexer
 * states that the "@" wrapping-job tests never reach. The parse only fills the
 * context (the base64 blocks are decoded but never crypto-verified), so this is
 * still a token-free, portable unit test.
 */

#define WK_FIXTURE_PATH "test_wrappedkey_fixture.tmp"

static int write_fixture(const char *content)
{
    FILE *f = fopen(WK_FIXTURE_PATH, "wb");
    if (f == NULL) {
        return -1;
    }
    fwrite(content, 1, strlen(content), f);
    fclose(f);
    return 0;
}

/* Write CONTENT to a scratch file, parse it, remove the file, return the ctx
 * (NULL on any parse error). */
static wrappedKeyCtx *parse_file(pkcs11Context *p11, const char *content)
{
    wrappedKeyCtx *wctx;
    if (write_fixture(content) != 0) {
        return NULL;
    }
    wctx = pkcs11_new_wrapped_key_from_file(p11, (char *) WK_FIXTURE_PATH);
    remove(WK_FIXTURE_PATH);
    return wctx;
}

/*
 * The <PEM><<EOF>> lexer rules end the scan without returning to the INITIAL
 * start condition, leaving the shared (non-reentrant) lexer stuck in a PEM
 * state. Harmless in the real tools (one parse per process) but it would
 * corrupt the next parse here. Feed a lone END marker so the END-marker rule
 * runs BEGIN(INITIAL) and restores the lexer.
 */
static void wk_recover_pem_state(pkcs11Context *p11)
{
    wrappedKeyCtx *w = parse_file(p11, "-----END WRAPPED KEY-----\n");
    if (w) {
        pkcs11_free_wrappedkeycontext(w);
    }
}

static void test_file_simple_wkey(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = parse_file(p11,
        "Content-Type: application/pkcs11-tools\n"
        "Grammar-Version: 2.3\n"
        "Wrapping-Key: \"kek\"\n"
        "Wrapping-Algorithm: oaep\n"
        "CKA_CLASS: CKO_SECRET_KEY\n"
        "CKA_KEY_TYPE: CKK_AES\n"
        "CKA_LABEL: \"target\"\n"
        "CKA_ID: 0xa1b2\n"
        "CKA_TOKEN: true\n"
        "CKA_ENCRYPT: true\n"
        "-----BEGIN WRAPPED KEY-----\n"
        "QUJDREVGR0hJSktMTU5PUA==\n"
        "-----END WRAPPED KEY-----\n");

    TH_CHECK(wctx != NULL, "a complete wrapped-key file parses");
    if (wctx) {
        TH_CHECK(lone_meth(wctx) == w_pkcs1_oaep, "algorithm captured as oaep");
        TH_CHECK(wctx->is_envelope == CK_FALSE, "single block is not an envelope");
        TH_CHECK(wctx->wrappingkeylabel != NULL &&
                 strcmp(wctx->wrappingkeylabel, "kek") == 0,
                 "Wrapping-Key label captured");
        TH_CHECK(wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrapped_key_buffer != NULL &&
                 wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrapped_key_len > 0,
                 "wrapped-key cryptogram decoded");
        pkcs11_free_wrappedkeycontext(wctx);
    }
    free(p11);
}

static void test_file_envelope(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = parse_file(p11,
        "Content-Type: application/pkcs11-tools\n"
        "Grammar-Version: 2.3\n"
        "Wrapping-Key: \"kek\"\n"
        "Wrapping-Algorithm: envelope(inner=rfc3394,outer=oaep)\n"
        "CKA_CLASS: CKO_SECRET_KEY\n"
        "CKA_KEY_TYPE: CKK_AES\n"
        "CKA_LABEL: \"target\"\n"
        "-----BEGIN OUTER WRAPPED KEY-----\n"
        "T1VURVJDUllQVE8=\n"
        "-----END OUTER WRAPPED KEY-----\n"
        "-----BEGIN INNER WRAPPED KEY-----\n"
        "SU5ORVJDUllQVE8=\n"
        "-----END INNER WRAPPED KEY-----\n");

    TH_CHECK(wctx != NULL, "an envelope wrapped-key file parses");
    if (wctx) {
        TH_CHECK(wctx->is_envelope == CK_TRUE, "envelope flag set");
        TH_CHECK(wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrapping_meth == w_pkcs1_oaep,
                 "outer method is oaep");
        TH_CHECK(wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrapping_meth == w_rfc3394,
                 "inner method is rfc3394");
        TH_CHECK(wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrapped_key_buffer != NULL,
                 "outer cryptogram decoded");
        TH_CHECK(wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrapped_key_buffer != NULL,
                 "inner cryptogram decoded");
        pkcs11_free_wrappedkeycontext(wctx);
    }
    free(p11);
}

static void test_file_privkey_with_pubk(void)
{
    /* wrapping a private key appends a PUBLIC KEY section (the pubk production) */
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = parse_file(p11,
        "Content-Type: application/pkcs11-tools\n"
        "Grammar-Version: 2.3\n"
        "Wrapping-Key: \"kek\"\n"
        "Wrapping-Algorithm: rfc5649\n"
        "CKA_CLASS: CKO_PRIVATE_KEY\n"
        "CKA_KEY_TYPE: CKK_RSA\n"
        "CKA_LABEL: \"privtarget\"\n"
        "-----BEGIN WRAPPED KEY-----\n"
        "UFJJVkFURUtFWUJZVEVT\n"
        "-----END WRAPPED KEY-----\n"
        "CKA_CLASS: CKO_PUBLIC_KEY\n"
        "CKA_KEY_TYPE: CKK_RSA\n"
        "CKA_LABEL: \"privtarget\"\n"
        "-----BEGIN PUBLIC KEY-----\n"
        "UFVCTElDS0VZQllURVM=\n"
        "-----END PUBLIC KEY-----\n");

    TH_CHECK(wctx != NULL, "a wrapped private key with public key parses");
    if (wctx) {
        TH_CHECK(lone_meth(wctx) == w_rfc5649, "algorithm captured as rfc5649");
        TH_CHECK(wctx->pubk_buffer != NULL && wctx->pubk_len > 0,
                 "public-key block decoded");
        pkcs11_free_wrappedkeycontext(wctx);
    }
    free(p11);
}

static void test_file_all_attr_kinds(void)
{
    /*
     * Exercise every assignstmt value kind in the wkey block: boolean, string,
     * hex, object class, key type, an 8-digit date, a hex-encoded date, a
     * nested template and an allowed-mechanisms list.
     */
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = parse_file(p11,
        "Content-Type: application/pkcs11-tools\n"
        "Grammar-Version: 2.3\n"
        "Wrapping-Key: \"kek\"\n"
        "Wrapping-Algorithm: rfc3394\n"
        "CKA_CLASS: CKO_SECRET_KEY\n"
        "CKA_KEY_TYPE: CKK_AES\n"
        "CKA_LABEL: \"allattrs\"\n"
        "CKA_ID: 0xdeadbeef\n"
        "CKA_TOKEN: true\n"
        "CKA_ENCRYPT: true\n"
        "CKA_START_DATE: 20260101\n"
        "CKA_END_DATE: 0x3230323631323331\n"
        "CKA_WRAP_TEMPLATE: { CKA_ENCRYPT: true CKA_DECRYPT: false }\n"
        "CKA_ALLOWED_MECHANISMS: { CKM_AES_CBC CKM_AES_ECB }\n"
        "-----BEGIN WRAPPED KEY-----\n"
        "QUxMQVRUUklCVVRFUw==\n"
        "-----END WRAPPED KEY-----\n");

    TH_CHECK(wctx != NULL, "a wkey block with all attribute kinds parses");
    if (wctx) {
        TH_CHECK(lone_meth(wctx) == w_rfc3394, "algorithm captured as rfc3394");
        pkcs11_free_wrappedkeycontext(wctx);
    }
    free(p11);
}

static void test_file_wkey_all_templates(void)
{
    /*
     * A wkey block may carry up to five nested templates. all_attr_kinds
     * already exercises CKA_WRAP_TEMPLATE; here we drive the remaining four
     * (unwrap/derive/encapsulate/decapsulate) so every arm of the
     * _wrappedkey_parser_assign_list_to_template switch is covered.
     */
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = parse_file(p11,
        "Content-Type: application/pkcs11-tools\n"
        "Grammar-Version: 2.3\n"
        "Wrapping-Key: \"kek\"\n"
        "Wrapping-Algorithm: rfc3394\n"
        "CKA_CLASS: CKO_SECRET_KEY\n"
        "CKA_KEY_TYPE: CKK_AES\n"
        "CKA_LABEL: \"templates\"\n"
        "CKA_UNWRAP_TEMPLATE: { CKA_DECRYPT: true }\n"
        "CKA_DERIVE_TEMPLATE: { CKA_DERIVE: true }\n"
        "CKA_ENCAPSULATE_TEMPLATE: { CKA_ENCAPSULATE: true }\n"
        "CKA_DECAPSULATE_TEMPLATE: { CKA_DECAPSULATE: true }\n"
        "-----BEGIN WRAPPED KEY-----\n"
        "VEVNUExBVEVT\n"
        "-----END WRAPPED KEY-----\n");

    TH_CHECK(wctx != NULL, "a wkey block with four nested templates parses");
    if (wctx) {
        TH_CHECK(lone_meth(wctx) == w_rfc3394, "algorithm captured as rfc3394");
        pkcs11_free_wrappedkeycontext(wctx);
    }
    free(p11);
}

static void test_file_pubk_template(void)
{
    /*
     * A template inside the PUBLIC KEY (pubk) section drives the target_pubk
     * arm of the template-assignment helper (a different attribCtx than the
     * wkey block).
     */
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = parse_file(p11,
        "Content-Type: application/pkcs11-tools\n"
        "Grammar-Version: 2.3\n"
        "Wrapping-Key: \"kek\"\n"
        "Wrapping-Algorithm: rfc5649\n"
        "CKA_CLASS: CKO_PRIVATE_KEY\n"
        "CKA_KEY_TYPE: CKK_RSA\n"
        "CKA_LABEL: \"pubktmpl\"\n"
        "-----BEGIN WRAPPED KEY-----\n"
        "UFJJVkFURUtFWQ==\n"
        "-----END WRAPPED KEY-----\n"
        "CKA_CLASS: CKO_PUBLIC_KEY\n"
        "CKA_KEY_TYPE: CKK_RSA\n"
        "CKA_LABEL: \"pubktmpl\"\n"
        "CKA_WRAP_TEMPLATE: { CKA_ENCRYPT: true }\n"
        "-----BEGIN PUBLIC KEY-----\n"
        "UFVCTElDS0VZ\n"
        "-----END PUBLIC KEY-----\n");

    TH_CHECK(wctx != NULL, "a template in the pubk block parses");
    if (wctx) {
        TH_CHECK(wctx->pubk_buffer != NULL && wctx->pubk_len > 0,
                 "public-key block decoded alongside its template");
        pkcs11_free_wrappedkeycontext(wctx);
    }
    free(p11);
}

static void test_file_comments_and_version_header(void)
{
    /*
     * Comment lines (^#) must be skipped, and here the FIRST real line is
     * Grammar-Version, which drives the headers GRAMMAR_VERSION production
     * (the simple/envelope fixtures lead with Content-Type instead).
     */
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = parse_file(p11,
        "# a comment line\n"
        "Grammar-Version: 2.3\n"
        "# another comment\n"
        "Content-Type: application/pkcs11-tools\n"
        "Wrapping-Key: \"kek\"\n"
        "Wrapping-Algorithm: pkcs1\n"
        "CKA_CLASS: CKO_SECRET_KEY\n"
        "CKA_KEY_TYPE: CKK_AES\n"
        "CKA_LABEL: \"commented\"\n"
        "# comment before the block\n"
        "-----BEGIN WRAPPED KEY-----\n"
        "Q09NTUVOVEVE\n"
        "-----END WRAPPED KEY-----\n"
        "# trailing comment\n");

    TH_CHECK(wctx != NULL, "comments and a version header parse");
    if (wctx) {
        TH_CHECK(lone_meth(wctx) == w_pkcs1_15, "algorithm captured as pkcs1");
        pkcs11_free_wrappedkeycontext(wctx);
    }
    free(p11);
}

static void test_file_grammar_version_too_high_error(void)
{
    /* a grammar version beyond SUPPORTED_GRAMMAR_VERSION must be rejected */
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = parse_file(p11,
        "Content-Type: application/pkcs11-tools\n"
        "Grammar-Version: 99.0\n"
        "Wrapping-Key: \"kek\"\n"
        "Wrapping-Algorithm: pkcs1\n"
        "CKA_CLASS: CKO_SECRET_KEY\n"
        "CKA_KEY_TYPE: CKK_AES\n"
        "CKA_LABEL: \"toonew\"\n"
        "-----BEGIN WRAPPED KEY-----\n"
        "VE9PTkVX\n"
        "-----END WRAPPED KEY-----\n");

    TH_CHECK(wctx == NULL, "an unsupported grammar version is rejected");
    if (wctx) {
        pkcs11_free_wrappedkeycontext(wctx);
    }
    free(p11);
}

static void test_file_missing_error(void)
{
    /* a non-existent filename must fail cleanly (returns NULL) */
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx =
        pkcs11_new_wrapped_key_from_file(p11, (char *) "no_such_wrapped_file.xyz");

    TH_CHECK(wctx == NULL, "a missing file is rejected");
    if (wctx) {
        pkcs11_free_wrappedkeycontext(wctx);
    }
    free(p11);
}

static void test_file_incomplete_pem_error(void)
{
    /* a PEM block with no END marker hits the <PEM><<EOF>> lexer rule */
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = parse_file(p11,
        "Content-Type: application/pkcs11-tools\n"
        "Grammar-Version: 2.3\n"
        "Wrapping-Key: \"kek\"\n"
        "Wrapping-Algorithm: pkcs1\n"
        "CKA_CLASS: CKO_SECRET_KEY\n"
        "CKA_KEY_TYPE: CKK_AES\n"
        "CKA_LABEL: \"incomplete\"\n"
        "-----BEGIN WRAPPED KEY-----\n"
        "SU5DT01QTEVURQ==\n");

    TH_CHECK(wctx == NULL, "an incomplete PEM block is rejected");
    if (wctx) {
        pkcs11_free_wrappedkeycontext(wctx);
    }
    /* the aborted PEM scan left the lexer in a PEM state - restore it */
    wk_recover_pem_state(p11);
    free(p11);
}

/* --- plain algorithms ------------------------------------------------- */

static void test_algo_pkcs1(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=pkcs1", &rc);

    TH_CHECK(rc == rc_ok, "algorithm=pkcs1 parses");
    TH_CHECK(lone_meth(wctx) == w_pkcs1_15, "method is w_pkcs1_15");
    TH_CHECK(wctx->is_envelope == CK_FALSE, "pkcs1 is not an envelope");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_algo_rfc3394(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=rfc3394", &rc);

    TH_CHECK(rc == rc_ok, "algorithm=rfc3394 parses");
    TH_CHECK(lone_meth(wctx) == w_rfc3394, "method is w_rfc3394");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_algo_rfc5649(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=rfc5649", &rc);

    TH_CHECK(rc == rc_ok, "algorithm=rfc5649 parses");
    TH_CHECK(lone_meth(wctx) == w_rfc5649, "method is w_rfc5649");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_algo_cbcpad(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=cbcpad", &rc);

    TH_CHECK(rc == rc_ok, "algorithm=cbcpad parses");
    TH_CHECK(lone_meth(wctx) == w_cbcpad, "method is w_cbcpad");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_algo_versioned(void)
{
    /* the grammar accepts an optional /version suffix after the algorithm id */
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=pkcs1/1.0", &rc);

    TH_CHECK(rc == rc_ok, "versioned algorithm parses");
    TH_CHECK(lone_meth(wctx) == w_pkcs1_15, "versioned pkcs1 is w_pkcs1_15");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

/* --- OAEP with default and explicit parameters ----------------------- */

static void test_oaep_defaults(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=oaep", &rc);

    TH_CHECK(rc == rc_ok, "algorithm=oaep parses");
    TH_CHECK(lone_meth(wctx) == w_pkcs1_oaep, "method is w_pkcs1_oaep");
    /* the helper installs SHA-1 defaults for a bare oaep */
    TH_CHECK(wctx->oaep_params != NULL, "oaep_params allocated");
    if (wctx->oaep_params) {
        TH_CHECK(wctx->oaep_params->hashAlg == CKM_SHA_1,
                 "default OAEP hash is SHA-1");
        TH_CHECK(wctx->oaep_params->mgf == CKG_MGF1_SHA1,
                 "default OAEP mgf is MGF1-SHA1");
    }
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_oaep_explicit_params(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(
        p11, "algorithm=oaep(hash=CKM_SHA256,mgf=CKG_MGF1_SHA256,label=\"lbl\")",
        &rc);

    TH_CHECK(rc == rc_ok, "OAEP with explicit params parses");
    TH_CHECK(lone_meth(wctx) == w_pkcs1_oaep, "method is w_pkcs1_oaep");
    if (wctx->oaep_params) {
        TH_CHECK(wctx->oaep_params->hashAlg == CKM_SHA256,
                 "OAEP hash overridden to SHA-256");
        TH_CHECK(wctx->oaep_params->mgf == CKG_MGF1_SHA256,
                 "OAEP mgf overridden to MGF1-SHA256");
        TH_CHECK(wctx->oaep_params->ulSourceDataLen == 3 &&
                 wctx->oaep_params->pSourceData != NULL &&
                 memcmp(wctx->oaep_params->pSourceData, "lbl", 3) == 0,
                 "OAEP label captured");
    }
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_oaep_bad_hash_error(void)
{
    /* MD5 is not an accepted OAEP hash -> helper rejects it -> parse error */
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_ok;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=oaep(hash=CKM_MD5)", &rc);

    TH_CHECK(rc != rc_ok, "unsupported OAEP hash is rejected");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

/* --- CBCPAD IV parameter --------------------------------------------- */

static void test_cbcpad_iv(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    const unsigned char expect[] = { 0x00, 0x11, 0x22, 0x33,
                                     0x44, 0x55, 0x66, 0x77 };
    wrappedKeyCtx *wctx =
        parse_job(p11, "algorithm=cbcpad(iv=0x0011223344556677)", &rc);

    TH_CHECK(rc == rc_ok, "cbcpad with iv parses");
    TH_CHECK(lone_meth(wctx) == w_cbcpad, "method is w_cbcpad");
    TH_CHECK(wctx->aes_params.iv_len == 8, "iv length is 8");
    TH_CHECK(wctx->aes_params.iv != NULL &&
             memcmp(wctx->aes_params.iv, expect, 8) == 0,
             "iv bytes captured from hex");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

/* --- RFC5649 flavour ------------------------------------------------- */

static void test_rfc5649_flavour(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx =
        parse_job(p11, "algorithm=rfc5649(flavour=CKM_AES_KEY_WRAP_PAD)", &rc);

    TH_CHECK(rc == rc_ok, "rfc5649 with flavour parses");
    TH_CHECK(lone_meth(wctx) == w_rfc5649, "method is w_rfc5649");
    TH_CHECK(wctx->aes_params.aes_wrapping_mech == CKM_AES_KEY_WRAP_PAD,
             "flavour recorded as the wrapping mechanism");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

/* --- envelope wrapping ----------------------------------------------- */

static void test_envelope_defaults(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=envelope", &rc);

    TH_CHECK(rc == rc_ok, "algorithm=envelope parses");
    TH_CHECK(wctx->is_envelope == CK_TRUE, "envelope flag set");
    TH_CHECK(wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrapping_meth == w_pkcs1_oaep,
             "default outer method is OAEP");
    TH_CHECK(wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrapping_meth == w_cbcpad,
             "default inner method is cbcpad");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_envelope_explicit(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx =
        parse_job(p11, "algorithm=envelope(inner=rfc5649,outer=pkcs1)", &rc);

    TH_CHECK(rc == rc_ok, "explicit envelope parses");
    TH_CHECK(wctx->is_envelope == CK_TRUE, "envelope flag set");
    TH_CHECK(wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrapping_meth == w_pkcs1_15,
             "outer method overridden to pkcs1");
    TH_CHECK(wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrapping_meth == w_rfc5649,
             "inner method overridden to rfc5649");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_envelope_nested_error(void)
{
    /* envelope() may not be nested inside envelope() */
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_ok;
    wrappedKeyCtx *wctx =
        parse_job(p11, "algorithm=envelope(inner=envelope)", &rc);

    TH_CHECK(rc != rc_ok, "nested envelope is rejected");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

/* --- wrapping key label and filename --------------------------------- */

static void test_wrappingkey_and_filename(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(
        p11, "wrappingkey=\"my-kek\",algorithm=pkcs1,filename=\"out.wrapped\"",
        &rc);

    TH_CHECK(rc == rc_ok, "full wrapping job parses");
    TH_CHECK(lone_meth(wctx) == w_pkcs1_15, "algorithm captured");
    TH_CHECK(wctx->wrappingkeylabel != NULL &&
             strcmp(wctx->wrappingkeylabel, "my-kek") == 0,
             "wrapping key label captured");
    TH_CHECK(wctx->filename != NULL &&
             strcmp(wctx->filename, "out.wrapped") == 0,
             "filename captured");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_wrappingkey_twice_error(void)
{
    /* the wrapping key label may be specified only once */
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_ok;
    wrappedKeyCtx *wctx =
        parse_job(p11, "wrappingkey=\"a\",wrappingkey=\"b\",algorithm=pkcs1", &rc);

    TH_CHECK(rc != rc_ok, "duplicate wrapping key is rejected");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

/* --- error paths ----------------------------------------------------- */

static void test_missing_header_error(void)
{
    /* without the leading '@' the string is not a wrapping job */
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = pkcs11_new_wrappedkeycontext(p11);
    func_rc rc = pkcs11_prepare_wrappingctx(wctx, "algorithm=pkcs1");

    TH_CHECK(rc != rc_ok, "missing '@' header is a parse error");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_unknown_algorithm_error(void)
{
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_ok;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=nosuchalgo", &rc);

    TH_CHECK(rc != rc_ok, "unknown algorithm is rejected");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_null_arguments(void)
{
    /* defensive: NULL wrapping job / NULL context must not crash */
    pkcs11Context *p11 = dummy_p11ctx();
    wrappedKeyCtx *wctx = pkcs11_new_wrappedkeycontext(p11);

    TH_CHECK(pkcs11_prepare_wrappingctx(wctx, NULL) != rc_ok,
             "NULL wrapping job is rejected");
    TH_CHECK(pkcs11_prepare_wrappingctx(NULL, "@algorithm=pkcs1") != rc_ok,
             "NULL context is rejected");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

/* --- more wrapping-job algorithm forms ------------------------------- */

static void test_job_rfc3394_empty_parens(void)
{
    /* rfc3394 accepts an empty parameter list: rfc3394() */
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=rfc3394()", &rc);

    TH_CHECK(rc == rc_ok, "rfc3394() parses");
    TH_CHECK(lone_meth(wctx) == w_rfc3394, "method is w_rfc3394");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_job_versioned_algorithms(void)
{
    /* every algorithm id accepts an optional /version suffix */
    struct { const char *body; enum wrappingmethod meth; CK_BBOOL env; } cases[] = {
        { "algorithm=oaep/1.0",     w_pkcs1_oaep, CK_FALSE },
        { "algorithm=cbcpad/2.0",   w_cbcpad,     CK_FALSE },
        { "algorithm=rfc3394/1.0",  w_rfc3394,    CK_FALSE },
        { "algorithm=rfc5649/1.0",  w_rfc5649,    CK_FALSE },
        { "algorithm=envelope/1.0", w_pkcs1_oaep, CK_TRUE  },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pkcs11Context *p11 = dummy_p11ctx();
        func_rc rc = rc_error_other_error;
        wrappedKeyCtx *wctx = parse_job(p11, cases[i].body, &rc);
        TH_CHECK(rc == rc_ok, "versioned algorithm parses");
        if (cases[i].env) {
            TH_CHECK(wctx->is_envelope == CK_TRUE, "versioned envelope flagged");
        } else {
            TH_CHECK(lone_meth(wctx) == cases[i].meth, "versioned method matches");
        }
        pkcs11_free_wrappedkeycontext(wctx);
        free(p11);
    }
}

/* --- OAEP MGF variants, nss flavour, and rich envelope params -------- */

static void test_job_oaep_all_mgf(void)
{
    /* every MGFTYPE token, driven through the oaep mgf= parameter */
    struct { const char *body; CK_RSA_PKCS_MGF_TYPE mgf; } cases[] = {
        { "algorithm=oaep(hash=CKM_SHA224,mgf=CKG_MGF1_SHA224)", CKG_MGF1_SHA224 },
        { "algorithm=oaep(hash=CKM_SHA384,mgf=CKG_MGF1_SHA384)", CKG_MGF1_SHA384 },
        { "algorithm=oaep(hash=CKM_SHA512,mgf=CKG_MGF1_SHA512)", CKG_MGF1_SHA512 },
        { "algorithm=oaep(mgf=CKG_MGF1_SHA1)",                   CKG_MGF1_SHA1   },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pkcs11Context *p11 = dummy_p11ctx();
        func_rc rc = rc_error_other_error;
        wrappedKeyCtx *wctx = parse_job(p11, cases[i].body, &rc);
        TH_CHECK(rc == rc_ok, "oaep with mgf parses");
        if (wctx->oaep_params) {
            TH_CHECK(wctx->oaep_params->mgf == cases[i].mgf, "mgf recorded");
        }
        pkcs11_free_wrappedkeycontext(wctx);
        free(p11);
    }
}

static void test_job_rfc5649_nss_flavour(void)
{
    /* the 'nss' token maps to CKM_NSS_AES_KEY_WRAP_PAD as the rfc5649 flavour */
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(p11, "algorithm=rfc5649(flavour=nss)", &rc);

    TH_CHECK(rc == rc_ok, "rfc5649(flavour=nss) parses");
    TH_CHECK(lone_meth(wctx) == w_rfc5649, "method is w_rfc5649");
    TH_CHECK(wctx->aes_params.aes_wrapping_mech == CKM_NSS_AES_KEY_WRAP_PAD,
             "nss flavour recorded as the NSS wrap mechanism");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_job_envelope_explicit_params(void)
{
    /*
     * envelope() with fully-parameterised inner and outer algorithms - this
     * drives the parameter productions (iv, hash, mgf, label) inside the
     * envelope context, exercising envelope_keyindex assignment for both slots.
     */
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(
        p11,
        "algorithm=envelope("
        "inner=cbcpad(iv=0x0011223344556677),"
        "outer=oaep(hash=CKM_SHA256,mgf=CKG_MGF1_SHA256,label=\"lbl\"))",
        &rc);

    TH_CHECK(rc == rc_ok, "envelope with explicit inner/outer params parses");
    TH_CHECK(wctx->is_envelope == CK_TRUE, "envelope flag set");
    TH_CHECK(wctx->key[WRAPPEDKEYCTX_OUTER_KEY_INDEX].wrapping_meth == w_pkcs1_oaep,
             "outer is oaep");
    TH_CHECK(wctx->key[WRAPPEDKEYCTX_INNER_KEY_INDEX].wrapping_meth == w_cbcpad,
             "inner is cbcpad");
    TH_CHECK(wctx->aes_params.iv_len == 8, "inner cbcpad iv captured");
    if (wctx->oaep_params) {
        TH_CHECK(wctx->oaep_params->hashAlg == CKM_SHA256, "outer oaep hash captured");
    }
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_job_wrappingkey_via_at(void)
{
    /* the P_FILENAME + P_WRAPPINGKEY wrpjobstmt productions with algorithm */
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_error_other_error;
    wrappedKeyCtx *wctx = parse_job(
        p11, "algorithm=oaep,wrappingkey=\"kek2\",filename=\"o.wrapped\"", &rc);

    TH_CHECK(rc == rc_ok, "reordered wrapping-job statements parse");
    TH_CHECK(wctx->wrappingkeylabel != NULL &&
             strcmp(wctx->wrappingkeylabel, "kek2") == 0, "wrapping key captured");
    TH_CHECK(wctx->filename != NULL && strcmp(wctx->filename, "o.wrapped") == 0,
             "filename captured");
    pkcs11_free_wrappedkeycontext(wctx);
    free(p11);
}

static void test_job_unterminated_string_error(void)
{
    /* an unterminated quoted value hits the <STR><<EOF>> lexer rule */
    pkcs11Context *p11 = dummy_p11ctx();
    func_rc rc = rc_ok;
    wrappedKeyCtx *wctx = parse_job(p11, "wrappingkey=\"never closed", &rc);

    TH_CHECK(rc != rc_ok, "unterminated wrapping-key string is rejected");
    pkcs11_free_wrappedkeycontext(wctx);

    /*
     * As with the attribute lexer, <STR><<EOF>> ends the scan without returning
     * to INITIAL. Feed a lone closing quote so the STR end-quote rule runs
     * BEGIN(INITIAL) and restores the shared lexer for the following tests.
     */
    {
        func_rc rrc = rc_ok;
        wrappedKeyCtx *rctx = parse_job(p11, "\"", &rrc);
        pkcs11_free_wrappedkeycontext(rctx);
    }
    free(p11);
}

int main(void)
{
    TH_RUN(test_algo_pkcs1);
    TH_RUN(test_algo_rfc3394);
    TH_RUN(test_algo_rfc5649);
    TH_RUN(test_algo_cbcpad);
    TH_RUN(test_algo_versioned);
    TH_RUN(test_oaep_defaults);
    TH_RUN(test_oaep_explicit_params);
    TH_RUN(test_oaep_bad_hash_error);
    TH_RUN(test_cbcpad_iv);
    TH_RUN(test_rfc5649_flavour);
    TH_RUN(test_envelope_defaults);
    TH_RUN(test_envelope_explicit);
    TH_RUN(test_envelope_nested_error);
    TH_RUN(test_wrappingkey_and_filename);
    TH_RUN(test_wrappingkey_twice_error);
    TH_RUN(test_missing_header_error);
    TH_RUN(test_unknown_algorithm_error);
    TH_RUN(test_null_arguments);
    TH_RUN(test_job_rfc3394_empty_parens);
    TH_RUN(test_job_versioned_algorithms);
    TH_RUN(test_job_oaep_all_mgf);
    TH_RUN(test_job_rfc5649_nss_flavour);
    TH_RUN(test_job_envelope_explicit_params);
    TH_RUN(test_job_wrappingkey_via_at);
    TH_RUN(test_job_unterminated_string_error);
    TH_RUN(test_file_simple_wkey);
    TH_RUN(test_file_envelope);
    TH_RUN(test_file_privkey_with_pubk);
    TH_RUN(test_file_all_attr_kinds);
    TH_RUN(test_file_wkey_all_templates);
    TH_RUN(test_file_pubk_template);
    TH_RUN(test_file_comments_and_version_header);
    TH_RUN(test_file_grammar_version_too_high_error);
    TH_RUN(test_file_missing_error);
    TH_RUN(test_file_incomplete_pem_error);
    return TH_SUMMARY();
}
