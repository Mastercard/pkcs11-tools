/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2026 Mastercard
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
 * test_pqc.c: unit tests for the Post-Quantum parameter-set registry
 * (lib/pkcs11_pqc.c). Every function there is pure table lookup / string
 * formatting - no PKCS#11 token, no OpenSSL crypto operation - so the whole
 * file is exercised token-free and runs on every platform that builds the PQC
 * support in (Linux, FreeBSD, macOS, MinGW64). Where PQC is not compiled in
 * (--disable-pqc, or libcrypto < 3.5) the test skips cleanly.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_harness.h"

#if defined(WITH_PQC)

#include "pkcs11lib.h"

/* -k keyword <-> key type, both directions, case-insensitive, error paths. */
static void test_keytype_keyword(void)
{
    TH_CHECK(pkcs11_pqc_keytype_from_kw("mlkem")  == ml_kem,  "mlkem  -> ml_kem");
    TH_CHECK(pkcs11_pqc_keytype_from_kw("mldsa")  == ml_dsa,  "mldsa  -> ml_dsa");
    TH_CHECK(pkcs11_pqc_keytype_from_kw("slhdsa") == slh_dsa, "slhdsa -> slh_dsa");
    TH_CHECK(pkcs11_pqc_keytype_from_kw("MlDsa")  == ml_dsa,  "keyword match is case-insensitive");
    TH_CHECK(pkcs11_pqc_keytype_from_kw("rsa")    == unknown, "non-PQC keyword -> unknown");
    TH_CHECK(pkcs11_pqc_keytype_from_kw(NULL)     == unknown, "NULL keyword -> unknown");

    TH_CHECK(strcmp(pkcs11_pqc_keytype_kw(ml_kem),  "mlkem")  == 0, "ml_kem  -> mlkem");
    TH_CHECK(strcmp(pkcs11_pqc_keytype_kw(ml_dsa),  "mldsa")  == 0, "ml_dsa  -> mldsa");
    TH_CHECK(strcmp(pkcs11_pqc_keytype_kw(slh_dsa), "slhdsa") == 0, "slh_dsa -> slhdsa");
    TH_CHECK(pkcs11_pqc_keytype_kw(rsa) == NULL, "non-PQC key type -> NULL keyword");
}

/* Look up a parameter set by canonical name; verify every descriptor field. */
static void test_paramset_from_name(void)
{
    const pqc_paramset_t *ps = pkcs11_pqc_paramset_from_name("ml-dsa-65");
    TH_CHECK(ps != NULL, "ml-dsa-65 resolves");
    if (ps) {
        TH_CHECK(ps->keytype == ml_dsa,                       "ml-dsa-65 keytype is ml_dsa");
        TH_CHECK(ps->keygenmech == CKM_ML_DSA_KEY_PAIR_GEN,   "ml-dsa-65 keygen mech");
        TH_CHECK(ps->opmech == CKM_ML_DSA,                    "ml-dsa-65 op mech");
        TH_CHECK(strcmp(ps->cliname, "ml-dsa-65") == 0,       "ml-dsa-65 cliname");
        TH_CHECK(strcmp(ps->osslname, "ML-DSA-65") == 0,      "ml-dsa-65 OpenSSL fetch name");
        TH_CHECK(strcmp(ps->ckpname, "CKP_ML_DSA_65") == 0,   "ml-dsa-65 CKP symbol name");
    }

    /* case-insensitive */
    TH_CHECK(pkcs11_pqc_paramset_from_name("ML-DSA-65") == ps, "name match is case-insensitive");

    /* a KEM and an SLH-DSA variant also resolve */
    TH_CHECK(pkcs11_pqc_paramset_from_name("ml-kem-768") != NULL,        "ml-kem-768 resolves");
    TH_CHECK(pkcs11_pqc_paramset_from_name("slh-dsa-shake-256f") != NULL, "slh-dsa-shake-256f resolves");

    /* error paths */
    TH_CHECK(pkcs11_pqc_paramset_from_name("ml-dsa-99") == NULL, "unknown name -> NULL");
    TH_CHECK(pkcs11_pqc_paramset_from_name(NULL) == NULL,        "NULL name -> NULL");
}

/* paramset value accessor + reverse lookup by (keytype,value). */
static void test_paramset_value_roundtrip(void)
{
    const pqc_paramset_t *ps = pkcs11_pqc_paramset_from_name("ml-dsa-65");
    TH_CHECK(ps != NULL, "ml-dsa-65 resolves");
    if (ps) {
        CK_ULONG v = pkcs11_pqc_paramset_value(ps);
        TH_CHECK(v == CKP_ML_DSA_65, "paramset value is CKP_ML_DSA_65");
        TH_CHECK(pkcs11_pqc_paramset_from_value(ml_dsa, v) == ps,
                 "reverse lookup (ml_dsa, value) returns the same descriptor");
    }

    /* the reverse lookup is scoped by key type: the per-family CKP_* values
     * overlap numerically (CKP_ML_DSA_65 == CKP_ML_KEM_768 == 0x2), so the
     * keytype argument is what disambiguates them. */
    {
        const pqc_paramset_t *k44 = pkcs11_pqc_paramset_from_value(ml_dsa, CKP_ML_DSA_44);
        TH_CHECK(k44 && strcmp(k44->cliname, "ml-dsa-44") == 0,
                 "reverse lookup (ml_dsa, CKP_ML_DSA_44) -> ml-dsa-44");
        TH_CHECK(pkcs11_pqc_paramset_from_value(ml_kem, CKP_ML_KEM_768) != NULL,
                 "same numeric value under ml_kem resolves to a KEM set");
    }
    /* an out-of-range value */
    TH_CHECK(pkcs11_pqc_paramset_from_value(ml_dsa, 0x9999) == NULL,
             "unknown paramset value -> NULL");
    /* value of a NULL descriptor is 0 */
    TH_CHECK(pkcs11_pqc_paramset_value(NULL) == 0, "value(NULL) == 0");

    /* exercise the value accessor for each family (each reads a different union
     * member) and confirm the reverse lookup round-trips. */
    {
        const pqc_paramset_t *kem = pkcs11_pqc_paramset_from_name("ml-kem-768");
        const pqc_paramset_t *slh = pkcs11_pqc_paramset_from_name("slh-dsa-sha2-128s");
        TH_CHECK(kem && pkcs11_pqc_paramset_value(kem) == CKP_ML_KEM_768,
                 "ml-kem-768 value is CKP_ML_KEM_768");
        TH_CHECK(slh && pkcs11_pqc_paramset_value(slh) == CKP_SLH_DSA_SHA2_128S,
                 "slh-dsa-sha2-128s value is CKP_SLH_DSA_SHA2_128S");
        TH_CHECK(kem && pkcs11_pqc_paramset_from_value(ml_kem, CKP_ML_KEM_768) == kem,
                 "reverse lookup (ml_kem, value) round-trips");
        TH_CHECK(slh && pkcs11_pqc_paramset_from_value(slh_dsa, CKP_SLH_DSA_SHA2_128S) == slh,
                 "reverse lookup (slh_dsa, value) round-trips");
    }
}

/* default parameter set per algorithm. */
static void test_default_paramset(void)
{
    const pqc_paramset_t *k = pkcs11_pqc_default_paramset(ml_kem);
    const pqc_paramset_t *d = pkcs11_pqc_default_paramset(ml_dsa);
    const pqc_paramset_t *s = pkcs11_pqc_default_paramset(slh_dsa);

    TH_CHECK(k && strcmp(k->cliname, "ml-kem-768") == 0,        "ml_kem default is ml-kem-768");
    TH_CHECK(d && strcmp(d->cliname, "ml-dsa-65") == 0,         "ml_dsa default is ml-dsa-65");
    TH_CHECK(s && strcmp(s->cliname, "slh-dsa-sha2-128s") == 0, "slh_dsa default is slh-dsa-sha2-128s");
    TH_CHECK(pkcs11_pqc_default_paramset(rsa) == NULL,          "non-PQC default -> NULL");
}

/* CLI selector resolution: -b for ML-KEM/ML-DSA, -q for SLH-DSA. */
static void test_paramset_from_selector(void)
{
    const pqc_paramset_t *ps;

    /* ML-KEM / ML-DSA: numeric strength via kb (-b) */
    ps = pkcs11_pqc_paramset_from_selector(ml_kem, 768, NULL);
    TH_CHECK(ps && strcmp(ps->cliname, "ml-kem-768") == 0, "ml_kem kb=768 -> ml-kem-768");
    ps = pkcs11_pqc_paramset_from_selector(ml_dsa, 44, NULL);
    TH_CHECK(ps && strcmp(ps->cliname, "ml-dsa-44") == 0,  "ml_dsa kb=44 -> ml-dsa-44");
    TH_CHECK(pkcs11_pqc_paramset_from_selector(ml_dsa, 999, NULL) == NULL,
             "ml_dsa kb=999 (no such strength) -> NULL");

    /* ML-DSA: kb=0 with a full canonical name via qstr (-q) */
    ps = pkcs11_pqc_paramset_from_selector(ml_dsa, 0, "ml-dsa-87");
    TH_CHECK(ps && strcmp(ps->cliname, "ml-dsa-87") == 0, "ml_dsa qstr=ml-dsa-87 -> ml-dsa-87");
    /* qstr naming the wrong family is rejected */
    TH_CHECK(pkcs11_pqc_paramset_from_selector(ml_dsa, 0, "ml-kem-768") == NULL,
             "ml_dsa qstr naming a KEM -> NULL");
    /* kb=0, qstr=NULL falls back to the algorithm default */
    ps = pkcs11_pqc_paramset_from_selector(ml_dsa, 0, NULL);
    TH_CHECK(ps && strcmp(ps->cliname, "ml-dsa-65") == 0, "ml_dsa no selector -> default");

    /* SLH-DSA: variant suffix via qstr (-q) */
    ps = pkcs11_pqc_paramset_from_selector(slh_dsa, 0, "sha2-128s");
    TH_CHECK(ps && strcmp(ps->cliname, "slh-dsa-sha2-128s") == 0,
             "slh_dsa qstr=sha2-128s (suffix) -> slh-dsa-sha2-128s");
    /* the full canonical name is accepted too */
    ps = pkcs11_pqc_paramset_from_selector(slh_dsa, 0, "slh-dsa-shake-256f");
    TH_CHECK(ps && strcmp(ps->cliname, "slh-dsa-shake-256f") == 0,
             "slh_dsa qstr=full canonical name -> match");
    TH_CHECK(pkcs11_pqc_paramset_from_selector(slh_dsa, 0, "nope") == NULL,
             "slh_dsa qstr=bogus -> NULL");
    ps = pkcs11_pqc_paramset_from_selector(slh_dsa, 0, NULL);
    TH_CHECK(ps && strcmp(ps->cliname, "slh-dsa-sha2-128s") == 0,
             "slh_dsa no selector -> default");

    /* a non-PQC key type never resolves */
    TH_CHECK(pkcs11_pqc_paramset_from_selector(rsa, 2048, NULL) == NULL,
             "non-PQC keytype -> NULL");
}

/* the ec(prime256v1)-style listing display name. */
static void test_dispname(void)
{
    char buf[64];
    const pqc_paramset_t *ps;

    ps = pkcs11_pqc_paramset_from_name("ml-dsa-65");
    TH_CHECK(ps && pkcs11_pqc_paramset_dispname(ps, buf, sizeof buf) == buf, "dispname returns buf");
    TH_CHECK(ps && strcmp(buf, "mldsa(65)") == 0, "ml-dsa-65 -> mldsa(65)");

    ps = pkcs11_pqc_paramset_from_name("ml-kem-768");
    if (ps) { pkcs11_pqc_paramset_dispname(ps, buf, sizeof buf);
        TH_CHECK(strcmp(buf, "mlkem(768)") == 0, "ml-kem-768 -> mlkem(768)"); }

    ps = pkcs11_pqc_paramset_from_name("slh-dsa-sha2-128s");
    if (ps) { pkcs11_pqc_paramset_dispname(ps, buf, sizeof buf);
        TH_CHECK(strcmp(buf, "slhdsa(sha2-128s)") == 0, "slh-dsa-sha2-128s -> slhdsa(sha2-128s)"); }

    /* error paths: NULL descriptor / NULL buffer / zero length */
    TH_CHECK(pkcs11_pqc_paramset_dispname(NULL, buf, sizeof buf) == NULL, "dispname(NULL ps) -> NULL");
    ps = pkcs11_pqc_paramset_from_name("ml-dsa-65");
    TH_CHECK(pkcs11_pqc_paramset_dispname(ps, NULL, sizeof buf) == NULL, "dispname(NULL buf) -> NULL");
    TH_CHECK(pkcs11_pqc_paramset_dispname(ps, buf, 0) == NULL,           "dispname(buflen 0) -> NULL");
}

/* the usage/error paramset dump, captured through a temporary FILE. */
static void test_print_paramsets(void)
{
    FILE *fp = tmpfile();
    char content[4096];
    size_t n;

    TH_CHECK(fp != NULL, "tmpfile() available");
    if (!fp) { return; }

    pkcs11_pqc_print_paramsets(fp, ml_dsa);
    rewind(fp);
    n = fread(content, 1, sizeof content - 1, fp);
    content[n] = '\0';
    fclose(fp);

    TH_CHECK(strstr(content, "ml-dsa-44") != NULL, "ml_dsa dump lists ml-dsa-44");
    TH_CHECK(strstr(content, "ml-dsa-65") != NULL, "ml_dsa dump lists ml-dsa-65");
    TH_CHECK(strstr(content, "ml-dsa-87") != NULL, "ml_dsa dump lists ml-dsa-87");
    /* the dump is filtered by key type: no KEM entries under ml_dsa */
    TH_CHECK(strstr(content, "ml-kem") == NULL, "ml_dsa dump excludes ml-kem entries");
}

int main(void)
{
    TH_RUN(test_keytype_keyword);
    TH_RUN(test_paramset_from_name);
    TH_RUN(test_paramset_value_roundtrip);
    TH_RUN(test_default_paramset);
    TH_RUN(test_paramset_from_selector);
    TH_RUN(test_dispname);
    TH_RUN(test_print_paramsets);

    return TH_SUMMARY();
}

#else  /* !WITH_PQC */

int main(void)
{
    fprintf(stderr, "SKIP: built without PQC support (WITH_PQC undefined)\n");
    return 77;                  /* Automake protocol: 77 == skip */
}

#endif /* WITH_PQC */
