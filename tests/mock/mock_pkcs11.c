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
 * mock_pkcs11.c -- a small, programmable PKCS#11 module for the test suite.
 *
 * The pkcs11-tools binaries load their cryptographic module at run time with
 * dlopen() + C_GetFunctionList() (lib/pkcs11_context.c). A mock is therefore
 * just another loadable module: this file exports C_GetFunctionList() and
 * returns a CK_FUNCTION_LIST wired to in-process implementations backed by a
 * tiny in-memory model (slots, one token, sessions, objects).
 *
 * Why a mock in addition to SoftHSM2:
 *   - it advertises and "implements" mechanisms SoftHSM2 lacks (e.g.
 *     CKM_XOR_BASE_AND_DATA used by p11keycomp, the CBC-PAD / envelope wrapping
 *     variants), so the tool-side algorithm-selection and serialization code is
 *     exercised even though the crypto is faked;
 *   - it can inject deterministic errors (MOCK_P11_FAIL, see below) so the
 *     "if (rv != CKR_OK) { pkcs11_error(...); goto err; }" cleanup branches that
 *     a real, always-succeeding token never reaches become testable.
 *
 * The crypto here is deliberately fake but self-consistent: encrypt/decrypt and
 * wrap/unwrap are reversible so round-trips (and their KCVs) match. It is NOT a
 * security boundary and must never be shipped or used outside the test suite.
 *
 * Control plane -- all optional, sensible defaults otherwise (environment):
 *   MOCK_P11_TOKENS=N          number of slots that carry a token (default 1);
 *                              one extra empty slot is always appended.
 *   MOCK_P11_LOGIN_REQUIRED=0  clear CKF_LOGIN_REQUIRED on the token (default 1).
 *   MOCK_P11_PIN=1234          the user PIN C_Login checks (default "1234").
 *   MOCK_P11_FAIL=SPEC[;SPEC]  fault injection. Each SPEC is
 *                                  C_Name@N=CKR_CONST
 *                              meaning: the N-th call to C_Name returns the
 *                              given CK_RV instead of running. CKR_CONST may be
 *                              a symbolic name (a subset, see rv_from_name) or a
 *                              raw number (0x30 or 48). N counts from 1.
 *
 * Portable C: builds as a .so on Linux, the BSDs and macOS, and a .dll on
 * project's own include/cryptoki/cryptoki.h (so the struct layouts match).
 */

#include "cryptoki.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>

/* Post-quantum (ML-DSA / SLH-DSA / ML-KEM) needs OpenSSL >= 3.5, which brings
 * the native providers plus the raw-key export (OSSL_PKEY_PARAM_PUB_KEY) and
 * one-shot EVP_DigestSign the mock relies on. Below that the PQC arms compile
 * out and the mechanisms are simply not advertised (tests self-skip). */
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30500000L
#define MOCK_HAVE_PQC 1
#endif

/* ------------------------------------------------------------------------- */
/* Limits (static storage keeps the mock dependency-free and simple).        */

#define MOCK_MAX_SLOTS     4
#define MOCK_MAX_SESSIONS  32
#define MOCK_MAX_OBJECTS   256
#define MOCK_MAX_ATTRS     64
#define MOCK_MAX_FAULTS    32

/* ------------------------------------------------------------------------- */
/* In-memory model.                                                          */

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR       value; /* owned malloc'd copy, or NULL for a 0-length */
    CK_ULONG          len;
} mock_attr;

typedef struct {
    int         in_use;
    CK_ULONG    nattrs;
    mock_attr   attrs[MOCK_MAX_ATTRS];
} mock_object;

typedef struct {
    int              in_use;
    CK_SLOT_ID       slot;
    int              logged_in;
    /* active C_FindObjects cursor */
    int              find_active;
    CK_ULONG         find_pos;
    CK_ATTRIBUTE     find_tmpl[MOCK_MAX_ATTRS];
    CK_ULONG         find_ntmpl;
    /* single active crypto operation (encrypt/sign) */
    CK_MECHANISM_TYPE op_mech;
    CK_OBJECT_HANDLE  op_key;
} mock_session;

typedef struct {
    char             name[40];
    CK_ULONG         nth;   /* which call (1-based) trips */
    CK_RV            rv;    /* value to return */
    CK_ULONG         seen;  /* running call counter */
} mock_fault;

static int          g_initialized = 0;
static CK_ULONG     g_token_slots = 1;           /* slots carrying a token */
static int          g_login_required = 1;
static char         g_pin[64] = "1234";

static mock_object  g_objects[MOCK_MAX_OBJECTS];
static mock_session g_sessions[MOCK_MAX_SESSIONS];
static mock_fault   g_faults[MOCK_MAX_FAULTS];
static CK_ULONG     g_nfaults = 0;

/* Side table: real OpenSSL key material for asymmetric objects, keyed by the
 * object handle. Lets C_UnwrapKey(CKM_RSA_PKCS) actually RSA-decrypt and
 * (later) C_Sign produce real signatures, while the object store only carries
 * the public attributes the tools read (CKA_MODULUS, ...). */
typedef struct {
    CK_OBJECT_HANDLE h;
    EVP_PKEY        *pk;
} mock_pkey;
static mock_pkey    g_pkeys[MOCK_MAX_OBJECTS];

/* ------------------------------------------------------------------------- */
/* Small helpers.                                                            */

static void pad_set(CK_UTF8CHAR *dst, size_t n, const char *s)
{
    size_t l = strlen(s);
    if (l > n)
        l = n;
    memcpy(dst, s, l);
    if (n > l)
        memset(dst + l, ' ', n - l);
}

static const CK_VERSION g_ver = { 3, 2 };

/* ---- fault injection --------------------------------------------------- */

/* Translate a subset of CKR_* names to values; fall back to strtoul. The set
 * is limited to codes the tools actually surface in error paths. */
static CK_RV rv_from_name(const char *s)
{
    static const struct { const char *n; CK_RV v; } tbl[] = {
        { "CKR_OK",                     CKR_OK },
        { "CKR_GENERAL_ERROR",          CKR_GENERAL_ERROR },
        { "CKR_FUNCTION_FAILED",        CKR_FUNCTION_FAILED },
        { "CKR_ARGUMENTS_BAD",          CKR_ARGUMENTS_BAD },
        { "CKR_DEVICE_ERROR",           CKR_DEVICE_ERROR },
        { "CKR_DEVICE_MEMORY",          CKR_DEVICE_MEMORY },
        { "CKR_KEY_HANDLE_INVALID",     CKR_KEY_HANDLE_INVALID },
        { "CKR_MECHANISM_INVALID",      CKR_MECHANISM_INVALID },
        { "CKR_OBJECT_HANDLE_INVALID",  CKR_OBJECT_HANDLE_INVALID },
        { "CKR_TEMPLATE_INCONSISTENT",  CKR_TEMPLATE_INCONSISTENT },
        { "CKR_TEMPLATE_INCOMPLETE",    CKR_TEMPLATE_INCOMPLETE },
        { "CKR_ATTRIBUTE_VALUE_INVALID",CKR_ATTRIBUTE_VALUE_INVALID },
        { "CKR_PIN_INCORRECT",          CKR_PIN_INCORRECT },
        { "CKR_PIN_INVALID",            CKR_PIN_INVALID },
        { "CKR_TOKEN_WRITE_PROTECTED",  CKR_TOKEN_WRITE_PROTECTED },
        { "CKR_SESSION_HANDLE_INVALID", CKR_SESSION_HANDLE_INVALID },
        { "CKR_FUNCTION_NOT_SUPPORTED", CKR_FUNCTION_NOT_SUPPORTED },
        { "CKR_BUFFER_TOO_SMALL",       CKR_BUFFER_TOO_SMALL },
        { "CKR_KEY_SIZE_RANGE",         CKR_KEY_SIZE_RANGE },
        { "CKR_KEY_TYPE_INCONSISTENT",  CKR_KEY_TYPE_INCONSISTENT },
        { "CKR_WRAPPED_KEY_INVALID",    CKR_WRAPPED_KEY_INVALID },
        { "CKR_UNWRAPPING_KEY_HANDLE_INVALID", CKR_UNWRAPPING_KEY_HANDLE_INVALID },
        { "CKR_WRAPPING_KEY_HANDLE_INVALID",   CKR_WRAPPING_KEY_HANDLE_INVALID },
        { "CKR_PIN_LOCKED",             CKR_PIN_LOCKED },
        { "CKR_PIN_EXPIRED",            CKR_PIN_EXPIRED },
        { "CKR_TOKEN_NOT_PRESENT",      CKR_TOKEN_NOT_PRESENT },
        { "CKR_TOKEN_NOT_RECOGNIZED",   CKR_TOKEN_NOT_RECOGNIZED },
        { "CKR_USER_NOT_LOGGED_IN",     CKR_USER_NOT_LOGGED_IN },
        { "CKR_USER_ALREADY_LOGGED_IN", CKR_USER_ALREADY_LOGGED_IN },
        { "CKR_SESSION_CLOSED",         CKR_SESSION_CLOSED },
        { "CKR_SESSION_COUNT",          CKR_SESSION_COUNT },
        { "CKR_DATA_INVALID",           CKR_DATA_INVALID },
        { "CKR_DATA_LEN_RANGE",         CKR_DATA_LEN_RANGE },
        { "CKR_ENCRYPTED_DATA_INVALID", CKR_ENCRYPTED_DATA_INVALID },
        { "CKR_ENCRYPTED_DATA_LEN_RANGE", CKR_ENCRYPTED_DATA_LEN_RANGE },
        { "CKR_KEY_UNEXTRACTABLE",      CKR_KEY_UNEXTRACTABLE },
        { "CKR_ATTRIBUTE_TYPE_INVALID", CKR_ATTRIBUTE_TYPE_INVALID },
        { "CKR_FUNCTION_CANCELED",      CKR_FUNCTION_CANCELED },
    };
    size_t i;
    if (s == NULL)
        return CKR_FUNCTION_FAILED;
    for (i = 0; i < sizeof tbl / sizeof tbl[0]; i++)
        if (strcmp(s, tbl[i].n) == 0)
            return tbl[i].v;
    /* A "CKR_" spelling we do not know: fail safe with a non-OK code rather
     * than letting strtoul() silently yield CKR_OK (which would turn a typo
     * into a no-op fault). Numeric specs (decimal/0x hex) are still honored. */
    if (strncmp(s, "CKR_", 4) == 0)
        return CKR_FUNCTION_FAILED;
    return (CK_RV)strtoul(s, NULL, 0);
}

/* Parse MOCK_P11_FAIL into g_faults. Format: "C_Name@N=CKR_X;C_Other@1=0x30". */
static void parse_faults(const char *spec)
{
    char buf[1024];
    char *save = NULL, *tok;

    g_nfaults = 0;
    if (spec == NULL || *spec == '\0')
        return;

    strncpy(buf, spec, sizeof buf - 1);
    buf[sizeof buf - 1] = '\0';

    for (tok = strtok_r(buf, ";,", &save);
         tok != NULL && g_nfaults < MOCK_MAX_FAULTS;
         tok = strtok_r(NULL, ";,", &save)) {
        char *at = strchr(tok, '@');
        char *eq = strchr(tok, '=');
        mock_fault *f;
        if (at == NULL || eq == NULL || at > eq)
            continue;
        *at = '\0';
        *eq = '\0';
        f = &g_faults[g_nfaults];
        memset(f, 0, sizeof *f);
        strncpy(f->name, tok, sizeof f->name - 1);
        f->nth = (CK_ULONG)strtoul(at + 1, NULL, 0);
        if (f->nth == 0)
            f->nth = 1;
        f->rv = rv_from_name(eq + 1);
        g_nfaults++;
    }
}

/* If a fault is armed for `fn`, count this call and return 1 (+ *out) when the
 * configured call number is reached. */
static int fault_hit(const char *fn, CK_RV *out)
{
    CK_ULONG i;
    for (i = 0; i < g_nfaults; i++) {
        if (strcmp(g_faults[i].name, fn) == 0) {
            g_faults[i].seen++;
            if (g_faults[i].seen == g_faults[i].nth) {
                *out = g_faults[i].rv;
                return 1;
            }
        }
    }
    return 0;
}

/* Guard macro used at the top of each intercepted entry point. */
#define FAULT(fn)                                       \
    do {                                                \
        CK_RV _frv;                                     \
        if (fault_hit(fn, &_frv))                       \
            return _frv;                                \
    } while (0)

/* ---- object helpers ---------------------------------------------------- */

static mock_object *obj_from_handle(CK_OBJECT_HANDLE h)
{
    if (h == CK_INVALID_HANDLE || h > MOCK_MAX_OBJECTS)
        return NULL;
    if (!g_objects[h - 1].in_use)
        return NULL;
    return &g_objects[h - 1];
}

static mock_attr *obj_find_attr(mock_object *o, CK_ATTRIBUTE_TYPE t)
{
    CK_ULONG i;
    for (i = 0; i < o->nattrs; i++)
        if (o->attrs[i].type == t)
            return &o->attrs[i];
    return NULL;
}

static CK_RV obj_set_attr(mock_object *o, CK_ATTRIBUTE_TYPE t,
                          const void *val, CK_ULONG len)
{
    mock_attr *a = obj_find_attr(o, t);
    void *copy = NULL;
    if (len > 0) {
        copy = malloc(len);
        if (copy == NULL)
            return CKR_DEVICE_MEMORY;
        memcpy(copy, val, len);
    }
    if (a == NULL) {
        if (o->nattrs >= MOCK_MAX_ATTRS) {
            free(copy);
            return CKR_DEVICE_MEMORY;
        }
        a = &o->attrs[o->nattrs++];
        a->value = NULL;
    }
    free(a->value);
    a->type = t;
    a->value = copy;
    a->len = len;
    return CKR_OK;
}

/* Allocate a new object; returns its 1-based handle or CK_INVALID_HANDLE. */
static CK_OBJECT_HANDLE obj_alloc(void)
{
    CK_ULONG i;
    for (i = 0; i < MOCK_MAX_OBJECTS; i++) {
        if (!g_objects[i].in_use) {
            memset(&g_objects[i], 0, sizeof g_objects[i]);
            g_objects[i].in_use = 1;
            return (CK_OBJECT_HANDLE)(i + 1);
        }
    }
    return CK_INVALID_HANDLE;
}

static void obj_free(mock_object *o)
{
    CK_ULONG i;
    for (i = 0; i < o->nattrs; i++)
        free(o->attrs[i].value);
    memset(o, 0, sizeof *o);
}

static CK_OBJECT_HANDLE obj_create_from_template(CK_ATTRIBUTE_PTR t, CK_ULONG n)
{
    CK_OBJECT_HANDLE h = obj_alloc();
    mock_object *o;
    CK_ULONG i;
    if (h == CK_INVALID_HANDLE)
        return h;
    o = obj_from_handle(h);
    for (i = 0; i < n; i++) {
        if (obj_set_attr(o, t[i].type, t[i].pValue, t[i].ulValueLen) != CKR_OK) {
            obj_free(o);
            return CK_INVALID_HANDLE;
        }
    }
    return h;
}

/* True if object o matches every attribute in the search template. */
static int obj_matches(mock_object *o, CK_ATTRIBUTE_PTR t, CK_ULONG n)
{
    CK_ULONG i;
    for (i = 0; i < n; i++) {
        mock_attr *a = obj_find_attr(o, t[i].type);
        if (a == NULL)
            return 0;
        if (a->len != t[i].ulValueLen)
            return 0;
        if (t[i].ulValueLen > 0 &&
            memcmp(a->value, t[i].pValue, t[i].ulValueLen) != 0)
            return 0;
    }
    return 1;
}

/* ---- asymmetric key material side table -------------------------------- */

static void pkey_put(CK_OBJECT_HANDLE h, EVP_PKEY *pk)
{
    CK_ULONG i;
    for (i = 0; i < MOCK_MAX_OBJECTS; i++) {
        if (g_pkeys[i].pk == NULL) {
            g_pkeys[i].h = h;
            g_pkeys[i].pk = pk;
            return;
        }
    }
    EVP_PKEY_free(pk); /* table full: drop it rather than leak a slot */
}

static EVP_PKEY *pkey_get(CK_OBJECT_HANDLE h)
{
    CK_ULONG i;
    for (i = 0; i < MOCK_MAX_OBJECTS; i++)
        if (g_pkeys[i].pk != NULL && g_pkeys[i].h == h)
            return g_pkeys[i].pk;
    return NULL;
}

static void pkey_drop(CK_OBJECT_HANDLE h)
{
    CK_ULONG i;
    for (i = 0; i < MOCK_MAX_OBJECTS; i++)
        if (g_pkeys[i].pk != NULL && g_pkeys[i].h == h) {
            EVP_PKEY_free(g_pkeys[i].pk);
            g_pkeys[i].pk = NULL;
            g_pkeys[i].h = 0;
        }
}

/* ------------------------------------------------------------------------- */
/* Session helpers.                                                          */

static mock_session *sess_from_handle(CK_SESSION_HANDLE h)
{
    if (h == CK_INVALID_HANDLE || h > MOCK_MAX_SESSIONS)
        return NULL;
    if (!g_sessions[h - 1].in_use)
        return NULL;
    return &g_sessions[h - 1];
}

/* ------------------------------------------------------------------------- */
/* Configuration from the environment (parsed once at C_Initialize).         */

static void load_config(void)
{
    const char *s;

    g_token_slots = 1;
    g_login_required = 1;
    strcpy(g_pin, "1234");

    if ((s = getenv("MOCK_P11_TOKENS")) != NULL) {
        unsigned long v = strtoul(s, NULL, 0);
        if (v >= 1 && v < MOCK_MAX_SLOTS)
            g_token_slots = (CK_ULONG)v;
    }
    if ((s = getenv("MOCK_P11_LOGIN_REQUIRED")) != NULL)
        g_login_required = (strcmp(s, "0") != 0);
    if ((s = getenv("MOCK_P11_PIN")) != NULL) {
        strncpy(g_pin, s, sizeof g_pin - 1);
        g_pin[sizeof g_pin - 1] = '\0';
    }
    parse_faults(getenv("MOCK_P11_FAIL"));
}

#ifdef MOCK_HAVE_PQC
/* One row per PKCS#11 PQC parameter set. The OpenSSL fetch name MUST match
 * lib/pkcs11_pqc.c: that is what makes the raw public key the mock exports
 * round-trip through the tool-side SPKI reconstruction (pkcs11_SPKI_from_PQC)
 * and signature verification. */
typedef struct {
    CK_MECHANISM_TYPE genmech;
    CK_KEY_TYPE       keytype;
    CK_ULONG          paramset;   /* CKP_* value carried in CKA_PARAMETER_SET */
    const char       *osslname;
} pqc_row;

static const pqc_row g_pqc_rows[] = {
    { CKM_ML_DSA_KEY_PAIR_GEN,  CKK_ML_DSA,  CKP_ML_DSA_44, "ML-DSA-44" },
    { CKM_ML_DSA_KEY_PAIR_GEN,  CKK_ML_DSA,  CKP_ML_DSA_65, "ML-DSA-65" },
    { CKM_ML_DSA_KEY_PAIR_GEN,  CKK_ML_DSA,  CKP_ML_DSA_87, "ML-DSA-87" },
    { CKM_ML_KEM_KEY_PAIR_GEN,  CKK_ML_KEM,  CKP_ML_KEM_512,  "ML-KEM-512"  },
    { CKM_ML_KEM_KEY_PAIR_GEN,  CKK_ML_KEM,  CKP_ML_KEM_768,  "ML-KEM-768"  },
    { CKM_ML_KEM_KEY_PAIR_GEN,  CKK_ML_KEM,  CKP_ML_KEM_1024, "ML-KEM-1024" },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_128S,  "SLH-DSA-SHA2-128s"  },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHAKE_128S, "SLH-DSA-SHAKE-128s" },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_128F,  "SLH-DSA-SHA2-128f"  },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHAKE_128F, "SLH-DSA-SHAKE-128f" },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_192S,  "SLH-DSA-SHA2-192s"  },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHAKE_192S, "SLH-DSA-SHAKE-192s" },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_192F,  "SLH-DSA-SHA2-192f"  },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHAKE_192F, "SLH-DSA-SHAKE-192f" },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_256S,  "SLH-DSA-SHA2-256s"  },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHAKE_256S, "SLH-DSA-SHAKE-256s" },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_256F,  "SLH-DSA-SHA2-256f"  },
    { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHAKE_256F, "SLH-DSA-SHAKE-256f" },
};

/* keygen mechanism + CKA_PARAMETER_SET value -> OpenSSL fetch name */
static const char *pqc_ossl_name(CK_MECHANISM_TYPE mech, CK_ULONG ps)
{
    CK_ULONG i;
    for (i = 0; i < sizeof g_pqc_rows / sizeof g_pqc_rows[0]; i++)
        if (g_pqc_rows[i].genmech == mech && g_pqc_rows[i].paramset == ps)
            return g_pqc_rows[i].osslname;
    return NULL;
}

/* CKK_* key type carried on the generated PQC objects (read back by the tools
 * via CKA_KEY_TYPE to select the ml_dsa / slh_dsa / ml_kem code path). */
static CK_KEY_TYPE pqc_key_type(CK_MECHANISM_TYPE mech)
{
    switch (mech) {
    case CKM_ML_DSA_KEY_PAIR_GEN:  return CKK_ML_DSA;
    case CKM_ML_KEM_KEY_PAIR_GEN:  return CKK_ML_KEM;
    case CKM_SLH_DSA_KEY_PAIR_GEN: return CKK_SLH_DSA;
    }
    return 0;
}

/* Reverse lookup by OpenSSL fetch name, used to seed a persistent PQC key. */
static const pqc_row *pqc_row_from_name(const char *name)
{
    CK_ULONG i;
    if (name == NULL)
        return NULL;
    for (i = 0; i < sizeof g_pqc_rows / sizeof g_pqc_rows[0]; i++)
        if (strcmp(g_pqc_rows[i].osslname, name) == 0)
            return &g_pqc_rows[i];
    return NULL;
}
#endif /* MOCK_HAVE_PQC */

/* Seed the token with a couple of default objects so a bare `p11ls` lists
 * something even before any test creates keys. */
static void seed_default_objects(void)
{
    CK_OBJECT_CLASS seck = CKO_SECRET_KEY;
    CK_KEY_TYPE aes = CKK_AES;
    CK_BBOOL yes = CK_TRUE;
    unsigned char id[] = { 0x01 };
    unsigned char val[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &seck, sizeof seck },
        { CKA_KEY_TYPE, &aes,  sizeof aes  },
        { CKA_TOKEN,    &yes,  sizeof yes  },
        { CKA_LABEL,    (void *)"mockaes", 7 },
        { CKA_ID,       id,    sizeof id   },
        { CKA_VALUE,    val,   sizeof val  },
    };
    (void)obj_create_from_template(tmpl, sizeof tmpl / sizeof tmpl[0]);
}

/* Optionally seed a real RSA key pair (label from MOCK_P11_RSA_KEYPAIR) so a
 * separate p11keycomp process finds a usable RSA unwrapping key on the token.
 * The private object carries CKA_MODULUS/CKA_PUBLIC_EXPONENT (the tool reads
 * them to PKCS#1-encrypt the first component) and the matching EVP_PKEY lives
 * in the side table so C_UnwrapKey(CKM_RSA_PKCS) can actually decrypt. */
static void seed_default_keypair(void)
{
    const char *label = getenv("MOCK_P11_RSA_KEYPAIR");
    EVP_PKEY *pk;
    BIGNUM *bn_n = NULL, *bn_e = NULL;
    unsigned char nbuf[1024], ebuf[16];
    int nlen, elen;
    CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY, privc = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsa = CKK_RSA;
    CK_BBOOL yes = CK_TRUE;
    CK_OBJECT_HANDLE hp, hs;
    mock_object *op, *os;

    if (label == NULL || label[0] == '\0')
        return;
    pk = EVP_RSA_gen(2048);
    if (pk == NULL)
        return;
    if (!EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &bn_n) ||
        !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_E, &bn_e)) {
        BN_free(bn_n); BN_free(bn_e); EVP_PKEY_free(pk);
        return;
    }
    nlen = BN_bn2bin(bn_n, nbuf);
    elen = BN_bn2bin(bn_e, ebuf);
    BN_free(bn_n); BN_free(bn_e);

    {
        CK_ATTRIBUTE pubt[] = {
            { CKA_CLASS,    &pubc, sizeof pubc },
            { CKA_KEY_TYPE, &rsa,  sizeof rsa  },
            { CKA_TOKEN,    &yes,  sizeof yes  },
            { CKA_LABEL,    (void *)label, (CK_ULONG)strlen(label) },
        };
        CK_ATTRIBUTE privt[] = {
            { CKA_CLASS,    &privc, sizeof privc },
            { CKA_KEY_TYPE, &rsa,   sizeof rsa   },
            { CKA_TOKEN,    &yes,   sizeof yes   },
            { CKA_LABEL,    (void *)label, (CK_ULONG)strlen(label) },
            { CKA_UNWRAP,   &yes,   sizeof yes   },
            { CKA_DECRYPT,  &yes,   sizeof yes   },
        };
        hp = obj_create_from_template(pubt, sizeof pubt / sizeof pubt[0]);
        hs = obj_create_from_template(privt, sizeof privt / sizeof privt[0]);
    }
    if (hp == CK_INVALID_HANDLE || hs == CK_INVALID_HANDLE) {
        EVP_PKEY_free(pk);
        return;
    }
    op = obj_from_handle(hp);
    os = obj_from_handle(hs);
    obj_set_attr(op, CKA_MODULUS, nbuf, (CK_ULONG)nlen);
    obj_set_attr(op, CKA_PUBLIC_EXPONENT, ebuf, (CK_ULONG)elen);
    obj_set_attr(os, CKA_MODULUS, nbuf, (CK_ULONG)nlen);
    obj_set_attr(os, CKA_PUBLIC_EXPONENT, ebuf, (CK_ULONG)elen);
    EVP_PKEY_up_ref(pk);
    pkey_put(hp, pk);
    pkey_put(hs, pk);
}

#ifdef MOCK_HAVE_PQC
/* Optionally seed a real PQC key pair so a separate p11ls / p11od / p11req /
 * p11mkcert process finds a usable ML-DSA or SLH-DSA key on the token.
 *   MOCK_P11_PQC_KEYPAIR=<label>       (enables seeding)
 *   MOCK_P11_PQC_ALG=<OpenSSL name>    (default "ML-DSA-65")
 * The public object carries CKA_VALUE (raw public key) + CKA_PARAMETER_SET so
 * the tools rebuild the SPKI; the matching EVP_PKEY lives in the side table so
 * C_Sign produces a signature that verifies against it. */
static void seed_default_pqc_keypair(void)
{
    const char *label = getenv("MOCK_P11_PQC_KEYPAIR");
    const char *alg = getenv("MOCK_P11_PQC_ALG");
    const pqc_row *row;
    EVP_PKEY *pk;
    unsigned char pub[8192];
    size_t publen = sizeof pub;
    CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY, privc = CKO_PRIVATE_KEY;
    CK_BBOOL yes = CK_TRUE;
    CK_ULONG ps;
    CK_KEY_TYPE kt;
    unsigned char id[] = { 0x0b, 0x0c };
    CK_OBJECT_HANDLE hp, hs;
    mock_object *op, *os;

    if (label == NULL || label[0] == '\0')
        return;
    row = pqc_row_from_name(alg && alg[0] ? alg : "ML-DSA-65");
    if (row == NULL)
        return;
    ps = row->paramset;
    kt = row->keytype;

    pk = EVP_PKEY_Q_keygen(NULL, NULL, row->osslname);
    if (pk == NULL)
        return;
    if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, sizeof pub, &publen) != 1) {
        EVP_PKEY_free(pk);
        return;
    }
    {
        CK_ATTRIBUTE pubt[] = {
            { CKA_CLASS,         &pubc, sizeof pubc },
            { CKA_KEY_TYPE,      &kt,   sizeof kt   },
            { CKA_TOKEN,         &yes,  sizeof yes  },
            { CKA_LABEL,         (void *)label, (CK_ULONG)strlen(label) },
            { CKA_ID,            id,    sizeof id   },
            { CKA_PARAMETER_SET, &ps,   sizeof ps   },
            { CKA_VERIFY,        &yes,  sizeof yes  },
            { CKA_VALUE,         pub,   (CK_ULONG)publen },
        };
        CK_ATTRIBUTE privt[] = {
            { CKA_CLASS,         &privc, sizeof privc },
            { CKA_KEY_TYPE,      &kt,    sizeof kt    },
            { CKA_TOKEN,         &yes,   sizeof yes   },
            { CKA_LABEL,         (void *)label, (CK_ULONG)strlen(label) },
            { CKA_ID,            id,     sizeof id    },
            { CKA_PARAMETER_SET, &ps,    sizeof ps    },
            { CKA_SIGN,          &yes,   sizeof yes   },
        };
        hp = obj_create_from_template(pubt, sizeof pubt / sizeof pubt[0]);
        hs = obj_create_from_template(privt, sizeof privt / sizeof privt[0]);
    }
    if (hp == CK_INVALID_HANDLE || hs == CK_INVALID_HANDLE) {
        EVP_PKEY_free(pk);
        return;
    }
    op = obj_from_handle(hp);
    os = obj_from_handle(hs);
    (void)op;
    (void)os;
    EVP_PKEY_up_ref(pk);
    pkey_put(hp, pk);
    pkey_put(hs, pk);          /* private handle signs */
}
#endif /* MOCK_HAVE_PQC */

/* ========================================================================= */
/* PKCS#11 entry points.                                                     */
/* ========================================================================= */

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
    (void)pInitArgs;
    if (g_initialized)
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    memset(g_objects, 0, sizeof g_objects);
    memset(g_sessions, 0, sizeof g_sessions);
    memset(g_pkeys, 0, sizeof g_pkeys);
    load_config();          /* faults are parsed here, so FAULT() below is live */
    FAULT("C_Initialize");
    seed_default_objects();
    seed_default_keypair();
#ifdef MOCK_HAVE_PQC
    seed_default_pqc_keypair();
#endif
    g_initialized = 1;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
    CK_ULONG i;
    (void)pReserved;
    FAULT("C_Finalize");
    for (i = 0; i < MOCK_MAX_OBJECTS; i++) {
        if (g_objects[i].in_use)
            obj_free(&g_objects[i]);
        if (g_pkeys[i].pk != NULL) {
            EVP_PKEY_free(g_pkeys[i].pk);
            g_pkeys[i].pk = NULL;
        }
    }
    memset(g_sessions, 0, sizeof g_sessions);
    g_initialized = 0;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
    FAULT("C_GetInfo");
    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof *pInfo);
    pInfo->cryptokiVersion = g_ver;
    pad_set(pInfo->manufacturerID, 32, "pkcs11-tools test mock");
    pInfo->flags = 0;
    pad_set(pInfo->libraryDescription, 32, "mock PKCS#11 module");
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent,
                                         CK_SLOT_ID_PTR pSlotList,
                                         CK_ULONG_PTR pulCount)
{
    /* Slots 0..g_token_slots-1 carry a token; one extra empty slot follows. */
    CK_ULONG total = tokenPresent ? g_token_slots : g_token_slots + 1;
    CK_ULONG i;
    FAULT("C_GetSlotList");
    if (pulCount == NULL)
        return CKR_ARGUMENTS_BAD;
    if (pSlotList == NULL) {
        *pulCount = total;
        return CKR_OK;
    }
    if (*pulCount < total) {
        *pulCount = total;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (i = 0; i < total; i++)
        pSlotList[i] = (CK_SLOT_ID)i;
    *pulCount = total;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID,
                                         CK_SLOT_INFO_PTR pInfo)
{
    FAULT("C_GetSlotInfo");
    if (pInfo == NULL || slotID > g_token_slots)
        return CKR_SLOT_ID_INVALID;
    memset(pInfo, 0, sizeof *pInfo);
    pad_set(pInfo->slotDescription, 64, "pkcs11-tools mock slot");
    pad_set(pInfo->manufacturerID, 32, "pkcs11-tools test mock");
    pInfo->flags = CKF_HW_SLOT;
    if (slotID < g_token_slots)
        pInfo->flags |= CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion = g_ver;
    pInfo->firmwareVersion = g_ver;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID,
                                          CK_TOKEN_INFO_PTR pInfo)
{
    FAULT("C_GetTokenInfo");
    if (pInfo == NULL || slotID >= g_token_slots)
        return CKR_TOKEN_NOT_PRESENT;
    memset(pInfo, 0, sizeof *pInfo);
    pad_set(pInfo->label, 32, "p11test");
    pad_set(pInfo->manufacturerID, 32, "pkcs11-tools test mock");
    pad_set(pInfo->model, 16, "mock");
    pad_set(pInfo->serialNumber, 16, "0000000000000001");
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED |
                   CKF_RNG;
    if (g_login_required)
        pInfo->flags |= CKF_LOGIN_REQUIRED;
    pInfo->ulMaxSessionCount = MOCK_MAX_SESSIONS;
    pInfo->ulMaxRwSessionCount = MOCK_MAX_SESSIONS;
    pInfo->ulMaxPinLen = 64;
    pInfo->ulMinPinLen = 1;
    pInfo->ulTotalPublicMemory = (CK_ULONG)-1;
    pInfo->ulFreePublicMemory = (CK_ULONG)-1;
    pInfo->ulTotalPrivateMemory = (CK_ULONG)-1;
    pInfo->ulFreePrivateMemory = (CK_ULONG)-1;
    pInfo->hardwareVersion = g_ver;
    pInfo->firmwareVersion = g_ver;
    pad_set(pInfo->utcTime, 16, "0000000000000000");
    return CKR_OK;
}

/* ---- mechanisms -------------------------------------------------------- */

/* Everything the tools may enumerate/select, including the mechanisms
 * SoftHSM2 does not implement (XOR derive, CBC-PAD wrapping, ...). */
static const CK_MECHANISM_TYPE g_mechs[] = {
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_X9_31_KEY_PAIR_GEN,
    CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_X_509,
    CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKM_DSA_KEY_PAIR_GEN, CKM_DSA, CKM_DSA_SHA1, CKM_DSA_SHA256,
    CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, CKM_ECDSA_SHA256,
    CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA,
    CKM_DH_PKCS_KEY_PAIR_GEN, CKM_DH_PKCS_DERIVE,
    CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD,
    CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_PAD,
    CKM_DES3_KEY_GEN, CKM_DES3_CBC, CKM_DES3_CBC_PAD,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512,
    CKM_XOR_BASE_AND_DATA,
#ifdef MOCK_HAVE_PQC
    CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA,
    CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA,
    CKM_ML_KEM_KEY_PAIR_GEN,
#endif
};

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID,
                                              CK_MECHANISM_TYPE_PTR pList,
                                              CK_ULONG_PTR pulCount)
{
    CK_ULONG n = sizeof g_mechs / sizeof g_mechs[0];
    CK_ULONG i;
    FAULT("C_GetMechanismList");
    if (pulCount == NULL || slotID >= g_token_slots)
        return CKR_SLOT_ID_INVALID;
    if (pList == NULL) {
        *pulCount = n;
        return CKR_OK;
    }
    if (*pulCount < n) {
        *pulCount = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (i = 0; i < n; i++)
        pList[i] = g_mechs[i];
    *pulCount = n;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID,
                                              CK_MECHANISM_TYPE type,
                                              CK_MECHANISM_INFO_PTR pInfo)
{
    CK_ULONG i;
    int known = 0;
    FAULT("C_GetMechanismInfo");
    if (pInfo == NULL || slotID >= g_token_slots)
        return CKR_SLOT_ID_INVALID;
    for (i = 0; i < sizeof g_mechs / sizeof g_mechs[0]; i++)
        if (g_mechs[i] == type) {
            known = 1;
            break;
        }
    if (!known)
        return CKR_MECHANISM_INVALID;
    memset(pInfo, 0, sizeof *pInfo);
    pInfo->ulMinKeySize = 0;
    pInfo->ulMaxKeySize = 4096;
    pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY |
                   CKF_WRAP | CKF_UNWRAP | CKF_GENERATE |
                   CKF_GENERATE_KEY_PAIR | CKF_DERIVE;
    return CKR_OK;
}

/* ---- sessions & login -------------------------------------------------- */

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags,
                                         CK_VOID_PTR pApplication,
                                         CK_NOTIFY Notify,
                                         CK_SESSION_HANDLE_PTR phSession)
{
    CK_ULONG i;
    (void)pApplication;
    (void)Notify;
    FAULT("C_OpenSession");
    if (phSession == NULL || slotID >= g_token_slots)
        return CKR_SLOT_ID_INVALID;
    if (!(flags & CKF_SERIAL_SESSION))
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    for (i = 0; i < MOCK_MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            memset(&g_sessions[i], 0, sizeof g_sessions[i]);
            g_sessions[i].in_use = 1;
            g_sessions[i].slot = slotID;
            *phSession = (CK_SESSION_HANDLE)(i + 1);
            return CKR_OK;
        }
    }
    return CKR_SESSION_COUNT;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
    mock_session *s;
    FAULT("C_CloseSession");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    memset(s, 0, sizeof *s);
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession,
                                   CK_USER_TYPE userType,
                                   CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    mock_session *s;
    (void)userType;
    FAULT("C_Login");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (pPin != NULL) {
        if (ulPinLen != strlen(g_pin) ||
            memcmp(pPin, g_pin, ulPinLen) != 0)
            return CKR_PIN_INCORRECT;
    }
    s->logged_in = 1;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
    mock_session *s;
    FAULT("C_Logout");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    s->logged_in = 0;
    return CKR_OK;
}

/* ---- token / user-PIN initialization ----------------------------------- */

/* C_InitToken / C_InitPIN are deliberately no-ops here: the mock holds no
 * persistent token state across processes, so a successful (re)initialization
 * is simply acknowledged and NOTHING is erased -- which is exactly what makes
 * them safe to drive from the p11init tests. Their reason for existing is the
 * FAULT() hook: MOCK_P11_FAIL=C_InitToken@1=CKR_TOKEN_WRITE_PROTECTED (or
 * C_InitPIN@1=CKR_PIN_INVALID) exercises the driver-error branches of
 * lib/pkcs11_init.c that a real, succeeding token never reaches. */
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID,
                                       CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                                       CK_UTF8CHAR_PTR pLabel)
{
    (void)pPin;
    (void)ulPinLen;
    (void)pLabel;
    FAULT("C_InitToken");
    if (slotID >= g_token_slots)
        return CKR_TOKEN_NOT_PRESENT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession,
                                     CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    mock_session *s;
    (void)pPin;
    (void)ulPinLen;
    FAULT("C_InitPIN");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_OK;
}

/* ---- object management ------------------------------------------------- */

CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession,
                                          CK_ATTRIBUTE_PTR pTemplate,
                                          CK_ULONG ulCount,
                                          CK_OBJECT_HANDLE_PTR phObject)
{
    CK_OBJECT_HANDLE h;
    FAULT("C_CreateObject");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (phObject == NULL)
        return CKR_ARGUMENTS_BAD;
    h = obj_create_from_template(pTemplate, ulCount);
    if (h == CK_INVALID_HANDLE)
        return CKR_DEVICE_MEMORY;
    *phObject = h;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession,
                                        CK_OBJECT_HANDLE hObject,
                                        CK_ATTRIBUTE_PTR pTemplate,
                                        CK_ULONG ulCount,
                                        CK_OBJECT_HANDLE_PTR phNewObject)
{
    mock_object *src;
    CK_OBJECT_HANDLE h;
    mock_object *dst;
    CK_ULONG i;
    FAULT("C_CopyObject");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    src = obj_from_handle(hObject);
    if (src == NULL)
        return CKR_OBJECT_HANDLE_INVALID;
    h = obj_alloc();
    if (h == CK_INVALID_HANDLE)
        return CKR_DEVICE_MEMORY;
    dst = obj_from_handle(h);
    for (i = 0; i < src->nattrs; i++) {
        if (obj_set_attr(dst, src->attrs[i].type,
                         src->attrs[i].value, src->attrs[i].len) != CKR_OK) {
            obj_free(dst);
            return CKR_DEVICE_MEMORY;
        }
    }
    for (i = 0; i < ulCount; i++) {
        if (obj_set_attr(dst, pTemplate[i].type,
                         pTemplate[i].pValue, pTemplate[i].ulValueLen) != CKR_OK) {
            obj_free(dst);
            return CKR_DEVICE_MEMORY;
        }
    }
    if (phNewObject != NULL)
        *phNewObject = h;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession,
                                           CK_OBJECT_HANDLE hObject)
{
    mock_object *o;
    FAULT("C_DestroyObject");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    o = obj_from_handle(hObject);
    if (o == NULL)
        return CKR_OBJECT_HANDLE_INVALID;
    pkey_drop(hObject);
    obj_free(o);
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession,
                                           CK_OBJECT_HANDLE hObject,
                                           CK_ULONG_PTR pulSize)
{
    mock_object *o;
    CK_ULONG i, sz = 0;
    FAULT("C_GetObjectSize");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    o = obj_from_handle(hObject);
    if (o == NULL)
        return CKR_OBJECT_HANDLE_INVALID;
    for (i = 0; i < o->nattrs; i++)
        sz += o->attrs[i].len;
    if (pulSize != NULL)
        *pulSize = sz;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession,
                                               CK_OBJECT_HANDLE hObject,
                                               CK_ATTRIBUTE_PTR pTemplate,
                                               CK_ULONG ulCount)
{
    mock_object *o;
    CK_ULONG i;
    CK_RV rc = CKR_OK;
    FAULT("C_GetAttributeValue");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    o = obj_from_handle(hObject);
    if (o == NULL)
        return CKR_OBJECT_HANDLE_INVALID;
    for (i = 0; i < ulCount; i++) {
        mock_attr *a = obj_find_attr(o, pTemplate[i].type);
        if (a == NULL) {
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            rc = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        }
        if (pTemplate[i].pValue == NULL) {
            pTemplate[i].ulValueLen = a->len;    /* sizing pass */
            continue;
        }
        if (pTemplate[i].ulValueLen < a->len) {
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            rc = CKR_BUFFER_TOO_SMALL;
            continue;
        }
        if (a->len > 0)
            memcpy(pTemplate[i].pValue, a->value, a->len);
        pTemplate[i].ulValueLen = a->len;
    }
    return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession,
                                               CK_OBJECT_HANDLE hObject,
                                               CK_ATTRIBUTE_PTR pTemplate,
                                               CK_ULONG ulCount)
{
    mock_object *o;
    CK_ULONG i;
    FAULT("C_SetAttributeValue");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    o = obj_from_handle(hObject);
    if (o == NULL)
        return CKR_OBJECT_HANDLE_INVALID;
    for (i = 0; i < ulCount; i++)
        if (obj_set_attr(o, pTemplate[i].type,
                         pTemplate[i].pValue, pTemplate[i].ulValueLen) != CKR_OK)
            return CKR_DEVICE_MEMORY;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession,
                                             CK_ATTRIBUTE_PTR pTemplate,
                                             CK_ULONG ulCount)
{
    mock_session *s;
    CK_ULONG i;
    FAULT("C_FindObjectsInit");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (ulCount > MOCK_MAX_ATTRS)
        return CKR_ARGUMENTS_BAD;
    s->find_active = 1;
    s->find_pos = 0;
    s->find_ntmpl = ulCount;
    for (i = 0; i < ulCount; i++)
        s->find_tmpl[i] = pTemplate[i];
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession,
                                         CK_OBJECT_HANDLE_PTR phObject,
                                         CK_ULONG ulMaxObjectCount,
                                         CK_ULONG_PTR pulObjectCount)
{
    mock_session *s;
    CK_ULONG found = 0;
    FAULT("C_FindObjects");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->find_active)
        return CKR_OPERATION_NOT_INITIALIZED;
    while (s->find_pos < MOCK_MAX_OBJECTS && found < ulMaxObjectCount) {
        mock_object *o = &g_objects[s->find_pos];
        CK_ULONG idx = s->find_pos;
        s->find_pos++;
        if (o->in_use &&
            obj_matches(o, s->find_tmpl, s->find_ntmpl))
            phObject[found++] = (CK_OBJECT_HANDLE)(idx + 1);
    }
    if (pulObjectCount != NULL)
        *pulObjectCount = found;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
    mock_session *s;
    FAULT("C_FindObjectsFinal");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    s->find_active = 0;
    s->find_ntmpl = 0;
    return CKR_OK;
}

/* ---- random ------------------------------------------------------------ */

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession,
                                            CK_BYTE_PTR pRandomData,
                                            CK_ULONG ulRandomLen)
{
    CK_ULONG i;
    FAULT("C_GenerateRandom");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    /* Deterministic filler; not cryptographic, sufficient for the tools. */
    for (i = 0; i < ulRandomLen; i++)
        pRandomData[i] = (CK_BYTE)(0xA5 ^ (i & 0xFF));
    return CKR_OK;
}

/* ---- crypto: helpers --------------------------------------------------- */

/* Read a CK_ULONG-valued attribute from a template; return def if absent. */
static CK_ULONG tmpl_ulong(CK_ATTRIBUTE_PTR t, CK_ULONG n,
                           CK_ATTRIBUTE_TYPE type, CK_ULONG def)
{
    CK_ULONG i;
    for (i = 0; i < n; i++)
        if (t[i].type == type && t[i].pValue != NULL &&
            t[i].ulValueLen == sizeof(CK_ULONG))
            return *(CK_ULONG *)t[i].pValue;
    return def;
}

/* Create a CKO_SECRET_KEY object from a caller template plus a computed key
 * value. CKA_CLASS/CKA_KEY_TYPE default sensibly if the template omits them. */
static CK_OBJECT_HANDLE mk_secret(CK_ATTRIBUTE_PTR t, CK_ULONG n,
                                  const unsigned char *value, CK_ULONG vlen)
{
    CK_OBJECT_HANDLE h = obj_create_from_template(t, n);
    mock_object *o;
    if (h == CK_INVALID_HANDLE)
        return h;
    o = obj_from_handle(h);
    if (obj_find_attr(o, CKA_CLASS) == NULL) {
        CK_OBJECT_CLASS c = CKO_SECRET_KEY;
        obj_set_attr(o, CKA_CLASS, &c, sizeof c);
    }
    if (obj_set_attr(o, CKA_VALUE, value, vlen) != CKR_OK) {
        obj_free(o);
        return CK_INVALID_HANDLE;
    }
    return h;
}

/* A deterministic, key-dependent "cipher" used only for KCV/encrypt output.
 * Not real crypto: reproducible so a KCV is stable, and depends on the key. */
static void fake_cipher(const unsigned char *key, CK_ULONG klen,
                        const unsigned char *in, CK_ULONG len,
                        unsigned char *out)
{
    CK_ULONG i;
    for (i = 0; i < len; i++) {
        unsigned char k = klen ? key[i % klen] : 0;
        out[i] = (unsigned char)(in[i] ^ k ^ (unsigned char)(0x5A + (i & 0x1F)));
    }
}

/* ---- crypto: key generation -------------------------------------------- */

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession,
                                         CK_MECHANISM_PTR pMechanism,
                                         CK_ATTRIBUTE_PTR pTemplate,
                                         CK_ULONG ulCount,
                                         CK_OBJECT_HANDLE_PTR phKey)
{
    CK_ULONG vlen;
    CK_KEY_TYPE kt;
    unsigned char value[64];
    CK_OBJECT_HANDLE h;
    CK_ULONG i;
    FAULT("C_GenerateKey");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL || phKey == NULL)
        return CKR_ARGUMENTS_BAD;

    switch (pMechanism->mechanism) {
    case CKM_AES_KEY_GEN:          kt = CKK_AES;            vlen = 32; break;
    case CKM_DES3_KEY_GEN:         kt = CKK_DES3;           vlen = 24; break;
    case CKM_GENERIC_SECRET_KEY_GEN: kt = CKK_GENERIC_SECRET; vlen = 32; break;
    default:                       return CKR_MECHANISM_INVALID;
    }
    vlen = tmpl_ulong(pTemplate, ulCount, CKA_VALUE_LEN, vlen);
    if (vlen == 0 || vlen > sizeof value)
        return CKR_KEY_SIZE_RANGE;
    for (i = 0; i < vlen; i++)
        value[i] = (unsigned char)(0x11 * (i + 1));

    h = mk_secret(pTemplate, ulCount, value, vlen);
    if (h == CK_INVALID_HANDLE)
        return CKR_DEVICE_MEMORY;
    {
        mock_object *o = obj_from_handle(h);
        if (obj_find_attr(o, CKA_KEY_TYPE) == NULL)
            obj_set_attr(o, CKA_KEY_TYPE, &kt, sizeof kt);
    }
    *phKey = h;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(
        CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
        CK_ATTRIBUTE_PTR pPubTmpl, CK_ULONG ulPubCount,
        CK_ATTRIBUTE_PTR pPrivTmpl, CK_ULONG ulPrivCount,
        CK_OBJECT_HANDLE_PTR phPub, CK_OBJECT_HANDLE_PTR phPriv)
{
    FAULT("C_GenerateKeyPair");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL || phPub == NULL || phPriv == NULL)
        return CKR_ARGUMENTS_BAD;

    if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN ||
        pMechanism->mechanism == CKM_RSA_X9_31_KEY_PAIR_GEN) {
        CK_ULONG bits = tmpl_ulong(pPubTmpl, ulPubCount, CKA_MODULUS_BITS, 2048);
        EVP_PKEY *pk = EVP_RSA_gen((unsigned int)bits);
        BIGNUM *bn_n = NULL, *bn_e = NULL;
        unsigned char nbuf[1024], ebuf[16];
        int nlen, elen;
        CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY, privc = CKO_PRIVATE_KEY;
        CK_KEY_TYPE rsa = CKK_RSA;
        CK_OBJECT_HANDLE hp, hs;
        mock_object *op, *os;

        if (pk == NULL)
            return CKR_FUNCTION_FAILED;
        if (!EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &bn_n) ||
            !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_E, &bn_e)) {
            BN_free(bn_n); BN_free(bn_e); EVP_PKEY_free(pk);
            return CKR_FUNCTION_FAILED;
        }
        nlen = BN_bn2bin(bn_n, nbuf);
        elen = BN_bn2bin(bn_e, ebuf);
        BN_free(bn_n); BN_free(bn_e);

        hp = obj_create_from_template(pPubTmpl, ulPubCount);
        hs = obj_create_from_template(pPrivTmpl, ulPrivCount);
        if (hp == CK_INVALID_HANDLE || hs == CK_INVALID_HANDLE) {
            EVP_PKEY_free(pk);
            return CKR_DEVICE_MEMORY;
        }
        op = obj_from_handle(hp);
        os = obj_from_handle(hs);
        obj_set_attr(op, CKA_CLASS, &pubc, sizeof pubc);
        obj_set_attr(op, CKA_KEY_TYPE, &rsa, sizeof rsa);
        obj_set_attr(op, CKA_MODULUS, nbuf, (CK_ULONG)nlen);
        obj_set_attr(op, CKA_PUBLIC_EXPONENT, ebuf, (CK_ULONG)elen);
        obj_set_attr(os, CKA_CLASS, &privc, sizeof privc);
        obj_set_attr(os, CKA_KEY_TYPE, &rsa, sizeof rsa);
        obj_set_attr(os, CKA_MODULUS, nbuf, (CK_ULONG)nlen);
        obj_set_attr(os, CKA_PUBLIC_EXPONENT, ebuf, (CK_ULONG)elen);

        EVP_PKEY_up_ref(pk);
        pkey_put(hp, pk);          /* public handle owns one ref */
        pkey_put(hs, pk);          /* private handle owns the other */
        *phPub = hp;
        *phPriv = hs;
        return CKR_OK;
    }

#ifdef MOCK_HAVE_PQC
    if (pMechanism->mechanism == CKM_ML_DSA_KEY_PAIR_GEN ||
        pMechanism->mechanism == CKM_SLH_DSA_KEY_PAIR_GEN ||
        pMechanism->mechanism == CKM_ML_KEM_KEY_PAIR_GEN) {
        CK_ULONG ps = tmpl_ulong(pPubTmpl, ulPubCount, CKA_PARAMETER_SET, 0);
        const char *name = pqc_ossl_name(pMechanism->mechanism, ps);
        CK_KEY_TYPE kt = pqc_key_type(pMechanism->mechanism);
        CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY, privc = CKO_PRIVATE_KEY;
        unsigned char pub[8192];
        size_t publen = sizeof pub;
        EVP_PKEY *pk;
        CK_OBJECT_HANDLE hp, hs;
        mock_object *op, *os;

        if (name == NULL)
            return CKR_TEMPLATE_INCONSISTENT;   /* unknown parameter set */
        pk = EVP_PKEY_Q_keygen(NULL, NULL, name);
        if (pk == NULL)
            return CKR_FUNCTION_FAILED;
        /* raw public key -> stored on the public object as CKA_VALUE, which is
         * what the tools read (with CKA_PARAMETER_SET) to rebuild the SPKI. */
        if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY,
                                            pub, sizeof pub, &publen) != 1) {
            EVP_PKEY_free(pk);
            return CKR_FUNCTION_FAILED;
        }
        hp = obj_create_from_template(pPubTmpl, ulPubCount);
        hs = obj_create_from_template(pPrivTmpl, ulPrivCount);
        if (hp == CK_INVALID_HANDLE || hs == CK_INVALID_HANDLE) {
            EVP_PKEY_free(pk);
            return CKR_DEVICE_MEMORY;
        }
        op = obj_from_handle(hp);
        os = obj_from_handle(hs);
        /* CKA_PARAMETER_SET / CKA_LABEL / CKA_ID already copied from the
         * templates; add the class, key type and the raw public value. */
        obj_set_attr(op, CKA_CLASS, &pubc, sizeof pubc);
        obj_set_attr(op, CKA_KEY_TYPE, &kt, sizeof kt);
        obj_set_attr(op, CKA_VALUE, pub, (CK_ULONG)publen);
        obj_set_attr(os, CKA_CLASS, &privc, sizeof privc);
        obj_set_attr(os, CKA_KEY_TYPE, &kt, sizeof kt);

        EVP_PKEY_up_ref(pk);
        pkey_put(hp, pk);          /* public handle owns one ref */
        pkey_put(hs, pk);          /* private handle owns the other (signs) */
        *phPub = hp;
        *phPriv = hs;
        return CKR_OK;
    }
#endif /* MOCK_HAVE_PQC */

    return CKR_MECHANISM_INVALID;  /* EC/DSA/EdDSA: added in a later phase */
}

/* ---- crypto: encrypt (used for KCV) ------------------------------------ */

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession,
                                         CK_MECHANISM_PTR pMechanism,
                                         CK_OBJECT_HANDLE hKey)
{
    mock_session *s;
    FAULT("C_EncryptInit");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (obj_from_handle(hKey) == NULL)
        return CKR_KEY_HANDLE_INVALID;
    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;
    s->op_mech = pMechanism->mechanism;
    s->op_key = hKey;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession,
                                     CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                     CK_BYTE_PTR pEncryptedData,
                                     CK_ULONG_PTR pulEncryptedDataLen)
{
    mock_session *s;
    mock_object *k;
    mock_attr *val;
    FAULT("C_Encrypt");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    k = obj_from_handle(s->op_key);
    if (k == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;
    if (pulEncryptedDataLen == NULL)
        return CKR_ARGUMENTS_BAD;
    if (pEncryptedData == NULL) {
        *pulEncryptedDataLen = ulDataLen;   /* sizing pass */
        return CKR_OK;
    }
    if (*pulEncryptedDataLen < ulDataLen) {
        *pulEncryptedDataLen = ulDataLen;
        return CKR_BUFFER_TOO_SMALL;
    }
    val = obj_find_attr(k, CKA_VALUE);
    fake_cipher(val ? val->value : NULL, val ? val->len : 0,
                pData, ulDataLen, pEncryptedData);
    *pulEncryptedDataLen = ulDataLen;
    return CKR_OK;
}

/* ---- crypto: sign (PQC one-shot ML-DSA / SLH-DSA) ---------------------- */

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession,
                                      CK_MECHANISM_PTR pMechanism,
                                      CK_OBJECT_HANDLE hKey)
{
    mock_session *s;
    FAULT("C_SignInit");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (obj_from_handle(hKey) == NULL)
        return CKR_KEY_HANDLE_INVALID;
    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;
    s->op_mech = pMechanism->mechanism;
    s->op_key = hKey;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession,
                                  CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                  CK_BYTE_PTR pSignature,
                                  CK_ULONG_PTR pulSignatureLen)
{
    mock_session *s;
    FAULT("C_Sign");
    s = sess_from_handle(hSession);
    if (s == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (pulSignatureLen == NULL)
        return CKR_ARGUMENTS_BAD;
    if (obj_from_handle(s->op_key) == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;
#ifdef MOCK_HAVE_PQC
    if (s->op_mech == CKM_ML_DSA || s->op_mech == CKM_SLH_DSA) {
        /* One-shot signature with the private EVP_PKEY stored at keygen time.
         * ML-DSA/SLH-DSA sign the raw message (no external digest, mdname NULL),
         * exactly like EdDSA. The result verifies against the SPKI the tools
         * rebuild from CKA_VALUE. */
        EVP_PKEY *pk = pkey_get(s->op_key);
        EVP_MD_CTX *mc;
        size_t need = 0;
        CK_RV rv = CKR_OK;

        if (pk == NULL)
            return CKR_KEY_HANDLE_INVALID;
        mc = EVP_MD_CTX_new();
        if (mc == NULL)
            return CKR_DEVICE_MEMORY;
        if (EVP_DigestSignInit_ex(mc, NULL, NULL, NULL, NULL, pk, NULL) != 1 ||
            EVP_DigestSign(mc, NULL, &need, pData, ulDataLen) != 1) {
            EVP_MD_CTX_free(mc);
            return CKR_FUNCTION_FAILED;
        }
        if (pSignature == NULL) {                 /* sizing pass */
            *pulSignatureLen = (CK_ULONG)need;
            EVP_MD_CTX_free(mc);
            return CKR_OK;
        }
        if ((size_t)*pulSignatureLen < need) {
            *pulSignatureLen = (CK_ULONG)need;
            EVP_MD_CTX_free(mc);
            return CKR_BUFFER_TOO_SMALL;
        }
        {
            size_t slen = (size_t)*pulSignatureLen;
            if (EVP_DigestSign(mc, pSignature, &slen, pData, ulDataLen) != 1)
                rv = CKR_FUNCTION_FAILED;
            else
                *pulSignatureLen = (CK_ULONG)slen;
        }
        EVP_MD_CTX_free(mc);
        return rv;
    }
#endif /* MOCK_HAVE_PQC */
    return CKR_MECHANISM_INVALID;
}

/* ---- crypto: wrap / unwrap --------------------------------------------- */

CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession,
                                     CK_MECHANISM_PTR pMechanism,
                                     CK_OBJECT_HANDLE hWrappingKey,
                                     CK_OBJECT_HANDLE hKey,
                                     CK_BYTE_PTR pWrappedKey,
                                     CK_ULONG_PTR pulWrappedKeyLen)
{
    mock_object *target;
    mock_attr *val;
    FAULT("C_WrapKey");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL || pulWrappedKeyLen == NULL)
        return CKR_ARGUMENTS_BAD;
    target = obj_from_handle(hKey);
    if (target == NULL)
        return CKR_KEY_HANDLE_INVALID;
    val = obj_find_attr(target, CKA_VALUE);
    if (val == NULL)
        return CKR_KEY_UNEXTRACTABLE;

    if (pMechanism->mechanism == CKM_RSA_PKCS ||
        pMechanism->mechanism == CKM_RSA_PKCS_OAEP) {
        /* RSA key transport: encrypt the target value with the public key. */
        EVP_PKEY *pk = pkey_get(hWrappingKey);
        EVP_PKEY_CTX *ctx;
        size_t out = 0;
        int pad = (pMechanism->mechanism == CKM_RSA_PKCS_OAEP)
                      ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING;
        if (pk == NULL)
            return CKR_WRAPPING_KEY_HANDLE_INVALID;
        ctx = EVP_PKEY_CTX_new(pk, NULL);
        if (ctx == NULL || EVP_PKEY_encrypt_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0 ||
            EVP_PKEY_encrypt(ctx, NULL, &out, val->value, val->len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return CKR_FUNCTION_FAILED;
        }
        if (pWrappedKey == NULL) {
            *pulWrappedKeyLen = (CK_ULONG)out;
            EVP_PKEY_CTX_free(ctx);
            return CKR_OK;
        }
        if (*pulWrappedKeyLen < out) {
            *pulWrappedKeyLen = (CK_ULONG)out;
            EVP_PKEY_CTX_free(ctx);
            return CKR_BUFFER_TOO_SMALL;
        }
        if (EVP_PKEY_encrypt(ctx, pWrappedKey, &out,
                             val->value, val->len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return CKR_FUNCTION_FAILED;
        }
        *pulWrappedKeyLen = (CK_ULONG)out;
        EVP_PKEY_CTX_free(ctx);
        return CKR_OK;
    }

    /* Symmetric wrap (AES_KEY_WRAP(_PAD), CBC-PAD, DES3-CBC-PAD, ...): an
     * identity "wrap" so an unwrap round-trips the exact key value (and its
     * KCV). Sufficient to exercise the tool-side algorithm selection and
     * output serialization, which is the point of the mock. */
    if (pWrappedKey == NULL) {
        *pulWrappedKeyLen = val->len;
        return CKR_OK;
    }
    if (*pulWrappedKeyLen < val->len) {
        *pulWrappedKeyLen = val->len;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(pWrappedKey, val->value, val->len);
    *pulWrappedKeyLen = val->len;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hUnwrappingKey,
                                       CK_BYTE_PTR pWrappedKey,
                                       CK_ULONG ulWrappedKeyLen,
                                       CK_ATTRIBUTE_PTR pTemplate,
                                       CK_ULONG ulCount,
                                       CK_OBJECT_HANDLE_PTR phKey)
{
    CK_OBJECT_HANDLE h;
    FAULT("C_UnwrapKey");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL || phKey == NULL)
        return CKR_ARGUMENTS_BAD;

    if (pMechanism->mechanism == CKM_RSA_PKCS ||
        pMechanism->mechanism == CKM_RSA_PKCS_OAEP) {
        EVP_PKEY *pk = pkey_get(hUnwrappingKey);
        EVP_PKEY_CTX *ctx;
        unsigned char plain[1024];
        size_t plen = sizeof plain;
        int pad = (pMechanism->mechanism == CKM_RSA_PKCS_OAEP)
                      ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING;
        if (pk == NULL)
            return CKR_UNWRAPPING_KEY_HANDLE_INVALID;
        ctx = EVP_PKEY_CTX_new(pk, NULL);
        if (ctx == NULL || EVP_PKEY_decrypt_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0 ||
            EVP_PKEY_decrypt(ctx, plain, &plen,
                             pWrappedKey, ulWrappedKeyLen) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return CKR_WRAPPED_KEY_INVALID;
        }
        EVP_PKEY_CTX_free(ctx);
        h = mk_secret(pTemplate, ulCount, plain, (CK_ULONG)plen);
        if (h == CK_INVALID_HANDLE)
            return CKR_DEVICE_MEMORY;
        *phKey = h;
        return CKR_OK;
    }

    /* Symmetric: reverse of the identity wrap above. */
    h = mk_secret(pTemplate, ulCount, pWrappedKey, ulWrappedKeyLen);
    if (h == CK_INVALID_HANDLE)
        return CKR_DEVICE_MEMORY;
    *phKey = h;
    return CKR_OK;
}

/* ---- crypto: derive (CKM_XOR_BASE_AND_DATA, used by p11keycomp) --------- */

CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hBaseKey,
                                       CK_ATTRIBUTE_PTR pTemplate,
                                       CK_ULONG ulCount,
                                       CK_OBJECT_HANDLE_PTR phKey)
{
    mock_object *base;
    mock_attr *bval;
    unsigned char out[64];
    CK_ULONG i, vlen;
    CK_OBJECT_HANDLE h;
    FAULT("C_DeriveKey");
    if (sess_from_handle(hSession) == NULL)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL || phKey == NULL)
        return CKR_ARGUMENTS_BAD;
    base = obj_from_handle(hBaseKey);
    if (base == NULL)
        return CKR_KEY_HANDLE_INVALID;
    bval = obj_find_attr(base, CKA_VALUE);
    if (bval == NULL)
        return CKR_KEY_HANDLE_INVALID;
    vlen = bval->len;
    if (vlen > sizeof out)
        vlen = sizeof out;
    memcpy(out, bval->value, vlen);

    if (pMechanism->mechanism == CKM_XOR_BASE_AND_DATA) {
        CK_KEY_DERIVATION_STRING_DATA *d =
            (CK_KEY_DERIVATION_STRING_DATA *)pMechanism->pParameter;
        if (d != NULL && d->pData != NULL) {
            CK_ULONG n = d->ulLen < vlen ? d->ulLen : vlen;
            for (i = 0; i < n; i++)
                out[i] ^= d->pData[i];
        }
    } else {
        return CKR_MECHANISM_INVALID;
    }

    h = mk_secret(pTemplate, ulCount, out, vlen);
    if (h == CK_INVALID_HANDLE)
        return CKR_DEVICE_MEMORY;
    *phKey = h;
    return CKR_OK;
}

/* ------------------------------------------------------------------------- */
/* other slot stays NULL (the tools never dereference them).                  */

static CK_FUNCTION_LIST g_function_list = {
    { 3, 2 },                        /* version */
    /* Designated initializers: order-independent, and every function pointer
     * we do not set stays NULL. The tools only ever call the members wired
     * here (inventory confirmed against lib/ + src/). */
    .C_Initialize        = C_Initialize,
    .C_Finalize          = C_Finalize,
    .C_GetInfo           = C_GetInfo,
    .C_GetFunctionList   = C_GetFunctionList,
    .C_GetSlotList       = C_GetSlotList,
    .C_GetSlotInfo       = C_GetSlotInfo,
    .C_GetTokenInfo      = C_GetTokenInfo,
    .C_GetMechanismList  = C_GetMechanismList,
    .C_GetMechanismInfo  = C_GetMechanismInfo,
    .C_OpenSession       = C_OpenSession,
    .C_CloseSession      = C_CloseSession,
    .C_Login             = C_Login,
    .C_Logout            = C_Logout,
    .C_InitToken         = C_InitToken,
    .C_InitPIN           = C_InitPIN,
    .C_CreateObject      = C_CreateObject,
    .C_CopyObject        = C_CopyObject,
    .C_DestroyObject     = C_DestroyObject,
    .C_GetObjectSize     = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit   = C_FindObjectsInit,
    .C_FindObjects       = C_FindObjects,
    .C_FindObjectsFinal  = C_FindObjectsFinal,
    .C_GenerateKey       = C_GenerateKey,
    .C_GenerateKeyPair   = C_GenerateKeyPair,
    .C_EncryptInit       = C_EncryptInit,
    .C_Encrypt           = C_Encrypt,
    .C_SignInit          = C_SignInit,
    .C_Sign              = C_Sign,
    .C_WrapKey           = C_WrapKey,
    .C_UnwrapKey         = C_UnwrapKey,
    .C_DeriveKey         = C_DeriveKey,
    .C_GenerateRandom    = C_GenerateRandom,
};

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppList)
{
    if (ppList == NULL)
        return CKR_ARGUMENTS_BAD;
    *ppList = &g_function_list;
    return CKR_OK;
}
