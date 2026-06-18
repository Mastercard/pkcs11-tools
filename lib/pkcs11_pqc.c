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

#include <config.h>

#if defined(WITH_PQC)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "pkcs11lib.h"

/*
 * Central registry for the three supported Post-Quantum algorithms:
 * ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
 *
 * Each parameter set is, following OpenSSL 3.5 conventions, its own
 * algorithm/fetch name (e.g. "ML-DSA-65"), not an EC-style group parameter.
 * CLI names are the lower-case spelling and are matched case-insensitively.
 */

static const pqc_paramset_t pqc_paramsets[] = {
    /* ML-KEM (FIPS 203) - key encapsulation */
    { ml_kem,  { .mlkem  = CKP_ML_KEM_512  }, CKM_ML_KEM_KEY_PAIR_GEN,  CKM_ML_KEM,  "ml-kem-512",  "ML-KEM-512",  "CKP_ML_KEM_512"  },
    { ml_kem,  { .mlkem  = CKP_ML_KEM_768  }, CKM_ML_KEM_KEY_PAIR_GEN,  CKM_ML_KEM,  "ml-kem-768",  "ML-KEM-768",  "CKP_ML_KEM_768"  },
    { ml_kem,  { .mlkem  = CKP_ML_KEM_1024 }, CKM_ML_KEM_KEY_PAIR_GEN,  CKM_ML_KEM,  "ml-kem-1024", "ML-KEM-1024", "CKP_ML_KEM_1024" },

    /* ML-DSA (FIPS 204) - lattice signatures */
    { ml_dsa,  { .mldsa  = CKP_ML_DSA_44 },   CKM_ML_DSA_KEY_PAIR_GEN,  CKM_ML_DSA,  "ml-dsa-44",   "ML-DSA-44",   "CKP_ML_DSA_44"   },
    { ml_dsa,  { .mldsa  = CKP_ML_DSA_65 },   CKM_ML_DSA_KEY_PAIR_GEN,  CKM_ML_DSA,  "ml-dsa-65",   "ML-DSA-65",   "CKP_ML_DSA_65"   },
    { ml_dsa,  { .mldsa  = CKP_ML_DSA_87 },   CKM_ML_DSA_KEY_PAIR_GEN,  CKM_ML_DSA,  "ml-dsa-87",   "ML-DSA-87",   "CKP_ML_DSA_87"   },

    /* SLH-DSA (FIPS 205) - hash-based signatures */
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHA2_128S  }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-sha2-128s",  "SLH-DSA-SHA2-128s",  "CKP_SLH_DSA_SHA2_128S"  },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHAKE_128S }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-shake-128s", "SLH-DSA-SHAKE-128s", "CKP_SLH_DSA_SHAKE_128S" },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHA2_128F  }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-sha2-128f",  "SLH-DSA-SHA2-128f",  "CKP_SLH_DSA_SHA2_128F"  },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHAKE_128F }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-shake-128f", "SLH-DSA-SHAKE-128f", "CKP_SLH_DSA_SHAKE_128F" },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHA2_192S  }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-sha2-192s",  "SLH-DSA-SHA2-192s",  "CKP_SLH_DSA_SHA2_192S"  },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHAKE_192S }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-shake-192s", "SLH-DSA-SHAKE-192s", "CKP_SLH_DSA_SHAKE_192S" },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHA2_192F  }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-sha2-192f",  "SLH-DSA-SHA2-192f",  "CKP_SLH_DSA_SHA2_192F"  },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHAKE_192F }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-shake-192f", "SLH-DSA-SHAKE-192f", "CKP_SLH_DSA_SHAKE_192F" },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHA2_256S  }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-sha2-256s",  "SLH-DSA-SHA2-256s",  "CKP_SLH_DSA_SHA2_256S"  },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHAKE_256S }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-shake-256s", "SLH-DSA-SHAKE-256s", "CKP_SLH_DSA_SHAKE_256S" },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHA2_256F  }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-sha2-256f",  "SLH-DSA-SHA2-256f",  "CKP_SLH_DSA_SHA2_256F"  },
    { slh_dsa, { .slhdsa = CKP_SLH_DSA_SHAKE_256F }, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, "slh-dsa-shake-256f", "SLH-DSA-SHAKE-256f", "CKP_SLH_DSA_SHAKE_256F" },
};

#define PQC_NUM_PARAMSETS (sizeof pqc_paramsets / sizeof(pqc_paramset_t))

/* keyword table for the '-k' command-line option */
static const struct {
    key_type_t  keytype;
    const char *kw;
} pqc_keywords[] = {
    { ml_kem,  "mlkem"  },
    { ml_dsa,  "mldsa"  },
    { slh_dsa, "slhdsa" },
};

#define PQC_NUM_KEYWORDS (sizeof pqc_keywords / sizeof pqc_keywords[0])

/* default parameter set name per algorithm, matching common NIST category 2-3 choices */
static const char *pqc_default_name[] = {
    /* ml_kem  */ "ml-kem-768",
    /* ml_dsa  */ "ml-dsa-65",
    /* slh_dsa */ "slh-dsa-sha2-128s",
};


key_type_t pkcs11_pqc_keytype_from_kw(const char *kw)
{
    size_t i;

    if(kw==NULL) { return unknown; }

    for(i=0; i<PQC_NUM_KEYWORDS; i++) {
	if(strcasecmp(kw, pqc_keywords[i].kw)==0) {
	    return pqc_keywords[i].keytype;
	}
    }
    return unknown;
}


const char *pkcs11_pqc_keytype_kw(key_type_t keytype)
{
    size_t i;

    for(i=0; i<PQC_NUM_KEYWORDS; i++) {
	if(pqc_keywords[i].keytype==keytype) {
	    return pqc_keywords[i].kw;
	}
    }
    return NULL;
}


const pqc_paramset_t *pkcs11_pqc_paramset_from_name(const char *name)
{
    size_t i;

    if(name==NULL) { return NULL; }

    for(i=0; i<PQC_NUM_PARAMSETS; i++) {
	if(strcasecmp(name, pqc_paramsets[i].cliname)==0) {
	    return &pqc_paramsets[i];
	}
    }
    return NULL;
}


/* return the CKA_PARAMETER_SET value (CKP_*) held by a descriptor, reading the
 * union member that matches its key type */
CK_ULONG pkcs11_pqc_paramset_value(const pqc_paramset_t *ps)
{
    if(ps==NULL) { return 0; }

    switch(ps->keytype) {
    case ml_kem:  return ps->paramset.mlkem;
    case ml_dsa:  return ps->paramset.mldsa;
    case slh_dsa: return ps->paramset.slhdsa;
    default:      return 0;
    }
}


const pqc_paramset_t *pkcs11_pqc_paramset_from_value(key_type_t keytype, CK_ULONG paramset)
{
    size_t i;

    for(i=0; i<PQC_NUM_PARAMSETS; i++) {
	if(pqc_paramsets[i].keytype==keytype && pkcs11_pqc_paramset_value(&pqc_paramsets[i])==paramset) {
	    return &pqc_paramsets[i];
	}
    }
    return NULL;
}


const pqc_paramset_t *pkcs11_pqc_default_paramset(key_type_t keytype)
{
    switch(keytype) {
    case ml_kem:  return pkcs11_pqc_paramset_from_name(pqc_default_name[0]);
    case ml_dsa:  return pkcs11_pqc_paramset_from_name(pqc_default_name[1]);
    case slh_dsa: return pkcs11_pqc_paramset_from_name(pqc_default_name[2]);
    default:      return NULL;
    }
}


/*
 * Return the "parameter" portion of a CLI name, i.e. the part shown inside the
 * parentheses by the listing tools and accepted as the keygen selector:
 *   "ml-kem-768"        -> "768"
 *   "ml-dsa-65"         -> "65"
 *   "slh-dsa-sha2-128s" -> "sha2-128s"
 * The family prefix is stripped from the canonical (cliname) spelling.
 */
static const char *pqc_paramset_suffix(const pqc_paramset_t *ps)
{
    static const struct { key_type_t keytype; const char *prefix; } prefixes[] = {
	{ ml_kem,  "ml-kem-"  },
	{ ml_dsa,  "ml-dsa-"  },
	{ slh_dsa, "slh-dsa-" },
    };
    size_t i;

    for(i=0; i<sizeof prefixes/sizeof prefixes[0]; i++) {
	if(prefixes[i].keytype==ps->keytype) {
	    size_t plen = strlen(prefixes[i].prefix);
	    if(strncmp(ps->cliname, prefixes[i].prefix, plen)==0) {
		return ps->cliname + plen;
	    }
	}
    }
    return ps->cliname;
}


const char *pkcs11_pqc_paramset_dispname(const pqc_paramset_t *ps, char *buf, size_t buflen)
{
    const char *kw;

    if(ps==NULL || buf==NULL || buflen==0) { return NULL; }

    kw = pkcs11_pqc_keytype_kw(ps->keytype);
    snprintf(buf, buflen, "%s(%s)", kw ? kw : "pqc", pqc_paramset_suffix(ps));
    return buf;
}


const pqc_paramset_t *pkcs11_pqc_paramset_from_selector(key_type_t keytype, CK_ULONG kb, const char *qstr)
{
    size_t i;

    switch(keytype) {
    case ml_kem:
    case ml_dsa:
	/* ML-KEM and ML-DSA are selected by their numeric strength via -b */
	if(kb != 0) {
	    for(i=0; i<PQC_NUM_PARAMSETS; i++) {
		if(pqc_paramsets[i].keytype==keytype &&
		   strtoul(pqc_paramset_suffix(&pqc_paramsets[i]), NULL, 10)==kb) {
		    return &pqc_paramsets[i];
		}
	    }
	    return NULL;
	}
	/* no -b: accept a full canonical name passed via -q, else default */
	if(qstr != NULL) {
	    const pqc_paramset_t *ps = pkcs11_pqc_paramset_from_name(qstr);
	    if(ps && ps->keytype==keytype) { return ps; }
	    return NULL;
	}
	return pkcs11_pqc_default_paramset(keytype);

    case slh_dsa:
	/* SLH-DSA is selected by its {sha2,shake}-{128,192,256}{s,f} variant via -q */
	if(qstr != NULL) {
	    for(i=0; i<PQC_NUM_PARAMSETS; i++) {
		if(pqc_paramsets[i].keytype==slh_dsa &&
		   strcasecmp(pqc_paramset_suffix(&pqc_paramsets[i]), qstr)==0) {
		    return &pqc_paramsets[i];
		}
	    }
	    /* fall back to a full canonical name (e.g. slh-dsa-sha2-128s) */
	    {
		const pqc_paramset_t *ps = pkcs11_pqc_paramset_from_name(qstr);
		if(ps && ps->keytype==slh_dsa) { return ps; }
	    }
	    return NULL;
	}
	return pkcs11_pqc_default_paramset(slh_dsa);

    default:
	return NULL;
    }
}


void pkcs11_pqc_print_paramsets(FILE *fp, key_type_t keytype)
{
    size_t i;

    for(i=0; i<PQC_NUM_PARAMSETS; i++) {
	if(pqc_paramsets[i].keytype==keytype) {
	    fprintf(fp, "    %s\n", pqc_paramsets[i].cliname);
	}
    }
}

#endif /* WITH_PQC */

/* EOF */
