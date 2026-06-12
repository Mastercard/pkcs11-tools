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
 * EVP_PKEY helpers using only stable OpenSSL 3 APIs:
 *   - OSSL_PARAM / OSSL_PARAM_BLD
 *   - EVP_PKEY_fromdata
 *   - EVP_PKEY_get_bn_param / get_octet_string_param / get_utf8_string_param
 *   - OSSL_ENCODER / OSSL_DECODER
 *
 * Used to replace deprecated low-level APIs (RSA_new + RSA_set0_*,
 * DSA_get0_*, DH_get0_*, EC_KEY_*, EVP_PKEY_set1_RSA, PEM_*params, etc.).
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/ec.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/sha.h>

#include "pkcs11lib.h"


/* ---------------------------------------------------------------------- */
/* Generic getters                                                          */
/* ---------------------------------------------------------------------- */

/*
 * Fetch a BIGNUM-typed OSSL parameter from an EVP_PKEY.
 *
 * Thin wrapper over EVP_PKEY_get_bn_param() that always sets *out (NULL on
 * failure, freshly allocated BIGNUM on success). Caller owns *out and must
 * BN_free() it on success.
 *
 * Returns 1 on success, 0 on any failure (NULL inputs, missing parameter,
 * allocation error). Replaces the deprecated RSA_get0_xxx / DSA_get0_xxx
 * / DH_get0_xxx accessors.
 */
int pkcs11_pkey_get_bn(EVP_PKEY *pk, const char *param, BIGNUM **out)
{
    if (pk == NULL || param == NULL || out == NULL) {
	return 0;
    }
    *out = NULL;
    if (EVP_PKEY_get_bn_param(pk, param, out) != 1) {
	/* libcrypto may have partially allocated *out before failing; clean it
	 * up so the caller sees NULL on the failure path */
	if (*out) {
	    BN_free(*out);
	    *out = NULL;
	}
	return 0;
    }
    return 1;
}


/*
 * Fetch an octet-string OSSL parameter (e.g. OSSL_PKEY_PARAM_PUB_KEY for EC,
 * OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY for Ed) from an EVP_PKEY.
 *
 * Two-pass: queries the required length first, then allocates and fills.
 * On success, *out is an OPENSSL_malloc'd buffer of *out_len bytes the
 * caller must OPENSSL_free(). On failure, both are set to NULL/0.
 *
 * Returns 1 on success, 0 on any failure.
 */
int pkcs11_pkey_get_octets(EVP_PKEY *pk, const char *param,
			   unsigned char **out, size_t *out_len)
{
    size_t needed = 0;
    unsigned char *buf = NULL;

    if (pk == NULL || param == NULL || out == NULL || out_len == NULL) {
	return 0;
    }
    *out = NULL;
    *out_len = 0;

    /* first pass: discover the required buffer size */
    if (EVP_PKEY_get_octet_string_param(pk, param, NULL, 0, &needed) != 1) {
	return 0;
    }
    if (needed == 0) {
	return 0;
    }
    buf = OPENSSL_malloc(needed);
    if (buf == NULL) {
	return 0;
    }
    /* second pass: fetch the actual octet string into the freshly sized buffer */
    if (EVP_PKEY_get_octet_string_param(pk, param, buf, needed, out_len) != 1) {
	OPENSSL_free(buf);
	return 0;
    }
    *out = buf;
    return 1;
}


/*
 * Fetch a UTF-8 string OSSL parameter (e.g. OSSL_PKEY_PARAM_GROUP_NAME for
 * EC) into a caller-supplied fixed buffer. The result is always
 * NUL-terminated (the buffer is zeroed up front so partial writes do not
 * leak garbage).
 *
 * Returns 1 on success, 0 on failure or if the value did not fit.
 */
int pkcs11_pkey_get_utf8(EVP_PKEY *pk, const char *param,
			 char *out, size_t out_size)
{
    if (pk == NULL || param == NULL || out == NULL || out_size == 0) {
	return 0;
    }
    out[0] = '\0';
    return EVP_PKEY_get_utf8_string_param(pk, param, out, out_size, NULL) == 1;
}


/* ---------------------------------------------------------------------- */
/* Builders (public-key only) via EVP_PKEY_fromdata                         */
/* ---------------------------------------------------------------------- */

/*
 * Internal: build an EVP_PKEY of the given algorithm `type` ("RSA", "DSA",
 * "DH", "EC", ...) from an already-built OSSL_PARAM array, using the
 * standard three-step fromdata sequence:
 *   1. allocate an EVP_PKEY_CTX from the algorithm name,
 *   2. initialize it for fromdata,
 *   3. assemble the EVP_PKEY from the OSSL_PARAMs and `selection` mask
 *      (e.g. EVP_PKEY_PUBLIC_KEY, EVP_PKEY_KEY_PARAMETERS).
 *
 * Returns a freshly allocated EVP_PKEY on success (caller frees with
 * EVP_PKEY_free()), or NULL on any failure.
 */
static EVP_PKEY *pkey_fromdata(const char *type, OSSL_PARAM *params, int selection)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pk = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    if (ctx == NULL) {
	goto out;
    }
    if (EVP_PKEY_fromdata_init(ctx) != 1) {
	goto out;
    }
    if (EVP_PKEY_fromdata(ctx, &pk, selection, params) != 1) {
	/* defensive: ensure we never leak a half-built key on failure */
	pk = NULL;
	goto out;
    }
out:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return pk;
}


/*
 * Build an RSA public-key EVP_PKEY from its modulus `n` and public
 * exponent `e`. Replaces the deprecated RSA_new() + RSA_set0_key() +
 * EVP_PKEY_assign_RSA() sequence.
 *
 * Returns NULL if either component is missing or any allocation step
 * fails.
 */
EVP_PKEY *pkcs11_pkey_from_rsa_public(const BIGNUM *n, const BIGNUM *e)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pk = NULL;

    if (n == NULL || e == NULL) {
	return NULL;
    }
    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) goto out;

    /* RSA public key: only n (modulus) and e (public exponent) are required */
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n)) goto out;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) goto out;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) goto out;

    pk = pkey_fromdata("RSA", params, EVP_PKEY_PUBLIC_KEY);

out:
    if (params) OSSL_PARAM_free(params);
    if (bld) OSSL_PARAM_BLD_free(bld);
    return pk;
}


/*
 * Build a DSA public-key EVP_PKEY from the FFC domain parameters
 * (p, q, g) and the public value `pub`. Replaces the deprecated
 * DSA_new() + DSA_set0_pqg() + DSA_set0_key() sequence.
 *
 * All four BIGNUMs are mandatory. Returns NULL on any failure.
 */
EVP_PKEY *pkcs11_pkey_from_dsa_public(const BIGNUM *p, const BIGNUM *q,
				      const BIGNUM *g, const BIGNUM *pub)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pk = NULL;

    if (p == NULL || q == NULL || g == NULL || pub == NULL) {
	return NULL;
    }
    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) goto out;

    /* FFC domain parameters (p, q, g) plus the public value */
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p)) goto out;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q)) goto out;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)) goto out;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, pub)) goto out;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) goto out;

    pk = pkey_fromdata("DSA", params, EVP_PKEY_PUBLIC_KEY);

out:
    if (params) OSSL_PARAM_free(params);
    if (bld) OSSL_PARAM_BLD_free(bld);
    return pk;
}


/*
 * Build a Diffie-Hellman public-key EVP_PKEY from the FFC domain
 * parameters (p, g, optional q) and the public value `pub`. Replaces
 * the deprecated DH_new() + DH_set0_pqg() + DH_set0_key() sequence.
 *
 * `q` is optional - PKCS#3 DH groups (the most common case) do not carry
 * a subgroup order, while X9.42 DH groups do. Pass NULL when absent.
 *
 * Returns NULL if any mandatory component is missing or any allocation
 * step fails.
 */
EVP_PKEY *pkcs11_pkey_from_dh_public(const BIGNUM *p, const BIGNUM *g,
				     const BIGNUM *q /* may be NULL */,
				     const BIGNUM *pub)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pk = NULL;

    if (p == NULL || g == NULL || pub == NULL) {
	return NULL;
    }
    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) goto out;

    /* mandatory PKCS#3 components */
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p)) goto out;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)) goto out;
    /* optional X9.42 subgroup order */
    if (q && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q)) goto out;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, pub)) goto out;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) goto out;

    pk = pkey_fromdata("DH", params, EVP_PKEY_PUBLIC_KEY);

out:
    if (params) OSSL_PARAM_free(params);
    if (bld) OSSL_PARAM_BLD_free(bld);
    return pk;
}


/*
 * Build an EC public-key EVP_PKEY from a named curve and the encoded
 * public point. `group_name` is an OpenSSL short name (e.g. "prime256v1",
 * "secp384r1"); `pub` is the EC point in uncompressed octet form
 * (typically 0x04 || X || Y for prime curves), as produced by PKCS#11
 * CKA_EC_POINT after stripping its DER OCTET STRING header.
 *
 * Replaces the deprecated EC_KEY_new_by_curve_name() +
 * EC_KEY_set_public_key() + EVP_PKEY_assign_EC_KEY() sequence.
 *
 * Returns NULL on any failure.
 */
EVP_PKEY *pkcs11_pkey_from_ec_public(const char *group_name,
				     const unsigned char *pub, size_t pub_len)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pk = NULL;

    if (group_name == NULL || pub == NULL || pub_len == 0) {
	return NULL;
    }
    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) goto out;

    /* EC public key: named curve + encoded public point */
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
					 group_name, 0)) goto out;
    if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
					  pub, pub_len)) goto out;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) goto out;

    pk = pkey_fromdata("EC", params, EVP_PKEY_PUBLIC_KEY);

out:
    if (params) OSSL_PARAM_free(params);
    if (bld) OSSL_PARAM_BLD_free(bld);
    return pk;
}


/* ---------------------------------------------------------------------- */
/* SHA-1 helper                                                            */
/* ---------------------------------------------------------------------- */

/*
 * Compute SHA-1 over `data` (length `data_len`) and place the result
 * into a freshly OPENSSL_malloc'd buffer assigned to *out. Caller is
 * responsible for OPENSSL_free(*out) on success.
 *
 * Returns the digest length (SHA_DIGEST_LENGTH = 20) on success, 0 on
 * failure. *out is set to NULL on failure.
 */
size_t pkcs11_pkey_sha1_to_buf(const unsigned char *data, size_t data_len,
			       unsigned char **out)
{
    EVP_MD_CTX *mdctx = NULL;
    unsigned int md_len = 0;
    size_t rv = 0;

    if (data == NULL || data_len == 0 || out == NULL) {
	return 0;
    }
    *out = OPENSSL_malloc(SHA_DIGEST_LENGTH);
    if (*out == NULL) {
	return 0;
    }
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
	OPENSSL_free(*out);
	*out = NULL;
	return 0;
    }
    /* one-shot SHA-1: init + update + final into the caller's buffer */
    if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) == 1 &&
	EVP_DigestUpdate(mdctx, data, data_len) == 1 &&
	EVP_DigestFinal_ex(mdctx, *out, &md_len) == 1) {
	rv = md_len;
    } else {
	OPENSSL_free(*out);
	*out = NULL;
    }
    EVP_MD_CTX_free(mdctx);
    return rv;
}


/* ---------------------------------------------------------------------- */
/* PEM/DER params I/O via OSSL_ENCODER / OSSL_DECODER                       */
/* ---------------------------------------------------------------------- */

/*
 * Write key parameters as PEM (type-specific structure: "DH PARAMETERS",
 * "DSA PARAMETERS", "EC PARAMETERS"). Compatible with the legacy
 * PEM_write_bio_*params output.
 */
int pkcs11_pkey_write_params_pem(BIO *out, EVP_PKEY *pk)
{
    OSSL_ENCODER_CTX *ectx = NULL;
    int rv = 0;

    if (out == NULL || pk == NULL) {
	return 0;
    }
    ectx = OSSL_ENCODER_CTX_new_for_pkey(pk, EVP_PKEY_KEY_PARAMETERS,
					 "PEM", "type-specific", NULL);
    if (ectx == NULL) {
	goto cleanup;
    }
    if (OSSL_ENCODER_to_bio(ectx, out) != 1) {
	goto cleanup;
    }
    rv = 1;

cleanup:
    if (ectx) OSSL_ENCODER_CTX_free(ectx);
    return rv;
}


/*
 * Write an RSA public key in PKCS#1 PEM (BEGIN RSA PUBLIC KEY) using
 * OSSL_ENCODER. Replaces deprecated PEM_write_bio_RSAPublicKey.
 */
int pkcs11_pkey_write_rsa_pubkey_pkcs1_pem(BIO *out, EVP_PKEY *pk)
{
    OSSL_ENCODER_CTX *ectx = NULL;
    int rv = 0;

    if (out == NULL || pk == NULL) {
	return 0;
    }
    ectx = OSSL_ENCODER_CTX_new_for_pkey(pk, EVP_PKEY_PUBLIC_KEY,
					 "PEM", "PKCS1", NULL);
    if (ectx == NULL) {
	goto cleanup;
    }
    if (OSSL_ENCODER_to_bio(ectx, out) != 1) {
	goto cleanup;
    }
    rv = 1;

cleanup:
    if (ectx) OSSL_ENCODER_CTX_free(ectx);
    return rv;
}


/*
 * Encode key parameters as DER (type-specific) into a freshly allocated
 * buffer. Caller must OPENSSL_free *out on success. Replaces deprecated
 * i2d_*params on RSA/DSA/DH/EC ECPKParameters.
 *
 * Returns 1 on success (and sets *out / *out_len), 0 on failure.
 */
int pkcs11_pkey_write_params_der(EVP_PKEY *pk, unsigned char **out, size_t *out_len)
{
    OSSL_ENCODER_CTX *ectx = NULL;
    unsigned char *buf = NULL;
    size_t len = 0;
    int rv = 0;

    if (out == NULL || out_len == NULL || pk == NULL) {
	return 0;
    }
    *out = NULL;
    *out_len = 0;

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pk, EVP_PKEY_KEY_PARAMETERS,
					 "DER", "type-specific", NULL);
    if (ectx == NULL) {
	goto cleanup;
    }
    if (OSSL_ENCODER_to_data(ectx, &buf, &len) != 1) {
	goto cleanup;
    }
    *out = buf;
    *out_len = len;
    buf = NULL;
    rv = 1;

cleanup:
    if (buf) OPENSSL_free(buf);
    if (ectx) OSSL_ENCODER_CTX_free(ectx);
    return rv;
}


/*
 * Resolve the OpenSSL short curve name (e.g. "prime256v1", "secp384r1")
 * from a PKCS#11 CKA_EC_PARAMS attribute (DER-encoded ECPKParameters,
 * usually a named curve OID). Returns NULL if the curve is not a named
 * curve or is unknown. The returned string is owned by libcrypto and
 * must not be freed.
 */
const char *pkcs11_pkey_ec_group_name_from_ecparams(const unsigned char *ecparams,
						    size_t ecparams_len)
{
    EC_GROUP *group = NULL;
    const unsigned char *pp = ecparams;
    int nid;
    const char *name = NULL;

    if (ecparams == NULL || ecparams_len == 0) {
	return NULL;
    }

    if (d2i_ECPKParameters(&group, &pp, (long)ecparams_len) == NULL) {
	return NULL;
    }

    nid = EC_GROUP_get_curve_name(group);
    if (nid != NID_undef) {
	name = OBJ_nid2sn(nid);
    }

    EC_GROUP_free(group);
    return name;
}


/*
 * Read key parameters from a FILE* in DER or PEM (auto-detect), for the
 * given key `type` ("DH", "DSA", "EC", ...). Returns a fresh EVP_PKEY of
 * that type containing only domain parameters (no public/private key).
 *
 * Replaces the legacy `d2i_*params_fp` + `PEM_read_*params` two-step.
 */
EVP_PKEY *pkcs11_pkey_read_params_fp(FILE *fp, const char *type)
{
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pk = NULL;
    BIO *bio = NULL;
    long pos;

    if (fp == NULL || type == NULL) {
	return NULL;
    }

    /* remember the current stream position so we can rewind if the decoder
     * fails - lets the caller fall back to alternate parsers without losing
     * already-buffered bytes */
    pos = ftell(fp);

    bio = BIO_new_fp(fp, BIO_NOCLOSE);
    if (bio == NULL) goto out;

    /*
     * input_type=NULL lets the decoder try both PEM and DER.
     * structure=NULL accepts type-specific or generic encodings.
     */
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pk,
					 NULL /* any input format */,
					 NULL /* any structure */,
					 type,
					 EVP_PKEY_KEY_PARAMETERS,
					 NULL, NULL);
    if (dctx == NULL) goto out;

    if (OSSL_DECODER_from_bio(dctx, bio) != 1) {
	if (pk) {
	    EVP_PKEY_free(pk);
	    pk = NULL;
	}
	if (pos >= 0) {
	    /* Restore stream position so caller may try alternate parsers. */
	    (void)fseek(fp, pos, SEEK_SET);
	}
    }

out:
    if (dctx) OSSL_DECODER_CTX_free(dctx);
    if (bio) BIO_free(bio);
    return pk;
}
