/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2018 Mastercard
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>
#include "pkcs11lib.h"

/* OpenSSL version tag */

inline const char * pkcs11_openssl_version(void)
{
	return OpenSSL_version(OPENSSL_VERSION);
}


/* OpenSSL error management */

void pkcs11_openssl_error(char *file, int line)
{
	const char *err_func = NULL;
	const char *err_data = NULL;
	int err_flags = 0;
    int err_line;
    const char *err_file;
    unsigned long err;
	char err_buf[256];

	err = ERR_get_error_all(&err_file, &err_line, &err_func, &err_data, &err_flags);
    if(err) {
	ERR_error_string_n(err, err_buf, sizeof err_buf);
	fprintf(stderr, "*** OpenSSL ERROR at %s:%d  '%s' - (from %s:%d)\n", file, line, err_buf, err_file, err_line );
    }
}


/* SHA-1 goodies, namely used for generating SHA-1 over public key components */
/* to setup ID */

CK_ULONG pkcs11_openssl_alloc_and_sha1(CK_BYTE_PTR data, CK_ULONG datalen, CK_VOID_PTR_PTR buf)
{
    CK_ULONG rv=0;

    if(data!=NULL && datalen>0 && *buf==NULL) {
	EVP_MD_CTX *mdctx = NULL;
	const EVP_MD *md = NULL;
	unsigned int md_len;

	if( (*buf = OPENSSL_malloc(SHA_DIGEST_LENGTH)) == NULL ) {
		P_ERR();
		goto error;
	    }

	if(*buf) {
	    md = EVP_sha1();
	    if ((mdctx = EVP_MD_CTX_new()) == NULL ) {
		P_ERR();
		goto error;
	    }

	    if(EVP_DigestInit_ex(mdctx, md, NULL) == 0 ){
		P_ERR();
		goto error;
	    }

	    if(EVP_DigestUpdate(mdctx, data, datalen) == 0) {
		P_ERR();
		goto error;
	    }

	    if(EVP_DigestFinal_ex(mdctx, *buf, &md_len) == 0) {
		P_ERR();
		goto error;
	    }

	    rv = md_len;
	}

    error:

	if(mdctx) { EVP_MD_CTX_free(mdctx); mdctx=NULL; }

    }
    return rv;
}

inline void pkcs11_openssl_free(CK_VOID_PTR_PTR buf)
{
    if(buf && *buf) {
	OPENSSL_free(*buf);
	*buf=NULL;
    }
}
