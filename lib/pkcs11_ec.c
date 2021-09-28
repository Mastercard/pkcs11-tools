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
#include <ctype.h>
#include <stddef.h>
#include <unistd.h>
#include <assert.h>
#include "pkcs11lib.h"

#include <openssl/objects.h>
#include <openssl/err.h>

static const uint8_t id_edwards25519[] = { 0x13, 0x0C, 'e', 'd', 'w', 'a', 'r', 'd', 's', '2', '5', '5', '1', '9' };
static const uint8_t id_edwards448[] = { 0x13, 0x0A, 'e', 'd', 'w', 'a', 'r', 'd', 's', '4', '4', '8' };

/* Edwards curves may be specified it two flavours: 
 * - as an OID, in which case it will be parsed by d2i_ASN1_OBJECT
 * - as a PrintableString 'edwards25519' or 'edwards448'
 * the later case cannot be converted directly to an OID
 * The two following functions implement that detection.
 */

inline bool pkcs11_is_ed_param_named_25519(const uint8_t *ecparam, size_t ecparamlen)
{
    return ecparamlen==sizeof id_edwards25519 && memcmp(ecparam, id_edwards25519, sizeof id_edwards25519)==0;
}

inline bool pkcs11_is_ed_param_named_448(const uint8_t *ecparam, size_t ecparamlen)
{
    return ecparamlen==sizeof id_edwards448 && memcmp(ecparam, id_edwards448, sizeof id_edwards448)==0;
}


bool pkcs11_ex_curvename2oid(char *name, CK_BYTE **where, CK_ULONG *len, key_type_t keytype)
{
    bool rc = false;
    ASN1_OBJECT *obj=NULL;

    unsigned char *pp = NULL;
    char repr[80];
    char uname[80]; 		/* to uppercase the name. Limited to 80 chars */
    int i2dlen;

    /* first we try to convert string to ASN.1 object */

    *where = NULL;
    *len = 0;

    if(name && where && len ) {
	/* For Edwards, we expect to have an uppercase string */
	strncpy(uname, name, sizeof uname); uname[sizeof uname -1]=0;
	int i;
	for(i=0; i<strlen(uname); i++) {
	    uname[i] = toupper(uname[i]);
	}

	if ( (obj = OBJ_txt2obj(name, 0)) == NULL && (obj = OBJ_txt2obj(uname, 0)) == NULL ) {
	    P_ERR();
	    goto err;
	}

	/* we convert back to an OID in order to compare the prefix */
	/* with well-known OID for elliptic curves */

#define ANSI_X9_62_CURVES "1.2.840.10045.3"
#define CERTICOM_CURVES   "1.3.132.0"
#define WAP_WSG_CURVES    "2.23.43.1.4"

#define ED25519           "1.3.101.112"
#define ED448             "1.3.101.113"

	OBJ_obj2txt(repr, sizeof repr - 1, obj, 1);

	/* TODO do a better job at doing this */
	if( keytype == ec && ( strncmp(ANSI_X9_62_CURVES, repr, strlen(ANSI_X9_62_CURVES)) == 0
			       ||
			       strncmp(CERTICOM_CURVES, repr, strlen(CERTICOM_CURVES)) == 0
			       ||
			       strncmp(WAP_WSG_CURVES, repr, strlen(WAP_WSG_CURVES)) == 0 ) ) {

	    /* if it is EC, we allocate the DER space onto target pointer */
	    i2dlen = i2d_ASN1_OBJECT(obj, NULL);
	    if(i2dlen<0) {
		P_ERR();
		goto err;
	    } else {
		*where = OPENSSL_malloc(i2dlen);

		if(*where==NULL) {
		    P_ERR();
		    goto err;
		}

		pp = *where;

		i2dlen = i2d_ASN1_OBJECT(obj, &pp);

		if(i2dlen<0) {
		    P_ERR();
		    goto err;
		}

		*len = i2dlen;
		rc = true;
	    }
	}
	/* although we could use the OID for key generation,                        */
	/* it seems like HSM implementations prefer using the curve strings instead */
	/* note that PKCS#11 3.0 requires to support both ways.                     */
	if ( keytype == ed ) {
	    size_t wanted_len;

	    if (strncmp(ED25519, repr, strlen(ED25519)) == 0) {
		wanted_len = sizeof id_edwards25519;
		pp = (uint8_t *)id_edwards25519;
	    }
	    else if (strncmp(ED448, repr, strlen(ED448)) == 0 ) {
		wanted_len = sizeof id_edwards448;
		pp = (uint8_t *)id_edwards448;
	    }
	    else {
		fprintf(stderr, "Error: unsupported edwards curve");
		goto err;
	    }

	    *where = OPENSSL_malloc(wanted_len);

	    if(*where==NULL) {
		P_ERR();
		goto err;
	    }
	    memcpy(*where,pp,wanted_len);

	    *len = wanted_len;
	    rc = true;
	}
    }

err:
    if(rc==false) {
	if(*where!=NULL) { OPENSSL_free(*where); *where = NULL; *len=0; }
    }

    if(obj) { ASN1_OBJECT_free(obj); }
    return rc;
}



/* aliases for EC and ED  */

inline bool pkcs11_ec_curvename2oid(char *name, CK_BYTE **where, CK_ULONG *len) {
    return pkcs11_ex_curvename2oid(name, where, len, ec);
}

inline bool pkcs11_ed_curvename2oid(char *name, CK_BYTE **where, CK_ULONG *len) {
    return pkcs11_ex_curvename2oid(name, where, len, ed);
}


static void pkcs11_ex_freeoid(CK_BYTE_PTR buf)
{
    if(buf) {
	OPENSSL_free(buf);
    }
}

/* aliases for EC and ED  */

void pkcs11_ec_freeoid(CK_BYTE_PTR buf) {
    pkcs11_ex_freeoid(buf);
}

void pkcs11_ed_freeoid(CK_BYTE_PTR buf) {
    pkcs11_ex_freeoid(buf);
}


static char * pkcs11_ex_oid2curvename(CK_BYTE *param, CK_ULONG param_len, char *where, size_t maxlen, key_type_t keytype)
{

    ASN1_OBJECT *obj = NULL;

    if(param && where && param_len>0 && maxlen>0) {

	const unsigned char *pp = param;

	switch(keytype) {
	case ec:
	    if( (obj = d2i_ASN1_OBJECT(NULL, &pp, param_len)) == NULL ) {
		P_ERR();
		strncpy(where, "unknown(\?\?\?)", maxlen);
		where[maxlen-1]=0;
		goto cleanup;
	    }

	    if( OBJ_obj2txt(where, maxlen, obj, 0) == 0 ) {
		P_ERR();
		strncpy(where, "unknown(\?\?\?)", maxlen);
		where[maxlen-1]=0;
	    }
	    break;

	case ed:
	    /* it will be a regular OID or one of the parameters below */
	    /*
	       13 0c 65 64 77 61 72 64 73 32 35 35 31 39        ..edwards25519
	       13 0a 65 64 77 61 72 64 73 34 34 38              ..edwards448
	     */
	{
	    if( ( obj = d2i_ASN1_OBJECT(NULL, &pp, param_len) ) != NULL) { /* case 1: OID - from public key */
		if( OBJ_obj2txt(where, maxlen, obj, 0) == 0 ) {
		    P_ERR();
		    strncpy(where, "unknown(\?\?\?)", maxlen);
		    where[maxlen-1]=0;
		}
		/* happy path here */
	    } else {
		if(param_len == sizeof id_edwards25519 && memcmp(id_edwards25519, param, sizeof id_edwards25519)==0 ) {
		    strncpy(where, "ED25519", maxlen);
		    where[maxlen-1]=0;
		} else if(param_len == sizeof id_edwards448 && memcmp(id_edwards448, param, sizeof id_edwards448)==0) {
		    strncpy(where, "ED448", maxlen);
		    where[maxlen-1]=0;
		} else {
		    strncpy(where, "unknown(\?\?\?)", maxlen);
		    where[maxlen-1]=0;
		}
	    }
	}
	break;

	default:
	    assert(0);
	}
    }

cleanup:
    if(obj) { ASN1_OBJECT_free(obj); }

    return where;
}

/* aliases for EC and ED  */

inline char * pkcs11_ec_oid2curvename(CK_BYTE *param, CK_ULONG param_len, char *where, size_t maxlen) {
    return pkcs11_ex_oid2curvename(param, param_len, where, maxlen, ec);
}

inline char * pkcs11_ed_oid2curvename(CK_BYTE *param, CK_ULONG param_len, char *where, size_t maxlen) {
    return pkcs11_ex_oid2curvename(param, param_len, where, maxlen, ed);
}

/* EOF */
