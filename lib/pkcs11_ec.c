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
#include <unistd.h>
#include "pkcs11lib.h"

#include <openssl/objects.h>
#include <openssl/err.h>


/*
CK_BYTE ec_x9_62_param_prime192v1[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01 };
CK_BYTE ec_x9_62_param_prime192v2[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x02 };
CK_BYTE ec_x9_62_param_prime192v3[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x03 };
CK_BYTE ec_x9_62_param_prime239v1[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x04 };
CK_BYTE ec_x9_62_param_prime239v2[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x05 };
CK_BYTE ec_x9_62_param_prime239v3[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x06 };
CK_BYTE ec_x9_62_param_prime256v1[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
*/


CK_BBOOL pkcs11_ec_curvename2oid(char *name, CK_BYTE **where, CK_ULONG *len)
{

    CK_BBOOL rc = CK_FALSE;
    ASN1_OBJECT *obj = NULL;

    unsigned char *pp = NULL;
    char repr[80];
    int i2dlen;

    /* first we try to convert string to ASN.1 object */

    *where = NULL;
    *len = 0;

    obj = OBJ_txt2obj(name, 0);
    
    if(obj==NULL) {
	P_ERR();
	goto err;
    }

    /* then we convert back to an OID in order to compare the prefix */
    /* with well-known OID for elliptic curves */

#define ANSI_X9_62_CURVES "1.2.840.10045.3"
#define CERTICOM_CURVES   "1.3.132.0"
#define WAP_WSG_CURVES    "2.23.43.1.4"

    OBJ_obj2txt(repr, 80, obj, 1);
    
    if(strncmp(ANSI_X9_62_CURVES, repr, strlen(ANSI_X9_62_CURVES)) == 0 
       ||
       strncmp(CERTICOM_CURVES, repr, strlen(CERTICOM_CURVES)) == 0 
       ||
       strncmp(WAP_WSG_CURVES, repr, strlen(WAP_WSG_CURVES)) == 0 
	) {

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
	    
	    if(len<0) {
		P_ERR();
		goto err;
	    }
	    
	    *len = i2dlen;
	    rc = CK_TRUE;
	}
    }
    
err:
    if(rc==CK_FALSE) {
	if(*where!=NULL) { OPENSSL_free(*where); *where = NULL; *len=0; }
    }

    if(obj) { ASN1_OBJECT_free(obj); }

    return rc;
}

void pkcs11_ec_freeoid(CK_BYTE_PTR buf)
{
    if(buf) {
	OPENSSL_free(buf);
    }
}


char * pkcs11_ec_oid2curvename(CK_BYTE *param, CK_ULONG param_len, char *where, size_t maxlen)
{

    ASN1_OBJECT *obj = NULL;

    if(param && where && param_len>0 && maxlen>0) {

	const unsigned char *pp = param;

	obj = d2i_ASN1_OBJECT(NULL, &pp, param_len);

	if(obj == NULL) {
	    P_ERR();
	    goto cleanup;
	}    
	

	if( OBJ_obj2txt(where, maxlen, obj, 0) == 0 ) {
	    /* we have got an error */
	    P_ERR();
	    
	    strncpy(where, "unknown(\?\?\?)", maxlen);
	    where[maxlen-1]=0;
	}

    }
    
cleanup:
    if(obj) { ASN1_OBJECT_free(obj); }

    return where;
}

/*
 *--------------------------------------------------------------------------------
 * $Log$
 *--------------------------------------------------------------------------------
 */
