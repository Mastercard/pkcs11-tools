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
#include <string.h>
#include <stdlib.h>
#include "pkcs11lib.h"

func_rc pkcs11_getrandombytes(pkcs11Context *p11Context, CK_BYTE_PTR buffer, CK_ULONG desired_length)
{
    func_rc rc=rc_ok;
    CK_RV rv;

    if(buffer==NULL) {
	fprintf(stderr, "input buffer not preallocated.\n");
	rc = rc_error_invalid_parameter_for_method;
	goto error;
    }

    rv = p11Context->FunctionList.C_GenerateRandom(p11Context->Session, buffer, desired_length);

    if(rv!=CKR_OK) {
	pkcs11_error(rv, "C_GenerateRandom");
	rc = rc_error_pkcs11_api;
	goto error;
    }
    

error:

    return rc;    
}
    
