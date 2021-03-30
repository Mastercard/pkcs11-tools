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
#include <stdarg.h>
#include <ctype.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include "pkcs11lib.h"


#define HAS_FLAG(a,fl,t,f) ( (a & fl) ? t : f )
#define IS_VENDOR_DEFINED(m,t,f) ( (m & CKM_VENDOR_DEFINED) == CKM_VENDOR_DEFINED ? t : f )

/* high-level search functions */

func_rc pkcs11_info_library(pkcs11Context *p11Context)
{
    func_rc rc=rc_error_library;

    if(p11Context && p11Context->initialized==CK_TRUE) {
	CK_INFO libinfo;
	CK_RV rv;
	
	if((rv = p11Context->FunctionList.C_GetInfo(&libinfo)) != CKR_OK ) {
	    pkcs11_error( rv, "C_GetInfo" );
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	fprintf( stdout, 		     
		 "PKCS#11 Library\n" 
		 "---------------\n"
		 "Name        : %s\n"
		 "Lib version : %d.%d\n"
		 "API version : %d.%d\n"
		 "Description : %.*s\n"
		 "Manufacturer: %.*s\n"
		 "\n",
		 p11Context->library,
		 libinfo.libraryVersion.major, libinfo.libraryVersion.minor,
		 libinfo.cryptokiVersion.major, libinfo.cryptokiVersion.minor,
		 (int)sizeof(libinfo.libraryDescription), libinfo.libraryDescription,
		 (int)sizeof(libinfo.manufacturerID), libinfo.manufacturerID
	    );

	rc = rc_ok;
    }

error:
    return rc;
}

/* EOF */
