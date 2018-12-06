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
#include <search.h>
#include <stdlib.h>
#include "pkcs11lib.h"



typedef struct s_mechanism_desc {
    CK_MECHANISM_TYPE type;
    const char *desc;
} MechanismDesc;


static MechanismDesc _m[] = {

#include "_mechinfo.h"

};



static int compare_CKM( const void *a, const void *b)
{
    int rc;

    if( ((MechanismDesc *)a)->type > ((MechanismDesc *)b)->type ) {
	rc = 1;
    } else if ( ((MechanismDesc *)a)->type < ((MechanismDesc *)b)->type ) {
	rc = -1;
    } else {
	rc = 0;
    }
    
    return rc;
}



const char *get_mechanism_name(CK_MECHANISM_TYPE mech)
{

    const char *retval = "unknown mechanism";
    size_t array_size = sizeof(_m)/sizeof(MechanismDesc);
    MechanismDesc candidate = { mech, "" };
    MechanismDesc *match = bsearch( &candidate, _m, array_size, sizeof(MechanismDesc), compare_CKM);
    
    if(match) { retval = ((MechanismDesc *)match)->desc; }
    else if(mech & CKM_VENDOR_DEFINED) {
	retval = "CKM_VENDOR_DEFINED";
    }

    return retval;
}


