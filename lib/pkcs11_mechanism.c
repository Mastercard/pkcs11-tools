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
#include <string.h>
#include "pkcs11lib.h"



typedef struct s_mechanism_desc {
    CK_MECHANISM_TYPE type;
    const char *desc;
} MechanismDesc;

/* ordered by type - the default in _mechinfo.h */
static MechanismDesc _m[] = {

#include "_mechinfo.h"

};

/* ordered by name - we must sort before first use */
static MechanismDesc _n[] = {

#include "_mechinfo.h"

};

static bool _n_sorted = false;

static int compare_CKM_desc( const void *a, const void *b)
{
    return strcasecmp(((MechanismDesc *)a)->desc, ((MechanismDesc *)b)->desc);
}


static int compare_CKM_type( const void *a, const void *b)
{
    /* because we are making a comparison between unsigned long, int might not reflect well */
    /* we need to use an intermediary value and divide it by itself (as absolute value)     */

    /* we explicitely use "signed" as some platform (MIPS) seem to work with unsigned by default */
    //avoiding undefined behaviour
    MechanismDesc* mech_a = (MechanismDesc*)a;
    MechanismDesc* mech_b = (MechanismDesc*)b;
    if(!mech_a || !mech_b) {
        fprintf(stderr, "***Error: failed to detect valid mechanism description...exiting.\n");
        exit(rc_error_invalid_argument);
    }
    signed long long item = (signed long long)(mech_a->type) - (signed long long)(mech_b->type);
    return item ? item/llabs(item) : 0;
}

CK_MECHANISM_TYPE pkcs11_get_mechanism_type_from_name(char *name)
{

    CK_MECHANISM_TYPE retval = 0xFFFFFFFF;

    size_t array_size = sizeof(_n)/sizeof(MechanismDesc);
    MechanismDesc candidate = { 0xFFFFFFFF, name };

    if(_n_sorted == false) {	/* sort the table using type member*/
	qsort( _n, array_size, sizeof(MechanismDesc), compare_CKM_desc);
	_n_sorted = true;
    }
    
    MechanismDesc *match = bsearch( &candidate, _n, array_size, sizeof(MechanismDesc), compare_CKM_desc);
    
    if(match) { retval = ((MechanismDesc *)match)->type; }

    return retval;
}

const char *pkcs11_get_mechanism_name_from_type(CK_MECHANISM_TYPE mech)
{
    const char *retval = "CKM_UNKNOWN_MECHANISM";
    size_t array_size = sizeof(_m)/sizeof(MechanismDesc);
    MechanismDesc candidate = { mech, "" };
    MechanismDesc *match = bsearch( &candidate, _m, array_size, sizeof(MechanismDesc), compare_CKM_type);
    
    if(match) { retval = ((MechanismDesc *)match)->desc; }
    else if(mech & CKM_VENDOR_DEFINED) {
	retval = "CKM_VENDOR_DEFINED";
    }

    return retval;
}


