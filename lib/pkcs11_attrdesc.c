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



typedef struct s_attr_desc {
    CK_ATTRIBUTE_TYPE type;
    const char *desc;
} AttributeDesc;


/* ordered by name */
static AttributeDesc _a[] = {

#include "_attrinfo.h"

};

/* ordered by type */
static AttributeDesc _b[] = {

#include "_attrinfo.h"
    
};
static bool _b_sorted = false;


static int compare_CKA_desc( const void *a, const void *b)
{
    return strcasecmp(((AttributeDesc *)a)->desc, ((AttributeDesc *)b)->desc);
}

static int compare_CKA_type( const void *a, const void *b)
{
    /* because we are making a comparison between unsigned long, int might not reflect well */
    /* we need to use an intermediary value and divide it by itself (as absolute value)     */
    
    long long item = ((AttributeDesc *)a)->type - ((AttributeDesc *)b)->type;

    return item ? item/llabs(item) : 0;
}


CK_ATTRIBUTE_TYPE pkcs11_get_attribute_type_from_name(char *name)
{

    CK_ATTRIBUTE_TYPE retval = 0xFFFFFFFF;

    size_t array_size = sizeof(_a)/sizeof(AttributeDesc);
    AttributeDesc candidate = { 0xFFFFFFFF, name };
    AttributeDesc *match = bsearch( &candidate, _a, array_size, sizeof(AttributeDesc), compare_CKA_desc);
    
    if(match) { retval = ((AttributeDesc *)match)->type; }

    return retval;
}


const char *pkcs11_get_attribute_name_from_type(CK_ATTRIBUTE_TYPE attrtyp)
{

    static char * attr_unknown = "CKA_UNKNOWN_ATTRIBUTE";
    size_t array_size = sizeof(_b)/sizeof(AttributeDesc);
    AttributeDesc candidate = { attrtyp, NULL };

    if(_b_sorted == false) {	/* sort the table using type member*/
	qsort( _b, array_size, sizeof(AttributeDesc), compare_CKA_type);
	_b_sorted = true;
    }
    
    AttributeDesc *match = bsearch( &candidate, _b, array_size, sizeof(AttributeDesc), compare_CKA_type);
    
    return match ? ((AttributeDesc *)match)->desc : attr_unknown;
}

/* EOF */
