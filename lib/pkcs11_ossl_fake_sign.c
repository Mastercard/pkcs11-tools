/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2020 Mastercard
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
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "pkcs11lib.h"

void fake_sign(unsigned char *sig, size_t siglen)
{
    /* we expect to get *siglen properly sized */
    int i;

    /* the following sequence will let appear "++FAKE++" once encoded in base64     */
    /* the same sesuence is repeated 3 times, but each time with a shift of 2 bits  */
    /* in order to cover all encoding possibilities                                 */
    
    unsigned char repeat[] = {
	0xfb, 0xe1, 0x40, 0x28, 0x4f, 0xbe, 0x3e, 0xf8,
	0x50, 0x0a, 0x13, 0xef, 0x8f, 0xbe, 0x14, 0x02,
	0x84, 0xfb, 0xe0, 
    };
    
    for(i=0; i<siglen; i++) {
	sig[i]=repeat[i%sizeof repeat];
    }
}


/* EOF */
