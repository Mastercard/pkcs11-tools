/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2023 Mastercard
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


/* This source code was built up from aws-cloudhsm-pkcs11-vendor-defs.h */
/* https://github.com/aws-samples/aws-cloudhsm-pkcs11-examples/blob/9026b84691435e59759ffee1bcf7323605920994/include/pkcs11/v2.40/cloudhsm_pkcs11_vendor_defs.h */
/* It has been modified to fit the need of the PKCS#11 toolkit */
/* The original license is stated here below. */

/*
 * Copyright (c) 2017, Cavium, Inc. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Cavium, Inc. nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY CAVIUM INC. ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CAVIUM, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#if !defined(_AWS_CLOUDHSM_H_)
#define _AWS_CLOUDHSM_H_

/* HMAC KDF Mechanism, defined by PKCS#11 3.00 */
#define CKM_CLOUDHSM_SP800_108_COUNTER_KDF      0x80000001UL /* original name is CKM_SP800_108_COUNTER_KDF */

#define CKM_CLOUDHSM_AES_GCM                    0x80001087UL

// More information can be found at https://docs.aws.amazon.com/cloudhsm/latest/userguide/manage-aes-key-wrapping.html
#define CKM_CLOUDHSM_AES_KEY_WRAP_NO_PAD        0x80002109UL
#define CKM_CLOUDHSM_AES_KEY_WRAP_PKCS5_PAD     0x8000210AUL
#define CKM_CLOUDHSM_AES_KEY_WRAP_ZERO_PAD      0x8000216FUL

#define CKM_CLOUDHSM_DES3_NIST_WRAP             0x80008000UL


#endif  /* _AWS_CLOUDHSM_H_ */
