/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2026 Mastercard
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

/* This source code was built up from pkcs11y.h, distributed /* 
/* by Yubico (https://github.com/Yubico/yubihsm-shell/blob/master/pkcs11/pkcs11y.h) */
/* it has been modified to fit the need of the PKCS#11 toolkit */
/* The original license is stated here below. */


/*
 * Copyright 2015-2018 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if !defined(_CRYPTOKI_YUBICO_H_)
#define _CRYPTOKI_YUBICO_H_


/* This is an offset for the vendor definitions to avoid clashes */
#define YUBICO_BASE_VENDOR         0x59554200UL


/*  YH_ALGO_AES128_CCM_WRAP */
#define CKK_YUBICO_AES128_CCM_WRAP 0xd955421dUL

/*  YH_ALGO_AES192_CCM_WRAP */
#define CKK_YUBICO_AES192_CCM_WRAP 0xd9554229UL

/*  YH_ALGO_AES256_CCM_WRAP */
#define CKK_YUBICO_AES256_CCM_WRAP 0xd955422aUL

/* YH_WRAP_KEY */
#define CKM_YUBICO_AES_CCM_WRAP    0xd9554204UL

/* YH_PUBLIC_WRAP_KEY */
#define CKM_YUBICO_RSA_WRAP        0xd9554209UL

#endif /* _CRYPTOKI_YUBICO_H_ */
