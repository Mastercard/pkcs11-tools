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

/* This source code was built up from pkcs11n.h, distributed with the NSS library */
/* it has been modified to fit the need of the PKCS#11 toolkit */
/* The original license is stated here below. */

/**************************************************************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#if !defined(_CRYPTOKI_NSS_H_)
#define _CRYPTOKI_NSS_H_
// Methods

//#define CKM_VENDOR_DEFINED 0x80000000
#define NSSCK_VENDOR_NSS 0x4E534350 /* NSCP */
//#define CKM_NSS 0xCE534350
#define CKM_NSS_AES_KEY_WRAP      0xCE534351
#define CKM_NSS_AES_KEY_WRAP_PAD  0xCE534352
#define CKM_NSS_HKDF_SHA1         0xCE534353
#define CKM_NSS_HKDF_SHA256       0xCE534354
#define CKM_NSS_HKDF_SHA384       0xCE534355
#define CKM_NSS_HKDF_SHA512       0xCE534356
#define CKM_NSS_JPAKE_ROUND1_SHA1   0xCE534357
#define CKM_NSS_JPAKE_ROUND1_SHA256 0xCE534358
#define CKM_NSS_JPAKE_ROUND1_SHA384 0xCE534359
#define CKM_NSS_JPAKE_ROUND1_SHA512 0xCE53435A
#define CKM_NSS_JPAKE_ROUND2_SHA1   0xCE53435B
#define CKM_NSS_JPAKE_ROUND2_SHA256 0xCE53435C
#define CKM_NSS_JPAKE_ROUND2_SHA384 0xCE53435D
#define CKM_NSS_JPAKE_ROUND2_SHA512 0xCE53435E
#define CKM_NSS_JPAKE_FINAL_SHA1    0xCE53435F
#define CKM_NSS_JPAKE_FINAL_SHA256  0xCE534360
#define CKM_NSS_JPAKE_FINAL_SHA384  0xCE534361
#define CKM_NSS_JPAKE_FINAL_SHA512  0xCE534362
#define CKM_NSS_HMAC_CONSTANT_TIME      0xCE534363
#define CKM_NSS_SSL3_MAC_CONSTANT_TIME  0xCE534364
#define CKM_NETSCAPE_PBE_SHA1_DES_CBC           0x80000002UL
#define CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC    0x80000003UL
#define CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC    0x80000004UL
#define CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC   0x80000005UL
#define CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4        0x80000006UL
#define CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4       0x80000007UL
#define CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC   0x80000008UL
#define CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN      0x80000009UL
#define CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN       0x8000000aUL
#define CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN       0x8000000bUL
//#define CKM_NETSCAPE_AES_KEY_WRAP	CKM_NSS_AES_KEY_WRAP
//#define CKM_NETSCAPE_AES_KEY_WRAP_PAD	CKM_NSS_AES_KEY_WRAP_PAD


// Objects, extracted from NSS:mozilla/security/nss/lib/util/pkcs11n.h

//#define NSSCK_VENDOR_NSS 0x4E534350 /* NSCP */
//#define CKO_NSS (CKO_VENDOR_DEFINED|NSSCK_VENDOR_NSS)

#define CKO_NSS_CRL                0xCE534351
#define CKO_NSS_SMIME              0xCE534352
#define CKO_NSS_TRUST              0xCE534353
#define CKO_NSS_BUILTIN_ROOT_LIST  0xCE534354
#define CKO_NSS_NEWSLOT            0xCE534355
#define CKO_NSS_DELSLOT            0xCE534356


/*
 * NSS-defined object attributes
 *
 */
//#define CKA_NSS (CKA_VENDOR_DEFINED|NSSCK_VENDOR_NSS)

#define CKA_NSS_URL                0xCE534351
#define CKA_NSS_EMAIL              0xCE534352
#define CKA_NSS_SMIME_INFO         0xCE534353
#define CKA_NSS_SMIME_TIMESTAMP    0xCE534354
#define CKA_NSS_PKCS8_SALT         0xCE534355
#define CKA_NSS_PASSWORD_CHECK     0xCE534356
#define CKA_NSS_EXPIRES            0xCE534357
#define CKA_NSS_KRL                0xCE534358

#define CKA_NSS_PQG_COUNTER        0xCE534364
#define CKA_NSS_PQG_SEED           0xCE534365
#define CKA_NSS_PQG_H              0xCE534366
#define CKA_NSS_PQG_SEED_BITS      0xCE534367
#define CKA_NSS_MODULE_SPEC        0xCE534368
#define CKA_NSS_OVERRIDE_EXTENSIONS 0xCE534369

#define CKA_NSS_JPAKE_SIGNERID     0xCE53436A
#define CKA_NSS_JPAKE_PEERID       0xCE53436B
#define CKA_NSS_JPAKE_GX1          0xCE53436C
#define CKA_NSS_JPAKE_GX2          0xCE53436D
#define CKA_NSS_JPAKE_GX3          0xCE53436E
#define CKA_NSS_JPAKE_GX4          0xCE53436F
#define CKA_NSS_JPAKE_X2           0xCE534370
#define CKA_NSS_JPAKE_X2S          0xCE534371

/*
 * Trust attributes:
 *
 * If trust goes standard, these probably will too.  So I'll
 * put them all in one place.
 */

//#define CKA_TRUST (CKA_NSS + 0x2000)

/* "Usage" key information */
#define CKA_NSS_TRUST_DIGITAL_SIGNATURE     0xCE536351
#define CKA_NSS_TRUST_NON_REPUDIATION       0xCE536352
#define CKA_NSS_TRUST_KEY_ENCIPHERMENT      0xCE536353
#define CKA_NSS_TRUST_DATA_ENCIPHERMENT     0xCE536354
#define CKA_NSS_TRUST_KEY_AGREEMENT         0xCE536355
#define CKA_NSS_TRUST_KEY_CERT_SIGN         0xCE536356
#define CKA_NSS_TRUST_CRL_SIGN              0xCE536357

/* "Purpose" trust information */
#define CKA_NSS_TRUST_SERVER_AUTH           0xCE536358
#define CKA_NSS_TRUST_CLIENT_AUTH           0xCE536359
#define CKA_NSS_TRUST_CODE_SIGNING          0xCE53635A
#define CKA_NSS_TRUST_EMAIL_PROTECTION      0xCE53635B
#define CKA_NSS_TRUST_IPSEC_END_SYSTEM      0xCE53635C
#define CKA_NSS_TRUST_IPSEC_TUNNEL          0xCE53635D
#define CKA_NSS_TRUST_IPSEC_USER            0xCE53635E
#define CKA_NSS_TRUST_TIME_STAMPING         0xCE53635F
#define CKA_NSS_TRUST_STEP_UP_APPROVED      0xCE536360

#define CKA_NSS_CERT_SHA1_HASH	        0xCE5363B4
#define CKA_NSS_CERT_MD5_HASH		0xCE5363B5

/* NSS trust stuff */

/*
 * Trust info
 *
 * This isn't part of the Cryptoki standard (yet), so I'm putting
 * all the definitions here.  Some of this would move to nssckt.h
 * if trust info were made part of the standard.  In view of this
 * possibility, I'm putting my (NSS) values in the NSS
 * vendor space, like everything else.
 */

typedef CK_ULONG          CK_TRUST;

/* The following trust types are defined: */
#define CKT_VENDOR_DEFINED     0x80000000

#define CKT_NSS (CKT_VENDOR_DEFINED|NSSCK_VENDOR_NSS)

/* If trust goes standard, these'll probably drop out of vendor space. */
#define CKT_NSS_TRUSTED            (CKT_NSS + 1)
#define CKT_NSS_TRUSTED_DELEGATOR  (CKT_NSS + 2)
#define CKT_NSS_MUST_VERIFY_TRUST  (CKT_NSS + 3)
#define CKT_NSS_NOT_TRUSTED        (CKT_NSS + 10)
#define CKT_NSS_TRUST_UNKNOWN      (CKT_NSS + 5) /* default */

/* 
 * These may well remain NSS-specific; I'm only using them
 * to cache resolution data.
 */
#define CKT_NSS_VALID_DELEGATOR    (CKT_NSS + 11)

#endif /* _CRYPTOKI_NSS_H_ */
