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

/* this file is derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)
 * original license follows */

/* cryptoki.h include file for PKCS #11. */
/* $Revision: 1.4 $ */

/* License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
 * (Cryptoki)" in all material mentioning or referencing this software.

 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)" in all material mentioning or 
 * referencing the derived work.

 * RSA Security Inc. makes no representations concerning either the 
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */

/* This is a sample file containing the top level include directives
 * for building Win32 Cryptoki libraries and applications.
 */

#ifndef CRYPTOKI_H
#define CRYPTOKI_H


#ifdef _MSC_VER
#if defined(_WIN32) /* win32 */
#define CK_PTR            *

#ifdef _DLL /* Win32, DLL build */
#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType __declspec(dllimport) (* name)
#else
     /* Win32, not DLL build */
#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (* name)
#endif

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)

#else
#error "Unsupported platform"
#endif

#else /* not windows */

#define CK_PTR            *
#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)
#endif

#ifndef NULL_PTR
#define NULL_PTR          0
#endif

#if defined(_WIN32)
#pragma pack(push, cryptoki, 1)
#endif

/* The standard RSA supplied header */
#include "pkcs11.h"

/* Non-standard API entry points, vendor defined constants */
#include "pkcs11extra.h"

#if defined(_WIN32)
#pragma pack(pop, cryptoki)
#endif

#endif /* CRYPTOKI_H */
