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

#ifndef PKCS11_EXTRA_H
#define PKCS11_EXTRA_H

#include "nss.h"		/* Nescape Security Services */

#if defined(HAVE_NCIPHER)
#include "ncipher.h"
#endif

#if defined(HAVE_LUNA)
#include "luna.h"
#endif

#endif /* PKCS11_EXTRA_H */
