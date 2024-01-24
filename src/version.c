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

#include "config.h"
#include "target.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pkcs11lib.h"

void print_version_info(char *progname)
{
    fprintf( stderr,
	     "%s belongs to " PACKAGE_NAME " v" PACKAGE_VERSION " (" __DATE__  ")\n",
	     pkcs11_ll_basename(progname) );
    fprintf( stderr, "arch/CPU/OS: %s/%s/%s\n", TARGET_ARCH_TYPE, TARGET_CPU_TYPE,TARGET_OS_TYPE);
    fprintf( stderr, "using openssl library: %s\n", pkcs11_openssl_version() );
#ifdef HAVE_DUPLICATES_ENABLED
    fprintf( stderr, "compiled with enable duplicate extentions\n");
#endif
#if defined(HAVE_NCIPHER)
    fprintf( stderr, "compiled with nCipher extensions\n");
#endif
#if defined(HAVE_LUNA)
    fprintf( stderr, "compiled with Gemalto Safenet Luna extensions\n");
#endif
#if defined(HAVE_AWSCLOUDHSM)
    fprintf( stderr, "compiled with AWS CloudHSM extensions\n");
#endif
    exit( RC_ERROR_USAGE );
}
