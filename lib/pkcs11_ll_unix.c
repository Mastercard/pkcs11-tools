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

/* -*- mode: cc; c-file-style:stroustrup; -*- */

/* pkcs11_ll_unix: low-level UNIX services */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <termios.h>
#include <ctype.h>
#include <byteswap.h>
#include "pkcs11lib.h"



void * pkcs11_ll_dynlib_open( const char *libname) {
    void * handle = NULL;

    if(libname) {
	if(( handle = dlopen( ( const char * ) libname, RTLD_LAZY|RTLD_GLOBAL ) ) == NULL )
	{
	    fprintf( stderr, "Error: dlopen() call failed: %s\n", dlerror() );
	}
    }
    return handle;
}


void pkcs11_ll_dynlib_close( void * handle ) {

    if(handle) {
	if(dlclose(handle)!=0) 
	{
	    fprintf( stderr, "Warning: dlclose() call failed: %s\n", dlerror() );
	}
    }
}


void * pkcs11_ll_dynlib_getfunc(void *handle, const char *funcname) {
    void * funcptr = NULL;

    if(handle && funcname) {
	if ((funcptr = dlsym( handle, funcname ) ) == NULL )
	{
	    fprintf( stderr, "Error: dlsym() call failed: %s\n", dlerror() );
	}
    }
    
    return funcptr;
}


void pkcs11_ll_echo_off(void)
{
    struct termios flags;
    
    if(tcgetattr(fileno(stdin), &flags) !=0 ) {
	perror("Issue with getting terminal attribute");
	exit( RC_ERROR_READ_INPUT );
    }
    
    flags.c_lflag &= ~ECHO;	        /* shut down ECHO */
    flags.c_lflag |= ECHONL | ICANON;	/*  set canonical mode and echoes new line character */
    
    if(tcsetattr(fileno(stdin), TCSANOW, &flags) != 0)  {
	perror("Oops cannot set terminal mode");
	exit( RC_ERROR_READ_INPUT );
    }
}


void pkcs11_ll_echo_on(void)
{
    struct termios flags;
    
    if(tcgetattr(fileno(stdin), &flags) !=0 ) {
	perror("Issue with getting terminal attribute");
	exit( RC_ERROR_READ_INPUT );
    }
    
    flags.c_lflag |= ECHO;	        /*  enable ECHO */
    flags.c_lflag |= ECHONL | ICANON;	/*  set canonical mode and echoes new line character */
    
    if(tcsetattr(fileno(stdin), TCSANOW, &flags) != 0)  {
	perror("Oops cannot set terminal mode");
	exit( RC_ERROR_READ_INPUT );
    }    
}

void pkcs11_ll_clear_screen(void)
{
    /* we clear the console using ANSI codes */
    printf("\033c\033[2J\033[H");

}


char *pkcs11_ll_basename(char *path)
{
    char *base = strrchr(path, '/');
    return base ? base+1 : path;
}


void pkcs11_ll_set_binary(FILE *fp)
{
    // do nothing. On unix, makes no difference.
}


/* we leverage on gnulib to define bswap_32 appropriately */
/* whatever the UNIX platform. */
/* if there is an error a compile time, please check m4/local_fix_bswap.m4 */
/* add add according support */

inline unsigned long pkcs11_ll_bigendian_ul(unsigned long argul)
{
#if defined(WORDS_BIGENDIAN)	/* we are in Big Endian */
    return argul;
#else                           /* we are in little Endian */

#if SIZEOF_UNSIGNED_LONG_INT==4
    return bswap_32(argul);
#elif SIZEOF_UNSIGNED_LONG_INT==8
    return bswap_64(argul);
#else
#error "Error: unsupported unsigned long size."    
#endif
#endif
}
