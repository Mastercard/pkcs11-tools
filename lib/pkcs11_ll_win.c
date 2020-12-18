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


/* pkcs11_ll_win: low-level Windows services */

#include <config.h>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <io.h>
#include <fcntl.h>

#include "pkcs11lib.h"



void * pkcs11_ll_dynlib_open( const char *libname) {
    void * handle = NULL;

    if(libname) {
	if(( handle = LoadLibrary( ( const char * ) libname ) ) == NULL )
	{
	    fprintf( stderr, "Error: LoadLibrary() returned %08.8lx\n", GetLastError() );
	}
    }
    return handle;
}


void pkcs11_ll_dynlib_close( void * handle ) {

    if(handle) {
	if(FreeLibrary(handle)!=TRUE) 
	{
	    fprintf( stderr, "Warning: FreeLibrary() returned %08.8lx\n", GetLastError() );
	}
    }
}


void * pkcs11_ll_dynlib_getfunc(void *handle, const char *funcname) {
    void * funcptr = NULL;

    if(handle && funcname) {
	if ((funcptr = GetProcAddress( handle, funcname ) ) == NULL )
	{
	    fprintf( stderr, "Error: GetProcAddress() returned %08.8lx\n", GetLastError() );
	}
    }
    
    return funcptr;
}


void pkcs11_ll_init_screen(void) {}

void pkcs11_ll_release_screen(void) {}


void pkcs11_ll_echo_off(void)
{
    DWORD con_mode;
    HANDLE hIn=GetStdHandle(STD_INPUT_HANDLE);

    GetConsoleMode( hIn, &con_mode );
    SetConsoleMode( hIn, con_mode & ~(ENABLE_ECHO_INPUT) );
}

void pkcs11_ll_echo_on(void)
{
    DWORD con_mode;
    HANDLE hIn=GetStdHandle(STD_INPUT_HANDLE);

    GetConsoleMode( hIn, &con_mode );
    SetConsoleMode( hIn, con_mode | ENABLE_ECHO_INPUT );
}



void pkcs11_ll_clear_screen(void)
{
    /* the code below has been taken from http://support.microsoft.com/kb/99261 */

    /* Standard error macro for reporting API errors */ 
#define PERR(bSuccess, api){if(!(bSuccess)) printf("%s:Error %d from %s on line %d\n", __FILE__, GetLastError(), api, __LINE__);}

    COORD coordScreen = { 0, 0 };    /* here's where we'll home the
                                        cursor */ 
    BOOL bSuccess;
    DWORD cCharsWritten;
    CONSOLE_SCREEN_BUFFER_INFO csbi; /* to get buffer info */ 
    DWORD dwConSize;                 /* number of character cells in
                                        the current buffer */ 
    HANDLE hConsole;

    /* get the number of character cells in the current buffer */ 
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    bSuccess = GetConsoleScreenBufferInfo( hConsole, &csbi );
    PERR( bSuccess, "GetConsoleScreenBufferInfo" );
    dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

    /* fill the entire screen with blanks */ 

    bSuccess = FillConsoleOutputCharacter( hConsole, (TCHAR) ' ', dwConSize, coordScreen, &cCharsWritten );
    PERR( bSuccess, "FillConsoleOutputCharacter" );

    /* get the current text attribute */ 

    bSuccess = GetConsoleScreenBufferInfo( hConsole, &csbi );
    PERR( bSuccess, "ConsoleScreenBufferInfo" );

    /* now set the buffer's attributes accordingly */ 

    bSuccess = FillConsoleOutputAttribute( hConsole, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten );
    PERR( bSuccess, "FillConsoleOutputAttribute" );

    /* put the cursor at (0, 0) */ 

    bSuccess = SetConsoleCursorPosition( hConsole, coordScreen );
    PERR( bSuccess, "SetConsoleCursorPosition" );
}


char *pkcs11_ll_basename(char *path)
{
    char *base = strrchr(path, '\\');
    return base ? base+1 : path;
}


void pkcs11_ll_set_binary(FILE *fp)
{
    int result;

    result = _setmode ( _fileno (fp), _O_BINARY );
    if(result== -1) {
	perror("Cannot set binary mode on file");
    }
}

/* we leverage on gnulib to define bswap_32 appropriately */
/* whatever the UNIX platform. */
/* if there is an error a compile time, please check m4/local_fix_bswap.m4 */
/* add add according support */

inline unsigned long pkcs11_ll_bigendian_ul(unsigned long argul)
{
#if defined(WORDS_BIGENDIAN)	/* we are in Big Endian */
    return argul;		/* very unlikely, but you never know... */
#else                           /* we are in little Endian */
#if SIZEOF_UNSIGNED_LONG_INT==4
    return _byteswap_ulong(argul);
#elif SIZEOF_UNSIGNED_LONG_INT==8
    return _byteswap_uint64(argul);
#else
#error "Error: unsupported unsigned long size."    
#endif
#endif
}
