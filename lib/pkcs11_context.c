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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* #include <link.h> */
#include <unistd.h>
#include "pkcs11lib.h"

pkcs11Context * pkcs11_newContext( char *libraryname, char *nssconfigdir )
{

    pkcs11Context * p11Context = NULL;
    char *nssinitparams = NULL;

    if ( ( access( libraryname, F_OK ) ) != 0 )
    {
	fprintf( stderr, "Error: PKCS#11 Library [ %s ] does not exist!\n", libraryname );
	goto err;
    }


    if(nssconfigdir!=NULL) {
	nssinitparams = malloc( strlen(nssconfigdir) + 13 ); /* configDir='<stuff>' */

	if(!nssinitparams) {
	    fprintf(stderr, "Error: Cannot allocate memory\n");
	    goto err;
	}
    }

    p11Context = calloc(1,sizeof(pkcs11Context)); /* we want it be cleared */

    if(p11Context==NULL) {
	fprintf(stderr, "Error: Cannot allocate memory\n");
	goto err;
    }

    p11Context->library = libraryname;
    if(nssconfigdir!=NULL) {
	sprintf(nssinitparams, "configDir='%s'", nssconfigdir);
    }

    p11Context->nssinitparams = nssinitparams;
    nssinitparams = NULL; 	/* transfer ownership */
#ifdef HAVE_DUPLICATES_ENABLED
	p11Context->can_duplicate = false;
#endif


err:
    if(nssinitparams) free(nssinitparams);

    return p11Context;
}


void pkcs11_freeContext( pkcs11Context *p11Context )
{
    if(p11Context) {
	if(p11Context->nssinitparams) { free(p11Context->nssinitparams); p11Context->nssinitparams = NULL; }
	free(p11Context);
    }
}

func_rc pkcs11_initialize( pkcs11Context * p11Context )
{
    func_rc rc = rc_ok;
    CK_RV rv;
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_C_GetFunctionList pC_GetFunctionList = NULL;
    CK_C_Initialize pC_Initialize;
    CK_C_INITIALIZE_ARGS InitArgs;
    CK_NSS_C_INITIALIZE_ARGS NSS_InitArgs;


    if ( ( p11Context->libhandle = pkcs11_ll_dynlib_open((const char *) p11Context->library) ) == NULL )
    {
	rc = rc_dlopen_error;
	goto err;
    }

    if ( ( pC_GetFunctionList = ( CK_C_GetFunctionList ) pkcs11_ll_dynlib_getfunc( p11Context->libhandle, "C_GetFunctionList" ) ) == NULL )
    {
	rc = rc_dlsym_error;
	goto err;
    }

    if ( ( rv = pC_GetFunctionList( &pFunctionList ) ) != CKR_OK )
    {
	pkcs11_error( rv, "C_GetFunctionList" );
	rc = rc_dlfunc_error;
	goto err;
    }

    p11Context->FunctionList = *pFunctionList;

    InitArgs.CreateMutex = NULL_PTR;
    InitArgs.DestroyMutex = NULL_PTR;
    InitArgs.LockMutex = NULL_PTR;
    InitArgs.UnlockMutex = NULL_PTR;
    InitArgs.flags = CKF_OS_LOCKING_OK; /* just pretend we do multithread calls, with native OS locking  */
                                        /* we don't use multithread, but some p11 libs want to see that flag */
    InitArgs.pReserved = NULL_PTR;

    NSS_InitArgs.CreateMutex = NULL_PTR;
    NSS_InitArgs.DestroyMutex = NULL_PTR;
    NSS_InitArgs.LockMutex = NULL_PTR;
    NSS_InitArgs.UnlockMutex = NULL_PTR;
    NSS_InitArgs.flags = CKF_OS_LOCKING_OK;
    NSS_InitArgs.LibraryParameters = (CK_CHAR_PTR *) p11Context->nssinitparams;
    NSS_InitArgs.pReserved = NULL_PTR;

    pC_Initialize = pFunctionList->C_Initialize;

    rv = pC_Initialize( &InitArgs );
    if ( rv!=CKR_OK && rv!=CKR_CRYPTOKI_ALREADY_INITIALIZED )
    {
	if(p11Context->nssinitparams==NULL) {
	    /* if we don't have NSS parameters, */
	    /* then show an error */
	    pkcs11_error( rv, "C_Initialize" );
	    rc = rc_error_pkcs11_api;
	    goto err;
	}

	else if ( rv == CKR_ARGUMENTS_BAD )
	{
	    rv = pC_Initialize( &NSS_InitArgs );
	    if ( rv == CKR_ARGUMENTS_BAD )
	    {
		pkcs11_error( rv, "C_Initialize" );

		rv = pC_Initialize( NULL_PTR );
		if ( rv == CKR_ARGUMENTS_BAD ) {
		    pkcs11_error( rv, "C_Initialize" );
		    rc = rc_error_pkcs11_api;
		    goto err;
		}
	    }
	}
    }

    p11Context->initialized = CK_TRUE;
err:
    return rc;
}

func_rc pkcs11_finalize( pkcs11Context * p11Context )
{
    func_rc rc = rc_ok;
    CK_RV retCode;

    if(p11Context && p11Context->initialized) {
	if( p11Context->FunctionList.C_Finalize ) {
	    if ( ( retCode = p11Context->FunctionList.C_Finalize( NULL_PTR ) ) != CKR_OK ) {
		pkcs11_error( retCode, "C_Finalize" );
		rc = rc_error_pkcs11_api;
	    }
	}

	p11Context->initialized = CK_FALSE;
	
	if(p11Context->libhandle) {
	    pkcs11_ll_dynlib_close(p11Context->libhandle);
	    p11Context->libhandle=NULL;
	}
    }
    return rc;
}


void pkcs11_exit(pkcs11Context *p11Context, int status)
{
    if(p11Context && p11Context->libhandle) {
	pkcs11_ll_dynlib_close(p11Context->libhandle);
    }
    exit(status);
}

/*
 *--------------------------------------------------------------------------------
 * $Log$
 *--------------------------------------------------------------------------------
 */
