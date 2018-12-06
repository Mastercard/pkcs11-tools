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
#include <ctype.h>
#include "pkcs11lib.h"



/* prototype */
static CK_UTF8CHAR_PTR rtrim(CK_UTF8CHAR_PTR str, int limit);


static CK_UTF8CHAR_PTR rtrim(CK_UTF8CHAR_PTR str, int limit)
{
    size_t n;

    if (limit>0) {
	n = strlen((const char *)str)>limit ? limit : strlen((const char *)str);
    } else {
	n = strlen((const char *)str);
    }

    
    while (n > 0 && isspace(str[n - 1])) {
	n--;
    }
    str[n] = '\0';

    return str;
}

func_rc pkcs11_open_session( pkcs11Context * p11Context, int slot, char *tokenlabel, char * password, int so, int interactive )
{
    CK_RV rv;
    func_rc rc = rc_ok;
    CK_C_GetSlotList pC_GetSlotList;
    CK_C_GetSlotInfo pC_GetSlotInfo;
    CK_C_GetTokenInfo pC_GetTokenInfo;
    CK_C_OpenSession pC_OpenSession;
    CK_C_Login pC_Login;
    CK_SLOT_ID hSlot;
    CK_SLOT_ID_PTR pSlotList = NULL;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
    CK_SESSION_HANDLE hSession;
    CK_ULONG ulSlotCount=0;
    long s;
    int i, x, y;
    int passLen = 0;
    char * tmpSlot = NULL;
    char * pass = NULL;
    char * cbpass = NULL;
    char * pEnd = NULL;

    /* Setup Function Pointers */
    pC_GetSlotList = p11Context->FunctionList.C_GetSlotList;
    pC_GetSlotInfo = p11Context->FunctionList.C_GetSlotInfo;
    pC_GetTokenInfo = p11Context->FunctionList.C_GetTokenInfo;
    pC_OpenSession = p11Context->FunctionList.C_OpenSession;
    pC_Login = p11Context->FunctionList.C_Login;

    /* Get the number of slots */
    if ( ( rv = pC_GetSlotList( CK_FALSE, NULL_PTR, &ulSlotCount ) ) != CKR_OK )
    {
	pkcs11_error( rv, "C_GetSlotList" );
	rc = rc_error_pkcs11_api;
	goto err;
    }

    /* Allocate memory for slots list */
    if ( ( pSlotList = ( CK_SLOT_ID_PTR ) malloc( ulSlotCount * sizeof ( CK_SLOT_ID ) ) ) == NULL )
    {
	fprintf( stderr, "Error: No memory available\n" );
	rc = rc_error_memory;
	goto err;
    }

    memset( pSlotList, 0x00, ( ulSlotCount * sizeof ( CK_SLOT_ID ) ) );

    if ( ( rv = pC_GetSlotList( CK_FALSE, pSlotList, &ulSlotCount ) ) != CKR_OK )
    {
	pkcs11_error( rv, "C_GetSlotList" );
	rc = rc_error_pkcs11_api;
	goto err;
    }
    /* OK, now we have a list of slots, from which we have to pick a slot number */
    /* given an index in the list */

    /* because of that, if an index is given, it must be bound to the array */
    /* of slots we have received - unless we enjoy core dumps. */

    /* we have to cleverly choose between interactive or batch mode */
    /* we are interactive when interactive==1 */
    /* otherwise, a slot has been choosen for us */
    /* so we won't bother requester for another slot */

    /* first, if a tokenlabel is given, then we are NEVER interactive */
    if ( tokenlabel != NULL ) {
	slot = -1;		/* ensure we forget slot */
	for ( i = 0; i < ulSlotCount; i++ ) {
	    if ( ( rv = pC_GetSlotInfo( pSlotList[i], &slotInfo ) ) != CKR_OK ) {
		pkcs11_error( rv, "C_GetSlotInfo" );
	    } else	{
		if ( (rv = pC_GetTokenInfo( pSlotList[i], &tokenInfo )) != CKR_OK) {
		    if(rv!=CKR_TOKEN_NOT_PRESENT) { /* in case there is no token, silently pass - this is not an error */
			pkcs11_error( rv, "C_GetTokenInfo" );
		    }
		} else {
		    if(strcasecmp(tokenlabel, (const char *)rtrim(tokenInfo.label, sizeof(tokenInfo.label) ))==0) {
			slot=i;	/* remember the slot number */
			break;	/* exit the loop */
		    }
		}
	    }
	}

	/* if slot==-1 here, it means that no match has been found. */
	/* signal the error and exit gracefully */
	if(slot==-1) {
	    fprintf(stderr, "*** Error: token with label '%s' not found\n", tokenlabel);
	    rc = rc_error_invalid_slot_or_token;
	    goto err;
	}
    }
    
    if ( slot < 0 || slot > ulSlotCount ) {
	
	/* if we are not interactive, exit directly */
	if(!interactive) {
	    fprintf(stderr, "*** Error: slot index value %d not within range [0,%lu]\n", slot, ulSlotCount-1);
	    rc = rc_error_invalid_slot_or_token;
	    goto err;
	}

	/* otherwise, list all slots and ask to pick one */
	fprintf( stderr, "PKCS#11 module slot list:\n" );
	
	for ( i = 0; i < ulSlotCount; i++ ) {
	    if ( ( rv = pC_GetSlotInfo( pSlotList[i], &slotInfo ) ) != CKR_OK ) {
		pkcs11_error( rv, "C_GetSlotInfo" );
	    } else	{
		fprintf( stderr, 		     
			 "Slot index: %d\n" 
			 "----------------\n"
			 "Description : %.*s\n", /* Print the slot description */
			 i,
			 (int)sizeof(slotInfo.slotDescription), slotInfo.slotDescription
		    );
		
		if ( ( rv = pC_GetTokenInfo( pSlotList[i], &tokenInfo ) ) != CKR_OK ) {
		    if(rv!=CKR_TOKEN_NOT_PRESENT) { /* in case there is no token, silently pass - this is not an error */
			pkcs11_error( rv, "C_GetTokenInfo" );
		    }
		} else {
		    fprintf( stderr, 
			     "Token Label : %.*s\n"		/* Print the Token Label */
			     "Manufacturer: %.*s\n\n",		/* Print the Token Manufacturer */
			     (int)sizeof(tokenInfo.label), tokenInfo.label,
			     (int)sizeof(tokenInfo.manufacturerID), tokenInfo.manufacturerID );
		}
	    }
	}

	s = -1;			/* just in case... */

	while ( 1 ) {

	    tmpSlot = pkcs11_prompt( SLOT_PROMPT_STRING, CK_TRUE );
	    if (tmpSlot==NULL) {
		rc = rc_error_prompt;
		goto err;
	    }

	    s = ( int ) strtol( tmpSlot, &pEnd, 0 );
	    pkcs11_prompt_free_buffer(tmpSlot);

	    if(s >=0 && s < ulSlotCount) {
		break;
	    }
	    fprintf(stderr, "*** Error: slot index value %ld not within range [0,%lu]\n", s, ulSlotCount-1);
	}

	p11Context->slot = hSlot = pSlotList[s];
	p11Context->slotindex = s;
    } else {
	/* take it from argument directly, we are good to go */
	p11Context->slot = hSlot = pSlotList[slot];
	p11Context->slotindex = slot;
    }


    rv = pC_OpenSession( hSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession );
    
    if ( rv == CKR_TOKEN_WRITE_PROTECTED  ) {
	/* try to open it read-only */
	rv = pC_OpenSession( hSlot, CKF_SERIAL_SESSION, NULL, NULL, &hSession );
    }
    
    if ( rv != CKR_OK ) {
	pkcs11_error( rv, "C_OpenSession" );
	rc = rc_error_pkcs11_api;
	goto err;
    }

    p11Context->Session = hSession;
    p11Context->logged_in = CK_FALSE; /* keep track of logged in status */

    if (password == NULL) {
	/* prompt for password */
	pass = cbpass = pkcs11_prompt( PASS_PROMPT_STRING, CK_FALSE );	
    } else if(strncmp(PASSWORD_EXEC, password, strlen(PASSWORD_EXEC)) == 0) {
	/* execute a command and use output as password */
	pass = cbpass = pkcs11_pipe_password(password);
    } else if(strcmp(PASSWORD_NOLOGIN, password) ==0 ) {
	/* do not attempt to login */
	pass = NULL;
    } else {
	pass = password;
    }

    if(pass!=NULL) {
	passLen = strlen( pass );

	if ( ( rv = pC_Login( hSession, (so>0) ? CKU_SO : CKU_USER, ( CK_CHAR * ) pass, passLen ) ) != CKR_OK )
	{
	    pkcs11_error( rv, "C_Login" );
	    rc = rc_error_pkcs11_api;
	    goto err;
	}
	p11Context->logged_in = CK_TRUE;
    }

err:
    pkcs11_prompt_free_buffer(cbpass);
    if(pSlotList) { free( pSlotList ); }
    return rc;
}


/*------------------------------------------------------------------------*/

func_rc pkcs11_close_session( pkcs11Context * p11Context )
{
    func_rc rc = rc_ok;
    CK_RV retCode;
    CK_C_CloseSession pC_CloseSession;
    CK_C_Logout pC_Logout;

    pC_CloseSession = p11Context->FunctionList.C_CloseSession;
    pC_Logout = p11Context->FunctionList.C_Logout;

    if( p11Context->logged_in == CK_TRUE ) {
	if ( ( retCode = pC_Logout( p11Context->Session ) ) != CKR_OK ) {
	    pkcs11_error( retCode, "C_Logout" );
//	    rc = rc_error_pkcs11_api;
//	    goto err;
	}
	p11Context->logged_in = CK_FALSE;
    }

    if ( ( retCode = pC_CloseSession( p11Context->Session ) ) != CKR_OK ) {
	pkcs11_error( retCode, "C_CloseSession" );
	rc = rc_error_pkcs11_api;
	goto err;
    }
err:
    return rc;
}

/*
 *--------------------------------------------------------------------------------
 * $Log$
 *--------------------------------------------------------------------------------
 */
