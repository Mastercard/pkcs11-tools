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



/* prototypes and small/inline functions */
static int tokenlabelcmp(const char *label, const char *reflabel, size_t reflabel_maxlen);
static int min(const int a, const int b);
static int max(const int a, const int b);

static int compare_mech_type(const void *a, const void *b)
{
    return *(const CK_MECHANISM_TYPE *)b- *(const CK_MECHANISM_TYPE *)a;
}


static inline int min(const int a, const int b) {
    return a<b ? a : b;
}

static inline int max(const int a, const int b) {
    return a>b ? a : b;
}

/* tokenlabelcmp: compare label based on tokeninfo.tokenlabel
**
** arguments:
**  - label: pointer to label to compare, assumed to be trimmed already
**  - reflabel: pointer to a possibly non-NULL terminated reference label,
**              ending with spaces
**  - reflabel_maxlen: maximum lenght of reflabel
**
** return code: int -> 0 when label and tokenlabel are matching, 1/-1 otherwise
**
** the function will try to determine the actual length of the reference string
** by counting space characters from the end, then perform a non-case sensitive 
** string comparison, limited in length by reflabel_maxlen
** 
** caution: if label length exceeds reflabel_maxlen, the function returns prematurely
**          with a warning.
*/

static int tokenlabelcmp(const char *label, const char *reflabel, size_t reflabel_maxlen)
{

    size_t label_len = strlen(label);

    if(label_len>reflabel_maxlen) {
	fprintf(stderr, "Warning: string '%s' is longer than %zu characters\n", label, reflabel_maxlen);
	return 1;		/* return prematurely */
    }

    /* tokenlabel may end with spaces (expected), and \0x0 (less expected), */
    /* let's try to find where the token label actually ends (first non-space character) */
    int reflabel_real_end=reflabel_maxlen;
    while( reflabel_real_end>0 && ( isspace(reflabel[reflabel_real_end-1]) || reflabel[reflabel_real_end-1]==0x00) ) {
	reflabel_real_end--;
    }

    /* return a string compare, using the longest chain, but limiting it to the max length of reflabel */
    /* (32 in our case) */
    return strncasecmp(label, reflabel, min(reflabel_maxlen, max(label_len, reflabel_real_end)));
}

func_rc pkcs11_open_session( pkcs11Context * p11Context, int slot, char *tokenlabel, char * password, int so, int interactive )
{
    CK_RV rv;
    func_rc rc = rc_ok;
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

    /* Get the number of slots */
    if ( ( rv = p11Context->FunctionList.C_GetSlotList( CK_FALSE, NULL_PTR, &ulSlotCount ) ) != CKR_OK )
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

    if ( ( rv = p11Context->FunctionList.C_GetSlotList( CK_FALSE, pSlotList, &ulSlotCount ) ) != CKR_OK )
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
	    if ( ( rv = p11Context->FunctionList.C_GetSlotInfo( pSlotList[i], &slotInfo ) ) != CKR_OK ) {
		pkcs11_error( rv, "C_GetSlotInfo" );
	    } else	{
		if ( (rv = p11Context->FunctionList.C_GetTokenInfo( pSlotList[i], &tokenInfo )) != CKR_OK) {
		    if(rv!=CKR_TOKEN_NOT_PRESENT) { /* in case there is no token, silently pass - this is not an error */
			pkcs11_error( rv, "C_GetTokenInfo" );
		    }
		} else {
		    /* comparison routine for the tokenlabel */
		    if(tokenlabelcmp(tokenlabel, (const char *)(tokenInfo.label), sizeof tokenInfo.label)==0) {
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
	    if ( ( rv = p11Context->FunctionList.C_GetSlotInfo( pSlotList[i], &slotInfo ) ) != CKR_OK ) {
		pkcs11_error( rv, "C_GetSlotInfo" );
	    } else	{
		fprintf( stderr,
			 "Slot index: %d\n"
			 "----------------\n"
			 "Description : %.*s\n", /* Print the slot description */
			 i,
			 (int)sizeof(slotInfo.slotDescription), slotInfo.slotDescription
		    );

		if ( ( rv = p11Context->FunctionList.C_GetTokenInfo( pSlotList[i], &tokenInfo ) ) != CKR_OK ) {
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

    /* fetch AES wrapping mechanisms, if supported */
    {
	CK_MECHANISM_TYPE_PTR mechlist = NULL_PTR;
	CK_ULONG mechlist_len = 0L;

	if (( rv = p11Context->FunctionList.C_GetMechanismList( p11Context->slot, NULL_PTR, &mechlist_len ) ) != CKR_OK ) {
	    pkcs11_error( rv, "C_GetMechanismList" );
	    rc = rc_error_pkcs11_api;
	    goto err;
	}

	mechlist=calloc( mechlist_len, sizeof(CK_MECHANISM_TYPE) );

	if(mechlist==NULL) {
	    fprintf(stderr, "Ouch, memory error.\n");
	    goto err;
	}

	if (( rv = p11Context->FunctionList.C_GetMechanismList( p11Context->slot, mechlist, &mechlist_len ) ) != CKR_OK ) {
	    pkcs11_error( rv, "C_GetMechanismList" );
	    rc = rc_error_pkcs11_api;
	    free(mechlist);
	    goto err;
	}

	/* now we have the full list, let's go through it, and add what we look for */
	for(CK_ULONG i=0; i<mechlist_len && p11Context->rfc3394_mech_size<AES_WRAP_MECH_SIZE_MAX; i++) {
	    switch(mechlist[i]) {
	    case CKM_AES_KEY_WRAP:     /* nCipher v12.50+, SoftHSM v2 */
	    case CKM_NSS_AES_KEY_WRAP: /* specific to NSS */
#if defined(HAVE_LUNA)
	    case CKM_LUNA_AES_KW:	/* on Safenet Gemalto Luna V7 */
#endif
		p11Context->rfc3394_mech[p11Context->rfc3394_mech_size++] = mechlist[i];
	    default:
		continue;
	    }
	}

	/* we sort in ascending order. This way, if we have several mechanisms supported, the standard */
	/* should be picked up first, assuming that vendor-specific mechanisms are higher in the list, */
	/* thanks to CKM_VENDOR_DEFINED. */
	qsort(p11Context->rfc3394_mech, p11Context->rfc3394_mech_size, sizeof(CK_MECHANISM_TYPE), compare_mech_type);

	for(CK_ULONG i=0; i<mechlist_len && p11Context->rfc5649_mech_size<AES_WRAP_MECH_SIZE_MAX; i++) {
	    switch(mechlist[i]) {
	    case CKM_AES_KEY_WRAP_PAD:     /* nCipher v12.50+, SoftHSM v2 */
	    case CKM_NSS_AES_KEY_WRAP_PAD: /* specific to NSS */
#if defined(HAVE_LUNA)
	    case CKM_LUNA_AES_KWP:	/* on Safenet Gemalto Luna V7 */
#endif
		p11Context->rfc5649_mech[p11Context->rfc5649_mech_size++] = mechlist[i];
	    default:
		continue;
	    }
	}

	/* same comment as above */
	qsort(p11Context->rfc5649_mech, p11Context->rfc5649_mech_size, sizeof(CK_MECHANISM_TYPE), compare_mech_type);

	free(mechlist);
    }

    rv = p11Context->FunctionList.C_OpenSession( hSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession );

    if ( rv == CKR_TOKEN_WRITE_PROTECTED  ) {
	/* try to open it read-only */
	rv = p11Context->FunctionList.C_OpenSession( hSlot, CKF_SERIAL_SESSION, NULL, NULL, &hSession );
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

	if ( ( rv = p11Context->FunctionList.C_Login( hSession, (so>0) ? CKU_SO : CKU_USER, ( CK_CHAR * ) pass, passLen ) ) != CKR_OK )
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
