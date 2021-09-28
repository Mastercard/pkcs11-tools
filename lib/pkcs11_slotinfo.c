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
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include "pkcs11lib.h"


#define HAS_FLAG(a,fl,t,f) ( (a & fl) ? t : f )
#define IS_VENDOR_DEFINED(m,t,f) ( (m & CKM_VENDOR_DEFINED) == CKM_VENDOR_DEFINED ? t : f )

/* high-level search functions */

func_rc pkcs11_info_slot(pkcs11Context *p11Context)
{
    func_rc rc=rc_ok;



    if(p11Context) {

	CK_SLOT_INFO slotinfo;
	CK_TOKEN_INFO tokeninfo;
	CK_RV rv;
	
	CK_MECHANISM_TYPE_PTR mechlist = NULL_PTR;
	CK_ULONG mechlist_len = 0L, i;
	
	
	if((rv = p11Context->FunctionList.C_GetSlotInfo( p11Context->slot, &slotinfo)) != CKR_OK ) {
	    pkcs11_error( rv, "C_GetSlotInfo" );
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	fprintf( stdout, 		     
		 "Slot[%d]\n" 
		 "-------------\n"
		 "Slot Number : %lu\n"
		 "Description : %.*s\n"  /* Print the slot description */
		 "Manufacturer: %.*s\n"
		 "Slot Flags  : [ %s%s%s]\n\n",
		 p11Context->slotindex,
		 p11Context->slot,
		 (int)sizeof(slotinfo.slotDescription), slotinfo.slotDescription,
		 (int)sizeof(slotinfo.manufacturerID), slotinfo.manufacturerID,
		 HAS_FLAG(slotinfo.flags, CKF_TOKEN_PRESENT, "CKF_TOKEN_PRESENT ",""),
		 HAS_FLAG(slotinfo.flags, CKF_REMOVABLE_DEVICE, "CKF_REMOVABLE_DEVICE ",""),		 
		 HAS_FLAG(slotinfo.flags, CKF_HW_SLOT, "CKF_HW_SLOT","")
	    );
	    
	if (( rv = p11Context->FunctionList.C_GetTokenInfo( p11Context->slot, &tokeninfo ) ) != CKR_OK ) {
	    pkcs11_error( rv, "C_GetTokenInfo" );
	    rc = rc_error_pkcs11_api;
	    goto error;
	} 
	
	fprintf( stdout, 
		 "Token\n"
		 "-------------\n"
		 "Label       : %.*s\n"		/* Print the Token Label */
		 "Manufacturer: %.*s\n\n"		/* Print the Token Manufacturer */
		 "Token Flags : [ %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s]\n\n",
		 (int)sizeof(tokeninfo.label), tokeninfo.label,
		 (int)sizeof(tokeninfo.manufacturerID), tokeninfo.manufacturerID,
		 HAS_FLAG(tokeninfo.flags, CKF_RNG, "CKF_RNG ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_WRITE_PROTECTED, "CKF_WRITE_PROTECTED ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_LOGIN_REQUIRED, "CKF_LOGIN_REQUIRED ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_USER_PIN_INITIALIZED, "CKF_USER_PIN_INITIALIZED ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_RESTORE_KEY_NOT_NEEDED, "CKF_RESTORE_KEY_NOT_NEEDED ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_CLOCK_ON_TOKEN, "CKF_CLOCK_ON_TOKEN ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_PROTECTED_AUTHENTICATION_PATH, "CKF_PROTECTED_AUTHENTICATION_PATH ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_DUAL_CRYPTO_OPERATIONS, "CKF_DUAL_CRYPTO_OPERATIONS ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_TOKEN_INITIALIZED, "CKF_TOKEN_INITIALIZED ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_SECONDARY_AUTHENTICATION, "CKF_SECONDARY_AUTHENTICATION ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_USER_PIN_COUNT_LOW, "CKF_USER_PIN_COUNT_LOW ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_USER_PIN_FINAL_TRY, "CKF_USER_PIN_FINAL_TRY ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_USER_PIN_LOCKED, "CKF_USER_PIN_LOCKED ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_USER_PIN_TO_BE_CHANGED, "CKF_USER_PIN_TO_BE_CHANGED ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_SO_PIN_COUNT_LOW, "CKF_SO_PIN_COUNT_LOW ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_SO_PIN_FINAL_TRY, "CKF_SO_PIN_FINAL_TRY ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_SO_PIN_LOCKED, "CKF_SO_PIN_LOCKED ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_SO_PIN_TO_BE_CHANGED, "CKF_SO_PIN_TO_BE_CHANGED ",""),
		 HAS_FLAG(tokeninfo.flags, CKF_ERROR_STATE, "CKF_ERROR_STATE","")
	    );
	
	
	if (( rv = p11Context->FunctionList.C_GetMechanismList( p11Context->slot, NULL_PTR, &mechlist_len ) ) != CKR_OK ) {
	    pkcs11_error( rv, "C_GetMechanismList" );
	    rc = rc_error_pkcs11_api;
	    goto error;
	} 

	mechlist=calloc( mechlist_len, sizeof(CK_MECHANISM_TYPE) );

	if(mechlist==NULL) {
	    fprintf(stderr, "Ouch, memory error.\n");
	    goto error;
	}
	
	if (( rv = p11Context->FunctionList.C_GetMechanismList( p11Context->slot, mechlist, &mechlist_len ) ) != CKR_OK ) {
	    pkcs11_error( rv, "C_GetMechanismList" );
	    rc = rc_error_pkcs11_api;
	    goto error;
	}

	fprintf( stdout, "Mechanisms:\n-----------\n");
	
	for(i=0; i<mechlist_len; i++) {
	    CK_MECHANISM_INFO mechinfo;
	    const char *mname = pkcs11_get_mechanism_name_from_type(mechlist[i]);
	    
	    if (( rv = p11Context->FunctionList.C_GetMechanismInfo( p11Context->slot, mechlist[i], &mechinfo ) ) != CKR_OK ) {
		pkcs11_error( rv, "C_GetMechanismInfo" );
		rc = rc_error_pkcs11_api;
		continue;
	    }
	    
	    fprintf(stdout, 
		    "%.*s%*.*s %c"
		    "%s %s %s %s %s %s %s %s %s %s %s %s %s (%08.8lx)", 
		    (int)strlen(mname), mname,
		    (int) (40-strlen(mname)), (int) (40-strlen(mname)),
		    "                                        ",
		    IS_VENDOR_DEFINED(mechlist[i], '*', ' '),
		    HAS_FLAG(mechinfo.flags, CKF_ENCRYPT, "enc", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_DECRYPT, "dec", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_DIGEST,  "hsh", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_SIGN,    "sig", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_SIGN_RECOVER, "sir", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_VERIFY,  "vfy", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_VERIFY_RECOVER, "vre", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_GENERATE, "gen", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_GENERATE_KEY_PAIR, "gkp", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_WRAP, "wra", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_UNWRAP, "unw", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_DERIVE, "der", "---"),
		    HAS_FLAG(mechinfo.flags, CKF_HW, "HW", "SW"),
		    mechlist[i]);

	    /* we have an elliptic curve mechanism, additional info to print */
	    if(mechinfo.flags & (CKF_EC_F_P | CKF_EC_F_2M) ) {
		fprintf(stdout,
			" ec: %s %s %s %s %s %s\n",
			HAS_FLAG(mechinfo.flags, CKF_EC_F_P, "F^p", "---"),
			HAS_FLAG(mechinfo.flags, CKF_EC_F_2M, "F2m", "---"),
			HAS_FLAG(mechinfo.flags, CKF_EC_ECPARAMETERS, "par", "---"),
			HAS_FLAG(mechinfo.flags, CKF_EC_NAMEDCURVE, "nam", "---"),
			HAS_FLAG(mechinfo.flags, CKF_EC_UNCOMPRESS, "unc", "---"),
			HAS_FLAG(mechinfo.flags, CKF_EC_COMPRESS, "cmp", "---")
		    );

	    } else {
		fputc('\n', stdout);
	    }
	}
	fputc('\n', stdout);


error:
	if(mechlist!=NULL) free(mechlist);	
	
    }

    return rc;

}


/* pkcs11_info_ecsupport: find out which named EC named curves are supported */

func_rc pkcs11_info_ecsupport(pkcs11Context *p11Context)
{
    func_rc rc=rc_ok;

    if(p11Context) {
	size_t crv_len = 0, n;
	EC_builtin_curve *curves = NULL;
		
	crv_len = EC_get_builtin_curves(NULL, 0);
	
	if(crv_len==0) {
	    P_ERR();
	    goto error;
	}

	curves = OPENSSL_malloc((int)(sizeof(EC_builtin_curve) * crv_len));
	
	if (curves == NULL) {
	    P_ERR();
	    goto error;
	}
	

	if (!EC_get_builtin_curves(curves, crv_len)) {
	    P_ERR();
	    goto error;
	}


	fprintf( stdout, "EC curves supported by token:\n-----------------------------\n");
	
	for (n = 0; n < crv_len; n++)
	{
	    const char *sname;
	    sname   = OBJ_nid2sn(curves[n].nid);
	    if (sname == NULL) {
		P_ERR();
		continue;
	    }
	    if ( pkcs11_testgenEC_support(p11Context, sname)==1 ) {
		fprintf(stdout, "%s\n",  sname );
	    }
	} 
	fputc('\n', stdout);
	
error:
	if(curves!=NULL) { OPENSSL_free(curves); }
	
    }

    return rc;

}


/* EOF */
