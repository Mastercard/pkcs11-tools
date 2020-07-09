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

#include "cryptoki.h"
#include "pkcs11lib.h"

/* prototype - function is not public */
func_rc _message( CK_RV rv, char * const prefix, char * const pkcs11_function );


/* implementation */


func_rc _message( CK_RV rv, char *prefix, char * pkcs11_function )
{
    switch ( rv )
    {
    case CKR_OK:
	fprintf( stderr, "--- PKCS#11 Info: %s() returned CKR_OK ( 0x%.08lx )\n", pkcs11_function, rv );
	break;

    case CKR_CANCEL:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_CANCEL ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_HOST_MEMORY:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_HOST_MEMORY ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SLOT_ID_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SLOT_ID_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_GENERAL_ERROR:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_GENERAL_ERROR ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_FUNCTION_FAILED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_FUNCTION_FAILED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_ARGUMENTS_BAD:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_ARGUMENTS_BAD ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_NO_EVENT:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_NO_EVENT ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_NEED_TO_CREATE_THREADS:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_NEED_TO_CREATE_THREADS ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_CANT_LOCK:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_CANT_LOCK ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_ATTRIBUTE_READ_ONLY:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_ATTRIBUTE_READ_ONLY ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_ATTRIBUTE_SENSITIVE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_ATTRIBUTE_SENSITIVE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_ATTRIBUTE_TYPE_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_ATTRIBUTE_TYPE_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_ATTRIBUTE_VALUE_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_ATTRIBUTE_VALUE_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_DATA_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_DATA_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_DATA_LEN_RANGE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_DATA_LEN_RANGE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_DEVICE_ERROR:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_DEVICE_ERROR ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_DEVICE_MEMORY:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_DEVICE_MEMORY ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_DEVICE_REMOVED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_DEVICE_REMOVED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_ENCRYPTED_DATA_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_ENCRYPTED_DATA_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_ENCRYPTED_DATA_LEN_RANGE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_ENCRYPTED_DATA_LEN_RANGE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_FUNCTION_CANCELED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_FUNCTION_CANCELED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_FUNCTION_NOT_PARALLEL:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_FUNCTION_NOT_PARALLEL ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_FUNCTION_NOT_SUPPORTED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_FUNCTION_NOT_SUPPORTED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_KEY_HANDLE_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_KEY_HANDLE_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_KEY_SIZE_RANGE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_KEY_SIZE_RANGE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_KEY_TYPE_INCONSISTENT:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_KEY_TYPE_INCONSISTENT ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_KEY_NOT_NEEDED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_KEY_NOT_NEEDED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_KEY_CHANGED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_KEY_CHANGED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_KEY_NEEDED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_KEY_NEEDED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_KEY_INDIGESTIBLE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_KEY_INDIGESTIBLE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_KEY_FUNCTION_NOT_PERMITTED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_KEY_FUNCTION_NOT_PERMITTED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_KEY_NOT_WRAPPABLE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_KEY_NOT_WRAPPABLE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_KEY_UNEXTRACTABLE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_KEY_UNEXTRACTABLE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_MECHANISM_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_MECHANISM_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_MECHANISM_PARAM_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_MECHANISM_PARAM_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_OBJECT_HANDLE_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_OBJECT_HANDLE_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_OPERATION_ACTIVE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_OPERATION_ACTIVE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_OPERATION_NOT_INITIALIZED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_OPERATION_NOT_INITIALIZED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_PIN_INCORRECT:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_PIN_INCORRECT ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_PIN_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_PIN_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_PIN_LEN_RANGE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_PIN_LEN_RANGE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_PIN_EXPIRED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_PIN_EXPIRED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_PIN_LOCKED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_PIN_LOCKED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SESSION_CLOSED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SESSION_CLOSED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SESSION_COUNT:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SESSION_COUNT ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SESSION_HANDLE_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SESSION_HANDLE_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SESSION_PARALLEL_NOT_SUPPORTED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SESSION_READ_ONLY:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SESSION_READ_ONLY ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SESSION_EXISTS:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SESSION_EXISTS ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SESSION_READ_ONLY_EXISTS:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SESSION_READ_ONLY_EXISTS ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SESSION_READ_WRITE_SO_EXISTS:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SESSION_READ_WRITE_SO_EXISTS ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SIGNATURE_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SIGNATURE_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SIGNATURE_LEN_RANGE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SIGNATURE_LEN_RANGE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_TEMPLATE_INCOMPLETE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_TEMPLATE_INCOMPLETE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_TEMPLATE_INCONSISTENT:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_TEMPLATE_INCONSISTENT ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_TOKEN_NOT_PRESENT:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_TOKEN_NOT_PRESENT ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_TOKEN_NOT_RECOGNIZED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_TOKEN_NOT_RECOGNIZED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_TOKEN_WRITE_PROTECTED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_TOKEN_WRITE_PROTECTED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_UNWRAPPING_KEY_HANDLE_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_UNWRAPPING_KEY_SIZE_RANGE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_UNWRAPPING_KEY_SIZE_RANGE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_USER_ALREADY_LOGGED_IN:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_USER_ALREADY_LOGGED_IN ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_USER_NOT_LOGGED_IN:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_USER_NOT_LOGGED_IN ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_USER_PIN_NOT_INITIALIZED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_USER_PIN_NOT_INITIALIZED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_USER_TYPE_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_USER_TYPE_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_USER_ANOTHER_ALREADY_LOGGED_IN ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_USER_TOO_MANY_TYPES:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_USER_TOO_MANY_TYPES ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_WRAPPED_KEY_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_WRAPPED_KEY_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_WRAPPED_KEY_LEN_RANGE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_WRAPPED_KEY_LEN_RANGE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_WRAPPING_KEY_HANDLE_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_WRAPPING_KEY_HANDLE_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_WRAPPING_KEY_SIZE_RANGE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_WRAPPING_KEY_SIZE_RANGE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_WRAPPING_KEY_TYPE_INCONSISTENT ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_RANDOM_SEED_NOT_SUPPORTED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_RANDOM_SEED_NOT_SUPPORTED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_RANDOM_NO_RNG:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_RANDOM_NO_RNG ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_DOMAIN_PARAMS_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_DOMAIN_PARAMS_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_BUFFER_TOO_SMALL:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_BUFFER_TOO_SMALL ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_SAVED_STATE_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_SAVED_STATE_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_INFORMATION_SENSITIVE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_INFORMATION_SENSITIVE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_STATE_UNSAVEABLE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_STATE_UNSAVEABLE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_CRYPTOKI_NOT_INITIALIZED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_CRYPTOKI_NOT_INITIALIZED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_CRYPTOKI_ALREADY_INITIALIZED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_CRYPTOKI_ALREADY_INITIALIZED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_MUTEX_BAD:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_MUTEX_BAD ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_MUTEX_NOT_LOCKED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_MUTEX_NOT_LOCKED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_NEW_PIN_MODE:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_NEW_PIN_MODE ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_NEXT_OTP:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_NEXT_OTP ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_EXCEEDED_MAX_ITERATIONS:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_EXCEEDED_MAX_ITERATIONS ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_FIPS_SELF_TEST_FAILED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_FIPS_SELF_TEST_FAILED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_LIBRARY_LOAD_FAILED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_LIBRARY_LOAD_FAILED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_PIN_TOO_WEAK:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_PIN_TOO_WEAK ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_PUBLIC_KEY_INVALID:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_PUBLIC_KEY_INVALID ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    case CKR_FUNCTION_REJECTED:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned CKR_FUNCTION_REJECTED ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;

    default:
	fprintf( stderr, "*** PKCS#11 %s: %s() returned unsupported error code ( 0x%.08lx )\n", prefix, pkcs11_function, rv );
	break;
    }

    return rv == CKR_OK ? rc_ok : rc_error_pkcs11_api;
}

inline func_rc pkcs11_error(CK_RV rv, char * const pkcs11_function) {
    return _message( rv, "Error", pkcs11_function );
}

inline func_rc pkcs11_warning(CK_RV rv, char * const pkcs11_function) {
    return _message( rv, "Warning", pkcs11_function );
}

/* EOF */
