/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2025 Mastercard
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

/*
 * test_error.c: unit tests for pkcs11_error() / pkcs11_warning().
 *
 * Both map a CK_RV to a human-readable message (printed on stderr) and return
 * a func_rc: rc_ok for CKR_OK, rc_error_pkcs11_api otherwise. They are pure
 * (no PKCS#11 token needed) and therefore run everywhere.
 *
 * Note: these functions print to stderr by design; the diagnostic lines that
 * appear in this test's log are expected, not failures.
 */

#include <stdlib.h>

#include "pkcs11lib.h"
#include "test_harness.h"

/* Every CK_RV explicitly handled by the switch in pkcs11_error.c (except
 * CKR_OK, which is checked separately). Iterating over all of them exercises
 * the full switch body. */
static const CK_RV error_codes[] = {
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_CANCEL,
    CKR_CANT_LOCK,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY,
    CKR_DEVICE_REMOVED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_EXCEEDED_MAX_ITERATIONS,
    CKR_FIPS_SELF_TEST_FAILED,
    CKR_FUNCTION_CANCELED,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_PARALLEL,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_FUNCTION_REJECTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_INFORMATION_SENSITIVE,
    CKR_KEY_CHANGED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_INDIGESTIBLE,
    CKR_KEY_NEEDED,
    CKR_KEY_NOT_NEEDED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_KEY_UNEXTRACTABLE,
    CKR_LIBRARY_LOAD_FAILED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_MUTEX_BAD,
    CKR_MUTEX_NOT_LOCKED,
    CKR_NEED_TO_CREATE_THREADS,
    CKR_NEW_PIN_MODE,
    CKR_NEXT_OTP,
    CKR_NO_EVENT,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_PIN_EXPIRED,
    CKR_PIN_INCORRECT,
    CKR_PIN_INVALID,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_LOCKED,
    CKR_PIN_TOO_WEAK,
    CKR_PUBLIC_KEY_INVALID,
    CKR_RANDOM_NO_RNG,
    CKR_RANDOM_SEED_NOT_SUPPORTED,
    CKR_SAVED_STATE_INVALID,
    CKR_SESSION_CLOSED,
    CKR_SESSION_COUNT,
    CKR_SESSION_EXISTS,
    CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_SESSION_READ_WRITE_SO_EXISTS,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_SLOT_ID_INVALID,
    CKR_STATE_UNSAVEABLE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TOKEN_NOT_PRESENT,
    CKR_TOKEN_NOT_RECOGNIZED,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    CKR_UNWRAPPING_KEY_SIZE_RANGE,
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_PIN_NOT_INITIALIZED,
    CKR_USER_TOO_MANY_TYPES,
    CKR_USER_TYPE_INVALID,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
    CKR_WRAPPING_KEY_HANDLE_INVALID,
    CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
};

/* pkcs11_error(): CKR_OK -> rc_ok, every other code -> rc_error_pkcs11_api. */
static void test_error_return_codes(void)
{
    size_t i;
    size_t n = sizeof error_codes / sizeof error_codes[0];
    int mismatches = 0;

    TH_CHECK(pkcs11_error(CKR_OK, "C_Test") == rc_ok,
             "pkcs11_error(CKR_OK) -> rc_ok");

    for (i = 0; i < n; i++) {
        if (pkcs11_error(error_codes[i], "C_Test") != rc_error_pkcs11_api)
            mismatches++;
    }
    TH_CHECK(mismatches == 0,
             "every error code maps to rc_error_pkcs11_api");
}

/* pkcs11_warning(): same return-code contract as pkcs11_error(). */
static void test_warning_return_codes(void)
{
    size_t i;
    size_t n = sizeof error_codes / sizeof error_codes[0];
    int mismatches = 0;

    TH_CHECK(pkcs11_warning(CKR_OK, "C_Test") == rc_ok,
             "pkcs11_warning(CKR_OK) -> rc_ok");

    for (i = 0; i < n; i++) {
        if (pkcs11_warning(error_codes[i], "C_Test") != rc_error_pkcs11_api)
            mismatches++;
    }
    TH_CHECK(mismatches == 0,
             "every warning code maps to rc_error_pkcs11_api");
}

/* An unknown CK_RV must hit the switch's default branch, not CKR_OK. */
static void test_error_unknown_code(void)
{
    CK_RV bogus = 0xDEADBEEFUL;

    TH_CHECK(pkcs11_error(bogus, "C_Test") == rc_error_pkcs11_api,
             "unknown CK_RV -> rc_error_pkcs11_api (default branch)");
    TH_CHECK(pkcs11_warning(bogus, "C_Test") == rc_error_pkcs11_api,
             "unknown CK_RV warning -> rc_error_pkcs11_api");
}

int main(void)
{
    TH_RUN(test_error_return_codes);
    TH_RUN(test_warning_return_codes);
    TH_RUN(test_error_unknown_code);

    return TH_SUMMARY();
}
