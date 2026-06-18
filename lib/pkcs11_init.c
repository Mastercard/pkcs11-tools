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
#include <errno.h>
#include "pkcs11lib.h"

/* the PKCS#11 token label field is a fixed-size, space-padded, */
/* NON null-terminated field of CK_TOKEN_INFO_LABEL_LEN octets.  */
#define CK_TOKEN_INFO_LABEL_LEN 32

#define NEW_USER_PIN_PROMPT_STRING "Enter new user (crypto officer) PIN: "
#define NEW_USER_PIN_CONFIRM_PROMPT_STRING "Confirm new user (crypto officer) PIN: "

/* ask_confirmation: interactive yes/no confirmation prompt.
**
** aligned with the other commands (p11rm, p11mv, ...): the prompt ends with
** '(y/N)', a whole line is read, and the answer is accepted when its first
** character is 'y' or 'Y'. Anything else (including an empty line) is a refusal.
**
** returns CK_TRUE when the user confirms, CK_FALSE otherwise.
*/
static CK_BBOOL ask_confirmation(const char *prompt)
{
    CK_BBOOL confirmed = CK_FALSE;
    char *answer = pkcs11_prompt((char *)prompt, CK_TRUE);

    if (answer != NULL) {
	if (tolower((unsigned char)answer[0]) == 'y') {
	    confirmed = CK_TRUE;
	}
	pkcs11_prompt_free_buffer(answer);
    }

    return confirmed;
}


/* print_slot_entry: print a slot/token description block, in the same layout as
** the interactive slot list used across the other commands.
*/
static void print_slot_entry(pkcs11Context *p11Context, CK_SLOT_ID slotID, CK_ULONG index)
{
    CK_RV rv;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;

    if ((rv = p11Context->FunctionList.C_GetSlotInfo(slotID, &slotInfo)) != CKR_OK) {
	pkcs11_error(rv, "C_GetSlotInfo");
	return;
    }

    fprintf(stderr,
	    "Slot index: %lu\n"
	    "----------------\n"
	    "Description : %.*s\n",
	    index,
	    (int)sizeof(slotInfo.slotDescription), slotInfo.slotDescription);

    if ((rv = p11Context->FunctionList.C_GetTokenInfo(slotID, &tokenInfo)) != CKR_OK) {
	if (rv != CKR_TOKEN_NOT_PRESENT) { /* no token: silently pass, this is not an error */
	    pkcs11_error(rv, "C_GetTokenInfo");
	}
	fprintf(stderr, "(no token present)\n\n");
    } else {
	fprintf(stderr,
		"Token Label : %.*s\n"
		"Manufacturer: %.*s\n\n",
		(int)sizeof(tokenInfo.label), tokenInfo.label,
		(int)sizeof(tokenInfo.manufacturerID), tokenInfo.manufacturerID);
    }
}


/* parse_slot_index_input: parse and validate a user-provided slot index string.
**
** accepted format: optional leading/trailing spaces and a signed decimal integer.
** rejected format: empty string, non-digit junk, and out-of-range values.
*/
static CK_BBOOL parse_slot_index_input(const char *input, long *out)
{
	char *endptr = NULL;

	if (input == NULL || out == NULL) {
	return CK_FALSE;
	}

	errno = 0;
	*out = strtol(input, &endptr, 10);

	/* no digit parsed */
	if (endptr == input) {
	return CK_FALSE;
	}

	/* only ERANGE is portable to detect overflow/underflow with strtol */
	if (errno == ERANGE) {
	return CK_FALSE;
	}

	/* allow trailing spaces only */
	while (*endptr != '\0') {
	if (!isspace((unsigned char)*endptr)) {
	    return CK_FALSE;
	}
	endptr++;
	}

	return CK_TRUE;
}


/* pkcs11_get_slotindex: resolve a slot index, in the same fashion as the other
**                       commands (pkcs11_open_session): when a slot index or a
**                       token label is given, it is resolved (and the selected
**                       slot is displayed); otherwise, when interactive, the full
**                       slot list is shown and a slot index is prompted for. No
**                       compatibility filtering is performed here: checking that
**                       the selected slot is suitable for the requested operation
**                       is left to the caller.
**
** arguments:
**  - p11Context:  an initialized context (C_Initialize already called).
**  - slotindex:   in/out pointer to the slot index. On input, a negative or
**                 out-of-range value means "not specified". On success, it is set
**                 to a valid slot index.
**  - tokenlabel:  when non-NULL, the slot is resolved by matching this token
**                 label instead of using slotindex.
**  - interactive: when non-zero, an unspecified slot triggers the display of the
**                 slot list and an interactive prompt; otherwise the function
**                 fails safely.
*/
func_rc pkcs11_get_slotindex(pkcs11Context *p11Context, int *slotindex, char *tokenlabel, int interactive)
{
    CK_RV rv;
    func_rc rc = rc_ok;
    CK_SLOT_ID_PTR pSlotList = NULL;
    CK_ULONG ulSlotCount = 0;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
    CK_ULONG i;
    long s;
    char *tmpSlot = NULL;

    if ((rv = p11Context->FunctionList.C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount)) != CKR_OK) {
	pkcs11_error(rv, "C_GetSlotList");
	rc = rc_error_pkcs11_api;
	goto err;
    }

    if ((pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount * sizeof(CK_SLOT_ID))) == NULL) {
	fprintf(stderr, "Error: No memory available\n");
	rc = rc_error_memory;
	goto err;
    }

    if ((rv = p11Context->FunctionList.C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount)) != CKR_OK) {
	pkcs11_error(rv, "C_GetSlotList");
	rc = rc_error_pkcs11_api;
	goto err;
    }

    /* if a token label is given, resolve it to a slot index */
    if (tokenlabel != NULL) {
	int found = -1;

	for (i = 0; i < ulSlotCount; i++) {
	    if (p11Context->FunctionList.C_GetTokenInfo(pSlotList[i], &tokenInfo) != CKR_OK) {
		continue;	/* no token here, skip */
	    }
	    if (tokenlabelcmp(tokenlabel, (const char *)tokenInfo.label, sizeof tokenInfo.label) == 0) {
		found = (int)i;
		break;
	    }
	}

	if (found < 0) {
	    fprintf(stderr, "*** Error: token with label '%s' not found\n", tokenlabel);
	    rc = rc_error_invalid_slot_or_token;
	    goto err;
	}

	*slotindex = found;
	/* echo the selected slot */
	print_slot_entry(p11Context, pSlotList[found], (CK_ULONG)found);
	goto err;		/* rc is still rc_ok */
    }

    /* if a valid slot index has already been provided, echo it and we are done */
    if (*slotindex >= 0 && (CK_ULONG)*slotindex < ulSlotCount) {
	print_slot_entry(p11Context, pSlotList[*slotindex], (CK_ULONG)*slotindex);
	goto err;		/* rc is still rc_ok */
    }

    /* otherwise, in batch mode we fail safely */
    if (!interactive) {
	fprintf(stderr, "*** Error: slot index value %d not within range [0,%lu]\n",
		*slotindex, ulSlotCount > 0 ? ulSlotCount - 1 : 0);
	rc = rc_error_invalid_slot_or_token;
	goto err;
    }

    /* interactive: list all slots and ask to pick one */
    fprintf(stderr, "PKCS#11 module slot list:\n");

    for (i = 0; i < ulSlotCount; i++) {
	if ((rv = p11Context->FunctionList.C_GetSlotInfo(pSlotList[i], &slotInfo)) != CKR_OK) {
	    pkcs11_error(rv, "C_GetSlotInfo");
	} else {
	    fprintf(stderr,
		    "Slot index: %lu\n"
		    "----------------\n"
		    "Description : %.*s\n",
		    i,
		    (int)sizeof(slotInfo.slotDescription), slotInfo.slotDescription);

	    if ((rv = p11Context->FunctionList.C_GetTokenInfo(pSlotList[i], &tokenInfo)) != CKR_OK) {
		if (rv != CKR_TOKEN_NOT_PRESENT) { /* no token: silently pass, this is not an error */
		    pkcs11_error(rv, "C_GetTokenInfo");
		}
	    } else {
		fprintf(stderr,
			"Token Label : %.*s\n"
			"Manufacturer: %.*s\n\n",
			(int)sizeof(tokenInfo.label), tokenInfo.label,
			(int)sizeof(tokenInfo.manufacturerID), tokenInfo.manufacturerID);
	    }
	}
    }

    while (1) {
	tmpSlot = pkcs11_prompt(SLOT_PROMPT_STRING, CK_TRUE);
	if (tmpSlot == NULL) {
	    rc = rc_error_prompt;
	    goto err;
	}

	if (parse_slot_index_input(tmpSlot, &s) != CK_TRUE) {
	    fprintf(stderr,
		    "*** Error: invalid slot index '%s' (expected a decimal integer)\n",
		    tmpSlot);
	    pkcs11_prompt_free_buffer(tmpSlot);
	    continue;
	}
	pkcs11_prompt_free_buffer(tmpSlot);

	if (s >= 0 && (CK_ULONG)s < ulSlotCount) {
	    break;
	}
	fprintf(stderr, "*** Error: slot index value %ld not within range [0,%lu]\n",
		s, ulSlotCount > 0 ? ulSlotCount - 1 : 0);
    }

    *slotindex = (int)s;

err:
    if (pSlotList) { free(pSlotList); }
    return rc;
}


/* slot_index_to_token_info: resolve a slot index to its CK_SLOT_ID and fetch the
** corresponding CK_TOKEN_INFO. The index is validated against the current slot list.
*/
static func_rc slot_index_to_token_info(pkcs11Context *p11Context,
					int slotindex,
					CK_SLOT_ID *phSlot,
					CK_TOKEN_INFO *pTokenInfo)
{
    CK_RV rv;
    func_rc rc = rc_ok;
    CK_SLOT_ID_PTR pSlotList = NULL;
    CK_ULONG ulSlotCount = 0;

    if ((rv = p11Context->FunctionList.C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount)) != CKR_OK) {
	pkcs11_error(rv, "C_GetSlotList");
	rc = rc_error_pkcs11_api;
	goto err;
    }

    if ((pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount * sizeof(CK_SLOT_ID))) == NULL) {
	fprintf(stderr, "Error: No memory available\n");
	rc = rc_error_memory;
	goto err;
    }

    if ((rv = p11Context->FunctionList.C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount)) != CKR_OK) {
	pkcs11_error(rv, "C_GetSlotList");
	rc = rc_error_pkcs11_api;
	goto err;
    }

    /* the token is always addressed by slot index for token initialization */
    if (slotindex < 0 || (CK_ULONG)slotindex >= ulSlotCount) {
	fprintf(stderr, "*** Error: slot index value %d not within range [0,%lu]\n",
		slotindex, ulSlotCount > 0 ? ulSlotCount - 1 : 0);
	rc = rc_error_invalid_slot_or_token;
	goto err;
    }

    *phSlot = pSlotList[slotindex];

    if ((rv = p11Context->FunctionList.C_GetTokenInfo(*phSlot, pTokenInfo)) != CKR_OK) {
	pkcs11_error(rv, "C_GetTokenInfo");
	rc = (rv == CKR_TOKEN_NOT_PRESENT) ? rc_error_invalid_slot_or_token : rc_error_pkcs11_api;
	goto err;
    }

err:
    if (pSlotList) { free(pSlotList); }
    return rc;
}


/* pkcs11_inittoken_guard: check whether a token may be initialized at the given
** slot index, BEFORE any token label or SO PIN is collected.
**
** It rejects an already initialized token unless reset_authorized is set, and
** (when interactive) prints a destruction warning and asks for an explicit
** confirmation. This lets the caller bail out early -- and avoid prompting the
** operator for a label/PIN -- when the chosen slot cannot or should not be
** (re)initialized.
**
** returns rc_ok when initialization may proceed.
*/
func_rc pkcs11_inittoken_guard(pkcs11Context *p11Context,
			       int slotindex,
			       int reset_authorized,
			       int interactive)
{
    func_rc rc;
    CK_SLOT_ID hSlot;
    CK_TOKEN_INFO tokenInfo;

    if ((rc = slot_index_to_token_info(p11Context, slotindex, &hSlot, &tokenInfo)) != rc_ok) {
	return rc;
    }

    /* guard against accidental destruction of an already initialized token */
    if (tokenInfo.flags & CKF_TOKEN_INITIALIZED) {
	if (!reset_authorized) {
	    fprintf(stderr,
		    "*** Error: token at slot index %d is already initialized.\n"
		    "           Reinitializing it would ERASE ALL of its content.\n"
		    "           To proceed, you must explicitly request a reset (-R option).\n",
		    slotindex);
	    return rc_error_usage;
	}

	if (interactive) {
	    fprintf(stderr,
		    "\n"
		    "*** WARNING: about to REINITIALIZE an already initialized token. ***\n"
		    "All objects and credentials stored on this token will be PERMANENTLY ERASED.\n"
		    "\n"
		    "  slot index  : %d\n"
		    "  token label : %.*s\n"
		    "  manufacturer: %.*s\n"
		    "  serial      : %.*s\n"
		    "\n",
		    slotindex,
		    (int)sizeof(tokenInfo.label), tokenInfo.label,
		    (int)sizeof(tokenInfo.manufacturerID), tokenInfo.manufacturerID,
		    (int)sizeof(tokenInfo.serialNumber), tokenInfo.serialNumber);

	    if (ask_confirmation("reinitialize (ERASE) this token ? (y/N)") != CK_TRUE) {
		fprintf(stderr, "Aborted: token has NOT been reinitialized.\n");
		return rc_error_other_error;
	    }
	}
    }

    return rc_ok;
}


/* pkcs11_init_token: initialize (or reinitialize) a token through C_InitToken.
**
** arguments:
**  - p11Context: an initialized context (C_Initialize already called), with NO
**                open session on the target token (a requirement of C_InitToken).
**  - slotindex: index of the slot in the slot list (NOT a slot number). It must
**               be a valid index (see pkcs11_get_slotindex).
**  - sopin: the Security Officer PIN (must already be resolved, never NULL).
**  - label: the token label to set (will be space-padded to the field length).
**  - reset_authorized: when non-zero, allows reinitializing an already
**                      initialized token (destructive operation).
**  - interactive: unused here; the destructive confirmation is handled upfront by
**                 pkcs11_inittoken_guard, which the caller must invoke first.
**
** Initializing an already initialized token erases all of its content. As a safety
** net this function still refuses to proceed on an initialized token unless
** reset_authorized is set; the interactive warning/confirmation lives in
** pkcs11_inittoken_guard so that it happens before any label/PIN is collected.
*/
func_rc pkcs11_init_token(pkcs11Context *p11Context,
			  int slotindex,
			  char *sopin,
			  char *label,
			  int reset_authorized,
			  int interactive)
{
    CK_RV rv;
    func_rc rc = rc_ok;
    CK_SLOT_ID hSlot;
    CK_TOKEN_INFO tokenInfo;
    CK_UTF8CHAR paddedLabel[CK_TOKEN_INFO_LABEL_LEN];
    size_t labelLen;

    (void)interactive; /* destruction confirmation is handled by pkcs11_inittoken_guard */

    if (sopin == NULL) {
	fprintf(stderr, "*** Error: a SO PIN is required to initialize a token\n");
	rc = rc_error_usage;
	goto err;
    }

    if (label == NULL) {
	fprintf(stderr, "*** Error: a token label is required to initialize a token\n");
	rc = rc_error_usage;
	goto err;
    }

    labelLen = strlen(label);
    if (labelLen > CK_TOKEN_INFO_LABEL_LEN) {
	fprintf(stderr, "*** Error: token label '%s' is longer than %d characters\n",
		label, CK_TOKEN_INFO_LABEL_LEN);
	rc = rc_error_invalid_label;
	goto err;
    }

    /* resolve the slot index to its slot ID and current token info */
    if ((rc = slot_index_to_token_info(p11Context, slotindex, &hSlot, &tokenInfo)) != rc_ok) {
	goto err;
    }

    /* safety net: never erase an already initialized token without authorization. */
    /* The interactive destruction warning/confirmation is performed beforehand by */
    /* pkcs11_inittoken_guard (so it happens before the label/PIN are collected).  */
    if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) && !reset_authorized) {
	fprintf(stderr,
		"*** Error: token at slot index %d is already initialized.\n"
		"           Reinitializing it would ERASE ALL of its content.\n"
		"           To proceed, you must explicitly request a reset (-R option).\n",
		slotindex);
	rc = rc_error_usage;
	goto err;
    }

    /* build the space-padded, non null-terminated label field */
    memset(paddedLabel, ' ', sizeof paddedLabel);
    memcpy(paddedLabel, label, labelLen);

    /* be a bit verbose about the operation being performed (the selected slot */
    /* details have already been displayed by the caller / slot selection).    */
    fprintf(stderr, "%s token at slot index %d with label '%s'...\n",
	    (tokenInfo.flags & CKF_TOKEN_INITIALIZED) ? "Reinitializing" : "Initializing",
	    slotindex, label);


    if ((rv = p11Context->FunctionList.C_InitToken(hSlot,
						   (CK_UTF8CHAR_PTR) sopin,
						   (CK_ULONG) strlen(sopin),
						   paddedLabel)) != CKR_OK) {
	pkcs11_error(rv, "C_InitToken");
	rc = rc_error_pkcs11_api;
	goto err;
    }

    fprintf(stderr, "Token at slot index %d initialized successfully.\n", slotindex);

err:
    return rc;
}


/* pkcs11_init_pin: set the normal user (crypto officer) PIN through C_InitPIN.
**
** arguments:
**  - p11Context: a context with an already open R/W session, logged in as SO.
**  - userpin: the new user PIN to set. When NULL and interactive is non-zero,
**             the user is prompted for it.
**  - interactive: when non-zero, prompt for the user PIN if it was not provided.
**
** C_InitPIN must be called on a session where the SO is logged in; the caller is
** responsible for opening such a session (see pkcs11_open_session with so=1).
*/
func_rc pkcs11_init_pin(pkcs11Context *p11Context, char *userpin, int interactive)
{
    CK_RV rv;
    func_rc rc = rc_ok;
    char *prompted = NULL;
    char *pin = userpin;

    if (pin == NULL) {
	if (!interactive) {
	    fprintf(stderr, "*** Error: a user PIN is required to initialize the user PIN\n");
	    rc = rc_error_usage;
	    goto err;
	}
	/* the user PIN is being DEFINED, so confirm it (twice) to catch typos */
	pin = prompted = pkcs11_prompt_new_secret(NEW_USER_PIN_PROMPT_STRING,
						  NEW_USER_PIN_CONFIRM_PROMPT_STRING);
	if (pin == NULL) {
	    rc = rc_error_prompt;
	    goto err;
	}
    }

    /* be a bit verbose about the operation being performed */
    fprintf(stderr, "Setting the user (crypto officer) PIN on slot index %d...\n", p11Context->slotindex);

    if ((rv = p11Context->FunctionList.C_InitPIN(p11Context->Session,
						 (CK_UTF8CHAR_PTR) pin,
						 (CK_ULONG) strlen(pin))) != CKR_OK) {
	pkcs11_error(rv, "C_InitPIN");
	rc = rc_error_pkcs11_api;
	goto err;
    }

    fprintf(stderr, "User (crypto officer) PIN initialized successfully.\n");

err:
    pkcs11_prompt_free_buffer(prompted);
    return rc;
}
