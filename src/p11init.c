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
#include <unistd.h>
#include "pkcs11lib.h"

#ifdef _WIN32
#include <openssl/applink.c>
#endif

#define COMMAND_SUMMARY \
    "Initialize a PKCS#11 token and/or its user (crypto officer) PIN.\n"			\
    "\n"										\
    "Three operations are supported, and can be combined:\n"				\
    "  -I : initialize a token (C_InitToken, Security Officer credentials)\n"		\
    "  -U : initialize/change the user (crypto officer) PIN (C_InitPIN)\n"		\
    "  -I -R : reinitialize (reset) an already initialized token (destructive)\n\n"

#define SO_PIN_PROMPT_STRING   "Enter Security Officer (SO) PIN: "
#define SO_PIN_CONFIRM_PROMPT_STRING "Confirm Security Officer (SO) PIN: "
#define NEW_LABEL_PROMPT_STRING "Enter new token label: "
#define CONFIRM_INITPIN_PROMPT_STRING \
    "(re)set the user (crypto officer) PIN of this token ? (y/N)"


/* prototypes */
void print_version_info(char *progname);
void print_usage(char *);
int main( int argc, char **argv);


/* resolve_pin: resolve a PIN argument provided on the command line.
**
** PIN arguments must be passed on the command line (the PKCS11PASSWORD environment
** variable is intentionally NOT honoured by this command). The ':::exec:<command>'
** convention is supported (the command output is used as the PIN). The ':::nologin'
** convention is explicitly rejected.
**
** A NULL argument is not an error here: it means "not provided", and the caller is
** expected to either prompt for it interactively (downstream) or fail in batch mode.
**
** On success, returns 0 and sets *resolved (possibly NULL when arg is NULL), and
** *allocated to 1 when the returned buffer must be freed with
** pkcs11_prompt_free_buffer(). On failure, returns non-zero.
*/
static int resolve_pin(const char *what, char *arg, char **resolved, int *allocated)
{
    *resolved = NULL;
    *allocated = 0;

    if (arg == NULL) {
	return 0;		/* not provided: deferred to an interactive prompt downstream */
    }

    if (strcmp(arg, PASSWORD_NOLOGIN) == 0) {
	fprintf(stderr, "*** Error: '%s' is not supported for %s.\n", PASSWORD_NOLOGIN, what);
	return 1;
    }

    if (strncmp(PASSWORD_EXEC, arg, strlen(PASSWORD_EXEC)) == 0) {
	char *piped = pkcs11_pipe_password(arg);
	if (piped == NULL) {
	    fprintf(stderr, "*** Error: could not retrieve %s from the specified command.\n", what);
	    return 1;
	}
	*resolved = piped;
	*allocated = 1;
	return 0;
    }

    *resolved = arg;
    return 0;
}


void print_usage(char *progname)
{
    fprintf( stderr,
	     "USAGE: %s OPTIONS\n"
	     "\n"
	     COMMAND_SUMMARY
	     "OPTIONS:\n"
	     "* -l <pkcs#11 library path> : path to PKCS#11 library\n"
	     "  -m <NSS config dir> ( e.g. '.' or 'sql:.' ) : NSS db directory\n"
	     "  -s <slot index> : slot index. When omitted in interactive mode, the slot\n"
	     "                    list is shown and a slot index is prompted for\n"
	     "  -t <token label> : token label, allowed only together with -U alone\n"
	     "                     (the token must already be initialized)\n"
	     "  -I : initialize a token (in batch mode, requires -s, -O and -T)\n"
	     "  -R : authorize reinitialization (reset) of an already initialized token\n"
	     "       (destructive, must be combined with -I)\n"
	     "  -U : initialize/change the user (crypto officer) PIN\n"
	     "       (in batch mode, requires -O and -P, plus -s or -t)\n"
	     "  -O <SO PIN | :::exec:<command>> : Security Officer PIN\n"
	     "  -P <user PIN | :::exec:<command>> : new user (crypto officer) PIN (used by -U)\n"
	     "  -T <token label> : token label to set when initializing a token (-I);\n"
	     "                     mandatory in batch mode, prompted for otherwise\n"
	     "  -B : batch mode, never prompt; all required values must be passed as arguments\n"
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
	     "|\n"
	     "+-> arguments marked with an asterisk(*) are mandatory\n"
	     "|   (except if environment variable sets the value)\n"
	     "\n"
	     " NOTES:\n"
	     "  - when run interactively (without -B) and no slot/token is given, the slot\n"
	     "    list is shown and a slot index is prompted for; when -s/-t is given, the\n"
	     "    selected slot is displayed. With -B, the slot/token must be known up-front.\n"
	     "  - for -I, the chosen slot must hold an UNINITIALIZED token, unless -R is given\n"
	     "    to authorize the (destructive) reinitialization of an already initialized one.\n"
	     "  - for a standalone -U, an explicit confirmation (y/N) is requested before\n"
	     "    the user PIN is (re)set.\n"
	     "  - the SO PIN and user PIN are NEVER read from the PKCS11PASSWORD environment\n"
	     "    variable; they must be passed as arguments or entered at the prompt.\n"
	     "  - a PIN that is being DEFINED interactively (the SO PIN when initializing a\n"
	     "    token, and the new user PIN) is asked twice and both entries must match.\n"
	     "  - unlike the other commands, p11init does NOT read the slot (PKCS11SLOT) or\n"
	     "    token label (PKCS11TOKENLABEL) from the environment: because its operations\n"
	     "    are destructive, the target must always be given explicitly via -s/-t (or\n"
	     "    selected from the interactive list).\n"
	     "  - the ':::exec:<command>' convention is supported for -O and -P.\n"
	     "  - the ':::nologin' convention is NOT supported.\n"
	     "  - a token is addressed by its slot INDEX for -I; the token label (-t) may\n"
	     "    only be used to address an already initialized token with -U.\n"
	     "\n"
	     " ENVIRONMENT VARIABLES:\n"
	     "    PKCS11LIB         : path to PKCS#11 library,\n"
	     "                        overridden by option -l\n"
	     "    PKCS11NSSDIR      : NSS configuration directory directive,\n"
	     "                        overridden by option -m\n"
	     "    (PKCS11SLOT, PKCS11TOKENLABEL and PKCS11PASSWORD are intentionally ignored)\n"
	     "\n"
	     , pkcs11_ll_basename(progname));

    exit( RC_ERROR_USAGE );
}


int main( int argc, char ** argv )
{
    extern char *optarg;
    extern int optind;
    int argnum = 0;
    int errflag = 0;
    char * library = NULL;
    char * nsscfgdir = NULL;
    int slot = -1;
    char * tokenlabel = NULL;
    char * sopinarg = NULL;
    char * userpinarg = NULL;
    char * newlabel = NULL;
    int do_inittoken = 0;
    int do_initpin = 0;
    int reset = 0;
    int batch = 0;
    int interactive = 1;

    char * sopin = NULL;
    char * userpin = NULL;
    int sopin_allocated = 0;
    int userpin_allocated = 0;
    int newlabel_allocated = 0;
    int session_opened = 0;

    pkcs11Context * p11Context = NULL;
    func_rc retcode = rc_error_usage;

    library = getenv("PKCS11LIB");
    nsscfgdir = getenv("PKCS11NSSDIR");
    /* Unlike the other commands, p11init intentionally does NOT read the slot   */
    /* (PKCS11SLOT) or token label (PKCS11TOKENLABEL) from the environment:      */
    /* its operations are destructive, so the target must be made explicit on    */
    /* the command line. PKCS11PASSWORD is likewise not honoured.                */

    while ( ( argnum = getopt( argc, argv, "l:m:s:t:IRUO:P:T:BhV" ) ) != -1 && errflag == 0 )
    {
	switch ( argnum )
	{
	case 'l':
	    library = optarg;
	    break;

	case 'm':
	    nsscfgdir = optarg;
	    break;

	case 's':
	{
	    /* using atoi() here could be dangerous, as an invalid parsing would return slot 0 */
	    /* a more accurate way to capture the slot number is implemented with sscanf() */
 	    int tmp;
 	    char extra;
 	    if (sscanf(optarg, "%d%c", &tmp, &extra) != 1 || tmp < 0) {
 		fprintf(stderr,
 			"*** Error: invalid slot index '%s' (must be a non-negative integer).\n",
 			optarg);
 		errflag++;
 		break;
 	    }
 	    slot = tmp;
	    break;
	}

	case 't':
	    tokenlabel = optarg;
	    break;

	case 'I':
	    do_inittoken = 1;
	    break;

	case 'R':
	    reset = 1;
	    break;

	case 'U':
	    do_initpin = 1;
	    break;

	case 'O':
	    sopinarg = optarg;
	    break;

	case 'P':
	    userpinarg = optarg;
	    break;

	case 'T':
	    newlabel = optarg;
	    break;

	case 'B':
	    batch = 1;
	    break;

	case 'h':
	    print_usage(argv[0]);
	    break;

	case 'V':
	    print_version_info(argv[0]);
	    break;

	default:
	    errflag++;
	    break;
	}
    }

    if ( errflag ) {
	fprintf(stderr, "Try `%s -h' for more information.\n", argv[0]);
	goto err;
    }

    /* --- safe-fail validation --- */

    interactive = !batch;

    if ( library == NULL ) {
	fprintf(stderr, "*** Error: no PKCS#11 library specified (use -l or PKCS11LIB).\n");
	goto err;
    }

    if ( !do_inittoken && !do_initpin ) {
	fprintf(stderr, "*** Error: at least one operation must be requested (-I and/or -U).\n");
	goto err;
    }

    if ( reset && !do_inittoken ) {
	fprintf(stderr, "*** Error: -R (reset) requires -I (token initialization).\n");
	goto err;
    }

    /* a token label (-t) may never be used to address a token for -I */
    if ( do_inittoken && tokenlabel != NULL ) {
	fprintf(stderr, "*** Error: a token label (-t) cannot be used to address a token for -I;\n"
			"           use a slot index (-s) instead.\n");
	goto err;
    }

    /* the new token label (-T) is mandatory for -I in batch mode; in interactive */
    /* mode it is prompted for further down (see step 1).                         */

    /* in batch mode, every required value must be provided up-front (safe fail). */
    /* in interactive mode, missing values are prompted for further down.         */
    if ( batch ) {
	if ( sopinarg == NULL ) {
	    fprintf(stderr, "*** Error: a SO PIN (-O) is required in batch mode.\n");
	    goto err;
	}
	if ( do_inittoken ) {
	    if ( slot < 0 ) {
		fprintf(stderr, "*** Error: token initialization (-I) requires a slot index (-s) in batch mode.\n");
		goto err;
	    }
	    if ( newlabel == NULL ) {
		fprintf(stderr, "*** Error: token initialization (-I) requires a token label (-T) in batch mode.\n");
		goto err;
	    }
	}
	if ( do_initpin ) {
	    if ( userpinarg == NULL ) {
		fprintf(stderr, "*** Error: user PIN initialization (-U) requires a new user PIN (-P) in batch mode.\n");
		goto err;
	    }
	    if ( !do_inittoken && slot < 0 && tokenlabel == NULL ) {
		fprintf(stderr, "*** Error: user PIN initialization (-U) requires a slot index (-s) or a token label (-t) in batch mode.\n");
		goto err;
	    }
	}
    }

    /* resolve PIN arguments (':::exec:' handling, ':::nologin' rejection). */
    /* A NULL result means "not provided" and will be prompted for when interactive. */
    if ( resolve_pin("the SO PIN (-O)", sopinarg, &sopin, &sopin_allocated) != 0 ) {
	goto err;
    }

    if ( do_initpin ) {
	if ( resolve_pin("the user PIN (-P)", userpinarg, &userpin, &userpin_allocated) != 0 ) {
	    goto err;
	}
    }

    /* --- proceed --- */

    if ( (p11Context = pkcs11_newContext( library, nsscfgdir )) == NULL ) {
	retcode = rc_error_library;
	goto err;
    }

    if ( ( retcode = pkcs11_initialize( p11Context ) ) != CKR_OK ) {
	goto err;
    }

    /* step 1: token initialization, if requested (no session must be open) */
    if ( do_inittoken ) {
	/* resolve the slot index, in the same fashion as the other commands:    */
	/* when -s is given, echo the selected slot; otherwise (interactive) list */
	/* all slots and prompt.                                                  */
	if ( ( retcode = pkcs11_get_slotindex( p11Context, &slot, NULL, interactive ) ) != rc_ok ) {
	    goto finalize;
	}

	/* check the chosen slot BEFORE collecting a token label / SO PIN: it must */
	/* hold an uninitialized token, unless -R authorizes a (confirmed) reset.  */
	if ( ( retcode = pkcs11_inittoken_guard( p11Context, slot, reset, interactive ) ) != rc_ok ) {
	    goto finalize;
	}

	/* prompt for the new token label (-T) if it was not provided (interactive only) */
	if ( newlabel == NULL ) {
	    newlabel = pkcs11_prompt( NEW_LABEL_PROMPT_STRING, CK_TRUE );
	    newlabel_allocated = 1;
	    if ( newlabel == NULL || newlabel[0] == '\0' ) {
		fprintf(stderr, "*** Error: a token label is required to initialize a token.\n");
		retcode = rc_error_usage;
		goto finalize;
	    }
	}

	/* prompt for the SO PIN if it was not provided (interactive only).      */
	/* this SO PIN is being DEFINED on the token, so confirm it (twice) to    */
	/* guard against a typo.                                                  */
	if ( sopin == NULL ) {
	    sopin = pkcs11_prompt_new_secret( SO_PIN_PROMPT_STRING, SO_PIN_CONFIRM_PROMPT_STRING );
	    sopin_allocated = 1;
	    if ( sopin == NULL ) {
		retcode = rc_error_prompt;
		goto finalize;
	    }
	}

	retcode = pkcs11_init_token( p11Context, slot, sopin, newlabel, reset, interactive );
	if ( retcode != rc_ok ) {
	    goto finalize;
	}
    }

    /* step 2: user PIN initialization, if requested (requires an SO session) */
    if ( do_initpin ) {
	/* After a fresh token init, the provider may reassign slot indexes, so we */
	/* re-address the token by the label we just set (-T) rather than by index. */
	char * uselabel = do_inittoken ? newlabel : tokenlabel;
	int useslot = do_inittoken ? -1 : slot;

	/* resolve and display the target slot (by label or index), or, when nothing */
	/* is specified interactively, list all slots and prompt for one.            */
	if ( ( retcode = pkcs11_get_slotindex( p11Context, &useslot, uselabel, interactive ) ) != rc_ok ) {
	    goto finalize;
	}

	/* for a standalone -U, ask for an explicit confirmation before (re)setting  */
	/* the user PIN of the selected token (it may lock out its current owner).    */
	if ( !do_inittoken && interactive ) {
	    char * answer = pkcs11_prompt( CONFIRM_INITPIN_PROMPT_STRING, CK_TRUE );
	    int confirmed = ( answer != NULL && tolower((unsigned char)answer[0]) == 'y' );
	    if ( answer != NULL ) { pkcs11_prompt_free_buffer( answer ); }
	    if ( !confirmed ) {
		fprintf(stderr, "Aborted: the user PIN has NOT been changed.\n");
		retcode = rc_error_other_error;
		goto finalize;
	    }
	}

	/* pkcs11_open_session prompts for the SO PIN (when NULL) on its own, */
	/* mirroring the other commands. The slot has already been resolved.  */
	retcode = pkcs11_open_session( p11Context, useslot, NULL, sopin, 1 /* SO */, interactive );
	if ( retcode != rc_ok ) {
	    goto finalize;
	}
	session_opened = 1;

	retcode = pkcs11_init_pin( p11Context, userpin, interactive );
    }

    if ( session_opened ) {
	pkcs11_close_session( p11Context );
    }

finalize:
    pkcs11_finalize( p11Context );

err:
    if ( sopin_allocated ) { pkcs11_prompt_free_buffer(sopin); }
    if ( userpin_allocated ) { pkcs11_prompt_free_buffer(userpin); }
    if ( newlabel_allocated ) { pkcs11_prompt_free_buffer(newlabel); }
    if ( p11Context ) { pkcs11_freeContext(p11Context); }

    return retcode;
}
