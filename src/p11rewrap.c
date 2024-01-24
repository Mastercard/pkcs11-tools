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
#include <unistd.h>
#include <sysexits.h>
#include "pkcs11lib.h"

#ifdef _WIN32
#include <openssl/applink.c>
#endif

#define COMMAND_SUMMARY                            \
    "Unwrap a key, and rewrap it under (an)other wrapping key(s), on a PKCS#11 token.\n\n"

typedef struct {
    char *wrappingkeylabel;
    char *algorithm;
    char *filename;
    char *fullstring;
    int fullstring_allocated;
    func_rc retcode;
} wrappingjob_t;

#define MAX_WRAPPINGJOB 32
#define DEFAULT_ALGORITHM "oaep"

/* prototypes */
void print_version_info(char *progname);

void print_usage(char *);

int main(int argc, char **argv);


void print_usage(char *progname) {
    fprintf(stderr,
	    "USAGE: %s OPTIONS\n"
	    "\n"
	    COMMAND_SUMMARY
	    " OPTIONS:\n"
	    "* -l <pkcs#11 library path> : path to PKCS#11 library\n"
	    "  -m <NSS config dir> ( e.g. '.' or 'sql:.' ) : NSS db directory \n"
	    "  -s <slot number>\n"
	    "  -t <token label> : if present, -s option is ignored\n"
	    "  -p <token PIN> | :::exec:<command> | :::nologin\n"
	    "* -f <file> : path to a wrapped key file\n"
	    "  -i <key_alias>: label/alias of key to wrap (not mandatory)\n"
	    "  -w <key_alias>: label/alias of a wrapping key, must have CKA_WRAP=true attribute\n"
	    "                  when present, overrides the Wrapping-Key value from wrapped key file\n"
	    "> -W wrappingkey=\"<label>\"[,algorithm=<algorithm>][,filename=\"<path>\"]\n"
	    "     a specifier for wrapping the key, with the following parameters:\n"
	    "   \"<label>\"    : the label of the wrapping key (double quotes are mandatory)\n"
	    "   <algorithm>  : wrapping algorithm (default: oaep)\n"
	    "                  - pkcs1          : PKCS#1 1.5 (RFC8017)\n"
	    "                  - oaep(args...)  : PKCS#1 OAEP (RFC8017)\n"
	    "                    args... can be one or several of the following parameters\n"
	    "                    (separated by commas)\n"
	    "                    (surround <algorithm> with single quotes, e.g. \n"
	    "                     'oaep(mgf=CKG_MGF1_SHA256,hash=CKM_SHA256)' \n"
	    "                     )\n"
	    "                      label=\"label-value\" : OAEP label or source argument\n"
	    "                      mgf  =[MGF], where MGF can be CKG_MGF1_SHA1, CKG_MGF1_SHA224, CKG_MGF1_SHA256,\n"
	    "                            CKG_MGF1_SHA384 or CKG_MGF1_SHA512\n"
	    "                            : mask generation function argument, default is CKG_MGF1_SHA1\n"
	    "                      hash =[HASH], where HASH can be CKM_SHA_1, CKM_SHA224, CKM_SHA256,\n"
	    "                            CKM_SHA384 or CKM_SHA512\n"
	    "                            : hashing algorithm argument, default is CKM_SHA_1\n"
	    "                      please refer to RFC8017 for information on arguments\n"
	    "                  - cbcpad(ags...) : private and secret key wrapping\n"
	    "                    (using CKM_xxx_CBC_PAD wrapping mehanisms)\n"
	    "                    args... can be one or several of the following parameters\n"
	    "                    (separated by commas)\n"
	    "                      iv=[HEX STRING prefixed with 0x] - Initialisation vector\n"
	    "                      please refer to PKCS#11 CKM_AES_CBC_PAD description for more details.\n"
	    "                  - rfc3394          : private and secret key wrapping, as documented in RFC3394\n"
	    "                                       and NIST.SP.800-38F, using CKM_AES_KEY_WRAP mechanism or\n"
	    "                                       equivalent vendor-specific\n"
	    "                  - rfc5649(args...) : private and secret key wrapping, as documented in RFC5649\n"
	    "                                       and NIST.SP.800-38F, using CKM_AES_KEY_WRAP_PAD mechanism\n"
	    "                                       or equivalent vendor-specific\n"
	    "                  - envelope(args...): envelope wrapping, i.e. a combination of an outer wrapping\n"
	    "                                       and an inner wrapping\n"
	    "                    args can be one or several of the following parameters\n"
	    "                    (separated by commas)\n"
	    "                      inner=[ALGORITHM], where ALGORITHM can be cbcpad, rfc3394 or rfc5649\n"
	    "                      outer=[ALGORITHM], where ALGORITHM can be pkcs1 or oaep\n"
	    "                      note that algoritms can be specified with their parameters\n"
	    "                      default: envelope(inner=cbcpad,outer=oaep)\n"
	    "   \"<path>\"     : path to the output file (double quotes are mandatory)\n"
	    "  -J <wrapping_key_id>: output JOSE Web Key (JWK)(RFC 7517) format, suppresses 'normal' pkcs11-tools format.\n"
	    "       Only works with directly wrapped keys, no envelope wrapping supported.\n"
	    "       You can supply an empty wrapping_key_id (\"\") to suppress the output of wrapping_key_id.\n"
	    "  -S : login with SO privilege\n"
	    "  -h : print usage information\n"
	    "  -V : print version information\n"
#ifdef HAVE_DUPLICATES_ENABLED
		"  -n : allow duplicate objects\n"
#endif
	    "|\n"
	    "+-> arguments marked with an asterix(*) are mandatory\n"
	    "|   (except if environment variable sets the value)\n"
	    "+-> arguments marked with a greater than sign(>) are mandatory and can be repeated\n"
	    "\n"
	    " ARGUMENTS: ATTRIBUTE=VALUE pairs\n"
	    "   supported attributes:\n"
	    "                 CKA_LABEL, CKA_ID,\n"
	    "                 CKA_WRAP, CKA_UNWRAP,\n"
	    "                 CKA_DECRYPT, CKA_ENCRYPT,\n"
	    "                 CKA_SIGN, CKA_VERIFY,\n"
	    "                 CKA_SIGN_RECOVER, CKA_VERIFY_RECOVER,\n"
	    "                 CKA_DERIVE,\n"
	    "                 CKA_TRUSTED, CKA_MODIFIABLE,\n"
	    "                 CKA_EXTRACTABLE, CKA_SENSITIVE\n"
	    "                 CKA_WRAP_WITH_TRUSTED\n"
	    "   supported values:\n"
	    "                 true / false / [ASCII-string]\n"
	    "\n"
	    "\n"
	    " ENVIRONMENT VARIABLES:\n"
	    "    PKCS11LIB         : path to PKCS#11 library,\n"
	    "                        overriden by option -l\n"
	    "    PKCS11NSSDIR      : NSS configuration directory directive,\n"
	    "                        overriden by option -m\n"
	    "    PKCS11SLOT        : token slot (integer)\n"
	    "                        overriden by PKCS11TOKENLABEL,\n"
	    "                        options -t or -s\n"
	    "    PKCS11TOKENLABEL  : token label\n"
	    "                        overriden by options -t or -s\n"
	    "    PKCS11PASSWORD    : password\n"
	    "                        overriden by option -p\n"
	    "\n", pkcs11_ll_basename(progname));

    exit(EX_USAGE);
}


int main(int argc, char **argv) {
    extern char *optarg;
    extern int optind, optopt;
    int argnum = 0;
    int errflag = 0;
    char *library = NULL;
    char *nsscfgdir = NULL;
    char *password = NULL;
    int so = 0;
    char *slotenv = NULL;
    int slot = -1;
    int interactive = 1;
    char *tokenlabel = NULL;
    char *filename = NULL;
    char *wrappingkeylabel = NULL;
    char *wrappedkeylabel = NULL;
    CK_OBJECT_HANDLE keyhandle = 0, pubkhandle = 0;
    pkcs11Context *p11Context = NULL;
    func_rc retcode = rc_ok;
    int p11rewraprc = EX_OK;
    wrappedKeyCtx *wctx = NULL;
    wrappingjob_t wrappingjob[MAX_WRAPPINGJOB];
    int numjobs = 0;
    int numfailed = 0;
    CK_ATTRIBUTE *attrs = NULL;
    size_t attrs_cnt = 0;
    bool jwkoutput = false;
    char *wrapping_key_id = NULL;
#ifdef HAVE_DUPLICATES_ENABLED
	bool can_duplicate = false;
#endif


    int i;
    for (i = 0; i < MAX_WRAPPINGJOB; i++) {
	wrappingjob[i].wrappingkeylabel = wrappingjob[i].filename = NULL;
	wrappingjob[i].algorithm = DEFAULT_ALGORITHM;
	wrappingjob[i].fullstring = NULL;
	wrappingjob[i].fullstring_allocated = 0;
    }

    library = getenv("PKCS11LIB");
    nsscfgdir = getenv("PKCS11NSSDIR");
    tokenlabel = getenv("PKCS11TOKENLABEL");
    if (tokenlabel == NULL) {
	slotenv = getenv("PKCS11SLOT");
	if (slotenv != NULL) {
	    slot = atoi(slotenv);
	}
    }
    password = getenv("PKCS11PASSWORD");

    /* if a slot or a token is given, interactive is null */
    if (slotenv != NULL || tokenlabel != NULL) {
	interactive = 0;
    }

    /* get the command-line arguments */
    while ((argnum = getopt(argc, argv, "l:m:i:s:t:p:f:ShVW:w:J:n")) != -1) {
	switch (argnum) {
	    case 'l' :
		library = optarg;
		break;

	    case 'm':
		nsscfgdir = optarg;
		break;

	    case 'p' :
		password = optarg;
		break;

	    case 'S':
		so = 1;
		break;

	    case 's':
		slot = atoi(optarg);
		interactive = 0;
		tokenlabel = NULL;
		break;

	    case 't':
		tokenlabel = optarg;
		interactive = 0;
		slot = -1;
		break;

	    case 'f':
		if (access(optarg, R_OK) != 0) {
		    perror("Error accessing file");
		} else {
		    filename = optarg;
		}
		break;

	    case 'i':
		wrappedkeylabel = optarg;
		break;

	    case 'w':
		wrappingkeylabel = optarg;
		break;

	    case 'h':
		print_usage(argv[0]);
		break;

	    case 'V':
		print_version_info(argv[0]);
		break;

	    case 'W':
		if (numjobs == MAX_WRAPPINGJOB) {
		    fprintf(stderr, "***Error: too many wrapping jobs requested\n");
		    errflag++;
		} else {
		    wrappingjob[numjobs].fullstring = optarg;
		    numjobs++;
		}
		break;

	    case 'J':
		jwkoutput = true;
		if(strlen(optarg) > 0) {
		    wrapping_key_id = optarg;
		}
		break;

#ifdef HAVE_DUPLICATES_ENABLED
		case 'n': {
			can_duplicate = true;
		}
		break;
#endif
	    default:
		errflag++;
		break;
	}
    }

    if (optind < argc) {
	if ((attrs_cnt = get_attributes_from_argv(&attrs, optind, argc, argv)) == 0) {
	    fprintf(stderr, "Attributes passed as argument could not be read.\n"
			    "Try `%s -h' for more information.\n", argv[0]);
	    retcode = rc_error_invalid_argument;
	    goto epilog;
	}
    }

    if (errflag) {
	fprintf(stderr, "Try `%s -h' for more information.\n", argv[0]);
	retcode = rc_error_usage;
	goto epilog;
    }

    if (library == NULL || filename == NULL || numjobs == 0) {
	fprintf(stderr, "At least one required option or argument is wrong or missing.\n"
			"Try `%s -h' for more information.\n", argv[0]);
	retcode = rc_error_usage;
	goto epilog;
    }

    if ((p11Context = pkcs11_newContext(library, nsscfgdir)) == NULL) {
	retcode = rc_error_memory;
	goto epilog;
    }

    /* validate the given provider library exists and can be opened */
    if ((retcode = pkcs11_initialize(p11Context)) != CKR_OK) {
	goto epilog;
    }


    retcode = pkcs11_open_session(p11Context, slot, tokenlabel, password, so, interactive);

    if (retcode == rc_ok) {

#ifdef HAVE_DUPLICATES_ENABLED
	p11Context->can_duplicate = can_duplicate;
#endif
	/* first step is to recover the key */
	wrappedKeyCtx *wctx = pkcs11_new_wrapped_key_from_file(p11Context, filename);

	if (wctx) {
	    retcode = pkcs11_unwrap(p11Context, wctx, wrappingkeylabel, wrappedkeylabel, attrs, attrs_cnt,
				    kg_session_for_wrapping);
	    if (retcode == rc_ok) {
		keyhandle = pkcs11_get_wrappedkeyhandle(wctx);
		pubkhandle = pkcs11_get_publickeyhandle(wctx);
		pkcs11_free_wrappedkeycontext(wctx);
	    } else {
		retcode = rc_error_parsing; /* set proper retcode, as not returned by pkcs11_new_wrapped_key_from_file() */
		goto epilog;
	    }

	    if (numjobs > 1) {
		fprintf(stderr, "There are %d rewrapping jobs to perform.\n", numjobs);
	    }

	    int i;

	    for (i = 0; i < numjobs; i++) {
		/* allocate wrapping context */
		if ((wctx = pkcs11_new_wrappedkeycontext(p11Context)) == NULL) {
		    fprintf(stderr, "***Error: memory allocation error while processing rewrapping job #%d\n", i + 1);
		    retcode = rc_error_memory;
		    continue;
		}

		/* we are good to go, but we must prefix the fullstring with a "@" character */
		size_t stringsize = strlen(wrappingjob[i].fullstring) + 2; /* one for the '@' and one for the \0 */
		char *tmp = wrappingjob[i].fullstring; /* remember it */

		wrappingjob[i].fullstring = malloc(stringsize);
		if (!wrappingjob[i].fullstring) {
		    fprintf(stderr, "***Error: memory allocation error while processing rewrapping job #%d\n", i + 1);
		    wrappingjob[i].retcode = rc_error_memory;
		    pkcs11_free_wrappedkeycontext(wctx);
		    wctx = NULL;
		    continue;
		}

		wrappingjob[i].fullstring_allocated = 1;
		snprintf(wrappingjob[i].fullstring, stringsize, "@%s", tmp);

		/* parsing will recognize this as a wrappingjob, thanks to the leading "@" character */
		if ((wrappingjob[i].retcode = pkcs11_prepare_wrappingctx(wctx, wrappingjob[i].fullstring)) != rc_ok) {
		    fprintf(stderr,
			    "***Error: parsing of '%s' failed.\nHint: wrapping key label and filename must be surrounded with double quotes\n",
			    wrappingjob[i].fullstring);
		    pkcs11_free_wrappedkeycontext(wctx);
		    wctx = NULL;
		    continue;
		}

		/* wrap */
		fprintf(stderr, ">>> job #%d: rewrapping key with parameters '%s'\n",
			i + 1,
			&wrappingjob[i].fullstring[1]);
		if ((wrappingjob[i].retcode = pkcs11_wrap_from_handle(wctx, keyhandle, pubkhandle)) != rc_ok) {
		    fprintf(stderr, "***Error: rewrapping operation failed for wrapping job #%d\n", i + 1);
		    pkcs11_free_wrappedkeycontext(wctx);
		    wctx = NULL;
		    numfailed++;
		    continue;
		}

		if ((wrappingjob[i].retcode = pkcs11_output_wrapped_key(wctx, jwkoutput, wrapping_key_id)) != rc_ok) {
		    fprintf(stderr, "***Error: could not output/save wrapped key for rewrapping job #%d\n", i + 1);
		    numfailed++;
		}
		pkcs11_free_wrappedkeycontext(wctx);
		wctx = NULL;
	    }
	    pkcs11_close_session(p11Context);
	}
	pkcs11_finalize(p11Context);

	for (i = 0; i < numjobs; i++) {
	    fprintf(stderr, "rewrapping job #%d return code: %d\n", i + 1, wrappingjob[i].retcode);
	    if (wrappingjob[i].retcode != rc_ok) { numfailed++; }
	}
    }
    epilog:

    /* free wrappingjob built strings */
    for (i = 0; i < numjobs; i++) {
	if (wrappingjob[i].fullstring_allocated == 1) { free(wrappingjob[i].fullstring); }
    }

    // wctx is always NULL - removing this
    /*
    if (wctx) {
	pkcs11_free_wrappedkeycontext(wctx);
	wctx = NULL;
    }
    */

    if (p11Context) {
	pkcs11_freeContext(p11Context);
	p11Context = NULL;
    }

    switch (retcode) {
	case rc_ok:
	    if (numfailed > 0) {
		p11rewraprc = numfailed;
		fprintf(stderr, "Some (%d) rewrapping jobs failed - returning code %d (0x%4.4x) to calling process\n",
			numfailed, p11rewraprc, p11rewraprc);
	    } else {
		fprintf(stderr, "Key rewrapping operations succeeded\n");
		p11rewraprc = EX_OK;
	    }
	    break;

	case rc_error_usage:
	case rc_error_invalid_argument:
	    p11rewraprc = EX_USAGE;
	    break;

	default:
	    p11rewraprc = retcode;
	    fprintf(stderr, "Key rewrapping operations failed - returning code %d (0x%4.4x) to calling process\n",
		    p11rewraprc, p11rewraprc);
    }
    return p11rewraprc;
}
