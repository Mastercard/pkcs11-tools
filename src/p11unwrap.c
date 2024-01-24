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

#define COMMAND_SUMMARY \
    "Unwrap a key, using another key on a PKCS#11 token.\n\n"


/* prototypes */
void print_version_info(char *progname);
void print_usage(char *);
int main( int argc, char **argv);


void print_usage(char *progname)
{
    fprintf( stderr,
	     "USAGE: %s OPTIONS ARGUMENTS\n"
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
	     "  -S : login with SO privilege\n"
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
#ifdef HAVE_DUPLICATES_ENABLED
		 "  -n: allow duplicate object\n"
#endif
	     "|\n"
	     "+-> arguments marked with an asterix(*) are mandatory\n"
             "|   (except if environment variable sets the value)\n"
	     "+-> arguments marked with a plus sign(+) can be repeated\n"
	     "\n"
	     " ARGUMENTS: ATTRIBUTE=VALUE pairs\n"
	     "   supported attributes (applied to private and secret key only):\n"
	     "                 CKA_LABEL, CKA_ID,\n"
             "                 CKA_UNWRAP,CKA_WRAP\n"
             "                 CKA_DECRYPT,CKA_ENCRYPT,\n"
	     "                 CKA_SIGN, CKA_VERIFY,\n"
	     "                 CKA_SIGN_RECOVER, CKA_VERIFY_RECOVER,\n"
	     "                 CKA_DERIVE,\n"
             "                 CKA_TRUSTED, CKA_MODIFIABLE,\n"
             "                 CKA_EXTRACTABLE, CKA_SENSITIVE\n"
	     "                 CKA_WRAP_WITH_TRUSTED\n"
	     "                 CKA_UNWRAP_TEMPLATE\n"
	     "   supported values:\n"
	     "                 true / false / [ASCII-string] / date / { template attributes }\n"
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
	     "\n"
	     , pkcs11_ll_basename(progname) );

    exit( EX_USAGE );
}

int main( int argc, char ** argv )
{
    extern char *optarg;
    extern int optind, optopt;
    int argnum = 0;
    int errflag = 0;
    char * library = NULL;
    char * nsscfgdir = NULL;
    char * filename = NULL;
    char * password = NULL;
    int so=0;
    char * slotenv = NULL;
    int slot = -1;
    int interactive = 1;
    char * tokenlabel = NULL;
    char * wrappedkeylabel = NULL;
    char * wrappingkeylabel = NULL;
    pkcs11Context * p11Context = NULL;
    func_rc retcode = rc_ok;
    int p11unwraprc = EX_OK;
#ifdef HAVE_DUPLICATES_ENABLED
	bool can_duplicate = false;
#endif

    attribCtx *actx = NULL;

    actx = pkcs11_new_attribcontext();

    if(actx==NULL) {
	goto err;
    }

    library = getenv("PKCS11LIB");
    nsscfgdir = getenv("PKCS11NSSDIR");
    tokenlabel = getenv("PKCS11TOKENLABEL");
    if(tokenlabel==NULL) {
	slotenv = getenv("PKCS11SLOT");
	if (slotenv!=NULL) {
	    slot=atoi(slotenv);
	}
    }
    password = getenv("PKCS11PASSWORD");

    /* if a slot or a token is given, interactive is null */
    if(slotenv!=NULL || tokenlabel!=NULL) {
	interactive=0;
    }

    /* get the command-line arguments */
    while ( ( argnum = getopt( argc, argv, "l:m:i:s:t:p:w:f:ShVn" ) ) != -1 )
    {
	switch ( argnum )
	{
	case 'l' :
	    library =  optarg;
	    break;

	case 'm':
	    nsscfgdir = optarg;
	    break;

	case 'p' :
	    password = optarg;
	    break;

	case 'S':
	    so=1;
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
	    if( access(optarg, R_OK) != 0 ) {
		perror("Error accessing file");
	    } else {
		filename = optarg;
	    }
	    break;

	case 'i':
	    wrappedkeylabel= optarg;
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

    if(optind<argc) {
	retcode = pkcs11_parse_attribs_from_argv(actx, optind, argc, argv, NULL);
	if(retcode!=rc_ok) {
	    errflag++;
	}
    }

    if ( errflag ) {
	fprintf(stderr, "Try `%s -h' for more information.\n", argv[0]);
	retcode = rc_error_usage;
	goto err;
    }

    if ( library == NULL || filename == NULL ) {
	fprintf( stderr, "At least one required option or argument is wrong or missing.\n"
		 "Try `%s -h' for more information.\n", argv[0]);
	retcode = rc_error_usage;
	goto err;
    }

    if((p11Context = pkcs11_newContext( library, nsscfgdir ))==NULL) {
	goto err;
    }

    /* validate the given provider library exists and can be opened */
    if (( retcode = pkcs11_initialize( p11Context ) ) != CKR_OK ) {
	goto err;
    }

    retcode = pkcs11_open_session( p11Context, slot, tokenlabel, password, so, interactive);

    if ( retcode == rc_ok ) {

#ifdef HAVE_DUPLICATES_ENABLED
	p11Context->can_duplicate = can_duplicate;
#endif
	wrappedKeyCtx *wctx = pkcs11_new_wrapped_key_from_file(p11Context, filename);

	if(wctx) {
	    retcode = pkcs11_unwrap( p11Context,
				     wctx,
				     wrappingkeylabel,
				     wrappedkeylabel,
				     pkcs11_get_attrlist_from_attribctx(actx),
				     pkcs11_get_attrnum_from_attribctx(actx),
				     kg_token);

	    pkcs11_free_wrappedkeycontext( wctx );
	} else {
	    retcode = rc_error_parsing; /* set proper retcode, as not returned by pkcs11_new_wrapped_key_from_file() */
	}
    }

    pkcs11_close_session( p11Context );
    pkcs11_finalize( p11Context );

err:

    pkcs11_freeContext(p11Context);
    if(actx) { pkcs11_free_attribcontext(actx); actx = NULL; }

    switch(retcode) {
    case rc_error_usage:
    case rc_error_invalid_argument:
	p11unwraprc = EX_USAGE;
	break;

    case rc_ok:
	fprintf(stderr, "Key unwrapping operation succeeded\n");
	p11unwraprc = EX_OK;
	break;
	
    default:
	p11unwraprc = retcode;
	fprintf(stderr, "Key wrapping operations failed - returning code %d (0x%4.4x) to calling process\n", p11unwraprc, p11unwraprc);
    }    
    return p11unwraprc;
}
