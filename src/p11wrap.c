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
#include "pkcs11lib.h"


#define COMMAND_SUMMARY \
    "Wrap a key, using another key on a PKCS#11 token.\n\n"


/* prototypes */
void print_version_info(char *progname);
void print_usage(char *);
int main( int argc, char **argv);


void print_usage(char *progname)
{
    fprintf( stderr,
	     "USAGE: %s OPTIONS\n"
	     "\n"
	     COMMAND_SUMMARY
	     " OPTIONS:\n"
	     "* -l <pkcs#11 library path> : path to PKCS#11 library\n"
	     "  -m <NSS config dir> ( e.g. '.' or 'sql:.' ) : NSS db directory \n"
	     "  -s <slot number>\n"
	     "  -t <token label> : if present, -s option is ignored\n"
	     "  -p <token PIN> | :::exec:<command> | :::nologin\n"
	     "* -i <key_alias>: label/alias of key to wrap\n"
	     "* -w <key_alias>: label/alias of a wrapping key, must have CKA_WRAP=true attribute\n"
	     "  -a <algorithm>: wrapping algorithm (default: pkcs1)\n"
	     "                  - pkcs1          : PKCS#1 1.5\n"
	     "                  - oaep(args...)  : PKCS#1 OAEP\n"
	     "                    args... can be one or several of the following parameters\n"
             "                    (separated by commas)\n"
	     "                      label=\"label-value\" - OAEP label or source argument\n"
	     "                      mgf=CKG_MGF1_SHA1|CKG_MGF1_SHA256|CKG_MGF_SHA384|CKG_MGF_SHA512 - MGF argument\n"
	     "                      hash=CKM_SHA_1|CKM_SHA224|CKM_SHA256|CKM_SHA384|CKM_SHA512 - hashing alg. argument\n"
	     "                      please refer to PKCS#1 standard, or RFC3447 for information on arguments\n"
	     "                  - cbcpad(ags...) : private and secret key wrapping (using CKM_xxx_CBC_PAD wrapping mehanisms)\n"
	     "                    args... can be one or several of the following parameters\n"
             "                    (separated by commas)\n"
	     "                      iv=[HEX STRING prefixed with 0x] - Initialisation vector\n"
	     "                      please refer to PKCS#11 CKM_AES_CBC_PAD description for more details.\n"
	     "                  - rfc3394        : private and secret key wrapping, as documented in RFC3394\n"
	     "                                     and NIST.SP.800-38F, using CKM_AES_KEY_WRAP mechanism or\n"
	     "                                     equivalent vendor-specific\n"
	     "                  - rfc5649        : private and secret key wrapping, as documented in RFC5649\n"
	     "                                     and NIST.SP.800-38F, using CKM_AES_KEY_WRAP_PAD mechanism\n"
	     "                                     or equivalent vendor-specific\n"
	     "  -S : login with SO privilege\n"
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
	     "|\n"
	     "+-> arguments marked with an asterix(*) are mandatory\n"
             "|   (except if environment variable sets the value)\n"
	     "+-> arguments marked with a plus sign(+) can be repeated\n"
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

    exit( RC_ERROR_USAGE );
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
    CK_RV retcode = EXIT_FAILURE;
    char *algostring = "pkcs1";	/* is the default algorithm */
    wrappedKeyCtx *wctx = NULL;

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
    while ( ( argnum = getopt( argc, argv, "l:m:i:s:t:p:w:a:o:ShV" ) ) != -1 )
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

	case 'i':
	    wrappedkeylabel= optarg;
	    break;

	case 'w':
	    wrappingkeylabel = optarg;
	    break;

	case 'a':
	    /* as we can, for some of the wrapping algoritms below, support parameters */
	    /* we just check for now the name. */
	    /* the whole string is kept apart, and is parsed through the same parsing rules */
	    /* than in wrappedkey_parser.y  */
	    algostring = optarg;
	    break;

	case 'o':
	    filename=optarg;
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

    if ( library == NULL || wrappedkeylabel == NULL || wrappingkeylabel == NULL || algostring == NULL ) {
	fprintf( stderr, "At least one required option or argument is wrong or missing.\n"
		 "Try `%s -h' for more information.\n", argv[0]);
	goto err;
    }

    if((p11Context = pkcs11_newContext( library, nsscfgdir ))==NULL) {
	retcode = rc_error_memory;
	goto err;
    }

    /* validate the given provider library exists and can be opened */
    if (( retcode = pkcs11_initialize( p11Context ) ) != CKR_OK ) {
	goto err;
    }

    if(( wctx = pkcs11_new_wrappedkeycontext(p11Context))==NULL) {
	retcode = rc_error_memory;
	goto err;
    }

    /* extract the algorithm from -a argument */
    if(( retcode = pkcs11_parse_wrappingalgorithm(wctx, algostring))!=rc_ok) {
	goto err;
    }

    retcode = pkcs11_open_session( p11Context, slot, tokenlabel, password, so, interactive);

    if ( retcode == rc_ok ) {
	/* wrap */
	retcode = pkcs11_wrap( wctx, wrappingkeylabel, wrappedkeylabel );

	if(retcode == rc_ok) {
	    /* print result */
	    retcode = pkcs11_output_wrapped_key( wctx, filename );
	}

	pkcs11_close_session( p11Context );

    }

    pkcs11_finalize( p11Context );

err:
    if(retcode != rc_ok ) {
	fprintf(stderr, "key wrapping failed - returning code %d to calling process\n", (unsigned int)retcode);
    } else {
	fprintf(stderr, "key wrapping succeeded\n");
    }

    pkcs11_free_wrappedkeycontext(wctx);

    pkcs11_freeContext(p11Context);

    return ( retcode );
}
