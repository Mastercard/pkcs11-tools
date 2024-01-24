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

#ifdef _WIN32
#include <openssl/applink.c>
#endif

#define COMMAND_SUMMARY \
    "Import key components of a symmetric key onto a PKCS#11 token.\n\n"


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
	     "* -i <key_alias>: label/alias of destination key\n"
	     "* -c <components> : number of key components\n"
	     "* -w <key_alias>: label/alias of an RSA key pair\n"
	     "  -S : login with SO privilege\n"
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
#ifdef HAVE_DUPLICATES_ENABLED
		 "  -n : allow duplicate objects\n"
#endif
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
    int num_components = -1;
    char * library = NULL;
    char * nsscfgdir = NULL;
    char * password = NULL;
    int so=0;
    char * slotenv = NULL;
    int slot = -1;
    int interactive = 1;
    char * tokenlabel = NULL;
    char * targetlabel = NULL;
    char * wrappingkeylabel = NULL;
    pkcs11Context * p11Context = NULL;
    CK_RV retcode = EXIT_FAILURE;
#ifdef HAVE_DUPLICATES_ENABLED
	bool can_duplicate = false;
#endif

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
    while ( ( argnum = getopt( argc, argv, "l:m:i:s:c:t:p:w:ShVn" ) ) != -1 )
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
	    targetlabel= optarg;
	    break;

	case 'w':
	    wrappingkeylabel = optarg;
	    break;

	case 'c':
	    num_components = atoi(optarg);
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

    if ( errflag ) {
	fprintf(stderr, "Try `%s -h' for more information.\n", argv[0]);
	goto err;
    }

    if ( library == NULL || targetlabel == NULL || wrappingkeylabel == NULL || num_components==-1 ) {
	fprintf( stderr, "At least one required option or argument is wrong or missing.\n" 
		 "Try `%s -h' for more information.\n", argv[0]);
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
	KeyImportCtx *kctx;

#ifdef HAVE_DUPLICATES_ENABLED
	p11Context->can_duplicate = can_duplicate;
#endif
	kctx = pkcs11_import_component_init( p11Context, wrappingkeylabel, targetlabel);

	if(kctx) {
	    
	    int i;
	    unsigned char comp[16];
	    func_rc rc;

	    for(i=0; i<num_components; i++) {
		pkcs11_ll_clear_screen();

		printf( "\n\n\n");
		printf( "**************************** CAUTION ***********************************\n");
		printf( " AS KEY COMPONENTS ARE INPUT IN THE CLEAR ON A TERMINAL CONSOLE,\n");
		printf( " SECURITY OF COMPONENTS IS POTENTIALLY COMPROMIZED \n");
		printf( " IF NO APPROPRIATE SURROUNDING PROCEDURES AND CONTROLS ARE IN PLACE.\n");
		printf( " IF UNSURE, HIT CTRL+C AT PROMPT TO CANCEL PROCEDURE.\n");
		printf( "**************************** CAUTION ***********************************\n\n\n");

		printf("Component %d of %d\n\n", i+1, num_components);
		prompt_for_hex("Enter Key Component", "HEX>", (char *)comp, sizeof comp);
		rc = pkcs11_import_component( kctx, comp, sizeof comp);

		memset(comp, 0x00, sizeof comp); /* 1st clear buffer */
		memset(comp, 0xff, sizeof comp); /* 2nd clear buffer */
		memset(comp, 0x00, sizeof comp); /* 3rd clear buffer */

		if(rc!=rc_ok) {
		    goto err_premature_close;
		}
	    }

	    pkcs11_ll_clear_screen();
	    pkcs11_import_component_final(kctx);

	}
	
    err_premature_close:
	pkcs11_close_session( p11Context );
    }
    pkcs11_finalize( p11Context );

err:

    pkcs11_freeContext(p11Context);
    
    return ( retcode );
}
