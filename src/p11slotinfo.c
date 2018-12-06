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
    "Print slot information/available methods of a PKCS#11 slot or token.\n\n"

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
	     "OPTIONS:\n"
	     "* -l <pkcs#11 library path> : path to PKCS#11 library\n"
	     "  -m <NSS config dir> ( e.g. '.' or 'sql:.' ) : NSS db directory\n"
	     "  -s <slot number>\n"
	     "  -t <token label> : if present, -s option is ignored\n"
	     "  -S : login with SO privilege\n"
	     "  -e : list also named elliptic curves supported by the token\n"
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
    char * password = ":::nologin";
    char * slotenv = NULL;
    int slot = -1;
    int interactive = 1;
    char * tokenlabel = NULL;
    int ec_support = 0;
    int so=0;

    pkcs11Context * p11Context = NULL;
    func_rc retcode;

    library = getenv("PKCS11LIB");
    nsscfgdir = getenv("PKCS11NSSDIR");
    tokenlabel = getenv("PKCS11TOKENLABEL");    
    if(tokenlabel==NULL) {
	slotenv = getenv("PKCS11SLOT");
	if (slotenv!=NULL) {
	    slot=atoi(slotenv);
	}
    }	
    /* we ignore password value */

    /* if a slot or a token is given, interactive is null */
    if(slotenv!=NULL || tokenlabel!=NULL) {
	interactive=0;
    }
    
    /* get the command-line arguments */
    while ( ( argnum = getopt( argc, argv, "l:m:s:t:eShV" ) ) != -1 )
    {
	switch ( argnum )
	{
	case 'l' :
	    library =  optarg;
	    break;

	case 'm':
	    nsscfgdir = optarg;
	    break;

	case 's':
	    slot = atoi(optarg);
	    tokenlabel = NULL;
	    interactive = 0;
	    break;

	case 't':
	    tokenlabel = optarg;
	    slot = -1;
	    interactive = 0;
	    break;

	case 'e':
	    ec_support = 1;
	    break;

	case 'S':
	    so=1;
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


    if ( library == NULL ) {
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

    {
	
	retcode = pkcs11_open_session( p11Context, slot, tokenlabel, password, so, interactive);
	
	if( retcode == rc_ok ) {
	    pkcs11_info_slot(p11Context);

	    if(ec_support==1) {
		pkcs11_info_ecsupport(p11Context);
	    }

	    pkcs11_close_session( p11Context );
	}
    }
    
    retcode = pkcs11_finalize( p11Context );

    /* free allocated memory */
 err:
    pkcs11_freeContext(p11Context);

    return ( retcode );
}
