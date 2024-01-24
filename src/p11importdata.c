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
    "Import data from a file onto PKCS#11 token.\n\n"

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
	     "* -f <file> : path to a file\n"
	     "* -i <alias>: label/alias to give to data object\n"
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
    char * library = NULL;
    char * nsscfgdir = NULL;
    char * filename = NULL;
    char * password = NULL;
    char * slotenv = NULL;
    int slot = -1;
    int interactive = 1;
    char * tokenlabel = NULL;
    char * label = NULL;
#ifdef HAVE_DUPLICATES_ENABLED
	bool can_duplicate = false;
#endif

    pkcs11Context * p11Context = NULL;
    func_rc retcode = rc_error_other_error;

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
    while ( ( argnum = getopt( argc, argv, "l:m:f:i:s:t:phVn" ) ) != -1 )
    {
	switch ( argnum )
	{
	case 'f':
	    filename = optarg;
	    break;

	case 'l' :
	    library =  optarg;
	    break;

	case 'm':
	    nsscfgdir = optarg;
	    break;

	case 'p' :
	    password = optarg;
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
	    label= optarg;
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
	retcode = rc_error_usage;
	goto err;
    }

    if ( library == NULL || label == NULL || filename == NULL ) {
	fprintf( stderr, "At least one required option or argument is wrong or missing.\n" 
		 "Try `%s -h' for more information.\n", argv[0]);
	retcode = rc_error_usage;
	goto err;
    }

    if((p11Context = pkcs11_newContext( library, nsscfgdir ))==NULL) {
	retcode = rc_error_library;
	goto err;
    }

    /* validate the given provider library exists and can be opened */
    if (( retcode = pkcs11_initialize( p11Context ) ) != CKR_OK ) {
	goto err;
    }

    retcode = pkcs11_open_session( p11Context, slot, tokenlabel, password, 0, interactive);

    if ( retcode == rc_ok ) {
	CK_OBJECT_HANDLE imported_data = NULL_PTR;
#ifdef HAVE_DUPLICATES_ENABLED
	p11Context->can_duplicate = can_duplicate;
#endif

	if(pkcs11_data_exists(p11Context, label)) {
#ifdef HAVE_DUPLICATES_ENABLED
	if(p11Context->can_duplicate) {
	    fprintf(stdout, "data object with this label already exists, duplicating\n");
	}
	else {
#endif
	    fprintf(stderr, "data object with this label already exists, aborting\n");
	    retcode = rc_error_object_exists;
	    goto err;
#ifdef HAVE_DUPLICATES_ENABLED
	}
#endif
	}

	imported_data = pkcs11_importdata( p11Context, filename, label);
	    
	if ( imported_data ) {
	    printf( "%s: importing file succeeded.\n", argv[0]);
	} else {
	    fprintf( stderr, "%s: importing file failed.\n", argv[0]);
	}

	pkcs11_close_session( p11Context );
    }
    
    pkcs11_finalize( p11Context );

err:

    pkcs11_freeContext(p11Context);
    
    return retcode;
}
