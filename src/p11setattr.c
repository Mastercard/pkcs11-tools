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
    "Change attribute(s) of a PKCS#11 token object.\n\n"

/* prototypes */
void print_version_info(char *progname);
void print_usage(char *);
int main( int argc, char **argv);


void print_usage(char *progname)
{
    fprintf( stderr, 
	     "USAGE: %s TARGET ARGUMENTS\n"
	     "\n"
	     COMMAND_SUMMARY
	     " OPTIONS:\n"
	     "* -l <pkcs#11 library path> : path to PKCS#11 library\n"
	     "  -m <NSS config dir> ( e.g. '.' or 'sql:.' ) : NSS db directory \n"
	     "  -s <slot number>\n"
	     "  -t <token label> : if present, -s option is ignored\n"
	     "  -p <token PIN> | :::exec:<command> | :::nologin\n"
	     "  -S : login with SO privilege\n"
	     "  -y : force positive answer (non-interactive)\n"
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
	     "\n"
	     "TARGET: object filter to match, of the form:\n"
             "        - [TYPE/[ATTRIBUTE/]]VALUE\n"
	     "\n"
	     "        TYPE can be 'cert', 'pubk', 'prvk', 'seck', 'data'\n"
	     "        when omitted, all objects are considered\n"
	     "\n"
	     "        ATTRIBUTE is either:\n"
             "        - 'id', 'label' or 'sn'\n"
	     "        - an actual PKCS#11 attribute name (e.g. CKA_ENCRYPT)\n"
	     "          when omitted, default is 'label'\n"
	     "\n"
	     "        VALUE is either:\n"
	     "        - ASCII string\n"
	     "        - {hexadecimal values} between curly braces\n"
	     "\n"
	     " ARGUMENTS: ATTRIBUTE=VALUE pairs\n"
	     "  supported attributes:\n"
	     "        CKA_LABEL, CKA_ID,\n"
             "        CKA_WRAP, CKA_UNWRAP,\n" 
             "        CKA_DECRYPT, CKA_ENCRYPT,\n"
	     "        CKA_SIGN, CKA_VERIFY,\n"
	     "        CKA_SIGN_RECOVER, CKA_VERIFY_RECOVER,\n"
             "        CKA_TRUSTED, CKA_MODIFIABLE,\n"
             "        CKA_EXTRACTABLE, CKA_SENSITIVE\n"
	     "        CKA_WRAP_WITH_TRUSTED\n"
	     "  supported values:\n"
	     "                 true / false / ASCII string / {HEX string}\n"
	     "|\n"
	     "+-> arguments marked with an asterix(*) are mandatory\n"
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
	     "\n"
	     , progname );

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
    char * password = NULL;
    int so=0;
    char * slotenv = NULL;
    int slot = -1;
    char * tokenlabel = NULL;
    int interactive = 1;
    int ask_confirm = 1;
    char * label = NULL;
    pkcs11Context * p11Context = NULL;
    func_rc retcode;

    CK_ATTRIBUTE *attrs=NULL;
    size_t attrs_cnt=0;

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
    while ( ( argnum = getopt( argc, argv, "l:m:p:s:t:SyhV" ) ) != -1 )
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

	case 'y':
	    ask_confirm = 0;
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

    if(optind>argc-2) {
	fprintf(stderr, "Not enough arguments.\n");
	errflag++;
    }

    label = argv[optind];

    if( (attrs_cnt=get_attributes_from_argv( &attrs, optind+1 , argc, argv)) == 0 ) {
	errflag++;
    }

    if ( errflag ) {
	fprintf(stderr, "Try `%s -h' for more information.\n", argv[0]);
	goto err;
    }


    if ( library == NULL || attrs == NULL || label == NULL ) {
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
	
    if ( retcode == rc_ok )
    {
	pkcs11_change_object_attributes( p11Context, label, attrs, attrs_cnt, ask_confirm );
	pkcs11_close_session( p11Context );
    }    
    pkcs11_finalize( p11Context );

err:
    /* free allocated memory */
    release_attributes( attrs, attrs_cnt );    
    pkcs11_freeContext( p11Context );

    return retcode;
}
