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
    "List information about PKCS#11 token content.\n\n"

/* prototypes */
void print_version_info(char *progname);
void print_usage(char *);
int main( int argc, char **argv);


void print_usage(char *progname)
{
    fprintf( stderr, 
	     "USAGE: %s OPTIONS [FILTERS]\n"
	     "\n"
	     COMMAND_SUMMARY
	     " OPTIONS:\n"
	     "* -l <pkcs#11 library path> : path to PKCS#11 library\n"
	     "  -m <NSS config dir> ( e.g. '.' or 'sql:.' ) : NSS db directory \n"
	     "  -s <slot number>\n"
	     "  -t <token label> : if present, -s option is ignored\n"
	     "  -p <token PIN> | :::exec:<command> | :::nologin\n"
	     "  -S : login with SO privilege\n"
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
	     "|\n"
	     "+-> arguments marked with an asterix(*) are mandatory\n"
             "|   (except if environment variable sets the value)\n"
	     "+-> arguments marked with a plus sign(+) can be repeated\n"
	     "\n"
	     " FILTERS:\n"
	     "  FILTER [FILTER ...]: object filter to match, of the form:\n"
	     "                       - TYPE\n"
             "                       - [TYPE/[ATTRIBUTE/]]VALUE+ADDITIONAL_ATTRIBUTE/ADDITIONAL_VALUE\n"
	     "\n"
	     "                       TYPE can be 'cert', 'pubk', 'prvk', 'seck', 'data'\n"
	     "                       when omitted, all objects are listed\n"
	     "\n"
	     "                       ATTRIBUTE is either:\n"
             "                       - 'id', 'label' or 'sn'\n"
	     "                       - an actual PKCS#11 attribute name (e.g. CKA_ENCRYPT)\n"
	     "                       when omitted, default is 'label'\n"
	     "\n"
	     "                       VALUE is either:\n"
	     "                       - ASCII string\n"
	     "                       - {hexadecimal values} between curly braces\n"
		 "\n"
		 "                       ADDITIONAL_ATTRIBUTE/ADDITIONAL_VALUE:\n"
		 "                       - An additional attribute name and value pair can be concatenated\n"
		 "                       onto a filter by using the '+' symbol\n"
         "                       - example: p11ls cert/sn/12335344+CKA_ENCRYPT/{01}\n"
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
	     "OUTPUT:\n"
	     " each object is listed by its label and attributes\n"
	     " attributes are abbreviated as follows:\n"
	     "\n"
	     " AAU : the key requires authentication each time it is used\n"
	     " NAS : (historical) key has not always been sensitive\n"
	     " NSE : key is not sensitive (clear text value could leave token boudary)\n"
	     " WXT : (historical) key has been once extractable\n"
	     " alm : the key is restricted to (a) specific algorithm(s)\n"
	     " ase : (historical) key has always been sensitive\n"
	     " dec : supports decryption\n"
	     " drv : supports derivation\n"
	     " drt : derive template present\n"
	     " enc : supports encryption\n"
	     " imp : object is imported\n"
	     " loc : object has been created on this token\n"
	     " nxt : (historical) the key has never been extractable\n"
	     " r/o : not modifiable\n"
	     " r/w : modifiable\n"
	     " sen : key is sensitive (clear text value never leaves token in the clear)\n"
	     " ses : session object ( i.e. transcient)\n"
	     " sig : supports signature/MAC\n"
	     " sir : supports signature with recovery (private key)\n"
	     " tok : token object (i.e. persistent)\n"
	     " tru : the object is trusted\n"
	     " uwr : supports key unwrapping\n"
	     " uwt : unwrap template present\n"
	     " vfy : supports signature/MAC verification\n"
	     " vre : supports signature recovery (public key)\n"
	     " wra : supports key wrapping\n"
	     " wrt : wrap template present\n"
	     " wtt : the key may be wrapped with a trusted key only\n"
	     " XTR : key is extractable (it can be wrapped or exported in the clear)\n"
	     "\n"
	     " attributes in capital letter should bring your attention\n"
	     " as they may cause security or operational issues\n"

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
    char * password = NULL;
    char * slotenv = NULL;
    int slot = -1;
    int interactive = 1;
    char * tokenlabel = NULL;
    int so=0;

    pkcs11Context * p11Context = NULL;
    func_rc retcode = rc_error_usage;

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
    while ( ( argnum = getopt( argc, argv, "l:m:p:s:t:ShV" ) ) != -1 )
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


    if ( library == NULL) {
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
	if(optind==argc) {
	    pkcs11_ls( p11Context, "CKA_TOKEN/{01}");

	} else {
	    while(optind<argc) {
		pkcs11_ls(p11Context, argv[optind++]);
	    }
	}

	pkcs11_close_session( p11Context );
    }

    pkcs11_finalize( p11Context );

    /* free allocated memory */
err:
    pkcs11_freeContext(p11Context);

    return retcode;
}
