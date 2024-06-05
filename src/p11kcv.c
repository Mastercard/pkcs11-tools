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
    "Computes key check value for a symmetric key on PKCS#11 token.\n"			\
	"\n"										\
	"Supported algorithms:\n"							\
	"  - Key check value as found in CKA_CHECK_VALUE attribute\n"			\
	"  - ECB encryption of a blocksize buffer of 0x00 (requires CKA_ENCRYPT)\n"     \
	"  - MACing of a blocksize buffer of 0x00 (FIPS PUB 113)\n"			\
	"  - CMAC (RFC4493)\n"								\
	"  - AES-XCBC-MAC (RFC3566)\n"							\
	"  - AES-XCBC-MAC-96 (RFC3566)\n"						\
	"  - HMAC of a variable length buffer of 0x00\n\n"


/* prototypes */
void print_version_info(char *progname);
void print_usage(char *);
int main( int argc, char **argv);


mac_alg_t pick_algo(char *name, int *errflag) {

	if(strcasecmp(name,"kcv")==0) {
		return kcv;
	}

    if(strcasecmp(name,"cmac")==0) {
		return cmac;
    }

    if(strcasecmp(name,"aes-xcbc-mac96")==0 || strcasecmp(name,"aes-xcbc-mac-96")==0) {
		return aes_xcbc_mac_96;
    }

    if(strcasecmp(name,"aes-xcbc-mac")==0) {
		return aes_xcbc_mac;
    }

    if(strcasecmp(name,"mac")==0) {
		return mac;
    }

    if(strcasecmp(name,"legacy")==0 || strcasecmp(name,"ecb")==0) {
		return legacy;
    }

    fprintf(stderr,"***Invalid KCV algorithm specified\n");
    *errflag++;

    return legacy;
}




void print_usage(char *progname)
{
    fprintf( stderr,
	     "USAGE: %s OPTIONS FILTERS\n"
	     "\n"
	     COMMAND_SUMMARY
	     "OPTIONS:\n"
	     "* -l <pkcs#11 library path> : path to PKCS#11 library\n"
	     "  -m <NSS config dir> ( e.g. '.' or 'sql:.' ) : NSS db directory \n"
	     "  -s <slot number>\n"
	     "  -t <token label> : if present, -s option is ignored\n"
	     "  -p <token PIN> | :::exec:<command> | :::nologin\n"
	     "  -S : login with SO privilege\n"
	     "  -b <len>: size of buffer to HMAC, for HMAC keys (max: %d, default: 0)\n"
	     "  -n <len>: size of produced KCV in bytes (default: 3)\n"
	     "  -f flavour: KCV algorithm flavour (default: legacy)\n"
	     "              - for all keys: kcv, returns the CKA_CHECK_VALUE attribute value if present\n"
	     "              - for DES keys: ecb, legacy(=ecb) or mac\n"
	     "              - for 2DES and 3DES keys: ecb, legacy(=ecb), mac or cmac\n"
	     "              - for AES keys: ecb, legacy(=ecb), mac, cmac, aes-xcbc-mac or aes-xcbc-mac-96\n"
	     "              - for HMAC keys: ignored\n"
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
	     "|\n"
	     "+-> arguments marked with an asterix(*) are mandatory\n"
	     "|   (except if environment variable sets the value)\n"
	     "+-> arguments marked with a plus sign(+) can be repeated\n"
	     "\n"
	     "FILTERS:\n"
	     " FILTER [FILTER ...]: object filter to match, of the form:\n"
	     "                      - TYPE\n"
	     "                      - [TYPE/[ATTRIBUTE/]]VALUE\n"
	     "\n"
	     "                      TYPE must be be 'seck'\n"
	     "\n"
	     "                      ATTRIBUTE is either:\n"
	     "                      - 'id', 'label' or 'sn'\n"
	     "                      - an actual PKCS#11 attribute name (e.g. CKA_ENCRYPT)\n"
	     "                      when omitted, default is 'label'\n"
	     "\n"
	     "                      VALUE is either:\n"
	     "                      - ASCII string\n"
	     "                      - {hexadecimal values} between curly braces\n"
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
	     , pkcs11_ll_basename(progname),
	     MAX_KCV_CLEARTEXT_SIZE);

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
    unsigned hmacdatasize = 0;
    mac_alg_t algo = legacy;
    size_t kcvlen = 3;

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

    /* get the command-line arguments */
    while ( ( argnum = getopt( argc, argv, "l:m:p:s:t:Sb:hf:n:V" ) ) != -1  && errflag == 0 )
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
	    interactive = 0;
	    tokenlabel = NULL;
	    break;

	case 't':
	    tokenlabel = optarg;
	    interactive = 0;
	    slot = -1;
	    break;

	case 'b':
	    hmacdatasize=strtoul(optarg, NULL, 10);
	    break;

	case 'S':
	    so=1;
	  break;

	case 'h':
	    print_usage(argv[0]);
	    break;

	case 'f':
	    algo = pick_algo(optarg, &errflag);
	    break;

	case 'n':
	    kcvlen=atoi(optarg);
		if(kcvlen<3) kcvlen=3;
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


    if ( library == NULL || optind==argc ) {
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
	while(optind<argc) {
	    pkcs11_display_kcv(p11Context, argv[optind++], hmacdatasize, algo, kcvlen);
	}

	pkcs11_close_session( p11Context );
    }

    pkcs11_finalize( p11Context );

    /* free allocated memory */
 err:
    pkcs11_freeContext(p11Context);

    return retcode;
}
