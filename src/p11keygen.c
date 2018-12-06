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
    "Generate key on a PKCS#11 token.\n\n"


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
	     "* -i <key_alias>: label/alias of the key\n"
	     "* -k <key type> : aes, des, rsa, dsa, dh, ec, generic or hmac,\n"
#if defined(HAVE_NCIPHER)
             "                  hmacsha1, hmacsha224, hmacsha256, hmacsha384, hmacsha512\n"
#endif
	     "  -b <key length>: key length in bits. supported values:\n"
	     "                   - 128, 192, 256 for AES\n"
	     "                   - 128(=DES2), 192=(DES3) for DES\n"
	     "                   - 1024, 2048, 3072, 4096 for RSA\n"
	     "                   - any length>56 for generic and HMAC\n"
             "                   if unspeficied, defaults are:\n"
	     "                   - 256 for AES\n"
	     "                   - 192 for DES (DES3 key)\n"
	     "                   - 2048 for RSA\n"
	     "                   - 160 for Generic/HMAC\n"
	     "                   - ignored for DH/DSA (taken out from parameter file)\n"
	     "  -q <curve param>: curve parameter\n"
	     "                    if unspecified, default is prime256v1\n"
	     "  -d <dh/dsa param>  : DH or DSA parameter file\n"
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
	     "|\n"
	     "+-> parameters marked with an asterix(*) are mandatory\n"
             "|   (except if environment variable sets the value)\n"
	     "+-> arguments marked with a plus sign(+) can be repeated\n"
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
    char * password = NULL;
    char * slotenv = NULL;
    int slot = -1;
    int interactive = 1;
    char * tokenlabel = NULL;
    char * label = NULL;

    pkcs11Context * p11Context = NULL;
    func_rc retcode;

//    enum keytype { unknown, aes, des, rsa, ec, dsa, dh, generic };

    enum keytype kt = unknown;
    CK_ULONG kb=0;
    char *param=NULL;

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
    while ( ( argnum = getopt( argc, argv, "l:m:i:s:t:p:k:b:q:d:hV" ) ) != -1 )
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

	case 'i':
	    label= optarg;
	    break;

	case 'd':
	    param= optarg;
	    break;

	case 'k':
	    if(strcasecmp(optarg,"aes")==0) {
		kt = aes;
		kb = 256;
	    } else if(strcasecmp(optarg,"des")==0) {
		kt = des;
		kb = 192;
	    } else if(strcasecmp(optarg,"rsa")==0) {
		kt = rsa;
		kb = 2048;
	    } else if(strcasecmp(optarg,"ec")==0) {
		kt = ec;
		if(param==NULL) { param = "prime256v1"; }
	    } else if(strcasecmp(optarg,"dsa")==0) {
		kt = dsa;
	    } else if(strcasecmp(optarg,"dh")==0) {
		kt = dh;
	    }
#if defined(HAVE_NCIPHER)
	      else if(strcasecmp(optarg,"hmacsha1")==0) {
		kt = hmacsha1;
		kb = 160;
	    } else if(strcasecmp(optarg,"hmacsha224")==0) {
		kt = hmacsha224;
		kb = 224;
	    } else if(strcasecmp(optarg,"hmacsha256")==0) {
		kt = hmacsha256;
		kb = 256;
	    } else if(strcasecmp(optarg,"hmacsha384")==0) {
		kt = hmacsha384;
		kb = 384;
	    } else if(strcasecmp(optarg,"hmacsha512")==0) {
		kt = hmacsha512;
		kb = 512;
	    }
#endif
	      else if(strcasecmp(optarg,"generic")==0 || strcasecmp(optarg,"hmac")==0) {
		kt = generic;
		kb = 160;
	    }
	    break;

	case 'b':
	    kb = strtoul(optarg, NULL, 10);
	    break;

	case 'q':		/* elliptic curve parameter */
	    param = optarg;
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

    if(optind<argc) {
	if( (attrs_cnt=get_attributes_from_argv( &attrs, optind , argc, argv)) == 0 ) {
	    fprintf( stderr, "Try `%s -h' for more information.\n", argv[0]);
	    goto err;
	}
    }
    
    if ( errflag ) {
	fprintf(stderr, "Try `%s -h' for more information.\n", argv[0]);
	goto err;
    }

    if ( library == NULL || label == NULL || kt == unknown || (kb == 0 && param == NULL) ) {
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

	retcode = pkcs11_open_session( p11Context, slot, tokenlabel, password, 0, interactive);
	
	if ( retcode == rc_ok )
	{
	    
	    int rc=0;
	    CK_OBJECT_HANDLE hSecretKey, hPublicKey, hPrivateKey;
	    CK_BBOOL ck_true = CK_TRUE;
	    CK_BBOOL ck_false = CK_FALSE;

	    if(pkcs11_label_exists(p11Context, label)) {
		fprintf(stderr, "an object with this label already exists, aborting\n");
		retcode = rc_error_object_exists;
		goto err_object_exists;
	    }

	    printf("Generating, please wait...\n");

	    switch(kt) {
	    case aes:
		rc = pkcs11_genAES( p11Context, label, kb, 
				    attrs,
				    attrs_cnt,
				    &hSecretKey);
		break;
		
	    case des:
		rc = pkcs11_genDESX( p11Context, label, kb, 
				     attrs,
				     attrs_cnt,
				     &hSecretKey);
		break;

	    case generic:	/* HMAC */
	    case hmacsha1:
	    case hmacsha224:
	    case hmacsha256:
	    case hmacsha384:
	    case hmacsha512:

		rc = pkcs11_genGeneric( p11Context, label, kt, kb, 
					attrs,
					attrs_cnt,
					&hSecretKey);
		break;

	    case rsa:
		rc = pkcs11_genRSA( p11Context, label, kb, 
				    attrs,
				    attrs_cnt,
				    &hPublicKey,
				    &hPrivateKey);
		
		if(rc) {
		    rc = pkcs11_adjust_keypair_id(p11Context, hPublicKey, hPrivateKey);
		}

		break;

	    case ec:
		rc = pkcs11_genECDSA( p11Context, label, param, 
				      attrs,
				      attrs_cnt,
				      &hPublicKey,
				      &hPrivateKey);

		if(rc) {
		    rc = pkcs11_adjust_keypair_id(p11Context, hPublicKey, hPrivateKey);
		}
		break;

	    case dsa:
		rc = pkcs11_genDSA( p11Context, label, param,
				    attrs,
				    attrs_cnt,
				    &hPublicKey,
				    &hPrivateKey);

		if(rc) {
		    rc = pkcs11_adjust_keypair_id(p11Context, hPublicKey, hPrivateKey);
		}
		break;

	    case dh:
		rc = pkcs11_genDH( p11Context, label, param,
				   attrs,
				   attrs_cnt,
				   &hPublicKey,
				   &hPrivateKey);

		if(rc) {
		    rc = pkcs11_adjust_keypair_id(p11Context, hPublicKey, hPrivateKey);
		}
		break;


	    default:
		break;
		
	    }
	    
	    printf("key generation %s\n", rc ? "succeeded" : "failed" );

	err_object_exists:
	    pkcs11_close_session( p11Context );
	}
    }
    pkcs11_finalize( p11Context );
    
    /* free allocated memory */
err:
    release_attributes( attrs, attrs_cnt );
    pkcs11_freeContext(p11Context);
    
    return retcode ;
}
