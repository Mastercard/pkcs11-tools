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
    "Generate key on a PKCS#11 token.\n\n"

typedef struct
{
    char *wrappingkeylabel;
    char *algorithm;
    char *filename;
    char *fullstring;
    int  fullstring_allocated;
    func_rc retcode;
} wrappingjob_t;

#define MAX_WRAPPINGJOB 32
#define DEFAULT_ALGORITHM "oaep"

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
	     "                    check out `openssl ecparam -list_curves` for a list of supported values\n"
	     "                    PKCS#11 libraries typically support prime256v1, secp384r1 and secp521r1\n"
	     "  -d <dh/dsa param>  : DH or DSA parameter file\n"
	     "  -W wrappingkey=\"<label>\"[,algorithm=<algorithm>][,filename=\"<path>\"]\n"
	     "     a specifier for wrapping the key, with the following parameters:\n"
	     "   \"<label>\"    : the label of the wrapping key (double quotes are mandatory)\n"
	     "   <algorithm>  : wrapping algorithm (default: oaep)\n"
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
	     "  -r : when wrapping a key, remove token copy (default is to leave a local copy on the token)\n"
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
    char * password = NULL;
    char * slotenv = NULL;
    int slot = -1;
    int interactive = 1;
    char * tokenlabel = NULL;
    char * label = NULL;

    pkcs11Context * p11Context = NULL;
    func_rc retcode;
    int p11keygenrc = EX_OK;

    key_type_t keytype = unknown;
    CK_ULONG kb=0;
    char *param=NULL;

    CK_ATTRIBUTE *attrs=NULL;
    size_t attrs_cnt=0;

    wrappedKeyCtx *wctx = NULL;
    wrappingjob_t wrappingjob[MAX_WRAPPINGJOB];
    int numjobs = 0;
    int numfailed = 0;
    int removetokencopy = 0;

    int i;
    for(i=0; i<MAX_WRAPPINGJOB;i++) {
	wrappingjob[i].wrappingkeylabel = wrappingjob[i].filename = NULL;
	wrappingjob[i].algorithm = DEFAULT_ALGORITHM;
	wrappingjob[i].fullstring = NULL;
	wrappingjob[i].fullstring_allocated = 0;
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
    while ( ( argnum = getopt( argc, argv, "l:m:i:s:t:p:k:b:q:d:rhVW:" ) ) != -1 ) {
	switch ( argnum ) {
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
		keytype = aes;
		kb = 256;
	    } else if(strcasecmp(optarg,"des")==0) {
		keytype = des;
		kb = 192;
	    } else if(strcasecmp(optarg,"rsa")==0) {
		keytype = rsa;
		kb = 2048;
	    } else if(strcasecmp(optarg,"ec")==0) {
		keytype = ec;
		if(param==NULL) { param = "prime256v1"; }
	    } else if(strcasecmp(optarg,"dsa")==0) {
		keytype = dsa;
	    } else if(strcasecmp(optarg,"dh")==0) {
		keytype = dh;
	    }
#if defined(HAVE_NCIPHER)
	      else if(strcasecmp(optarg,"hmacsha1")==0) {
		keytype = hmacsha1;
		kb = 160;
	    } else if(strcasecmp(optarg,"hmacsha224")==0) {
		keytype = hmacsha224;
		kb = 224;
	    } else if(strcasecmp(optarg,"hmacsha256")==0) {
		keytype = hmacsha256;
		kb = 256;
	    } else if(strcasecmp(optarg,"hmacsha384")==0) {
		keytype = hmacsha384;
		kb = 384;
	    } else if(strcasecmp(optarg,"hmacsha512")==0) {
		keytype = hmacsha512;
		kb = 512;
	    }
#endif
	      else if(strcasecmp(optarg,"generic")==0 || strcasecmp(optarg,"hmac")==0) {
		keytype = generic;
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

	case 'W':
	    if(numjobs==MAX_WRAPPINGJOB) {
		fprintf(stderr, "***Error: too many wrapping jobs requested\n");
		errflag++;
	    } else {
		wrappingjob[numjobs].fullstring = optarg;
		numjobs++;
	    }
	    break;

	case 'r':
	    removetokencopy = 1;
	    break;

	default:
	    errflag++;
	    break;
	}
    }

    if(optind<argc) {
	if( (attrs_cnt=get_attributes_from_argv( &attrs, optind , argc, argv)) == 0 ) {
	    fprintf( stderr, "Try `%s -h' for more information.\n", argv[0]);
	    retcode = rc_error_invalid_argument;
	    goto epilog;
	}
    }

    if ( errflag ) {
	fprintf(stderr, "Try `%s -h' for more information.\n", argv[0]);
	retcode = rc_error_usage;
	goto epilog;
    }

    if ( library == NULL || label == NULL || keytype == unknown || (kb == 0 && param == NULL) ) {
	fprintf( stderr, "At least one required option or argument is wrong or missing.\n"
		 "Try `%s -h' for more information.\n", argv[0]);
	retcode = rc_error_usage;
	goto epilog;
    }

    if (numjobs==0 && removetokencopy==1) {
	fprintf( stderr, "-r optional argument is valid only when wrapping keys.\n"
		 "Try `%s -h' for more information.\n", argv[0]);
	retcode = rc_error_usage;
	goto epilog;
    }

    if((p11Context = pkcs11_newContext( library, nsscfgdir ))==NULL) {
      goto epilog;
    }

    /* validate the given provider library exists and can be opened */
    if (( retcode = pkcs11_initialize( p11Context ) ) != CKR_OK ) {
      goto epilog;
    }

    {
	retcode = pkcs11_open_session( p11Context, slot, tokenlabel, password, 0, interactive);

	if ( retcode == rc_ok )
	{
	    CK_OBJECT_HANDLE keyhandle=0, pubkhandle=0; /* keyhandle will receive either private or secret key handle */
	    CK_BBOOL ck_true = CK_TRUE;
	    CK_BBOOL ck_false = CK_FALSE;
	    key_generation_t keygentype;

	    if(pkcs11_label_exists(p11Context, label)) {
		fprintf(stderr, "an object with this label already exists, aborting\n");
		retcode = rc_error_object_exists;
		goto err_object_exists;
	    }

	    keygentype = numjobs>0 ? removetokencopy ? kg_session_for_wrapping : kg_token_for_wrapping : kg_token;

	    printf("Generating, please wait...\n");

	    switch(keytype) {
	    case aes:
		retcode = pkcs11_genAES( p11Context, label, kb,
					 attrs,
					 attrs_cnt,
					 &keyhandle,
					 keygentype
		    );
		break;

	    case des:
		retcode = pkcs11_genDESX( p11Context, label, kb,
					  attrs,
					  attrs_cnt,
					  &keyhandle,
					  keygentype);
		break;

	    case generic:	/* HMAC */
#if defined(HAVE_NCIPHER)
	    case hmacsha1:
	    case hmacsha224:
	    case hmacsha256:
	    case hmacsha384:
	    case hmacsha512:
#endif
		retcode = pkcs11_genGeneric( p11Context, label, keytype, kb,
					     attrs,
					     attrs_cnt,
					     &keyhandle,
					     keygentype);
		break;

	    case rsa:
		retcode = pkcs11_genRSA( p11Context, label, kb,
					 attrs,
					 attrs_cnt,
					 &pubkhandle,
					 &keyhandle,
					 keygentype);

		if(retcode==rc_ok) {
		    retcode = pkcs11_adjust_keypair_id(p11Context, pubkhandle, keyhandle);
		}

		break;

	    case ec:
		retcode = pkcs11_genEC( p11Context, label, param,
					attrs,
					attrs_cnt,
					&pubkhandle,
					&keyhandle,
					keygentype);

		if(retcode==rc_ok) {
		    retcode = pkcs11_adjust_keypair_id(p11Context, pubkhandle, keyhandle);
		}
		break;

	    case dsa:
		retcode = pkcs11_genDSA( p11Context, label, param,
					 attrs,
					 attrs_cnt,
					 &pubkhandle,
					 &keyhandle,
					 keygentype);

		if(retcode == rc_ok) {
		    retcode = pkcs11_adjust_keypair_id(p11Context, pubkhandle, keyhandle);
		}
		break;

	    case dh:
		retcode = pkcs11_genDH( p11Context, label, param,
					attrs,
					attrs_cnt,
					&pubkhandle,
					&keyhandle,
					keygentype);

		if(retcode == rc_ok) {
		    retcode = pkcs11_adjust_keypair_id(p11Context, pubkhandle, keyhandle);
		}
		break;


	    default:
		break;
	    }

	    fprintf(stderr, ">>> key %sgenerated\n", retcode==rc_ok ? "" : "not " );

	    if(retcode==rc_ok && numjobs>0) { 	/* we've got to wrap things */
		int i;

		for(i=0; i<numjobs; i++) {
		    /* allocate wrapping context */
		    if(( wctx = pkcs11_new_wrappedkeycontext(p11Context))==NULL) {
			fprintf(stderr, "***Error: memory allocation error while processing wrapping job #%d\n", i+1);
			retcode = rc_error_memory;
			continue;
		    }

		    /* we are good to go, but we must prefix the fullstring with a "@" character */
		    size_t stringsize = strlen(wrappingjob[i].fullstring) + 2; /* one for the '@' and one for the \0 */
		    char *tmp = wrappingjob[i].fullstring; /* remember it */

		    wrappingjob[i].fullstring = malloc(stringsize);
		    if(!wrappingjob[i].fullstring) {
			fprintf(stderr, "***Error: memory allocation error while processing wrapping job #%d\n", i+1);
			wrappingjob[i].retcode = rc_error_memory;
			pkcs11_free_wrappedkeycontext(wctx); wctx = NULL;
			continue;
		    }
		    wrappingjob[i].fullstring_allocated = 1;
		    snprintf( wrappingjob[i].fullstring, stringsize, "@%s", tmp);

		    /* parsing will recognize this as a wrappingjob, thanks to the leading "@" character */
		    if(( wrappingjob[i].retcode = pkcs11_prepare_wrappingctx(wctx, wrappingjob[i].fullstring))!=rc_ok) {
			fprintf(stderr, "***Error: parsing of '%s' failed.\nHint: wrapping key label and filename must be surrounded with double quotes\n", wrappingjob[i].fullstring);
			pkcs11_free_wrappedkeycontext(wctx); wctx = NULL;
			continue;
		    }

		    /* wrap */
		    fprintf(stderr, ">>> job #%d: wrapping key '%s' with parameters '%s'\n",
			    i+1,
			    label,
			    &wrappingjob[i].fullstring[1] );
		    if(( wrappingjob[i].retcode = pkcs11_wrap_from_handle(wctx, keyhandle, pubkhandle)) != rc_ok) {
			fprintf(stderr, "***Error: wrapping operation failed for wrapping job #%d\n", i+1);
			pkcs11_free_wrappedkeycontext(wctx); wctx = NULL;
			numfailed++;
			continue;
		    }

		    if(( wrappingjob[i].retcode = pkcs11_output_wrapped_key(wctx)) != rc_ok ) {
			fprintf(stderr, "***Error: could not output/save wrapped key for wrapping job #%d\n", i+1);
			numfailed++;
		    }
		    pkcs11_free_wrappedkeycontext(wctx); wctx = NULL;
		}
	    }

	err_object_exists:
	    pkcs11_close_session( p11Context );
	}
    }
    pkcs11_finalize( p11Context );

    /* free allocated memory */
epilog:
    /* free wrappingjob built strings */
    for(i=0; i<numjobs;i++) {
	if(wrappingjob[i].fullstring_allocated==1) { free(wrappingjob[i].fullstring); }
    }
    if(wctx) { pkcs11_free_wrappedkeycontext(wctx); wctx = NULL; }
    release_attributes( attrs, attrs_cnt );
    pkcs11_freeContext(p11Context);

    switch(retcode) {
    case rc_ok:
	if(numfailed>0) {
	    p11keygenrc = numfailed;
	    fprintf(stderr, "some (%d) wrapping jobs failed - returning code %d (0x%04.4x) to calling process\n", numfailed, p11keygenrc, p11keygenrc);
	} else {
	    fprintf(stderr, "key generation succeeded\n");
	}
	break;

    case rc_error_usage:
    case rc_error_invalid_argument:
	p11keygenrc = EX_USAGE;
	break;

    default:
	p11keygenrc = retcode;
	fprintf(stderr, "key generation failed - returning code %d (0x%04.4x) to calling process\n", p11keygenrc, p11keygenrc);
    }
    return p11keygenrc;
}
