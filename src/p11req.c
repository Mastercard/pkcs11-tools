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

#define COMMAND_SUMMARY							\
    "Generate and output a PKCS#10 Certification Signing Request (CSR) using a key stored on PKCS#11 token.\n\n"

#ifdef _WIN32
#include <openssl/applink.c>
#endif

#define MAX_SAN  1000
#define WARN_SAN 25

/* prototypes */
void print_version_info(char *progname);
void print_usage(char *);
int main( int argc, char **argv);



void print_usage(char *progname)
{
    fprintf( stderr, "USAGE: %s OPTIONS\n"
	     "\n"
	     COMMAND_SUMMARY
	     "OPTIONS:\n"
	     "* -l <pkcs#11 library path> : path to PKCS#11 library\n"
	     "  -m <NSS config dir> ( e.g. '.' or 'sql:.' ) : NSS db directory \n"
	     "  -s <slot number>\n"
	     "  -t <token label> : if present, -s option is ignored\n"
	     "  -p <token PIN> | :::exec:<command> | :::nologin\n"
	     "* -i <key_alias>: label/alias of the key\n"
	     "* -d <SubjectDN>: subject DN, OpenSSL formatted, e.g. /CN=mysite.net/O=My Org/C=BE\n"
	     "  -r reverse order of subject DN (for compatibility with previous versions)\n"
	     "  -o <file> : output file for PKCS#10 request (stdout if not specified)\n"
	     "  -a <algo> : signature algorithm for RSA (default is RSA PKCS#1 v1.5)\n"
	     "              - pkcs|pkcs1 : RSA PKCS#1 v1.5 signature (insecure and deprecated)\n"
	     "              - pss        : RSA PSS signature\n"
	     "  -H sha1|sha224|sha2 or sha256|sha384|sha512: hash algorithm (default is sha256)\n"
	     "+ -e <SANField> : Subject Alternative Name field, OpenSSL formatted.\n"
	     "                  possible values are: \n"
	     "                  - DNS:[host name]\n"
	     "                  - email:[rfc822 compatible mail address]\n"
	     "                  - IP:[IPv4 address]\n"
	     "  -X : add Subject Key Identifier X509v3 to request (value is SHA1 of key modulus)\n"
	     "  -F : fake signing, do not sign and put dummy information in signature\n"
             "  -v : be verbose, output content of generated PKCS#10 to standard output\n"	    
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
	     "|\n"
	     "+-> options marked with an asterix(*) are mandatory\n"
             "|   (except if environment variable sets the value)\n"
	     "+-> options marked with a plus sign(+) can be repeated\n"
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
    int interactive = 1;
    char * slotenv = NULL;
    int slot = -1;
    char * tokenlabel = NULL;
    char * label = NULL;
    char *dn = NULL;
    char *san[MAX_SAN];
    size_t san_cnt=0;
    bool ski=false;			/* add Subject Key Identifier */
    bool verbose = false;
    bool fake = false;
    bool reverse = false;

    hash_alg_t hash_alg = sha256; 	/* as of release 0.25.3, sha256 is the default */
    sig_alg_t sig_alg = s_default;	/* signature algorithm set to default (handled inside pkcs11_req) */

    pkcs11Context * p11Context = NULL;
    CK_RV retcode = EXIT_FAILURE;

    CK_ATTRIBUTE *argv_attrs=NULL;
    size_t argv_attrs_cnt=0;

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
    while ( ( argnum = getopt( argc, argv, "l:m:o:a:i:s:t:d:re:p:XH:vFhV" ) ) != -1 )
    {
	switch ( argnum )
	{
	case 'o':
	    filename = optarg;
	    break;

	case 'a':
		if(strcasecmp(optarg, "pkcs")==0 || strcasecmp(optarg, "pkcs1")==0) {
			sig_alg = s_rsa_pkcs1;
		} else if(strcasecmp(optarg, "pss")==0) {
			sig_alg = s_rsa_pss;
		} else {
			fprintf(stderr, "Error: unknown signature algorithm (%s)\n", optarg);
			++errflag;
		}
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
	    slot = -1;
	    interactive = 0;
	    tokenlabel = optarg;
	    break;

	case 'i':
	    label= optarg;
	    break;

	case 'H':
	    if(strcasecmp(optarg,"sha1")==0 || strcasecmp(optarg,"sha")==0 ) { 
		hash_alg = sha1;
	    } else if (strcasecmp(optarg,"sha224")==0) { 
		hash_alg = sha224;
	    } else if (strcasecmp(optarg,"sha256")==0) { 
		hash_alg = sha256;
	    } else if (strcasecmp(optarg,"sha2")==0) { /* alias for sha256 */
		hash_alg = sha256;
	    } else if (strcasecmp(optarg,"sha384")==0) { 
		hash_alg = sha384;
	    } else if (strcasecmp(optarg,"sha512")==0) { 
		hash_alg = sha512;
	    } else {
		fprintf( stderr, "Error: unknown hash algorithm (%s)\n", optarg);
		++errflag;
	    }
	    break;
    
	case 'd':
	    if(!pkcs11_X509_check_DN(optarg)) {
		fprintf( stderr , "Error: invalid DN field\n");
		errflag++;
	    } else {
		dn = optarg;
	    }
	    break;

	case 'r':
	    reverse=true;
	    break;
	    
	case 'e':
	    if(san_cnt>MAX_SAN) {
		fprintf( stderr , "Error: too many SAN fields (max %d)\n", MAX_SAN);
		errflag++;
	    } else {

		if(san_cnt==WARN_SAN) {
		    fprintf( stderr , "Warning: many SAN fields (>=%d). You may encounter SSL/TLS performance issues.\n", WARN_SAN);
		}

		san[san_cnt++] = optarg;
	    }
	    break;


	case 'X':
	    ski = true;		/* we want a subject key identifier */
	    break;

	case 'v':
	    verbose = true;
	    break;

	case 'F':
	    fake = true;
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
	if( (argv_attrs_cnt=get_attributes_from_argv( &argv_attrs, optind , argc, argv)) == 0 ) {
	    errflag++;
	}
    }

    if ( errflag ) {
	fprintf(stderr, "Try `%s -h' for more information.\n", argv[0]);
	goto err;
    }


    if ( library == NULL || label == NULL || dn == NULL ) {
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

	
    retcode = pkcs11_open_session( p11Context, slot, tokenlabel, password, 0, interactive);

    if ( retcode == rc_ok )
    {
	CK_OBJECT_HANDLE hPublicKey=NULL_PTR;
	CK_OBJECT_HANDLE hPrivateKey=NULL_PTR;
	CK_OBJECT_HANDLE handle_for_attributes=NULL_PTR;
	pkcs11AttrList *attrlist = NULL;

	if( pkcs11_findkeypair(p11Context, label, &hPublicKey, &hPrivateKey)==0 ) {
	    fprintf(stderr, "Error: Cannot find key pair with label '%s'.\n", label);
	    retcode = rc_error_object_not_found;
	    goto err;
	}
	    
	/* at this point, we have a key. Let's see if it is a EC, DSA or RSA. */
	key_type_t detected_key_type = pkcs11_get_key_type(p11Context, hPrivateKey);

	switch(detected_key_type) {
	case rsa:
	    handle_for_attributes = hPrivateKey;
	    attrlist = pkcs11_new_attrlist( p11Context,
					    _ATTR(CKA_MODULUS),
					    _ATTR(CKA_PUBLIC_EXPONENT),
					    _ATTR(CKA_ID),
					    _ATTR_END);
	    break;

	case dsa:
	    /* for DSA, we work with the public key, as the public key value is stored into CKA_VALUE */
	    /* instead of a specific attribute, which maps to the private key value, on the private key */
	    /* which is forcing us to use the public key object instead. */
	    if(hPublicKey==NULL_PTR) {
		fprintf(stderr, "Error: a public key is required in order to generate a DSA certificate request.\n");
		retcode = rc_error_dsa_missing_public_key;
		goto err;
	    }

	    handle_for_attributes = hPublicKey;
	    attrlist = pkcs11_new_attrlist( p11Context,
					    _ATTR(CKA_PRIME),
					    _ATTR(CKA_SUBPRIME),
					    _ATTR(CKA_BASE),
					    _ATTR(CKA_VALUE),
					    _ATTR(CKA_ID),
					    _ATTR_END);

	    if(!attrlist) {
		fprintf(stderr,"Error: could not create attribute list object\n");
		retcode = rc_error_other_error;
		goto err;
	    }
	    break;

	case ec:
	case ed:
	    /* for EC and ED, we work with the public key, as the public key value is stored into CKA_POINT    */
	    /* which is not present in the private key object */
	    if(hPublicKey==NULL_PTR) {
		fprintf(stderr, "Error: a public key is required in order to generate an ECDSA/EDDSA certificate request.\n");
		retcode = rc_error_ec_or_ed_missing_public_key;
		goto err;
	    }
	    handle_for_attributes = hPublicKey;
	    attrlist = pkcs11_new_attrlist( p11Context,
					    _ATTR(CKA_EC_PARAMS),
					    _ATTR(CKA_EC_POINT),
					    _ATTR(CKA_ID),
					    _ATTR_END);
	    break;

	    
	default:
	    fprintf(stderr, "Error: unsupported key type\n");
	    retcode = rc_error_unsupported;
	    goto err;
	}

	if(attrlist && pkcs11_read_attr_from_handle (attrlist, handle_for_attributes)) {
	    CK_VOID_PTR req = pkcs11_create_X509_REQ(p11Context,
						     dn,
						     reverse,
						     fake,
						     san,
						     san_cnt,
						     ski,
						     detected_key_type,
							 sig_alg,
						     hash_alg,
						     hPrivateKey,
						     attrlist);

	    if(req) {
		write_X509_REQ(req, filename, verbose);
		pkcs11_free_X509_REQ(req);
	    } else {
		fprintf(stderr, "Error: Unable to generate certificate request\n");
	    }
	    pkcs11_delete_attrlist(attrlist);
	} else {
	    fprintf(stderr,"Error: could not create attribute list object, or read attributes from token\n");
	    retcode = rc_error_other_error;
	    /* TODO goto err */
	}
	pkcs11_close_session( p11Context );
    }


    /* free allocated memory */
err:
    pkcs11_finalize( p11Context );

    release_attributes( argv_attrs, argv_attrs_cnt );
    
    pkcs11_freeContext(p11Context);
    
    return retcode;
}
