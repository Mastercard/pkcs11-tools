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

typedef struct {
    hash_alg_t a;
    CK_MECHANISM_TYPE h;

} st_hash_alg_map ;



static const st_hash_alg_map rsa_hash_mech[] = {
    { sha1, CKM_SHA1_RSA_PKCS },
    { sha224, CKM_SHA224_RSA_PKCS },
    { sha256, CKM_SHA256_RSA_PKCS },
    { sha384, CKM_SHA384_RSA_PKCS },
    { sha512, CKM_SHA512_RSA_PKCS },
};


static const st_hash_alg_map dsa_hash_mech[] = {
    { sha1, CKM_DSA_SHA1 },
    { sha224, CKM_DSA_SHA224 },
    { sha256, CKM_DSA_SHA256 },
    { sha384, CKM_DSA_SHA384 },
    { sha512, CKM_DSA_SHA512 },
};


static const st_hash_alg_map ecdsa_hash_mech[] = {
    { sha1, CKM_ECDSA_SHA1 },
    { sha224, CKM_ECDSA_SHA224 },
    { sha256, CKM_ECDSA_SHA256 },
    { sha384, CKM_ECDSA_SHA384 },
    { sha512, CKM_ECDSA_SHA512 },
};



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
    int ski=0;			/* add Subject Key Identifier */
    int verbose = 0;
    int fake = 0;
    int reverse = 0;

    hash_alg_t hash_alg = sha256; 	/* as of release 0.25.3, sha256 is the default */

    pkcs11Context * p11Context = NULL;
    CK_RV retcode = EXIT_FAILURE;

    CK_ATTRIBUTE *argv_attrs=NULL;
    size_t argv_attrs_cnt=0;

    CK_ATTRIBUTE *default_attrs=NULL;
    size_t default_attrs_cnt=0;

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
    while ( ( argnum = getopt( argc, argv, "l:m:o:i:s:t:d:re:p:XH:vFhV" ) ) != -1 )
    {
	switch ( argnum )
	{
	case 'o':
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
	    if(!pkcs11_X509_REQ_check_DN(optarg)) {
		fprintf( stderr , "Error: invalid DN field\n");
		errflag++;
	    } else {
		dn = optarg;
	    }
	    break;

	case 'r':
	    reverse=1;
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
	    ski = 1;		/* we want a subject key identifier */
	    break;

	case 'v':
	    verbose = 1;
	    break;

	case 'F':
	    fake = 1;
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
	int rc;
	CK_OBJECT_HANDLE hPublicKey=NULL_PTR;
	CK_OBJECT_HANDLE hPrivateKey=NULL_PTR;


	if( pkcs11_findkeypair(p11Context, label, &hPublicKey, &hPrivateKey)==0 ) {
	    fprintf(stderr, "Error: Cannot find key pair with label '%s'.\n", label);
	    retcode = rc_error_object_not_found;
	    goto err;
	}
	    
	/* at this point, we have a key. Let's see if it is a EC, DSA or RSA. */
	CK_ATTRIBUTE keytype;
	keytype.type= CKA_KEY_TYPE;
	    
	if( pkcs11_getObjectAttributes( p11Context, hPrivateKey, &keytype, sizeof keytype/sizeof (CK_ATTRIBUTE)) ==CKR_OK ) {
	    switch( *(CK_KEY_TYPE *) keytype.pValue)  {

	    case CKK_RSA:

	    {
		/* get modulus and exponent */
		CK_ATTRIBUTE attr[2];

		attr[0].type = CKA_MODULUS;
		attr[1].type = CKA_PUBLIC_EXPONENT;

		if( pkcs11_getObjectAttributes( p11Context, hPrivateKey, attr, sizeof attr/sizeof (CK_ATTRIBUTE) ) == CKR_OK ) {
		    /* if object is found, CKA_ID is aligned to contain SHA1 of key modulus  */
		    /* the same CKA_ID is applied to both public key and private key objects */
		    CK_ATTRIBUTE id_attr = {CKA_ID, NULL_PTR, 0 };
		    id_attr.ulValueLen = pkcs11_openssl_alloc_and_sha1( attr[0].pValue, attr[0].ulValueLen, &id_attr.pValue);
		    if(id_attr.ulValueLen>0) {
			pkcs11_setObjectAttribute( p11Context, hPrivateKey, &id_attr );
			
			if(hPublicKey != NULL_PTR) {
			    pkcs11_setObjectAttribute( p11Context, hPublicKey, &id_attr );
			}
			    
			/* ok, now we are in the req business */
			
			{
			    CK_VOID_PTR x509_req = pkcs11_create_unsigned_X509_REQ(dn, reverse,
										   san, san_cnt,
										   ski ? &id_attr : NULL,
										   &attr[0],
										   &attr[1]);
			    
			    if(x509_req) {
				CK_MECHANISM_TYPE hash = 0;

				int i;

				for(i=0;i<sizeof rsa_hash_mech/sizeof(st_hash_alg_map); i++) {
				    if (rsa_hash_mech[i].a == hash_alg) {
					hash = rsa_hash_mech[i].h;
					break;
				    }
				}

				int keybits = pkcs11_get_rsa_modulus_bits(p11Context, hPrivateKey);
				int keybytes = (keybits>>3) + (keybits%8 ? 1 : 0);
				int rv = pkcs11_sign_X509_REQ(p11Context, x509_req, keybytes, hPrivateKey, hash, fake);
				
				if(rv==1) {
				    write_X509_REQ(x509_req, filename, verbose);
				}
			    } else {
				printf("Unable to generate or CSR");
			    }
			    
			    /* free stuff */
			}

			pkcs11_openssl_free(&id_attr.pValue);
			id_attr.ulValueLen = 0;
		    }
		    pkcs11_freeObjectAttributesValues( attr, sizeof attr/sizeof (CK_ATTRIBUTE));
		}
	    }
	    break;


	    case CKK_DSA:
	    {
		/* get DSA params + public key */
		CK_ATTRIBUTE attr[] = {
		    { CKA_PRIME, NULL, 0L },
		    { CKA_SUBPRIME, NULL, 0L },
		    { CKA_BASE, NULL, 0L },
		    { CKA_VALUE, NULL, 0L },
		    { CKA_ID, NULL, 0L },
		};

		if( pkcs11_getObjectAttributes( p11Context, hPublicKey, attr, sizeof attr/sizeof (CK_ATTRIBUTE) ) == CKR_OK ) {
		    CK_VOID_PTR x509_req = pkcs11_create_unsigned_X509_REQ_DSA(dn, reverse,
									       san, san_cnt, 
									       ski ? &attr[4] : NULL, 
									       &attr[0],
									       &attr[1],
									       &attr[2],
									       &attr[3] );
		    
		    if(x509_req) {
			CK_MECHANISM_TYPE hash = 0;
			
			int i;
			
			for(i=0;i<sizeof dsa_hash_mech/sizeof(st_hash_alg_map); i++) {
			    if (dsa_hash_mech[i].a == hash_alg) {
				hash = dsa_hash_mech[i].h;
				break;
			    }
			}
			
			int keybits = pkcs11_get_dsa_pubkey_bits(p11Context, hPublicKey);
			int keybytes = (keybits>>3) + (keybits%8 ? 1 : 0);
			int rv = pkcs11_sign_X509_REQ(p11Context, x509_req, keybytes, hPrivateKey, hash, fake);
			
			if(rv==1) {
			    write_X509_REQ(x509_req, filename, verbose);
			}
		    } else {
			printf("Unable to sign CSR\n");
		    }
		    
		    pkcs11_freeObjectAttributesValues( attr, sizeof attr/sizeof (CK_ATTRIBUTE));
		} else {
		    printf("Issue with DSA key\n");
		}
	    }
	    break;

	    case CKK_EC:
	    {
		/* get modulus and exponent */
		CK_ATTRIBUTE attr[3];

		attr[0].type = CKA_EC_PARAMS;
		attr[1].type = CKA_EC_POINT;
		attr[2].type = CKA_ID; /* for subject key identifier */

		if( pkcs11_getObjectAttributes( p11Context, hPublicKey, attr, sizeof attr/sizeof (CK_ATTRIBUTE) ) == CKR_OK ) {

		    char curvename[40];

		    pkcs11_ec_oid2curvename(attr[0].pValue, attr[0].ulValueLen, curvename, sizeof curvename);
		
		    /* ok, now we are in the req business */
		    {

			int degree;
			CK_VOID_PTR x509_req = pkcs11_create_unsigned_X509_REQ_EC(dn, reverse,
										  san, san_cnt,
										  ski ? &attr[2] : NULL,
										  curvename,
										  &attr[1],
										  &degree);
		    
			if(x509_req) {
			    CK_MECHANISM_TYPE hash = 0;
				    
			    int i;
			    int keybytes = (degree<<1) + (degree%8 ? 2 : 0); /* if degree is not congruent modulo 8, we need to add */
			                                                     /* two extra bytes: one per coordinate of the point    */

			    for(i=0;i<sizeof ecdsa_hash_mech/sizeof(st_hash_alg_map); i++) {
				if (ecdsa_hash_mech[i].a == hash_alg) {
				    hash = ecdsa_hash_mech[i].h;
				    break;
				}
			    }

			    int rv = pkcs11_sign_X509_REQ(p11Context, x509_req, degree<<1, hPrivateKey, hash, fake);
			
			    if(rv==1) {
				write_X509_REQ(x509_req, filename, verbose);
			    }
			} else {
			    printf("Unable to sign CSR\n");
			}
		    
			/* free stuff */
		    } 
		    pkcs11_freeObjectAttributesValues( attr, sizeof attr/sizeof (CK_ATTRIBUTE));
		} else {
		    printf("Unknown EC\n");
		}
	    }
	    break;

	    default:
		fprintf(stderr, "unhandled key type, sorry.\n");
		break;
	    }
	}
	pkcs11_close_session( p11Context );
    }

    pkcs11_finalize( p11Context );

    /* free allocated memory */
err:
    release_attributes( argv_attrs, argv_attrs_cnt );
    
    pkcs11_freeContext(p11Context);
    
    return retcode;
}
