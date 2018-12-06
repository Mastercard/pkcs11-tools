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
#include <getopt.h>
#include "pkcs11lib.h"


#define MAX_SAN  1000
#define WARN_SAN 25

#define COMMAND_SUMMARY \
    "Masquerade PKCS#10 request - adapt subjet and extensions, without resigning.\n\n"

/* prototypes */
void print_version_info(char *progname);
void print_usage(char *);
int main( int argc, char **argv);


void print_usage(char *progname)
{
    fprintf( stderr, 
	     "USAGE: %s ARGUMENTS\n"
	     "\n"
	     COMMAND_SUMMARY
	     "* -c <file> : input file with PKCS#10 request, to extract public key from\n"
	     "  -o <file> : output file for PKCS#10 request (stdout if not specified)\n"
	     "  -H sha1|sha256|sha384|sha512: Hashing algorithm (default is sha1)\n"
	     "* -d <SubjectDN>: subject DN, OpenSSL formatted, e.g. /CN=mysite.net/O=My Org/C=BE\n"
	     "  -r reverse order of subject DN (for compatibility with previous versions)\n"
	     "+ -e <SANField> : subject alternative Name field, OpenSSL formatted.\n"
	     "                  possible values are: \n"
	     "                  - DNS:[host name]\n"
	     "                  - email:[rfc822 compatible mail address]\n"
	     "                  - IP:[IPv4 address]\n"
	     "  -S : add Subject Key Identifier X509v3 to request (value is SHA1 of key modulus)\n"
             "  -v be verbose, output content of generated PKCS#10 request to standard output\n"
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
	     "\n"
	     "|\n"
	     "+-> arguments marked with an asterix(*) are mandatory\n"
	     "+-> arguments marked with a plus sign(+) can be repeated\n"
	     "\n"
	     , pkcs11_ll_basename(progname) );

    exit( RC_ERROR_USAGE );
}

int main( int argc, char ** argv )
{
    int argnum = 0;
    int errflag = 0;
    char * filename = NULL;
    char * inputcsr = NULL;
    int slot = -1;
    char *dn = NULL;
    char *san[MAX_SAN];
    size_t san_cnt=0;
    int ski=0;			/* add Subject Key Identifier */
    int verbose=0;
    int reverse = 0;

    CK_MECHANISM_TYPE hash = CKM_SHA1_RSA_PKCS;

    CK_RV retcode = EXIT_FAILURE;
    
    /* get the command-line arguments */
    while ( ( argnum = getopt( argc, argv, "c:o:d:re:H:SvhV" ) ) != -1 )
    {
	switch ( argnum )
	{
	case 'c':
	    inputcsr = optarg;
	    break;

	case 'o':
	    filename = optarg;
	    break;

	case 'H':
	    if(strcasecmp(optarg,"sha1")==0) { 
		hash = CKM_SHA1_RSA_PKCS;
	    } else if (strcasecmp(optarg,"sha1")==0) { 
		hash = CKM_SHA1_RSA_PKCS;
	    } else if (strcasecmp(optarg,"sha256")==0) { 
		hash = CKM_SHA256_RSA_PKCS;
	    } else if (strcasecmp(optarg,"sha384")==0) { 
		hash = CKM_SHA384_RSA_PKCS;
	    } else if (strcasecmp(optarg,"sha512")==0) { 
		hash = CKM_SHA512_RSA_PKCS;
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

	case 'S':
	  ski = 1;		/* we want a subject key identifier */
	  break;

	case 'v':
	    verbose = 1;
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


    if ( dn == NULL || inputcsr == NULL ) {
	fprintf( stderr, "At least one required option or argument is wrong or missing.\n" 
		 "Try `%s -h' for more information.\n", argv[0]);
	goto err;
    }


    {	    
	/* get modulus and exponent */
	CK_ATTRIBUTE modulus;
	CK_ATTRIBUTE exponent;

	if( pkcs11_extract_pubk_from_X509_REQ(inputcsr, &modulus, &exponent) == CK_TRUE) {
	    
	    /* extract SHA-1 from modulus, in case we want to use an SKI */
	    CK_ATTRIBUTE id_attr = {CKA_ID, NULL_PTR, 0 };
	    id_attr.ulValueLen = pkcs11_openssl_alloc_and_sha1( modulus.pValue, modulus.ulValueLen, &id_attr.pValue);

	    {
		CK_VOID_PTR x509_req = pkcs11_create_unsigned_X509_REQ(dn, reverse, san, san_cnt, ski ? &id_attr : NULL, &modulus, &exponent);
		
		if(x509_req) {
		    int rv = pkcs11_fakesign_X509_REQ(x509_req, modulus.ulValueLen*8, hash);
		    
		    if(rv==1) {
			write_X509_REQ(x509_req, filename, verbose);
		    }
		} else {
		    printf("Unable to sign CSR");
		}
	    }

	    pkcs11_free_X509_REQ_attributes(&modulus, &exponent);	    
	    pkcs11_openssl_free(&id_attr.pValue);
	}
    }

    /* free allocated memory */
 err:

    return ( retcode );
}
