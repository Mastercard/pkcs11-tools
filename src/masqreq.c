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
    "Masquerade PKCS#10 request - adapt subjet and extensions, without resigning.\n\n"

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
	     "  -X : add Subject Key Identifier X509v3 to request (value is SHA1 of key modulus)\n"
             "  -v be verbose, output content of generated PKCS#10 request to standard output\n"
	     "  -h : print usage information\n"
	     "  -V : print version information\n"
	     "\n"
	     "|\n"
	     "+-> arguments marked with an asterix(*) are mandatory\n"
	     "+-> arguments marked with a plus sign(+) can be repeated\n"
	     "\n"
	     , pkcs11_ll_basename(progname) );
    exit(rc_error_usage);
}

int main( int argc, char ** argv )
{
    extern char *optarg;
    extern int optind, optopt;
    int argnum = 0;
    int errflag = 0;
    char *csrfilename = NULL;
    char * filename = NULL;
    char *dn = NULL;
    char *san[MAX_SAN];
    size_t san_cnt=0;
    bool ski=false;			/* add Subject Key Identifier */
    bool verbose = false;
    bool reverse = false;
    x509_req_handle_t *req = NULL;

    func_rc retcode = rc_ok;

    /* get the command-line arguments */
    while ( ( argnum = getopt( argc, argv, "c:o:d:re:XvhV" ) ) != -1 )
    {
	switch ( argnum )
	{
	case 'c':
	    csrfilename = optarg;
	    break;
	    
	case 'o':
	    filename = optarg;
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
	retcode = rc_error_usage;
	goto err;
    }


    if ( dn == NULL || csrfilename == NULL ) {
	fprintf( stderr, "At least one required option or argument is wrong or missing.\n" 
		 "Try `%s -h' for more information.\n", argv[0]);
	retcode = rc_error_usage;
	goto err;
    }

    req = pkcs11_get_X509_REQ_from_file(csrfilename);

    if(!req) {
	fprintf(stderr, "Error: could not load PKCS#10 file <%s>\n", csrfilename);
	retcode = rc_error_object_not_found;
	goto err;
    }


    if(!pkcs11_masq_X509_REQ(req, dn, reverse, san, san_cnt, ski)) {
	fprintf(stderr, "Error: could not masquerade PKCS#10 file <%s>\n", csrfilename);
	retcode = rc_error_other_error;
	goto err;
    }

    write_X509_REQ(req, filename, verbose);

    retcode = rc_ok;
err:
    
    if(req) { x509_req_handle_t_free(req); }
    return retcode;
}
