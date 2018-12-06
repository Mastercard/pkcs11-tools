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
#include <ctype.h>
#include "pkcs11lib.h"

static CK_ATTRIBUTE_PTR new_attribute_for_bool(CK_ATTRIBUTE_TYPE argattrtype, CK_BBOOL argval);
static CK_ATTRIBUTE_PTR new_attribute_for_string(CK_ATTRIBUTE_TYPE argattrtype, char *arg);
static CK_ATTRIBUTE_PTR new_attribute_for_null_term_string(CK_ATTRIBUTE_TYPE argattrtype, char *arg);
static CK_ATTRIBUTE_PTR new_attribute_for_hex_string(CK_ATTRIBUTE_TYPE argattrtype, char *arg);

char * pkcs11_prompt( char * prompt, CK_BBOOL echo )
{
    char * buf = NULL;
    char * res = NULL;
    int n;

    if ( ( buf = (char *) malloc( sizeof( char ) * MAXBUFSIZE ) ) == NULL )
    {
	fprintf( stderr, "Error: Unable to allocate system memory, exiting.\n" );
	exit( RC_ERROR_MEMORY );
    }

    fprintf( stderr, "\n%s", prompt );
    fflush( stdout );

    if ( !echo ) {
	pkcs11_ll_echo_off();
    }

    if ( ( res = fgets( buf, MAXBUFSIZE, stdin ) ) == NULL )
    {
	fprintf( stderr, "Error: Unable to read input, exiting.\n" );
	exit( RC_ERROR_READ_INPUT );
    }

    n = strlen( res );

    while ( buf[n - 1] != '\n' )
    {
	if ( ( buf = ( char * ) realloc( buf, n + MAXBUFSIZE ) ) == NULL )
	{
	    fprintf( stderr, "Error: Unable to allocate system memory, exiting\n" );
	    exit( RC_ERROR_MEMORY );
	}

	if ( ( res = fgets( buf + n, MAXBUFSIZE, stdin ) ) == NULL )
	{
	    fprintf( stderr, "Error: Unable to read input, exiting.\n" );
	    exit( RC_ERROR_READ_INPUT );
	}

	n += strlen( res );
    }

    buf[ n -1 ] = 0;

    if ( !echo )
    {
	pkcs11_ll_echo_on();
    }

    printf("\n" );
    return buf;
}

void pkcs11_prompt_free_buffer(char *arg)
{
    if(arg) free(arg);
}


char * pkcs11_pipe_password( char * passwordexec )
{
    char * buf = NULL;

    if(passwordexec!=NULL && strncmp(PASSWORD_EXEC, passwordexec, strlen(PASSWORD_EXEC))==0 ) {

	size_t len=0, actual;
	FILE * exec_pipe = popen (&passwordexec[strlen(PASSWORD_EXEC)], "r");

	if(exec_pipe != NULL) {
	    actual = getline(&buf, &len, exec_pipe); /* password is allocated here */
	    pclose(exec_pipe);	/* close the pipe */
	    if(buf[actual-1]=='\n') { buf[actual-1]=0x0; } /* clear line feed if found */		
	}


    }

    return buf;
}


/*--------------------------------------------------------------------*/


char * print_keyClass( CK_ULONG keyClass )
{
    char * rv = NULL;

    switch ( keyClass )
    {
    case CKO_DATA :
	rv = "CKO_DATA";
	break;

    case CKO_CERTIFICATE :
	rv = "CKO_CERTIFICATE";
	break;

    case CKO_PUBLIC_KEY :
	rv = "CKO_PUBLIC_KEY";
	break;

    case CKO_PRIVATE_KEY :
	rv = "CKO_PRIVATE_KEY";
	break;

    case CKO_SECRET_KEY :
	rv = "CKO_SECRET_KEY";
	break;

    case CKO_HW_FEATURE :
	rv = "CKO_HW_FEATURE";
	break;

    case CKO_DOMAIN_PARAMETERS :
	rv = "CKO_DOMAIN_PARAMETERS";
	break;

    case CKO_MECHANISM :
	rv = "CKO_MECHANISM";
	break;
    }
    return rv;
}

CK_ULONG get_object_class(char *arg)
{
    CK_ULONG class = 0;

    if (strcasecmp(arg, "CKO_CERTIFICATE")==0) {
	class = CKO_CERTIFICATE;
    } else if (strcasecmp(arg, "CKO_PUBLIC_KEY")==0) {
	class = CKO_PUBLIC_KEY;
    } else if (strcasecmp(arg, "CKO_PRIVATE_KEY")==0) {
	class = CKO_PRIVATE_KEY;
    } else if (strcasecmp(arg, "CKO_SECRET_KEY")==0) {
	class = CKO_SECRET_KEY;
    }

    return class;
}


CK_ATTRIBUTE_TYPE get_attribute_type(char *arg)
{
    CK_ATTRIBUTE_TYPE attrtype = 0xFFFFFFFF;

    if (strcasecmp(arg, "CKA_ID")==0) {
	attrtype = CKA_ID;
    } else if (strcasecmp(arg, "CKA_LABEL")==0) {
	attrtype = CKA_LABEL;
    } else if (strcasecmp(arg, "CKA_WRAP")==0) {
	attrtype = CKA_WRAP;
    } else if (strcasecmp(arg, "CKA_UNWRAP")==0) {
	attrtype = CKA_UNWRAP;
    } else if (strcasecmp(arg, "CKA_ENCRYPT")==0) {
	attrtype = CKA_ENCRYPT;
    } else if (strcasecmp(arg, "CKA_DECRYPT")==0) {
	attrtype = CKA_DECRYPT;
    } else if (strcasecmp(arg, "CKA_SIGN")==0) {
	attrtype = CKA_SIGN;
    } else if (strcasecmp(arg, "CKA_VERIFY")==0) {
	attrtype = CKA_VERIFY;
    } else if (strcasecmp(arg, "CKA_SIGN_RECOVER")==0) {
	attrtype = CKA_SIGN_RECOVER;
    } else if (strcasecmp(arg, "CKA_VERIFY_RECOVER")==0) {
	attrtype = CKA_VERIFY_RECOVER;
    } else if (strcasecmp(arg, "CKA_DERIVE")==0) {
	attrtype = CKA_DERIVE;
    } else if (strcasecmp(arg, "CKA_TRUSTED")==0) {
	attrtype = CKA_TRUSTED;
    } else if (strcasecmp(arg, "CKA_WRAP_WITH_TRUSTED")==0) {
	attrtype = CKA_WRAP_WITH_TRUSTED;
    } else if (strcasecmp(arg, "CKA_MODIFIABLE")==0) {
	attrtype = CKA_MODIFIABLE;
    } else if (strcasecmp(arg, "CKA_EXTRACTABLE")==0) {
	attrtype = CKA_EXTRACTABLE;
    } else if (strcasecmp(arg, "CKA_SENSITIVE")==0) {
	attrtype = CKA_SENSITIVE;
	/* EC attributes */
    } else if (strcasecmp(arg, "CKA_EC_PARAMS")==0) {
	attrtype = CKA_EC_PARAMS;
    	/* NSS attributes */
    } else if (strcasecmp(arg, "CKA_TRUST_SERVER_AUTH")==0) {
	attrtype = CKA_TRUST_SERVER_AUTH;
    } else if (strcasecmp(arg, "CKA_TRUST_CLIENT_AUTH")==0) {
	attrtype = CKA_TRUST_CLIENT_AUTH;
    } else if (strcasecmp(arg, "CKA_TRUST_CODE_SIGNING")==0) {
	attrtype = CKA_TRUST_CODE_SIGNING;
    } else if (strcasecmp(arg, "CKA_TRUST_EMAIL_PROTECTION")==0) {
	attrtype = CKA_TRUST_EMAIL_PROTECTION;
    }

    return attrtype;
}


static CK_ATTRIBUTE_PTR new_attribute_for_bool(CK_ATTRIBUTE_TYPE argattrtype, CK_BBOOL argval)
{
    CK_ATTRIBUTE_PTR attr = NULL;

    attr = malloc ( sizeof ( CK_ATTRIBUTE ) );

    if ( attr != NULL ) {
	CK_BBOOL* boolptr = malloc ( sizeof ( CK_BBOOL ) );
	
	if ( boolptr != NULL ) {
	    *boolptr = argval;	/* copy the value we received */
	    attr->type = argattrtype;
	    attr->pValue = boolptr;
	    attr->ulValueLen = sizeof( CK_BBOOL );
	} else {
	    fprintf( stderr, "Error: lack of memory\n");
	    free( attr);
	}
    } else {
	fprintf( stderr, "Error: lack of memory\n");
    }

    return attr;
}

CK_ATTRIBUTE_PTR new_attribute_for_string(CK_ATTRIBUTE_TYPE argattrtype, char *arg)
{
    if(strchr(arg, '{' ) && strrchr(arg, '}')) {
	/* we have an hex string */
	return new_attribute_for_hex_string( argattrtype, arg);
    } else {
	return new_attribute_for_null_term_string( argattrtype, arg);
    }
}

CK_ATTRIBUTE_PTR new_attribute_for_null_term_string(CK_ATTRIBUTE_TYPE argattrtype, char *arg)
{
    CK_ATTRIBUTE_PTR attr = NULL;

    attr = calloc ( 1, sizeof ( CK_ATTRIBUTE ) );

    if ( attr != NULL ) {
	char *strptr = calloc ( strlen(arg)+1, sizeof (char) );
	
	if ( strptr != NULL ) {
	    strcpy(strptr, arg);

	    attr->type = argattrtype;
	    attr->pValue = strptr;
	    attr->ulValueLen = strlen(arg); /* we stop at character's end */
	} else {
	    fprintf( stderr, "Error: lack of memory\n");
	    free(attr);
	}
    } else {
	fprintf( stderr, "Error: lack of memory\n");
    }

    return attr;
}

CK_ATTRIBUTE_PTR new_attribute_for_hex_string(CK_ATTRIBUTE_TYPE argattrtype, char *arg)
{
    CK_ATTRIBUTE_PTR attr = NULL;

    attr = calloc ( 1, sizeof ( CK_ATTRIBUTE ) );

    if ( attr != NULL ) {
	size_t outsize=0;
	char *hexstr = hex2bin_new( arg, strlen(arg), &outsize);
	
	if ( hexstr != NULL ) {

	    char *dupstr = malloc(outsize);

	    if ( dupstr != NULL ) {
		memcpy(dupstr,hexstr,outsize);
                /* duplicate buffer */
		/* and assign it */
		attr->type = argattrtype;
		attr->pValue = dupstr;
		attr->ulValueLen = outsize;
	    } else {
		fprintf( stderr, "Error: lack of memory\n");
		free(attr);
	    }
	    hex2bin_free(hexstr);	       /* free buf in any case */
	    
	} else {
	    fprintf( stderr, "Error: lack of memory\n");
	    free(attr);
	}
    } else {
	fprintf( stderr, "Error: lack of memory\n");
    }

    return attr;
}


char * hex2bin_new(char *label, int size, size_t *outsize)
{

    char *pos, *initpos;
    char *tmpbuf=NULL, *tmpbuf_s=NULL;
    char *target;
    size_t len;
    int ws_cnt, i;


    /* since there can be decoration characters in the input string, */
    /* and since the resulting hex chars can be an odd number */
    /* we first pass to count decoration chars,  */
    /* then we allocate buffer and prepend with a '0' if odd, */
    /* then we copy significant characters. */

    /* #1: count the number of decoration chars in the string */
    /*     see regular expression definition in calling function */
    /*     for the definition of a decoration character */

    for (i=0, ws_cnt=0; i<size; i++) {
	if( !isxdigit(label[i]) ) {
	    /* TODO: check if we indeed have a decorator character */
	    /*       to detect hex strings containing other alphabet letters */
	    ws_cnt++; 
	}
    }

    /* #2: allocate tmpbuf with right size and prepend with a leading '0' if needed */
    len = (size-ws_cnt)+ ((size-ws_cnt)%2);
    tmpbuf = malloc(len);

    tmpbuf_s=tmpbuf;	

    if((size-ws_cnt)%2) {		/* odd length, we need to prepend with a '0' */
	*tmpbuf_s++='0';
    }

    /* #3: copy characters, but skip whitespaces */
    for (i=0; i<size; i++) {
	if( isxdigit(label[i]) ) { 
	    *tmpbuf_s++=label[i];
	}
    }

    /* #4: output buffer determination */
    *outsize = len >> 1;
    target = malloc( *outsize );
    
    /* #5: scan resulting set and conversion */
    for( initpos = pos = tmpbuf; *pos && (pos-initpos < len); ++pos) 
    {
	unsigned int x;
	if( !((pos-initpos)&1) ) {
	    /* because sscanf returns the value as an unsigned int, */
	    /* we must pass through type casting to avoid memory/stack overflow */
	    sscanf(pos,"%2x", &x);
	    target[(pos-initpos)>>1]= (unsigned char)x;
	}
    }

    if(tmpbuf) {
	free(tmpbuf);
    }

    return target;

}

void hex2bin_free(char *ptr)
{
    if(ptr) { 
	free(ptr);
    }
}

CK_ATTRIBUTE_PTR get_attribute_for_type_and_value(CK_ATTRIBUTE_TYPE argattrtype, char *arg )
{
    
    CK_ATTRIBUTE_PTR attr = NULL;

    
    switch(argattrtype) {
	
    case CKA_WRAP:
    case CKA_UNWRAP:
    case CKA_ENCRYPT:
    case CKA_DECRYPT:
    case CKA_SIGN:
    case CKA_VERIFY:
    case CKA_SIGN_RECOVER:
    case CKA_VERIFY_RECOVER:
    case CKA_DERIVE:
    case CKA_TRUSTED:
    case CKA_WRAP_WITH_TRUSTED:
    case CKA_MODIFIABLE:
    case CKA_EXTRACTABLE:
    case CKA_SENSITIVE:
	/* NSS-specific */
    case CKA_TRUST_SERVER_AUTH:     
    case CKA_TRUST_CLIENT_AUTH:     
    case CKA_TRUST_CODE_SIGNING:    
    case CKA_TRUST_EMAIL_PROTECTION:
    {	
	CK_BBOOL val;
	
	if ( strcasecmp(arg, "true")==0 ) {
	    val = CK_TRUE;
	    attr = new_attribute_for_bool( argattrtype, val);
	} else if ( strcasecmp(arg, "false")==0 ) {
	    val = CK_FALSE;
	    attr = new_attribute_for_bool( argattrtype, val);
	} else {
	    fprintf(stderr, "Error: value for boolean attribute must be either TRUE or FALSE\n");
	}
    }
    break;

    case CKA_ID:
    case CKA_LABEL:
	attr = new_attribute_for_string(argattrtype, arg);
	break;

    default:
	fprintf( stderr, "please specify an attribute type before giving a value");
    }

    return attr;
}


char * print_keyType( CK_ULONG keyType )
{
    switch( keyType )
    {
    case CKK_AES :
	return "CKK_AES";
    case CKK_DES :
	return "CKK_DES";
    case CKK_DES3 :
	return "CKK_DES3";
    case CKK_RSA :
	return "CKK_RSA";
    case CKK_GENERIC_SECRET :
	return "CKK_GENERIC_SECRET";
#ifdef CKK_SHA_1_HMAC
    case CKK_SHA_1_HMAC :
	return "CKK_SHA_1_HMAC";
#endif
    default :
	return "CKK_VENDOR_DEFINED";
    }
}



int get_attributes_from_argv( CK_ATTRIBUTE *attrs[] , int pos, int argc, char **argv)
{

    int i;
    char *cpy = NULL;
    int rv = 0;
    int cnt = 0;
    
 
    for (i=pos; i<argc; ++i) {
	char *a, *v;
	CK_ATTRIBUTE_TYPE typ;
	CK_ATTRIBUTE_PTR  val;

	if((cpy = malloc( strlen(argv[i]) + 1 )) == NULL ) {
	    fprintf(stderr,"Error: can't allocate memory\n");
	    goto err;
	}
	strcpy(cpy, argv[i]);
	
	a = strtok(cpy, ":=");
	if(a==NULL) {
	    fprintf(stderr, "Error: argument ""%s"" contains no separator ( : or = )\n", argv[i]);
	    goto err;
	}

	typ = get_attribute_type(a);
	if(typ==0xFFFFFFFF) {
	    fprintf(stderr, "Error: unknown attribute type ""%s""\n", a);
	    goto err;

	}
	
	v = strtok(NULL, ":=");
	
	if(v==NULL) {
	    fprintf(stderr, "Error: argument ""%s"" has no value\n", argv[i]);
	    goto err;
	}
	val = get_attribute_for_type_and_value(typ, v);

	if(val==NULL) {
	    fprintf(stderr, "Error: wrong attribute value ""%s""\n", v);
	    goto err;
	}
	
	release_attribute(val); val=NULL;
	free(cpy); cpy=NULL;
	
	cnt++;
    }


    /* now allocate array of attributes */
    if(cnt==0) {
	fprintf(stderr, "Error: no attribute-value pair argument specified\n");
	goto err;
    }

    *attrs = calloc( cnt, sizeof(CK_ATTRIBUTE) ); /* allocate from heap */

    if(*attrs == NULL) {
	fprintf(stderr, "Error: can't allocate memory\n");
	goto err;
    }


    for(i=pos; i<argc; i++) {
	char *a, *v;
	CK_ATTRIBUTE_PTR item;
	
	a = strtok(argv[i], ":=");
	v = strtok(NULL, ":=");
	
	item = 	get_attribute_for_type_and_value( get_attribute_type(a), v );
	memcpy( &((*attrs)[i-pos]), item, sizeof( CK_ATTRIBUTE ) );
	item->pValue=NULL;	/* caution! we have moved pValue to the array  */
	                        /* we must clear it from the initial structure */
	release_attribute(item); 
    }
    
    rv = cnt;

err:
    if(cpy) { free(cpy); cpy = NULL; }
    
    return rv;
}

void release_attribute( CK_ATTRIBUTE_PTR arg)
{
    if(arg) {
	if (arg->pValue) {
	    free(arg->pValue);
	}
	free(arg);
    }
}


void release_attributes(CK_ATTRIBUTE attrs[], size_t cnt)
{
    if(attrs) {
	int i;
	
	for(i=0; i<cnt; i++) {
	    CK_ATTRIBUTE_PTR item = &attrs[i];
	    if (item->pValue) {
		free(item->pValue);
	    }
	}
	
	free(attrs);		/* free table, eventually */
    }
}

func_rc prompt_for_hex(char *message, char *prompt, char *target, int len)
{
    func_rc rc = RC_OK;

    char *spacer  = "                                                                ";
    char *helper1 = "00                11                  22                  33    ";
    char *helper2 = "1122334455667788990011223344556677889900112233445566778899001122";

    char *buf=NULL, *pos;
    size_t buf_len=0;
    
    if(message && prompt && target &&  len>0) {

	int prompt_len = strlen(prompt);

	printf("%s\n\n%.*s%.*s\n%.*s%.*s\n%s ",
	       message,
	       prompt_len+1, spacer, len<<1, helper1, 
	       prompt_len+1, spacer, len<<1, helper2,
	       prompt);

	fflush(stdout);

	getline(&buf, &buf_len, stdin); /* buffer is allocated */
	
	pos = buf;
	while( *pos )
	{
	    unsigned int x;
	    if( !((pos-buf)&1) ) {
		if (((pos-buf)>>1) == len ) break;
		/* because sscanf returns the value as an unsigned int, */
		/* we must pass through type casting to avoid memory/stack overflow */
		sscanf(pos,"%02x", &x);
		target[(pos-buf)>>1]= (unsigned char)x;
	    }
	    ++pos;
	}
	
	if(buf) free(buf);
    }
    
    return rc;
}





#define MAXOF(x,y) ((x)>(y)) ? (x) : (y)
#define MINOF(x,y) ((x)<(y)) ? (x) : (y)

#define UNLABELLED_OBJECT "???unlabelled object???"

char * label_or_id(CK_ATTRIBUTE_PTR label, CK_ATTRIBUTE_PTR id, char *buffer, int buffer_len)
{
    if(label && label->ulValueLen>0) {	/* we have a label, let's use it */
	/* label is NEVER null terminated */
	/* we cannot use strncpy */
	memcpy( buffer, label->pValue,  MINOF(buffer_len-1,label->ulValueLen));
	buffer[ MINOF(buffer_len-1,label->ulValueLen) ] = 0; /* terminate the string */
    } else if(id && id->ulValueLen>0) { /* we have no label apparently */
	char *hexidptr = buffer;
	CK_BYTE_PTR idptr = id->pValue;
	CK_ULONG idcnt=0;

	*hexidptr++='i';
	*hexidptr++='d';
	*hexidptr++='/';
	*hexidptr++='{';
	idptr = (CK_BYTE_PTR)id->pValue;
	
	while(hexidptr-buffer<(buffer_len - 2) && idcnt<id->ulValueLen) {
	    sprintf(hexidptr,"%02.2x", idptr[idcnt++]);
	    hexidptr+=2;
	}		    
	*hexidptr++='}';
	*hexidptr='\0';
    } else {			/* no id or label */
	strncpy(buffer, UNLABELLED_OBJECT , MINOF(buffer_len-1, strlen(UNLABELLED_OBJECT)));
	buffer[ MINOF(buffer_len-1, strlen(UNLABELLED_OBJECT)) ] = 0; /* terminate string */
    }

    return buffer;
}


/*
 *--------------------------------------------------------------------------------
 * $Log$
 *--------------------------------------------------------------------------------
 */
