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

/* wrapped key parser */
%define parse.error verbose
%define parse.trace

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* parsing_envelope will remember if we are parsing inside envelope(...) */
int parsing_envelope= 0;

/* envelope_keyindex will remember, when parsing inside envelope, if we care about inner or outer alg */
int envelope_keyindex=0;

%}

%code requires {

#include "pkcs11lib.h"
#include "wrappedkey_helper.h"

extern void yyerror(wrappedKeyCtx *ctx, const char *s, ...);
extern int yylex(void);

}

%parse-param { wrappedKeyCtx *ctx }


%union {
    CK_ATTRIBUTE_TYPE ckattr;
    CK_KEY_TYPE val_key;
    CK_OBJECT_CLASS val_cls;
    CK_BBOOL val_bool;
    CK_MECHANISM_TYPE val_hashalg;
    CK_RSA_PKCS_MGF_TYPE val_mgf;

    enum contenttype val_contenttype;
    enum wrappingmethod val_wrappingmethod;
    CK_MECHANISM_TYPE val_wrapalg;

    struct {			/* HEX encoded - or real string */
	char *val;
	size_t len;
	} val_str;

    union {
	struct {
	    char year[4];
	    char month[2];
	    char day[2];
	} as_ck_date;
        char as_buffer[8];
    } val_date;

    unsigned char *val_wrapped_key;
    char *val_dottednumber;
}

/* declare tokens */
%token <val_wrapped_key> OUTER INNER
%type  <val_wrapped_key> outerblock innerblock
%token <val_str> STRING
%token CTYPE
%token <val_contenttype> CTYPE_VAL
%token WRAPPING_ALG
%token WRAPPING_KEY
%token <val_wrappingmethod> PKCS1ALGO OAEPALGO CBCPADALGO RFC3394ALGO RFC5649ALGO ENVELOPEALGO
%type  <val_wrappingmethod> pkcs1algoid oaepalgoid cbcpadalgoid rfc3394algoid rfc5649algoid envelopealgoid
%token PARAMHASH
%token <val_hashalg> HASHALG
%token PARAMMGF
%token <val_mgf> MGFTYPE
%token PARAMLABEL
%token PARAMIV
%token PARAMFLAVOUR
%token <val_wrapalg> WRAPALG
%token PARAMOUTER
%token PARAMINNER

%token	<ckattr> CKATTR_BOOL CKATTR_STR CKATTR_DATE CKATTR_KEY CKATTR_CLASS
%token	<val_bool> TOK_BOOLEAN
%token	<val_date> TOK_DATE
%token	<val_key>  KEYTYPE
%token	<val_cls>  OCLASS
%token	<val_dottednumber> DOTTEDNUMBER

%%

wkey:	|	assignlist blocks
	|     	algo		/*TRICK: this is to parse command-line argument for p11wrap -a parameter */
		;

blocks:		innerblock
	|	innerblock outerblock
	|	outerblock innerblock
	;
innerblock:	INNER
		{
		    if(_wrappedkey_parser_append_cryptogram(ctx, $1, WRAPPEDKEYCTX_INNER_KEY_INDEX)!=rc_ok) {
			yyerror(ctx,"Error when parsing encrypted key cryptogram (inner)");
			YYERROR;
		    }
                    free($1);	/* free up mem */
		}
                ;

outerblock:	OUTER
		{
		    if(_wrappedkey_parser_append_cryptogram(ctx, $1, WRAPPEDKEYCTX_OUTER_KEY_INDEX)!=rc_ok) {
			yyerror(ctx,"Error when parsing encrypted key cryptogram (outer)");
			YYERROR;
		    }
                    free($1);	/* free up mem */
		}
                ;

assignlist: 			/*nothing, as assignlist can be empty*/
		| assignlist assignblk
		;

assignblk:	CTYPE ':' CTYPE_VAL
		| WRAPPING_ALG ':' algo /*algo or algo with param, see below */
		| WRAPPING_KEY ':' STRING /* for the time being, we capture just a key label */
		{
		    if(_wrappedkey_parser_set_wrapping_key(ctx, $3.val, $3.len)!=rc_ok) {
		        yyerror(ctx,"Parsing error with wrapping key identifier.");
                        YYERROR;
                    }
		}
		| CKATTR_BOOL  ':' TOK_BOOLEAN
                {
		    if(_wrappedkey_parser_append_attr(ctx, $1, &$3, sizeof(CK_BBOOL) )!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
		| CKATTR_STR ':' STRING
                {
		    if(_wrappedkey_parser_append_attr(ctx, $1, $3.val, $3.len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign bytes value.");
			YYERROR;
		    }
		}
		| CKATTR_DATE ':' TOK_DATE
                {
		    if(_wrappedkey_parser_append_attr(ctx, $1, $3.as_buffer, sizeof(CK_DATE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
		| CKATTR_DATE  ':' STRING /* if the date comes as 0x... format (not preferred but accepted) */
                {
		    if(_wrappedkey_parser_append_attr(ctx, $1, $3.val, $3.len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
		| CKATTR_KEY   ':' KEYTYPE
                {
		    if(_wrappedkey_parser_append_attr(ctx, $1, &$3, sizeof(CK_KEY_TYPE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
		| CKATTR_CLASS ':' OCLASS
                {
		    if(_wrappedkey_parser_append_attr(ctx, $1, &$3, sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
		;

/* we support these wrapping algorithms so far. */
/* algorithms themselves are tokenized separately to allow parameter check against requested algorithm */
algo:		pkcs1algo
		| oaepalgo
		| cbcpadalgo
                | rfc3394algo
                | rfc5649algo
                | envelopealgo
		;

pkcs1algo:	pkcs1algoheader
		;

pkcs1algoheader: pkcs1algoid
		{
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_set_wrapping_alg(ctx, $1, keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
		;

/* two syntax are supported */
/* TODO: check DOTTEDNUMBER to see if we agree with version     */
/* there should be at least a warning if version is beyond supported one  */
pkcs1algoid:	PKCS1ALGO
	|	PKCS1ALGO '/' DOTTEDNUMBER
		;

oaepalgo:	oaepalgoheader	/*take default parameters: all SHA1, label="" */
	|	oaepalgoheader '(' oaepparamlist ')'
		;

oaepalgoheader:	oaepalgoid
		{
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_set_wrapping_alg(ctx, $1, keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
		;

/* two syntax are supported */
/* TODO: check DOTTEDNUMBER to see if we agree with version     */
/* there should be at least a warning if version is beyond supported one  */
oaepalgoid:	OAEPALGO
	|	OAEPALGO '/' DOTTEDNUMBER
		;

oaepparamlist:	oaepparam
	|	oaepparamlist ',' oaepparam
		;

oaepparam:	PARAMHASH '=' HASHALG
		{
		    if(_wrappedkey_parser_set_wrapping_param_hash(ctx, $3)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
	|	PARAMMGF '=' MGFTYPE
		{
		    if(_wrappedkey_parser_set_wrapping_param_mgf(ctx, $3)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
	|	PARAMLABEL '=' STRING
		{
		    if(_wrappedkey_parser_set_wrapping_param_label(ctx, $3.val, $3.len)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
		;

cbcpadalgo:	cbcpadalgoheader
       |	cbcpadalgoheader '(' cbcpadparamlist ')'
		;


cbcpadalgoheader: cbcpadalgoid
		{
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_set_wrapping_alg(ctx, $1, keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
		;

/* two syntax are supported */
/* TODO: check DOTTEDNUMBER to see if we agree with version     */
/* there should be at least a warning if version is beyond supported one  */
cbcpadalgoid:	CBCPADALGO
	|	CBCPADALGO '/' DOTTEDNUMBER
		;


cbcpadparamlist: cbcpadparam
	|	 cbcpadparamlist ',' cbcpadparam
		;

cbcpadparam:	PARAMIV '=' STRING
		{
		    if(_wrappedkey_parser_set_wrapping_param_iv(ctx, $3.val, $3.len)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
	        ;

/* RFC3394: using CKM_AES_KEY_WRAP */

rfc3394algo:	rfc3394algoheader
       |	rfc3394algoheader '(' ')'
		;


rfc3394algoheader: rfc3394algoid
		{
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_set_wrapping_alg(ctx, $1, keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
		;

/* two syntax are supported */
/* TODO: check DOTTEDNUMBER to see if we agree with version     */
/* there should be at least a warning if version is beyond supported one  */
rfc3394algoid:	RFC3394ALGO
	|	RFC3394ALGO '/' DOTTEDNUMBER
		;

/* RFC5649: using CKM_AES_KEY_WRAP_PAD */

rfc5649algo:	rfc5649algoheader
       |	rfc5649algoheader '(' rfc5649paramlist ')'
		;

rfc5649algoheader: rfc5649algoid
		{
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_set_wrapping_alg(ctx, $1, keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
		;

/* two syntax are supported */
/* TODO: check DOTTEDNUMBER to see if we agree with version     */
/* there should be at least a warning if version is beyond supported one  */
rfc5649algoid:	RFC5649ALGO
	|	RFC5649ALGO '/' DOTTEDNUMBER
		;

rfc5649paramlist: rfc5649param
	|	  rfc5649paramlist ',' rfc5649param
		;

rfc5649param:   PARAMFLAVOUR '=' WRAPALG
		{
		    if(_wrappedkey_parser_set_wrapping_param_flavour(ctx, $3)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm flavour.");
			YYERROR;
		    }
		}
	        ;
/* envelope(): to support double wrapping */
envelopealgo:	envelopealgoheader	/*take default parameters: all SHA1, label="" */
	|	envelopealgoheader '('
                {
		    if(++parsing_envelope>1) {
			yyerror(ctx, "Nested envelope() algorithm not allowed.");
			YYERROR;
		    }
		}
		envelopeparamlist
		')' { --parsing_envelope; }
		;

envelopealgoheader:	envelopealgoid
		{
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_set_wrapping_alg(ctx, $1, keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
		;

/* two syntax are supported */
/* TODO: check DOTTEDNUMBER to see if we agree with version     */
/* there should be at least a warning if version is beyond supported one  */
envelopealgoid:	ENVELOPEALGO
	|	ENVELOPEALGO '/' DOTTEDNUMBER
		;

envelopeparamlist:	envelopeparam
	|	envelopeparamlist ',' envelopeparam
		;

envelopeparam:	PARAMOUTER '='
		{
		    envelope_keyindex = WRAPPEDKEYCTX_OUTER_KEY_INDEX;
		}
		outeralgo
	|	PARAMINNER '='
		{
		    envelope_keyindex = WRAPPEDKEYCTX_INNER_KEY_INDEX;
		}
		inneralgo
        	;

outeralgo:      pkcs1algo
	|     	oaepalgo
		;

inneralgo: 	cbcpadalgo
	|       rfc3394algo
        |       rfc5649algo
		;

%%
