/*
 * Copyright (c) 2021 Mastercard
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

/* cmdline attributes parser */
%define api.prefix {cl}
%define parse.error verbose
%define parse.trace

%code top {
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
}

			
%code requires {

#include "pkcs11lib.h"
#include "cmdline_helper.h"

    //extern void clerror(CmdLineCtx *ctx, const char *s, ...);
    //extern int cllex(void);

}

%code provides {
#define YY_DECL int yylex(CmdLineCtx* ctx)

    YY_DECL;

    extern void clerror(CmdLineCtx *ctx, const char *s, ...);
    
}
			
%param { CmdLineCtx *ctx }


%union {
    CK_ATTRIBUTE_TYPE ckattr;
    CK_KEY_TYPE val_key;
    CK_OBJECT_CLASS val_cls;
    CK_BBOOL val_bool;

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
}

/* declare tokens */
%token <val_str> STRING

%token <ckattr> CKATTR_BOOL CKATTR_STR CKATTR_DATE CKATTR_KEY CKATTR_CLASS CKATTR_TEMPLATE
%token <val_bool> TOK_BOOLEAN
%token <val_date> TOK_DATE
%token <val_key>  KEYTYPE
%token <val_cls>  OCLASS
%token CURLY_OPEN CURLY_CLOSE ASSIGN

%%

/* cmdline is used to parse the command line
 * we artifically expect to have a front "#" character
 * so we know we are in this parsing job
 */

cmdlinestmts:	cmdlinestmt
	|	cmdlinestmts cmdlinestmt
	;

/* TODO separate */
cmdlinestmt:	CKATTR_TEMPLATE '=' CURLY_OPEN cmdlinestmts CURLY_CLOSE
		{
		    if(_cmdline_parser_assign_list_to_template(ctx, $1)!=rc_ok) {
			clerror(ctx, "Error during parsing, cannot assign attribute list to a template attribute.");
			YYERROR;
		    /* TODO work on parsing substatement */
			}
		}
	|	CKATTR_BOOL  '=' TOK_BOOLEAN
                {
		    if(_cmdline_parser_append_attr(ctx, $1, &$3, sizeof(CK_BBOOL) )!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
	|	CKATTR_STR '=' STRING
                {
		    if(_cmdline_parser_append_attr(ctx, $1, $3.val, $3.len)!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign bytes value.");
			YYERROR;
		    }
		    free($3.val); /* we must free() as the buffer was copied */
		}
	|	CKATTR_DATE '=' TOK_DATE
                {
		    if(_cmdline_parser_append_attr(ctx, $1, $3.as_buffer, sizeof(CK_DATE))!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
	|	CKATTR_DATE  '=' STRING /* if the date comes as 0x... format (not preferred but accepted) */
                {
		    if(_cmdline_parser_append_attr(ctx, $1, $3.val, $3.len)!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		    free($3.val); /* we must free() as the buffer was copied */
		}
	|	CKATTR_KEY   '=' KEYTYPE
                {
		    if(_cmdline_parser_append_attr(ctx, $1, &$3, sizeof(CK_KEY_TYPE))!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
	|	CKATTR_CLASS '=' OCLASS
                {
		    if(_cmdline_parser_append_attr(ctx, $1, &$3, sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
		;

%%	      
