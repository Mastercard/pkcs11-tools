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
/* %define lr.type canonical-lr */

%code top {
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
}

			
%code requires {
#include "pkcs11lib.h"
#include "cmdline_helper.h"
}

%code provides {
#define YY_DECL int yylex(cmdLineCtx* ctx)

YY_DECL;
extern void clerror(cmdLineCtx *ctx, const char *s, ...);
    
}
			
%param { cmdLineCtx *ctx }


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
%nonassoc NO
%token ASSIGN CURLY_OPEN CURLY_CLOSE			

%%

/* cmdline is used to parse the command line
 * we artifically expect to have a front "#" character
 * so we know we are in this parsing job
 */

statement:	expression
	|       statement expression
	;

expression:	simple_expr
	|	template_expr
	;

simple_expr:	CKATTR_BOOL ASSIGN TOK_BOOLEAN
                {
		    if(_cmdline_parser_append_attr(ctx, $1, &$3, sizeof(CK_BBOOL) )!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
	|	NO CKATTR_BOOL
                {
		    CK_BBOOL bfalse = CK_FALSE;
		    
		    if(_cmdline_parser_append_attr(ctx, $2, &bfalse, sizeof(CK_BBOOL) )!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}		
	|	CKATTR_BOOL
                {
		    CK_BBOOL btrue = CK_TRUE;
		    
		    if(_cmdline_parser_append_attr(ctx, $1, &btrue, sizeof(CK_BBOOL) )!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
	|	CKATTR_STR ASSIGN STRING
                {
		    if(_cmdline_parser_append_attr(ctx, $1, $3.val, $3.len)!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign bytes value.");
			YYERROR;
		    }
		    free($3.val); /* we must free() as the buffer was copied */
		}
	|	CKATTR_DATE ASSIGN TOK_DATE
                {
		    if(_cmdline_parser_append_attr(ctx, $1, $3.as_buffer, sizeof(CK_DATE))!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
	|	CKATTR_DATE  ASSIGN STRING /* if the date comes as 0x... format (not preferred but accepted) */
                {
		    if(_cmdline_parser_append_attr(ctx, $1, $3.val, $3.len)!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		    free($3.val); /* we must free() as the buffer was copied */
		}
	|	CKATTR_KEY ASSIGN KEYTYPE
                {
		    if(_cmdline_parser_append_attr(ctx, $1, &$3, sizeof(CK_KEY_TYPE))!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
	|	CKATTR_CLASS ASSIGN OCLASS
                {
		    if(_cmdline_parser_append_attr(ctx, $1, &$3, sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			clerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
		;

template_expr:	CKATTR_TEMPLATE ASSIGN CURLY_OPEN
		{
		    if(ctx->level==1) {
			clerror(ctx, "***Error: nesting templates not allowed");
			YYERROR;
		    }
                    ctx->level++; /*remind we are in a curly brace */
		    
		    ctx->current_idx = ctx->saved_idx + 1; /*increment current idx from ctx->saved_idx */
		    if(ctx->current_idx>=4) {
			clerror(ctx, "***Error: too many templates specified");
			YYERROR;
                   } 		    
		}
		statement CURLY_CLOSE
		{

		    if(ctx->level==0) {
		        clerror(ctx, "***Error: no matching opening curly brace");
			YYERROR;
                    }
                    ctx->level--; /*out of curly brace now */

		    ctx->saved_idx = ctx->current_idx; /* remember which index we used last */
		    ctx->current_idx = ctx->mainlist_idx; /* should be always 0 */

		    if(_cmdline_parser_assign_list_to_template(ctx, $1)!=rc_ok) {
			clerror(ctx, "Error during parsing, cannot assign attribute list to a template attribute.");
			YYERROR;
		    }		    
		}
	;

%%	      
