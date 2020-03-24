/* A Bison parser, made by GNU Bison 3.5.3.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

#ifndef YY_YY_WRAPPEDKEY_PARSER_H_INCLUDED
# define YY_YY_WRAPPEDKEY_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 1
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
#line 29 "wrappedkey_parser.y"


#include "pkcs11lib.h"
#include "wrappedkey_helper.h"

extern void yyerror(wrappedKeyCtx *ctx, const char *s, ...);
extern int yylex(void);


#line 58 "wrappedkey_parser.h"

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    PKCSBLOCK = 258,
    STRING = 259,
    CTYPE = 260,
    CTYPE_VAL = 261,
    WRAPPING_ALG = 262,
    WRAPPING_KEY = 263,
    PKCS1ALGO = 264,
    OAEPALGO = 265,
    CBCPADALGO = 266,
    RFC3394ALGO = 267,
    RFC5649ALGO = 268,
    PARAMHASH = 269,
    HASHALG = 270,
    PARAMMGF = 271,
    MGFTYPE = 272,
    PARAMLABEL = 273,
    PARAMIV = 274,
    CKATTR_BOOL = 275,
    CKATTR_STR = 276,
    CKATTR_DATE = 277,
    CKATTR_KEY = 278,
    CKATTR_CLASS = 279,
    TOK_BOOLEAN = 280,
    TOK_DATE = 281,
    KEYTYPE = 282,
    OCLASS = 283,
    DOTTEDNUMBER = 284
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 42 "wrappedkey_parser.y"

    CK_ATTRIBUTE_TYPE ckattr;
    CK_KEY_TYPE val_key;
    CK_OBJECT_CLASS val_cls;
    CK_BBOOL val_bool;
    CK_MECHANISM_TYPE val_hashalg;
    CK_RSA_PKCS_MGF_TYPE val_mgf;

    enum contenttype val_contenttype;
    enum wrappingmethod val_wrappingmethod;

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

    unsigned char *pkcs;
    char *val_dottednumber;

#line 128 "wrappedkey_parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (wrappedKeyCtx *ctx);

#endif /* !YY_YY_WRAPPEDKEY_PARSER_H_INCLUDED  */
