/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

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

#ifndef YY_YY_WRAPPEDKEY_PARSER_H_INCLUDED
# define YY_YY_WRAPPEDKEY_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
#line 40 "wrappedkey_parser.y" /* yacc.c:1909  */


#include "pkcs11lib.h"
#include "wrappedkey_helper.h"

extern void yyerror(wrappedKeyCtx *ctx, const char *s, ...);
extern int yylex(void);


#line 54 "wrappedkey_parser.h" /* yacc.c:1909  */

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    OUTER = 258,
    INNER = 259,
    PUBK = 260,
    STRING = 261,
    CTYPE = 262,
    GRAMMAR_VERSION = 263,
    CTYPE_VAL = 264,
    WRAPPING_ALG = 265,
    WRAPPING_KEY = 266,
    PKCS1ALGO = 267,
    OAEPALGO = 268,
    CBCPADALGO = 269,
    RFC3394ALGO = 270,
    RFC5649ALGO = 271,
    ENVELOPEALGO = 272,
    PARAMHASH = 273,
    PARAMMGF = 274,
    MGFTYPE = 275,
    PARAMLABEL = 276,
    PARAMIV = 277,
    PARAMFLAVOUR = 278,
    PARAMOUTER = 279,
    PARAMINNER = 280,
    CKATTR_BOOL = 281,
    CKATTR_STR = 282,
    CKATTR_DATE = 283,
    CKATTR_KEY = 284,
    CKATTR_CLASS = 285,
    CKATTR_TEMPLATE = 286,
    CKATTR_ALLOWEDMECH = 287,
    TOK_BOOLEAN = 288,
    TOK_DATE = 289,
    KEYTYPE = 290,
    OCLASS = 291,
    CKMECH = 292,
    DOTTEDNUMBER = 293,
    WRAPPINGJOBHEADER = 294,
    P_WRAPPINGKEY = 295,
    P_FILENAME = 296,
    P_ALGORITHM = 297
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 53 "wrappedkey_parser.y" /* yacc.c:1909  */

    CK_ATTRIBUTE_TYPE ckattr;
    CK_KEY_TYPE val_key;
    CK_OBJECT_CLASS val_cls;
    CK_BBOOL val_bool;
    CK_MECHANISM_TYPE val_mech;
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

    unsigned char *val_pem;	/* used to hold PEM-encoded blocks */
    char *val_dottednumber;

#line 139 "wrappedkey_parser.h" /* yacc.c:1909  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (wrappedKeyCtx *ctx);

#endif /* !YY_YY_WRAPPEDKEY_PARSER_H_INCLUDED  */
