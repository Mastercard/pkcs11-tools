/* A Bison parser, made by GNU Bison 3.6.4.  */

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

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
#line 34 "wrappedkey_parser.y"


#include "pkcs11lib.h"
#include "wrappedkey_helper.h"

extern void yyerror(wrappedKeyCtx *ctx, const char *s, ...);
extern int yylex(void);


#line 59 "wrappedkey_parser.h"

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    OUTER = 258,                   /* OUTER  */
    INNER = 259,                   /* INNER  */
    STRING = 260,                  /* STRING  */
    CTYPE = 261,                   /* CTYPE  */
    CTYPE_VAL = 262,               /* CTYPE_VAL  */
    WRAPPING_ALG = 263,            /* WRAPPING_ALG  */
    WRAPPING_KEY = 264,            /* WRAPPING_KEY  */
    PKCS1ALGO = 265,               /* PKCS1ALGO  */
    OAEPALGO = 266,                /* OAEPALGO  */
    CBCPADALGO = 267,              /* CBCPADALGO  */
    RFC3394ALGO = 268,             /* RFC3394ALGO  */
    RFC5649ALGO = 269,             /* RFC5649ALGO  */
    ENVELOPEALGO = 270,            /* ENVELOPEALGO  */
    PARAMHASH = 271,               /* PARAMHASH  */
    HASHALG = 272,                 /* HASHALG  */
    PARAMMGF = 273,                /* PARAMMGF  */
    MGFTYPE = 274,                 /* MGFTYPE  */
    PARAMLABEL = 275,              /* PARAMLABEL  */
    PARAMIV = 276,                 /* PARAMIV  */
    PARAMFLAVOUR = 277,            /* PARAMFLAVOUR  */
    WRAPALG = 278,                 /* WRAPALG  */
    PARAMOUTER = 279,              /* PARAMOUTER  */
    PARAMINNER = 280,              /* PARAMINNER  */
    CKATTR_BOOL = 281,             /* CKATTR_BOOL  */
    CKATTR_STR = 282,              /* CKATTR_STR  */
    CKATTR_DATE = 283,             /* CKATTR_DATE  */
    CKATTR_KEY = 284,              /* CKATTR_KEY  */
    CKATTR_CLASS = 285,            /* CKATTR_CLASS  */
    TOK_BOOLEAN = 286,             /* TOK_BOOLEAN  */
    TOK_DATE = 287,                /* TOK_DATE  */
    KEYTYPE = 288,                 /* KEYTYPE  */
    OCLASS = 289,                  /* OCLASS  */
    DOTTEDNUMBER = 290             /* DOTTEDNUMBER  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 47 "wrappedkey_parser.y"

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

#line 141 "wrappedkey_parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (wrappedKeyCtx *ctx);

#endif /* !YY_YY_WRAPPEDKEY_PARSER_H_INCLUDED  */
