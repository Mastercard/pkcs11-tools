/* A Bison parser, made by GNU Bison 3.7.5.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
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

#ifndef YY_CL_CMDLINE_PARSER_H_INCLUDED
# define YY_CL_CMDLINE_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef CLDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define CLDEBUG 1
#  else
#   define CLDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define CLDEBUG 1
# endif /* ! defined YYDEBUG */
#endif  /* ! defined CLDEBUG */
#if CLDEBUG
extern int cldebug;
#endif
/* "%code requires" blocks.  */
#line 29 "cmdline_parser.y"


#include "pkcs11lib.h"
#include "cmdline_helper.h"

    //extern void clerror(CmdLineCtx *ctx, const char *s, ...);
    //extern int cllex(void);


#line 67 "cmdline_parser.h"

/* Token kinds.  */
#ifndef CLTOKENTYPE
# define CLTOKENTYPE
  enum cltokentype
  {
    CLEMPTY = -2,
    CLEOF = 0,                     /* "end of file"  */
    CLerror = 256,                 /* error  */
    CLUNDEF = 257,                 /* "invalid token"  */
    STRING = 258,                  /* STRING  */
    CKATTR_BOOL = 259,             /* CKATTR_BOOL  */
    CKATTR_STR = 260,              /* CKATTR_STR  */
    CKATTR_DATE = 261,             /* CKATTR_DATE  */
    CKATTR_KEY = 262,              /* CKATTR_KEY  */
    CKATTR_CLASS = 263,            /* CKATTR_CLASS  */
    CKATTR_TEMPLATE = 264,         /* CKATTR_TEMPLATE  */
    TOK_BOOLEAN = 265,             /* TOK_BOOLEAN  */
    TOK_DATE = 266,                /* TOK_DATE  */
    KEYTYPE = 267,                 /* KEYTYPE  */
    OCLASS = 268,                  /* OCLASS  */
    CURLY_OPEN = 269,              /* CURLY_OPEN  */
    CURLY_CLOSE = 270,             /* CURLY_CLOSE  */
    ASSIGN = 271                   /* ASSIGN  */
  };
  typedef enum cltokentype cltoken_kind_t;
#endif

/* Value type.  */
#if ! defined CLSTYPE && ! defined CLSTYPE_IS_DECLARED
union CLSTYPE
{
#line 51 "cmdline_parser.y"

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

#line 121 "cmdline_parser.h"

};
typedef union CLSTYPE CLSTYPE;
# define CLSTYPE_IS_TRIVIAL 1
# define CLSTYPE_IS_DECLARED 1
#endif


extern CLSTYPE cllval;

int clparse (CmdLineCtx *ctx);
/* "%code provides" blocks.  */
#line 39 "cmdline_parser.y"

#define YY_DECL int yylex(CmdLineCtx* ctx)

    YY_DECL;

    extern void clerror(CmdLineCtx *ctx, const char *s, ...);
    

#line 143 "cmdline_parser.h"

#endif /* !YY_CL_CMDLINE_PARSER_H_INCLUDED  */
