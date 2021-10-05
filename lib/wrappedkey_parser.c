/* A Bison parser, made by GNU Bison 3.7.6.  */

/* Bison implementation for Yacc-like parsers in C

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
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30706

/* Bison version string.  */
#define YYBISON_VERSION "3.7.6"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* First part of user prologue.  */
#line 26 "wrappedkey_parser.y"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* parsing_envelope will remember if we are parsing inside envelope(...) */
int parsing_envelope= 0;

/* envelope_keyindex will remember, when parsing inside envelope, if we care about inner or outer alg */
int envelope_keyindex=0;


#line 84 "wrappedkey_parser.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
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
#line 39 "wrappedkey_parser.y"


#include "pkcs11lib.h"
#include "wrappedkey_helper.h"

extern void yyerror(wrappedKeyCtx *ctx, const char *s, ...);
extern int yylex(void);


#line 129 "wrappedkey_parser.c"

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
    PUBK = 260,                    /* PUBK  */
    STRING = 261,                  /* STRING  */
    CTYPE = 262,                   /* CTYPE  */
    GRAMMAR_VERSION = 263,         /* GRAMMAR_VERSION  */
    CTYPE_VAL = 264,               /* CTYPE_VAL  */
    WRAPPING_ALG = 265,            /* WRAPPING_ALG  */
    WRAPPING_KEY = 266,            /* WRAPPING_KEY  */
    PKCS1ALGO = 267,               /* PKCS1ALGO  */
    OAEPALGO = 268,                /* OAEPALGO  */
    CBCPADALGO = 269,              /* CBCPADALGO  */
    RFC3394ALGO = 270,             /* RFC3394ALGO  */
    RFC5649ALGO = 271,             /* RFC5649ALGO  */
    ENVELOPEALGO = 272,            /* ENVELOPEALGO  */
    PARAMHASH = 273,               /* PARAMHASH  */
    PARAMMGF = 274,                /* PARAMMGF  */
    MGFTYPE = 275,                 /* MGFTYPE  */
    PARAMLABEL = 276,              /* PARAMLABEL  */
    PARAMIV = 277,                 /* PARAMIV  */
    PARAMFLAVOUR = 278,            /* PARAMFLAVOUR  */
    PARAMOUTER = 279,              /* PARAMOUTER  */
    PARAMINNER = 280,              /* PARAMINNER  */
    CKATTR_BOOL = 281,             /* CKATTR_BOOL  */
    CKATTR_STR = 282,              /* CKATTR_STR  */
    CKATTR_DATE = 283,             /* CKATTR_DATE  */
    CKATTR_KEY = 284,              /* CKATTR_KEY  */
    CKATTR_CLASS = 285,            /* CKATTR_CLASS  */
    CKATTR_TEMPLATE = 286,         /* CKATTR_TEMPLATE  */
    CKATTR_ALLOWEDMECH = 287,      /* CKATTR_ALLOWEDMECH  */
    TOK_BOOLEAN = 288,             /* TOK_BOOLEAN  */
    TOK_DATE = 289,                /* TOK_DATE  */
    KEYTYPE = 290,                 /* KEYTYPE  */
    OCLASS = 291,                  /* OCLASS  */
    CKMECH = 292,                  /* CKMECH  */
    DOTTEDNUMBER = 293,            /* DOTTEDNUMBER  */
    WRAPPINGJOBHEADER = 294,       /* WRAPPINGJOBHEADER  */
    P_WRAPPINGKEY = 295,           /* P_WRAPPINGKEY  */
    P_FILENAME = 296,              /* P_FILENAME  */
    P_ALGORITHM = 297              /* P_ALGORITHM  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 52 "wrappedkey_parser.y"

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

#line 218 "wrappedkey_parser.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (wrappedKeyCtx *ctx);

#endif /* !YY_YY_WRAPPEDKEY_PARSER_H_INCLUDED  */
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_OUTER = 3,                      /* OUTER  */
  YYSYMBOL_INNER = 4,                      /* INNER  */
  YYSYMBOL_PUBK = 5,                       /* PUBK  */
  YYSYMBOL_STRING = 6,                     /* STRING  */
  YYSYMBOL_CTYPE = 7,                      /* CTYPE  */
  YYSYMBOL_GRAMMAR_VERSION = 8,            /* GRAMMAR_VERSION  */
  YYSYMBOL_CTYPE_VAL = 9,                  /* CTYPE_VAL  */
  YYSYMBOL_WRAPPING_ALG = 10,              /* WRAPPING_ALG  */
  YYSYMBOL_WRAPPING_KEY = 11,              /* WRAPPING_KEY  */
  YYSYMBOL_PKCS1ALGO = 12,                 /* PKCS1ALGO  */
  YYSYMBOL_OAEPALGO = 13,                  /* OAEPALGO  */
  YYSYMBOL_CBCPADALGO = 14,                /* CBCPADALGO  */
  YYSYMBOL_RFC3394ALGO = 15,               /* RFC3394ALGO  */
  YYSYMBOL_RFC5649ALGO = 16,               /* RFC5649ALGO  */
  YYSYMBOL_ENVELOPEALGO = 17,              /* ENVELOPEALGO  */
  YYSYMBOL_PARAMHASH = 18,                 /* PARAMHASH  */
  YYSYMBOL_PARAMMGF = 19,                  /* PARAMMGF  */
  YYSYMBOL_MGFTYPE = 20,                   /* MGFTYPE  */
  YYSYMBOL_PARAMLABEL = 21,                /* PARAMLABEL  */
  YYSYMBOL_PARAMIV = 22,                   /* PARAMIV  */
  YYSYMBOL_PARAMFLAVOUR = 23,              /* PARAMFLAVOUR  */
  YYSYMBOL_PARAMOUTER = 24,                /* PARAMOUTER  */
  YYSYMBOL_PARAMINNER = 25,                /* PARAMINNER  */
  YYSYMBOL_CKATTR_BOOL = 26,               /* CKATTR_BOOL  */
  YYSYMBOL_CKATTR_STR = 27,                /* CKATTR_STR  */
  YYSYMBOL_CKATTR_DATE = 28,               /* CKATTR_DATE  */
  YYSYMBOL_CKATTR_KEY = 29,                /* CKATTR_KEY  */
  YYSYMBOL_CKATTR_CLASS = 30,              /* CKATTR_CLASS  */
  YYSYMBOL_CKATTR_TEMPLATE = 31,           /* CKATTR_TEMPLATE  */
  YYSYMBOL_CKATTR_ALLOWEDMECH = 32,        /* CKATTR_ALLOWEDMECH  */
  YYSYMBOL_TOK_BOOLEAN = 33,               /* TOK_BOOLEAN  */
  YYSYMBOL_TOK_DATE = 34,                  /* TOK_DATE  */
  YYSYMBOL_KEYTYPE = 35,                   /* KEYTYPE  */
  YYSYMBOL_OCLASS = 36,                    /* OCLASS  */
  YYSYMBOL_CKMECH = 37,                    /* CKMECH  */
  YYSYMBOL_DOTTEDNUMBER = 38,              /* DOTTEDNUMBER  */
  YYSYMBOL_WRAPPINGJOBHEADER = 39,         /* WRAPPINGJOBHEADER  */
  YYSYMBOL_P_WRAPPINGKEY = 40,             /* P_WRAPPINGKEY  */
  YYSYMBOL_P_FILENAME = 41,                /* P_FILENAME  */
  YYSYMBOL_P_ALGORITHM = 42,               /* P_ALGORITHM  */
  YYSYMBOL_43_ = 43,                       /* ':'  */
  YYSYMBOL_44_ = 44,                       /* '{'  */
  YYSYMBOL_45_ = 45,                       /* '}'  */
  YYSYMBOL_46_ = 46,                       /* '/'  */
  YYSYMBOL_47_ = 47,                       /* '('  */
  YYSYMBOL_48_ = 48,                       /* ')'  */
  YYSYMBOL_49_ = 49,                       /* ','  */
  YYSYMBOL_50_ = 50,                       /* '='  */
  YYSYMBOL_YYACCEPT = 51,                  /* $accept  */
  YYSYMBOL_wkeyset = 52,                   /* wkeyset  */
  YYSYMBOL_headers = 53,                   /* headers  */
  YYSYMBOL_wkey = 54,                      /* wkey  */
  YYSYMBOL_wkeyblocks = 55,                /* wkeyblocks  */
  YYSYMBOL_innerblock = 56,                /* innerblock  */
  YYSYMBOL_outerblock = 57,                /* outerblock  */
  YYSYMBOL_wkeystmts = 58,                 /* wkeystmts  */
  YYSYMBOL_wkeystmt = 59,                  /* wkeystmt  */
  YYSYMBOL_metastmts = 60,                 /* metastmts  */
  YYSYMBOL_metastmt = 61,                  /* metastmt  */
  YYSYMBOL_assignstmts = 62,               /* assignstmts  */
  YYSYMBOL_assignstmt = 63,                /* assignstmt  */
  YYSYMBOL_64_1 = 64,                      /* $@1  */
  YYSYMBOL_mechanisms = 65,                /* mechanisms  */
  YYSYMBOL_mechanism = 66,                 /* mechanism  */
  YYSYMBOL_algo = 67,                      /* algo  */
  YYSYMBOL_pkcs1algo = 68,                 /* pkcs1algo  */
  YYSYMBOL_pkcs1algoheader = 69,           /* pkcs1algoheader  */
  YYSYMBOL_pkcs1algoid = 70,               /* pkcs1algoid  */
  YYSYMBOL_oaepalgo = 71,                  /* oaepalgo  */
  YYSYMBOL_oaepalgoheader = 72,            /* oaepalgoheader  */
  YYSYMBOL_oaepalgoid = 73,                /* oaepalgoid  */
  YYSYMBOL_oaepparamlist = 74,             /* oaepparamlist  */
  YYSYMBOL_oaepparam = 75,                 /* oaepparam  */
  YYSYMBOL_cbcpadalgo = 76,                /* cbcpadalgo  */
  YYSYMBOL_cbcpadalgoheader = 77,          /* cbcpadalgoheader  */
  YYSYMBOL_cbcpadalgoid = 78,              /* cbcpadalgoid  */
  YYSYMBOL_cbcpadparamlist = 79,           /* cbcpadparamlist  */
  YYSYMBOL_cbcpadparam = 80,               /* cbcpadparam  */
  YYSYMBOL_rfc3394algo = 81,               /* rfc3394algo  */
  YYSYMBOL_rfc3394algoheader = 82,         /* rfc3394algoheader  */
  YYSYMBOL_rfc3394algoid = 83,             /* rfc3394algoid  */
  YYSYMBOL_rfc5649algo = 84,               /* rfc5649algo  */
  YYSYMBOL_rfc5649algoheader = 85,         /* rfc5649algoheader  */
  YYSYMBOL_rfc5649algoid = 86,             /* rfc5649algoid  */
  YYSYMBOL_rfc5649paramlist = 87,          /* rfc5649paramlist  */
  YYSYMBOL_rfc5649param = 88,              /* rfc5649param  */
  YYSYMBOL_envelopealgo = 89,              /* envelopealgo  */
  YYSYMBOL_90_2 = 90,                      /* $@2  */
  YYSYMBOL_envelopealgoheader = 91,        /* envelopealgoheader  */
  YYSYMBOL_envelopealgoid = 92,            /* envelopealgoid  */
  YYSYMBOL_envelopeparamlist = 93,         /* envelopeparamlist  */
  YYSYMBOL_envelopeparam = 94,             /* envelopeparam  */
  YYSYMBOL_95_3 = 95,                      /* $@3  */
  YYSYMBOL_96_4 = 96,                      /* $@4  */
  YYSYMBOL_outeralgo = 97,                 /* outeralgo  */
  YYSYMBOL_inneralgo = 98,                 /* inneralgo  */
  YYSYMBOL_pubk = 99,                      /* pubk  */
  YYSYMBOL_pubkblock = 100,                /* pubkblock  */
  YYSYMBOL_pubkstmts = 101,                /* pubkstmts  */
  YYSYMBOL_pubkstmt = 102,                 /* pubkstmt  */
  YYSYMBOL_103_5 = 103,                    /* $@5  */
  YYSYMBOL_wrappingjob = 104,              /* wrappingjob  */
  YYSYMBOL_wrpjobstmts = 105,              /* wrpjobstmts  */
  YYSYMBOL_wrpjobstmt = 106                /* wrpjobstmt  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_uint8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if 1

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* 1 */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  14
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   197

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  51
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  56
/* YYNRULES -- Number of rules.  */
#define YYNRULES  112
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  203

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   297


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      47,    48,     2,     2,    49,     2,     2,    46,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    43,     2,
       2,    50,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    44,     2,    45,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   113,   113,   114,   115,   118,   119,   130,   133,   134,
     135,   138,   148,   158,   159,   162,   163,   166,   167,   170,
     171,   183,   184,   195,   196,   199,   206,   215,   222,   231,
     238,   246,   245,   276,   291,   292,   295,   307,   308,   309,
     310,   311,   312,   315,   318,   331,   332,   335,   336,   339,
     352,   353,   356,   357,   360,   367,   374,   385,   386,   390,
     403,   404,   408,   409,   412,   425,   426,   430,   443,   444,
     449,   450,   453,   466,   467,   470,   471,   474,   483,   485,
     484,   495,   508,   509,   512,   513,   517,   516,   522,   521,
     528,   529,   532,   533,   534,   539,   542,   552,   553,   557,
     564,   573,   580,   589,   596,   604,   603,   640,   643,   644,
     647,   656,   665
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if 1
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "OUTER", "INNER",
  "PUBK", "STRING", "CTYPE", "GRAMMAR_VERSION", "CTYPE_VAL",
  "WRAPPING_ALG", "WRAPPING_KEY", "PKCS1ALGO", "OAEPALGO", "CBCPADALGO",
  "RFC3394ALGO", "RFC5649ALGO", "ENVELOPEALGO", "PARAMHASH", "PARAMMGF",
  "MGFTYPE", "PARAMLABEL", "PARAMIV", "PARAMFLAVOUR", "PARAMOUTER",
  "PARAMINNER", "CKATTR_BOOL", "CKATTR_STR", "CKATTR_DATE", "CKATTR_KEY",
  "CKATTR_CLASS", "CKATTR_TEMPLATE", "CKATTR_ALLOWEDMECH", "TOK_BOOLEAN",
  "TOK_DATE", "KEYTYPE", "OCLASS", "CKMECH", "DOTTEDNUMBER",
  "WRAPPINGJOBHEADER", "P_WRAPPINGKEY", "P_FILENAME", "P_ALGORITHM", "':'",
  "'{'", "'}'", "'/'", "'('", "')'", "','", "'='", "$accept", "wkeyset",
  "headers", "wkey", "wkeyblocks", "innerblock", "outerblock", "wkeystmts",
  "wkeystmt", "metastmts", "metastmt", "assignstmts", "assignstmt", "$@1",
  "mechanisms", "mechanism", "algo", "pkcs1algo", "pkcs1algoheader",
  "pkcs1algoid", "oaepalgo", "oaepalgoheader", "oaepalgoid",
  "oaepparamlist", "oaepparam", "cbcpadalgo", "cbcpadalgoheader",
  "cbcpadalgoid", "cbcpadparamlist", "cbcpadparam", "rfc3394algo",
  "rfc3394algoheader", "rfc3394algoid", "rfc5649algo", "rfc5649algoheader",
  "rfc5649algoid", "rfc5649paramlist", "rfc5649param", "envelopealgo",
  "$@2", "envelopealgoheader", "envelopealgoid", "envelopeparamlist",
  "envelopeparam", "$@3", "$@4", "outeralgo", "inneralgo", "pubk",
  "pubkblock", "pubkstmts", "pubkstmt", "$@5", "wrappingjob",
  "wrpjobstmts", "wrpjobstmt", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,    58,   123,   125,    47,    40,    41,    44,
      61
};
#endif

#define YYPACT_NINF (-57)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
      -5,   -37,   -29,    23,    18,    29,   -57,    13,   -13,   -15,
      12,    59,    17,   -57,   -57,    67,    68,    69,    70,    71,
      72,    73,    74,    75,    77,    78,    55,     1,   -57,     9,
     -57,    48,   -57,   -57,   -57,   113,   116,    76,    23,   115,
      87,    76,   120,    94,   123,     4,    96,    97,    86,    88,
      91,    92,    93,    98,    99,   100,   -57,    16,   -57,   -57,
     -57,   -57,   134,   135,   -57,   -57,   -57,   -57,   -57,   101,
     102,   103,   104,   105,   106,   -57,   -57,   -57,   -57,   -57,
     107,   -57,   -57,   108,   -57,   -57,   109,   -57,   -57,   110,
     -57,   -57,   111,   -57,   -57,   -57,   -57,   -57,   -57,   -57,
     -57,   -57,   -57,   -57,   -57,   -57,   122,   112,   132,     7,
     118,   124,   117,   -57,   -57,   -57,   -57,   -57,   125,   126,
     127,   128,   129,   130,     5,   140,   121,   147,   -57,    48,
     -57,   -30,   -57,   -57,   -57,   -57,   -57,   -57,   -57,   -57,
     -57,   -57,   -57,   -57,   -57,   -57,    90,   131,   133,    49,
     -57,   136,    51,   -57,   -57,   137,    53,   -57,    79,    22,
     -57,   -57,    55,   138,   151,   166,   -57,     5,   167,   -57,
     140,   139,   -57,   147,   141,   142,    57,   -57,   -57,    42,
     -57,   -57,   -57,   -57,   -57,   -57,   -57,   -57,   -57,   -57,
     -57,    79,   -57,    95,    80,   -57,   -57,   -57,   -57,   -57,
     -57,   -57,   -57
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       0,     0,     0,     0,     0,     0,     4,     0,     0,     0,
       0,     0,   107,   108,     1,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     2,     0,    13,    15,
      17,    16,    23,     5,     6,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     3,     0,    97,    12,
      11,     7,     8,     0,    14,    18,    24,   110,   111,    45,
      50,    60,    68,    73,    82,   112,    37,    43,    44,    38,
      47,    49,    39,    57,    59,    40,    65,    67,    41,    70,
      72,    42,    78,    81,   109,    19,    20,    21,    22,    25,
      26,    28,    27,    29,    30,    31,     0,     0,     0,     0,
       0,     0,     0,    96,    95,    98,     9,    10,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    79,     0,
      36,     0,    34,    99,   100,   102,   101,   103,   104,   105,
      46,    51,    61,    69,    74,    83,     0,     0,     0,     0,
      52,     0,     0,    62,    66,     0,     0,    75,     0,     0,
      33,    35,     0,     0,     0,     0,    48,     0,     0,    58,
       0,     0,    71,     0,     0,     0,     0,    84,    32,     0,
      54,    55,    56,    53,    64,    63,    77,    76,    86,    88,
      80,     0,   106,     0,     0,    85,    90,    91,    87,    92,
      93,    94,    89
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -57,   -57,   -57,   -57,   -57,    81,    84,   -57,   150,   -57,
     145,    50,   -31,   -57,   -57,    47,   143,   -11,   -57,   -57,
      -8,   -57,   -57,   -57,    21,   -14,   -57,   -57,   -57,    19,
      -4,   -57,   -57,    -1,   -57,   -57,   -57,    24,   -57,   -57,
     -57,   -57,   -57,     3,   -57,   -57,   -57,   -57,   -57,   -57,
      33,   -56,   -57,   -57,   -57,   158
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,     4,     5,    26,    61,    62,    63,    27,    28,    29,
      30,    31,    32,   129,   131,   132,    75,    76,    77,    78,
      79,    80,    81,   149,   150,    82,    83,    84,   152,   153,
      85,    86,    87,    88,    89,    90,   156,   157,    91,   158,
      92,    93,   176,   177,   193,   194,   198,   202,    56,   114,
      57,    58,   162,     6,    12,    13
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
      66,   115,     1,     2,    59,    60,     7,   130,    15,    16,
     101,    17,    18,   135,     8,   160,    15,    16,    14,    17,
      18,   113,    33,   146,   147,    34,   148,    19,    20,    21,
      22,    23,    24,    25,     3,    35,    15,    16,   102,    17,
      18,   136,    50,    51,    52,    53,    54,    55,    19,    20,
      21,    22,    23,    24,    25,    19,    20,    21,    22,    23,
      24,    25,    36,     9,    10,    11,    38,   178,    50,    51,
      52,    53,    54,    55,    19,    20,    21,    22,    23,    24,
      25,    50,    51,    52,    53,    54,    55,   192,    69,    70,
      71,    72,    73,    74,    71,    72,    73,   166,   167,   169,
     170,   172,   173,   174,   175,   190,   191,    69,    70,    37,
      39,    40,    41,    42,    43,    44,    45,    46,    47,    67,
      48,    49,    68,   115,    95,    96,    98,    99,    66,   100,
     105,   103,   106,   104,   107,   108,   109,    59,   134,    60,
     163,   110,   111,   112,   117,   133,   116,   118,   119,   120,
     121,   122,   123,   137,   124,   125,   126,   127,   128,   130,
     138,   139,   151,   140,   141,   142,   143,   144,   145,   154,
     155,   181,   182,   184,    65,   180,   186,    64,   161,   159,
     199,   164,   196,   165,    97,   197,   168,   171,   183,   185,
     200,   188,   189,   201,   195,   179,    94,   187
};

static const yytype_uint8 yycheck[] =
{
      31,    57,     7,     8,     3,     4,    43,    37,     7,     8,
       6,    10,    11,     6,    43,    45,     7,     8,     0,    10,
      11,     5,     9,    18,    19,    38,    21,    26,    27,    28,
      29,    30,    31,    32,    39,    50,     7,     8,    34,    10,
      11,    34,    26,    27,    28,    29,    30,    31,    26,    27,
      28,    29,    30,    31,    32,    26,    27,    28,    29,    30,
      31,    32,    50,    40,    41,    42,    49,    45,    26,    27,
      28,    29,    30,    31,    26,    27,    28,    29,    30,    31,
      32,    26,    27,    28,    29,    30,    31,    45,    12,    13,
      14,    15,    16,    17,    14,    15,    16,    48,    49,    48,
      49,    48,    49,    24,    25,    48,    49,    12,    13,    50,
      43,    43,    43,    43,    43,    43,    43,    43,    43,     6,
      43,    43,     6,   179,     9,    38,     6,    33,   159,     6,
      44,    35,    44,    36,    43,    43,    43,     3,     6,     4,
      50,    43,    43,    43,    63,    33,    62,    46,    46,    46,
      46,    46,    46,    35,    47,    47,    47,    47,    47,    37,
      36,    44,    22,    38,    38,    38,    38,    38,    38,    48,
      23,    20,     6,     6,    29,    37,    37,    27,   131,   129,
     194,    50,   193,    50,    41,   193,    50,    50,   167,   170,
     194,    50,    50,   194,   191,   162,    38,   173
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     7,     8,    39,    52,    53,   104,    43,    43,    40,
      41,    42,   105,   106,     0,     7,     8,    10,    11,    26,
      27,    28,    29,    30,    31,    32,    54,    58,    59,    60,
      61,    62,    63,     9,    38,    50,    50,    50,    49,    43,
      43,    43,    43,    43,    43,    43,    43,    43,    43,    43,
      26,    27,    28,    29,    30,    31,    99,   101,   102,     3,
       4,    55,    56,    57,    59,    61,    63,     6,     6,    12,
      13,    14,    15,    16,    17,    67,    68,    69,    70,    71,
      72,    73,    76,    77,    78,    81,    82,    83,    84,    85,
      86,    89,    91,    92,   106,     9,    38,    67,     6,    33,
       6,     6,    34,    35,    36,    44,    44,    43,    43,    43,
      43,    43,    43,     5,   100,   102,    57,    56,    46,    46,
      46,    46,    46,    46,    47,    47,    47,    47,    47,    64,
      37,    65,    66,    33,     6,     6,    34,    35,    36,    44,
      38,    38,    38,    38,    38,    38,    18,    19,    21,    74,
      75,    22,    79,    80,    48,    23,    87,    88,    90,    62,
      45,    66,   103,    50,    50,    50,    48,    49,    50,    48,
      49,    50,    48,    49,    24,    25,    93,    94,    45,   101,
      37,    20,     6,    75,     6,    80,    37,    88,    50,    50,
      48,    49,    45,    95,    96,    94,    68,    71,    97,    76,
      81,    84,    98
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int8 yyr1[] =
{
       0,    51,    52,    52,    52,    53,    53,    54,    55,    55,
      55,    56,    57,    58,    58,    59,    59,    60,    60,    61,
      61,    61,    61,    62,    62,    63,    63,    63,    63,    63,
      63,    64,    63,    63,    65,    65,    66,    67,    67,    67,
      67,    67,    67,    68,    69,    70,    70,    71,    71,    72,
      73,    73,    74,    74,    75,    75,    75,    76,    76,    77,
      78,    78,    79,    79,    80,    81,    81,    82,    83,    83,
      84,    84,    85,    86,    86,    87,    87,    88,    89,    90,
      89,    91,    92,    92,    93,    93,    95,    94,    96,    94,
      97,    97,    98,    98,    98,    99,   100,   101,   101,   102,
     102,   102,   102,   102,   102,   103,   102,   104,   105,   105,
     106,   106,   106
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     2,     3,     1,     3,     3,     2,     1,     2,
       2,     1,     1,     1,     2,     1,     1,     1,     2,     3,
       3,     3,     3,     1,     2,     3,     3,     3,     3,     3,
       3,     0,     6,     5,     1,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     3,     1,     4,     1,
       1,     3,     1,     3,     3,     3,     3,     1,     4,     1,
       1,     3,     1,     3,     3,     1,     3,     1,     1,     3,
       1,     4,     1,     1,     3,     1,     3,     3,     1,     0,
       5,     1,     1,     3,     1,     3,     0,     4,     0,     4,
       1,     1,     1,     1,     1,     2,     1,     1,     2,     3,
       3,     3,     3,     3,     3,     0,     6,     2,     1,     3,
       3,     3,     3
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (ctx, YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
# ifndef YY_LOCATION_PRINT
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif


# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value, ctx); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, wrappedKeyCtx *ctx)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  YY_USE (ctx);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yykind < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yykind], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, wrappedKeyCtx *ctx)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep, ctx);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule, wrappedKeyCtx *ctx)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)], ctx);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, ctx); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


/* Context of a parse error.  */
typedef struct
{
  yy_state_t *yyssp;
  yysymbol_kind_t yytoken;
} yypcontext_t;

/* Put in YYARG at most YYARGN of the expected tokens given the
   current YYCTX, and return the number of tokens stored in YYARG.  If
   YYARG is null, return the number of expected tokens (guaranteed to
   be less than YYNTOKENS).  Return YYENOMEM on memory exhaustion.
   Return 0 if there are more than YYARGN expected tokens, yet fill
   YYARG up to YYARGN. */
static int
yypcontext_expected_tokens (const yypcontext_t *yyctx,
                            yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  int yyn = yypact[+*yyctx->yyssp];
  if (!yypact_value_is_default (yyn))
    {
      /* Start YYX at -YYN if negative to avoid negative indexes in
         YYCHECK.  In other words, skip the first -YYN actions for
         this state because they are default actions.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;
      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yyx;
      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
        if (yycheck[yyx + yyn] == yyx && yyx != YYSYMBOL_YYerror
            && !yytable_value_is_error (yytable[yyx + yyn]))
          {
            if (!yyarg)
              ++yycount;
            else if (yycount == yyargn)
              return 0;
            else
              yyarg[yycount++] = YY_CAST (yysymbol_kind_t, yyx);
          }
    }
  if (yyarg && yycount == 0 && 0 < yyargn)
    yyarg[0] = YYSYMBOL_YYEMPTY;
  return yycount;
}




#ifndef yystrlen
# if defined __GLIBC__ && defined _STRING_H
#  define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
# else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
# endif
#endif

#ifndef yystpcpy
# if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#  define yystpcpy stpcpy
# else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
# endif
#endif

#ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;
      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
#endif


static int
yy_syntax_error_arguments (const yypcontext_t *yyctx,
                           yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yyctx->yytoken != YYSYMBOL_YYEMPTY)
    {
      int yyn;
      if (yyarg)
        yyarg[yycount] = yyctx->yytoken;
      ++yycount;
      yyn = yypcontext_expected_tokens (yyctx,
                                        yyarg ? yyarg + 1 : yyarg, yyargn - 1);
      if (yyn == YYENOMEM)
        return YYENOMEM;
      else
        yycount += yyn;
    }
  return yycount;
}

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return -1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return YYENOMEM if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                const yypcontext_t *yyctx)
{
  enum { YYARGS_MAX = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  yysymbol_kind_t yyarg[YYARGS_MAX];
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* Actual size of YYARG. */
  int yycount = yy_syntax_error_arguments (yyctx, yyarg, YYARGS_MAX);
  if (yycount == YYENOMEM)
    return YYENOMEM;

  switch (yycount)
    {
#define YYCASE_(N, S)                       \
      case N:                               \
        yyformat = S;                       \
        break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
    }

  /* Compute error message size.  Don't count the "%s"s, but reserve
     room for the terminator.  */
  yysize = yystrlen (yyformat) - 2 * yycount + 1;
  {
    int yyi;
    for (yyi = 0; yyi < yycount; ++yyi)
      {
        YYPTRDIFF_T yysize1
          = yysize + yytnamerr (YY_NULLPTR, yytname[yyarg[yyi]]);
        if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
          yysize = yysize1;
        else
          return YYENOMEM;
      }
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return -1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yytname[yyarg[yyi++]]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep, wrappedKeyCtx *ctx)
{
  YY_USE (yyvaluep);
  YY_USE (ctx);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (wrappedKeyCtx *ctx)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 6: /* headers: GRAMMAR_VERSION ':' DOTTEDNUMBER  */
#line 120 "wrappedkey_parser.y"
                {
		    if(strcmp((yyvsp[0].val_dottednumber),SUPPORTED_GRAMMAR_VERSION)>0) {
			yyerror(ctx,"Grammar version (%s) not supported, max supported is %s please update pkcs11-tools\n", (yyvsp[0].val_dottednumber), SUPPORTED_GRAMMAR_VERSION);
			free((yyvsp[0].val_dottednumber));
			YYERROR;
		    }
		    free((yyvsp[0].val_dottednumber));
		}
#line 1743 "wrappedkey_parser.c"
    break;

  case 11: /* innerblock: INNER  */
#line 139 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_cryptogram(ctx, (yyvsp[0].val_pem), WRAPPEDKEYCTX_INNER_KEY_INDEX)!=rc_ok) {
			yyerror(ctx,"Error when parsing encrypted key cryptogram (inner)");
			YYERROR;
		    }
                    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1755 "wrappedkey_parser.c"
    break;

  case 12: /* outerblock: OUTER  */
#line 149 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_cryptogram(ctx, (yyvsp[0].val_pem), WRAPPEDKEYCTX_OUTER_KEY_INDEX)!=rc_ok) {
			yyerror(ctx,"Error when parsing encrypted key cryptogram (outer)");
			YYERROR;
		    }
                    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1767 "wrappedkey_parser.c"
    break;

  case 20: /* metastmt: GRAMMAR_VERSION ':' DOTTEDNUMBER  */
#line 172 "wrappedkey_parser.y"
                {
		    if(strcmp((yyvsp[0].val_dottednumber),SUPPORTED_GRAMMAR_VERSION)>0) {
			yyerror(ctx,
				"Grammar version %s not supported (highest supported version is %s)\n"
				"Please update pkcs11-tools\n",
				(yyvsp[0].val_dottednumber), SUPPORTED_GRAMMAR_VERSION);
			free((yyvsp[0].val_dottednumber));
			YYERROR;
		    }
		    free((yyvsp[0].val_dottednumber));
		}
#line 1783 "wrappedkey_parser.c"
    break;

  case 22: /* metastmt: WRAPPING_KEY ':' STRING  */
#line 185 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_key(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
		        yyerror(ctx,"Parsing error with wrapping key identifier.");
			free((yyvsp[0].val_str).val);
                        YYERROR;
                    }
                    free((yyvsp[0].val_str).val);
		}
#line 1796 "wrappedkey_parser.c"
    break;

  case 25: /* assignstmt: CKATTR_BOOL ':' TOK_BOOLEAN  */
#line 200 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_bool), sizeof(CK_BBOOL) )!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
#line 1807 "wrappedkey_parser.c"
    break;

  case 26: /* assignstmt: CKATTR_STR ':' STRING  */
#line 207 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign bytes value.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 1820 "wrappedkey_parser.c"
    break;

  case 27: /* assignstmt: CKATTR_DATE ':' TOK_DATE  */
#line 216 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_date).as_buffer, sizeof(CK_DATE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 1831 "wrappedkey_parser.c"
    break;

  case 28: /* assignstmt: CKATTR_DATE ':' STRING  */
#line 223 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 1844 "wrappedkey_parser.c"
    break;

  case 29: /* assignstmt: CKATTR_KEY ':' KEYTYPE  */
#line 232 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_key), sizeof(CK_KEY_TYPE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
#line 1855 "wrappedkey_parser.c"
    break;

  case 30: /* assignstmt: CKATTR_CLASS ':' OCLASS  */
#line 239 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_cls), sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
#line 1866 "wrappedkey_parser.c"
    break;

  case 31: /* $@1: %empty  */
#line 246 "wrappedkey_parser.y"
                {
		    if(ctx->wrpkattribs->level==1) {
			yyerror(ctx, "***Error: nesting templates not allowed");
			YYERROR;
		    }
                    ctx->wrpkattribs->level++; /*remind we are in a curly brace */
		    
		    ctx->wrpkattribs->current_idx = ctx->wrpkattribs->saved_idx + 1; /*increment current idx from ctx->saved_idx */
		    if(ctx->wrpkattribs->current_idx>=4) {
			/* There exist only 3 templates */
			yyerror(ctx, "***Error: too many templates specified");
			YYERROR;
                   } 		    
		}
#line 1885 "wrappedkey_parser.c"
    break;

  case 32: /* assignstmt: CKATTR_TEMPLATE ':' '{' $@1 assignstmts '}'  */
#line 261 "wrappedkey_parser.y"
                {
		    if(ctx->wrpkattribs->level==0) {
		        yyerror(ctx, "***Error: no matching opening curly brace");
			YYERROR;
                    }
                    ctx->wrpkattribs->level--; /*out of curly brace now */

		    ctx->wrpkattribs->saved_idx = ctx->wrpkattribs->current_idx; /* remember which index we used last */
		    ctx->wrpkattribs->current_idx = ctx->wrpkattribs->mainlist_idx; /* should be always 0 */

		    if(_wrappedkey_parser_wkey_assign_list_to_template(ctx, (yyvsp[-5].ckattr))!=rc_ok) {
			yyerror(ctx, "Error during parsing, cannot assign attribute list to a template attribute.");
			YYERROR;
		    }		    
		}
#line 1905 "wrappedkey_parser.c"
    break;

  case 33: /* assignstmt: CKATTR_ALLOWEDMECH ':' '{' mechanisms '}'  */
#line 277 "wrappedkey_parser.y"
                {
	            if( _wrappedkey_parser_wkey_append_attr( ctx,
							     (yyvsp[-4].ckattr),
							     pkcs11_wctx_get_allowed_mechanisms(ctx),
							     pkcs11_wctx_get_allowed_mechanisms_len(ctx))
			!= rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		    /* pointer stolen, we must forget it */		
		    pkcs11_wctx_forget_mechanisms(ctx);
		}
#line 1922 "wrappedkey_parser.c"
    break;

  case 36: /* mechanism: CKMECH  */
#line 296 "wrappedkey_parser.y"
                {
		    if( _wrappedkey_parser_add_mechanism(ctx, (yyvsp[0].val_mech))!=rc_ok) {
			yyerror(ctx, "Error during parsing, cannot assign mechanism to allowed mechanisms.");
			YYERROR;
		    }
		}
#line 1933 "wrappedkey_parser.c"
    break;

  case 44: /* pkcs1algoheader: pkcs1algoid  */
#line 319 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1945 "wrappedkey_parser.c"
    break;

  case 46: /* pkcs1algoid: PKCS1ALGO '/' DOTTEDNUMBER  */
#line 332 "wrappedkey_parser.y"
                                           { free((yyvsp[0].val_dottednumber)); }
#line 1951 "wrappedkey_parser.c"
    break;

  case 49: /* oaepalgoheader: oaepalgoid  */
#line 340 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1963 "wrappedkey_parser.c"
    break;

  case 51: /* oaepalgoid: OAEPALGO '/' DOTTEDNUMBER  */
#line 353 "wrappedkey_parser.y"
                                          { free((yyvsp[0].val_dottednumber)); }
#line 1969 "wrappedkey_parser.c"
    break;

  case 54: /* oaepparam: PARAMHASH '=' CKMECH  */
#line 361 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_hash(ctx, (yyvsp[0].val_mech))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1980 "wrappedkey_parser.c"
    break;

  case 55: /* oaepparam: PARAMMGF '=' MGFTYPE  */
#line 368 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_mgf(ctx, (yyvsp[0].val_mgf))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1991 "wrappedkey_parser.c"
    break;

  case 56: /* oaepparam: PARAMLABEL '=' STRING  */
#line 375 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_label(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
                        free((yyvsp[0].val_str).val);
			YYERROR;
		    }
                    free((yyvsp[0].val_str).val);
		}
#line 2004 "wrappedkey_parser.c"
    break;

  case 59: /* cbcpadalgoheader: cbcpadalgoid  */
#line 391 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 2016 "wrappedkey_parser.c"
    break;

  case 61: /* cbcpadalgoid: CBCPADALGO '/' DOTTEDNUMBER  */
#line 404 "wrappedkey_parser.y"
                                            { free((yyvsp[0].val_dottednumber)); }
#line 2022 "wrappedkey_parser.c"
    break;

  case 64: /* cbcpadparam: PARAMIV '=' STRING  */
#line 413 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_iv(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
                        free((yyvsp[0].val_str).val);
			YYERROR;
		    }
                    free((yyvsp[0].val_str).val);
		}
#line 2035 "wrappedkey_parser.c"
    break;

  case 67: /* rfc3394algoheader: rfc3394algoid  */
#line 431 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 2047 "wrappedkey_parser.c"
    break;

  case 69: /* rfc3394algoid: RFC3394ALGO '/' DOTTEDNUMBER  */
#line 444 "wrappedkey_parser.y"
                                             { free((yyvsp[0].val_dottednumber)); }
#line 2053 "wrappedkey_parser.c"
    break;

  case 72: /* rfc5649algoheader: rfc5649algoid  */
#line 454 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 2065 "wrappedkey_parser.c"
    break;

  case 74: /* rfc5649algoid: RFC5649ALGO '/' DOTTEDNUMBER  */
#line 467 "wrappedkey_parser.y"
                                             { free((yyvsp[0].val_dottednumber)); }
#line 2071 "wrappedkey_parser.c"
    break;

  case 77: /* rfc5649param: PARAMFLAVOUR '=' CKMECH  */
#line 475 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_flavour(ctx, (yyvsp[0].val_mech))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm flavour.");
			YYERROR;
		    }
		}
#line 2082 "wrappedkey_parser.c"
    break;

  case 79: /* $@2: %empty  */
#line 485 "wrappedkey_parser.y"
                {
		    if(++parsing_envelope>1) {
			yyerror(ctx, "Nested envelope() algorithm not allowed.");
			YYERROR;
		    }
		}
#line 2093 "wrappedkey_parser.c"
    break;

  case 80: /* envelopealgo: envelopealgoheader '(' $@2 envelopeparamlist ')'  */
#line 492 "wrappedkey_parser.y"
                    { --parsing_envelope; }
#line 2099 "wrappedkey_parser.c"
    break;

  case 81: /* envelopealgoheader: envelopealgoid  */
#line 496 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 2111 "wrappedkey_parser.c"
    break;

  case 83: /* envelopealgoid: ENVELOPEALGO '/' DOTTEDNUMBER  */
#line 509 "wrappedkey_parser.y"
                                              { free((yyvsp[0].val_dottednumber)); }
#line 2117 "wrappedkey_parser.c"
    break;

  case 86: /* $@3: %empty  */
#line 517 "wrappedkey_parser.y"
                {
		    envelope_keyindex = WRAPPEDKEYCTX_OUTER_KEY_INDEX;
		}
#line 2125 "wrappedkey_parser.c"
    break;

  case 88: /* $@4: %empty  */
#line 522 "wrappedkey_parser.y"
                {
		    envelope_keyindex = WRAPPEDKEYCTX_INNER_KEY_INDEX;
		}
#line 2133 "wrappedkey_parser.c"
    break;

  case 96: /* pubkblock: PUBK  */
#line 543 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_pem(ctx, (yyvsp[0].val_pem))!=rc_ok) {
			yyerror(ctx,"Error when parsing public key information");
			YYERROR;
		    }
                    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 2145 "wrappedkey_parser.c"
    break;

  case 99: /* pubkstmt: CKATTR_BOOL ':' TOK_BOOLEAN  */
#line 558 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_bool), sizeof(CK_BBOOL) )!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
#line 2156 "wrappedkey_parser.c"
    break;

  case 100: /* pubkstmt: CKATTR_STR ':' STRING  */
#line 565 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign bytes value.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 2169 "wrappedkey_parser.c"
    break;

  case 101: /* pubkstmt: CKATTR_DATE ':' TOK_DATE  */
#line 574 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_date).as_buffer, sizeof(CK_DATE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 2180 "wrappedkey_parser.c"
    break;

  case 102: /* pubkstmt: CKATTR_DATE ':' STRING  */
#line 581 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 2193 "wrappedkey_parser.c"
    break;

  case 103: /* pubkstmt: CKATTR_KEY ':' KEYTYPE  */
#line 590 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_key), sizeof(CK_KEY_TYPE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
#line 2204 "wrappedkey_parser.c"
    break;

  case 104: /* pubkstmt: CKATTR_CLASS ':' OCLASS  */
#line 597 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_cls), sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
#line 2215 "wrappedkey_parser.c"
    break;

  case 105: /* $@5: %empty  */
#line 604 "wrappedkey_parser.y"
                {
		    if(ctx->pubkattribs->level==1) {
			yyerror(ctx, "***Error: nesting templates not allowed");
			YYERROR;
		    }
                    ctx->pubkattribs->level++; /*remind we are in a curly brace */
		    
		    ctx->pubkattribs->current_idx = ctx->pubkattribs->saved_idx + 1; /*increment current idx from ctx->saved_idx */
		    if(ctx->pubkattribs->current_idx>=4) {
			/* There exist only 3 templates */
			yyerror(ctx, "***Error: too many templates specified");
			YYERROR;
                   } 		    
		}
#line 2234 "wrappedkey_parser.c"
    break;

  case 106: /* pubkstmt: CKATTR_TEMPLATE ':' '{' $@5 pubkstmts '}'  */
#line 619 "wrappedkey_parser.y"
                {
		    if(ctx->pubkattribs->level==0) {
		        yyerror(ctx, "***Error: no matching opening curly brace");
			YYERROR;
                    }
                    ctx->pubkattribs->level--; /*out of curly brace now */

		    ctx->pubkattribs->saved_idx = ctx->pubkattribs->current_idx; /* remember which index we used last */
		    ctx->pubkattribs->current_idx = ctx->pubkattribs->mainlist_idx; /* should be always 0 */

		    if(_wrappedkey_parser_pubk_assign_list_to_template(ctx, (yyvsp[-5].ckattr))!=rc_ok) {
			yyerror(ctx, "Error during parsing, cannot assign attribute list to a template attribute.");
			YYERROR;
		    }		    
		}
#line 2254 "wrappedkey_parser.c"
    break;

  case 110: /* wrpjobstmt: P_WRAPPINGKEY '=' STRING  */
#line 648 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_key(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
		        yyerror(ctx,"Parsing error with wrapping key identifier.");
			free((yyvsp[0].val_str).val);
                        YYERROR;
                    }
		    free((yyvsp[0].val_str).val);
		}
#line 2267 "wrappedkey_parser.c"
    break;

  case 111: /* wrpjobstmt: P_FILENAME '=' STRING  */
#line 657 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_filename(ctx, (yyvsp[0].val_str).val)!=rc_ok) {
		        yyerror(ctx,"Issue when saving filename");
			free((yyvsp[0].val_str).val);
                        YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
                }
#line 2280 "wrappedkey_parser.c"
    break;


#line 2284 "wrappedkey_parser.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      {
        yypcontext_t yyctx
          = {yyssp, yytoken};
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == -1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *,
                             YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (yymsg)
              {
                yysyntax_error_status
                  = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
                yymsgp = yymsg;
              }
            else
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = YYENOMEM;
              }
          }
        yyerror (ctx, yymsgp);
        if (yysyntax_error_status == YYENOMEM)
          goto yyexhaustedlab;
      }
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, ctx);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp, ctx);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if 1
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (ctx, YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturn;
#endif


/*-------------------------------------------------------.
| yyreturn -- parsing is finished, clean up and return.  |
`-------------------------------------------------------*/
yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, ctx);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp, ctx);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
  return yyresult;
}

#line 668 "wrappedkey_parser.y"

