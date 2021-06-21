/* A Bison parser, made by GNU Bison 3.7.5.  */

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
#define YYBISON 30705

/* Bison version string.  */
#define YYBISON_VERSION "3.7.5"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* First part of user prologue.  */
#line 21 "wrappedkey_parser.y"

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
    HASHALG = 274,                 /* HASHALG  */
    PARAMMGF = 275,                /* PARAMMGF  */
    MGFTYPE = 276,                 /* MGFTYPE  */
    PARAMLABEL = 277,              /* PARAMLABEL  */
    PARAMIV = 278,                 /* PARAMIV  */
    PARAMFLAVOUR = 279,            /* PARAMFLAVOUR  */
    WRAPALG = 280,                 /* WRAPALG  */
    PARAMOUTER = 281,              /* PARAMOUTER  */
    PARAMINNER = 282,              /* PARAMINNER  */
    CKATTR_BOOL = 283,             /* CKATTR_BOOL  */
    CKATTR_STR = 284,              /* CKATTR_STR  */
    CKATTR_DATE = 285,             /* CKATTR_DATE  */
    CKATTR_KEY = 286,              /* CKATTR_KEY  */
    CKATTR_CLASS = 287,            /* CKATTR_CLASS  */
    TOK_BOOLEAN = 288,             /* TOK_BOOLEAN  */
    TOK_DATE = 289,                /* TOK_DATE  */
    KEYTYPE = 290,                 /* KEYTYPE  */
    OCLASS = 291,                  /* OCLASS  */
    DOTTEDNUMBER = 292,            /* DOTTEDNUMBER  */
    WRAPPINGJOBHEADER = 293,       /* WRAPPINGJOBHEADER  */
    P_WRAPPINGKEY = 294,           /* P_WRAPPINGKEY  */
    P_FILENAME = 295,              /* P_FILENAME  */
    P_ALGORITHM = 296              /* P_ALGORITHM  */
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

    unsigned char *val_pem;	/* used to hold PEM-encoded blocks */
    char *val_dottednumber;

#line 217 "wrappedkey_parser.c"

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
  YYSYMBOL_HASHALG = 19,                   /* HASHALG  */
  YYSYMBOL_PARAMMGF = 20,                  /* PARAMMGF  */
  YYSYMBOL_MGFTYPE = 21,                   /* MGFTYPE  */
  YYSYMBOL_PARAMLABEL = 22,                /* PARAMLABEL  */
  YYSYMBOL_PARAMIV = 23,                   /* PARAMIV  */
  YYSYMBOL_PARAMFLAVOUR = 24,              /* PARAMFLAVOUR  */
  YYSYMBOL_WRAPALG = 25,                   /* WRAPALG  */
  YYSYMBOL_PARAMOUTER = 26,                /* PARAMOUTER  */
  YYSYMBOL_PARAMINNER = 27,                /* PARAMINNER  */
  YYSYMBOL_CKATTR_BOOL = 28,               /* CKATTR_BOOL  */
  YYSYMBOL_CKATTR_STR = 29,                /* CKATTR_STR  */
  YYSYMBOL_CKATTR_DATE = 30,               /* CKATTR_DATE  */
  YYSYMBOL_CKATTR_KEY = 31,                /* CKATTR_KEY  */
  YYSYMBOL_CKATTR_CLASS = 32,              /* CKATTR_CLASS  */
  YYSYMBOL_TOK_BOOLEAN = 33,               /* TOK_BOOLEAN  */
  YYSYMBOL_TOK_DATE = 34,                  /* TOK_DATE  */
  YYSYMBOL_KEYTYPE = 35,                   /* KEYTYPE  */
  YYSYMBOL_OCLASS = 36,                    /* OCLASS  */
  YYSYMBOL_DOTTEDNUMBER = 37,              /* DOTTEDNUMBER  */
  YYSYMBOL_WRAPPINGJOBHEADER = 38,         /* WRAPPINGJOBHEADER  */
  YYSYMBOL_P_WRAPPINGKEY = 39,             /* P_WRAPPINGKEY  */
  YYSYMBOL_P_FILENAME = 40,                /* P_FILENAME  */
  YYSYMBOL_P_ALGORITHM = 41,               /* P_ALGORITHM  */
  YYSYMBOL_42_ = 42,                       /* ':'  */
  YYSYMBOL_43_ = 43,                       /* '/'  */
  YYSYMBOL_44_ = 44,                       /* '('  */
  YYSYMBOL_45_ = 45,                       /* ')'  */
  YYSYMBOL_46_ = 46,                       /* ','  */
  YYSYMBOL_47_ = 47,                       /* '='  */
  YYSYMBOL_YYACCEPT = 48,                  /* $accept  */
  YYSYMBOL_wkeyset = 49,                   /* wkeyset  */
  YYSYMBOL_headers = 50,                   /* headers  */
  YYSYMBOL_wkey = 51,                      /* wkey  */
  YYSYMBOL_wkeyblocks = 52,                /* wkeyblocks  */
  YYSYMBOL_innerblock = 53,                /* innerblock  */
  YYSYMBOL_outerblock = 54,                /* outerblock  */
  YYSYMBOL_wkeymeta = 55,                  /* wkeymeta  */
  YYSYMBOL_wkeystmt = 56,                  /* wkeystmt  */
  YYSYMBOL_algo = 57,                      /* algo  */
  YYSYMBOL_pkcs1algo = 58,                 /* pkcs1algo  */
  YYSYMBOL_pkcs1algoheader = 59,           /* pkcs1algoheader  */
  YYSYMBOL_pkcs1algoid = 60,               /* pkcs1algoid  */
  YYSYMBOL_oaepalgo = 61,                  /* oaepalgo  */
  YYSYMBOL_oaepalgoheader = 62,            /* oaepalgoheader  */
  YYSYMBOL_oaepalgoid = 63,                /* oaepalgoid  */
  YYSYMBOL_oaepparamlist = 64,             /* oaepparamlist  */
  YYSYMBOL_oaepparam = 65,                 /* oaepparam  */
  YYSYMBOL_cbcpadalgo = 66,                /* cbcpadalgo  */
  YYSYMBOL_cbcpadalgoheader = 67,          /* cbcpadalgoheader  */
  YYSYMBOL_cbcpadalgoid = 68,              /* cbcpadalgoid  */
  YYSYMBOL_cbcpadparamlist = 69,           /* cbcpadparamlist  */
  YYSYMBOL_cbcpadparam = 70,               /* cbcpadparam  */
  YYSYMBOL_rfc3394algo = 71,               /* rfc3394algo  */
  YYSYMBOL_rfc3394algoheader = 72,         /* rfc3394algoheader  */
  YYSYMBOL_rfc3394algoid = 73,             /* rfc3394algoid  */
  YYSYMBOL_rfc5649algo = 74,               /* rfc5649algo  */
  YYSYMBOL_rfc5649algoheader = 75,         /* rfc5649algoheader  */
  YYSYMBOL_rfc5649algoid = 76,             /* rfc5649algoid  */
  YYSYMBOL_rfc5649paramlist = 77,          /* rfc5649paramlist  */
  YYSYMBOL_rfc5649param = 78,              /* rfc5649param  */
  YYSYMBOL_envelopealgo = 79,              /* envelopealgo  */
  YYSYMBOL_80_1 = 80,                      /* $@1  */
  YYSYMBOL_envelopealgoheader = 81,        /* envelopealgoheader  */
  YYSYMBOL_envelopealgoid = 82,            /* envelopealgoid  */
  YYSYMBOL_envelopeparamlist = 83,         /* envelopeparamlist  */
  YYSYMBOL_envelopeparam = 84,             /* envelopeparam  */
  YYSYMBOL_85_2 = 85,                      /* $@2  */
  YYSYMBOL_86_3 = 86,                      /* $@3  */
  YYSYMBOL_outeralgo = 87,                 /* outeralgo  */
  YYSYMBOL_inneralgo = 88,                 /* inneralgo  */
  YYSYMBOL_pubk = 89,                      /* pubk  */
  YYSYMBOL_pubkblock = 90,                 /* pubkblock  */
  YYSYMBOL_pubkmeta = 91,                  /* pubkmeta  */
  YYSYMBOL_pubkstmt = 92,                  /* pubkstmt  */
  YYSYMBOL_wrappingjob = 93,               /* wrappingjob  */
  YYSYMBOL_wrpjobstmts = 94,               /* wrpjobstmts  */
  YYSYMBOL_wrpjobstmt = 95                 /* wrpjobstmt  */
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
#define YYLAST   153

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  48
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  48
/* YYNRULES -- Number of rules.  */
#define YYNRULES  98
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  177

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   296


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
      44,    45,     2,     2,    46,     2,     2,    43,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    42,     2,
       2,    47,     2,     2,     2,     2,     2,     2,     2,     2,
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
      35,    36,    37,    38,    39,    40,    41
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   109,   109,   110,   111,   114,   115,   124,   127,   128,
     129,   132,   142,   152,   153,   156,   157,   167,   168,   175,
     182,   189,   196,   203,   210,   221,   222,   223,   224,   225,
     226,   229,   232,   245,   246,   249,   250,   253,   266,   267,
     270,   271,   274,   281,   288,   297,   298,   302,   315,   316,
     320,   321,   324,   335,   336,   340,   353,   354,   359,   360,
     363,   376,   377,   380,   381,   384,   393,   395,   394,   405,
     418,   419,   422,   423,   427,   426,   432,   431,   438,   439,
     442,   443,   444,   449,   452,   462,   463,   466,   473,   480,
     487,   494,   501,   514,   517,   518,   521,   528,   535
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
  "RFC3394ALGO", "RFC5649ALGO", "ENVELOPEALGO", "PARAMHASH", "HASHALG",
  "PARAMMGF", "MGFTYPE", "PARAMLABEL", "PARAMIV", "PARAMFLAVOUR",
  "WRAPALG", "PARAMOUTER", "PARAMINNER", "CKATTR_BOOL", "CKATTR_STR",
  "CKATTR_DATE", "CKATTR_KEY", "CKATTR_CLASS", "TOK_BOOLEAN", "TOK_DATE",
  "KEYTYPE", "OCLASS", "DOTTEDNUMBER", "WRAPPINGJOBHEADER",
  "P_WRAPPINGKEY", "P_FILENAME", "P_ALGORITHM", "':'", "'/'", "'('", "')'",
  "','", "'='", "$accept", "wkeyset", "headers", "wkey", "wkeyblocks",
  "innerblock", "outerblock", "wkeymeta", "wkeystmt", "algo", "pkcs1algo",
  "pkcs1algoheader", "pkcs1algoid", "oaepalgo", "oaepalgoheader",
  "oaepalgoid", "oaepparamlist", "oaepparam", "cbcpadalgo",
  "cbcpadalgoheader", "cbcpadalgoid", "cbcpadparamlist", "cbcpadparam",
  "rfc3394algo", "rfc3394algoheader", "rfc3394algoid", "rfc5649algo",
  "rfc5649algoheader", "rfc5649algoid", "rfc5649paramlist", "rfc5649param",
  "envelopealgo", "$@1", "envelopealgoheader", "envelopealgoid",
  "envelopeparamlist", "envelopeparam", "$@2", "$@3", "outeralgo",
  "inneralgo", "pubk", "pubkblock", "pubkmeta", "pubkstmt", "wrappingjob",
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
     295,   296,    58,    47,    40,    41,    44,    61
};
#endif

#define YYPACT_NINF (-67)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int8 yypact[] =
{
      -7,   -32,   -29,   -36,     6,    16,   -67,    29,   -12,     8,
      10,    25,    27,   -67,   -67,    32,    33,    34,    35,    37,
      38,    39,    41,    42,    21,     4,   -67,   -67,   -67,    72,
      76,     5,   -36,    77,    48,     5,    81,    55,    83,    -4,
      56,    54,    50,    51,    52,    53,    57,   -67,    11,   -67,
     -67,   -67,   -67,    93,    94,   -67,   -67,   -67,    59,    60,
      61,    62,    63,    64,   -67,   -67,   -67,   -67,   -67,    65,
     -67,   -67,    66,   -67,   -67,    67,   -67,   -67,    68,   -67,
     -67,    69,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,   -67,   -67,   -67,    75,    91,     3,    79,    80,   -67,
     -67,   -67,   -67,   -67,    78,    82,    84,    85,    86,    87,
      36,    95,    88,    96,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,   -67,   -67,   -67,   -67,   -67,   -67,    70,    89,    90,
     -17,   -67,    92,    17,   -67,   -67,    97,    19,   -67,    40,
     106,   105,   121,   -67,    36,   122,   -67,    95,   104,   -67,
      96,    98,    99,    23,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,   -67,   -67,   -67,   -67,   -67,    40,    58,    45,   -67,
     -67,   -67,   -67,   -67,   -67,   -67,   -67
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       0,     0,     0,     0,     0,     0,     4,     0,     0,     0,
       0,     0,    93,    94,     1,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     2,     0,    13,     5,     6,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     3,     0,    85,
      12,    11,     7,     8,     0,    14,    96,    97,    33,    38,
      48,    56,    61,    70,    98,    25,    31,    32,    26,    35,
      37,    27,    45,    47,    28,    53,    55,    29,    58,    60,
      30,    66,    69,    95,    15,    16,    17,    18,    19,    20,
      22,    21,    23,    24,     0,     0,     0,     0,     0,    84,
      83,    86,     9,    10,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    67,    87,    88,    90,    89,    91,
      92,    34,    39,    49,    57,    62,    71,     0,     0,     0,
       0,    40,     0,     0,    50,    54,     0,     0,    63,     0,
       0,     0,     0,    36,     0,     0,    46,     0,     0,    59,
       0,     0,     0,     0,    72,    42,    43,    44,    41,    52,
      51,    65,    64,    74,    76,    68,     0,     0,     0,    73,
      78,    79,    75,    80,    81,    82,    77
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -67,   -67,   -67,   -67,   -67,    46,   100,   -67,   107,   103,
     -66,   -67,   -67,   -37,   -67,   -67,   -67,   -13,   -34,   -67,
     -67,   -67,    -6,   -33,   -67,   -67,   -28,   -67,   -67,   -67,
      -8,   -67,   -67,   -67,   -67,   -67,   -23,   -67,   -67,   -67,
     -67,   -67,   -67,   -67,   101,   -67,   -67,   115
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,     4,     5,    24,    52,    53,    54,    25,    26,    64,
      65,    66,    67,    68,    69,    70,   130,   131,    71,    72,
      73,   133,   134,    74,    75,    76,    77,    78,    79,   137,
     138,    80,   139,    81,    82,   153,   154,   167,   168,   172,
     176,    47,   100,    48,    49,     6,    12,    13
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
       1,     2,    90,     9,    10,    11,    14,    50,    51,   117,
       7,    15,    16,     8,    17,    18,    99,    58,    59,    60,
      61,    62,    63,    15,    16,    28,    17,    18,   143,   144,
      91,     3,    19,    20,    21,    22,    23,   118,    27,    42,
      43,    44,    45,    46,    19,    20,    21,    22,    23,    42,
      43,    44,    45,    46,   127,    29,   128,    30,   129,    60,
      61,    62,   146,   147,   149,   150,   151,   152,   165,   166,
      58,    59,    31,    32,    33,    34,    35,    36,    56,    37,
      38,    39,    57,    40,    41,    85,    84,    87,    88,    89,
      93,    92,    94,    95,    96,    97,    50,   116,    51,    98,
     103,   170,   104,   105,   106,   107,   108,   109,   115,   110,
     111,   112,   113,   114,   119,   121,   120,   140,   132,   122,
     136,   123,   124,   125,   126,   155,   156,   157,   159,   161,
     171,   158,    55,   135,   173,   174,   141,   142,    86,   145,
     175,   160,   162,   169,   148,   163,   164,    83,     0,   101,
       0,     0,     0,   102
};

static const yytype_int16 yycheck[] =
{
       7,     8,     6,    39,    40,    41,     0,     3,     4,     6,
      42,     7,     8,    42,    10,    11,     5,    12,    13,    14,
      15,    16,    17,     7,     8,    37,    10,    11,    45,    46,
      34,    38,    28,    29,    30,    31,    32,    34,     9,    28,
      29,    30,    31,    32,    28,    29,    30,    31,    32,    28,
      29,    30,    31,    32,    18,    47,    20,    47,    22,    14,
      15,    16,    45,    46,    45,    46,    26,    27,    45,    46,
      12,    13,    47,    46,    42,    42,    42,    42,     6,    42,
      42,    42,     6,    42,    42,    37,     9,     6,    33,     6,
      36,    35,    42,    42,    42,    42,     3,     6,     4,    42,
      54,   167,    43,    43,    43,    43,    43,    43,    33,    44,
      44,    44,    44,    44,    35,    37,    36,    47,    23,    37,
      24,    37,    37,    37,    37,    19,    21,     6,     6,    25,
     167,   144,    25,    45,   168,   168,    47,    47,    35,    47,
     168,   147,   150,   166,    47,    47,    47,    32,    -1,    48,
      -1,    -1,    -1,    53
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     7,     8,    38,    49,    50,    93,    42,    42,    39,
      40,    41,    94,    95,     0,     7,     8,    10,    11,    28,
      29,    30,    31,    32,    51,    55,    56,     9,    37,    47,
      47,    47,    46,    42,    42,    42,    42,    42,    42,    42,
      42,    42,    28,    29,    30,    31,    32,    89,    91,    92,
       3,     4,    52,    53,    54,    56,     6,     6,    12,    13,
      14,    15,    16,    17,    57,    58,    59,    60,    61,    62,
      63,    66,    67,    68,    71,    72,    73,    74,    75,    76,
      79,    81,    82,    95,     9,    37,    57,     6,    33,     6,
       6,    34,    35,    36,    42,    42,    42,    42,    42,     5,
      90,    92,    54,    53,    43,    43,    43,    43,    43,    43,
      44,    44,    44,    44,    44,    33,     6,     6,    34,    35,
      36,    37,    37,    37,    37,    37,    37,    18,    20,    22,
      64,    65,    23,    69,    70,    45,    24,    77,    78,    80,
      47,    47,    47,    45,    46,    47,    45,    46,    47,    45,
      46,    26,    27,    83,    84,    19,    21,     6,    65,     6,
      70,    25,    78,    47,    47,    45,    46,    85,    86,    84,
      58,    61,    87,    66,    71,    74,    88
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int8 yyr1[] =
{
       0,    48,    49,    49,    49,    50,    50,    51,    52,    52,
      52,    53,    54,    55,    55,    56,    56,    56,    56,    56,
      56,    56,    56,    56,    56,    57,    57,    57,    57,    57,
      57,    58,    59,    60,    60,    61,    61,    62,    63,    63,
      64,    64,    65,    65,    65,    66,    66,    67,    68,    68,
      69,    69,    70,    71,    71,    72,    73,    73,    74,    74,
      75,    76,    76,    77,    77,    78,    79,    80,    79,    81,
      82,    82,    83,    83,    85,    84,    86,    84,    87,    87,
      88,    88,    88,    89,    90,    91,    91,    92,    92,    92,
      92,    92,    92,    93,    94,    94,    95,    95,    95
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     2,     3,     1,     3,     3,     2,     1,     2,
       2,     1,     1,     1,     2,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     3,     1,     4,     1,     1,     3,
       1,     3,     3,     3,     3,     1,     4,     1,     1,     3,
       1,     3,     3,     1,     3,     1,     1,     3,     1,     4,
       1,     1,     3,     1,     3,     3,     1,     0,     5,     1,
       1,     3,     1,     3,     0,     4,     0,     4,     1,     1,
       1,     1,     1,     2,     1,     1,     2,     3,     3,     3,
       3,     3,     3,     2,     1,     3,     3,     3,     3
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
#line 116 "wrappedkey_parser.y"
                {
		    if(strcmp((yyvsp[0].val_dottednumber),SUPPORTED_GRAMMAR_VERSION)>0) {
			yyerror(ctx,"Grammar version (%s) not supported, max supported is %s please update pkcs11-tools\n", (yyvsp[0].val_dottednumber), SUPPORTED_GRAMMAR_VERSION);
			YYERROR;
		    }
		}
#line 1701 "wrappedkey_parser.c"
    break;

  case 11: /* innerblock: INNER  */
#line 133 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_cryptogram(ctx, (yyvsp[0].val_pem), WRAPPEDKEYCTX_INNER_KEY_INDEX)!=rc_ok) {
			yyerror(ctx,"Error when parsing encrypted key cryptogram (inner)");
			YYERROR;
		    }
                    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1713 "wrappedkey_parser.c"
    break;

  case 12: /* outerblock: OUTER  */
#line 143 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_cryptogram(ctx, (yyvsp[0].val_pem), WRAPPEDKEYCTX_OUTER_KEY_INDEX)!=rc_ok) {
			yyerror(ctx,"Error when parsing encrypted key cryptogram (outer)");
			YYERROR;
		    }
                    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1725 "wrappedkey_parser.c"
    break;

  case 16: /* wkeystmt: GRAMMAR_VERSION ':' DOTTEDNUMBER  */
#line 158 "wrappedkey_parser.y"
                {
		    if(strcmp((yyvsp[0].val_dottednumber),SUPPORTED_GRAMMAR_VERSION)>0) {
			yyerror(ctx,
				"Grammar version %s not supported (highest supported version is %s)\n"
				"Please update pkcs11-tools\n",
				(yyvsp[0].val_dottednumber), SUPPORTED_GRAMMAR_VERSION);
			YYERROR;
		    }
		}
#line 1739 "wrappedkey_parser.c"
    break;

  case 18: /* wkeystmt: WRAPPING_KEY ':' STRING  */
#line 169 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_key(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
		        yyerror(ctx,"Parsing error with wrapping key identifier.");
                        YYERROR;
                    }
		}
#line 1750 "wrappedkey_parser.c"
    break;

  case 19: /* wkeystmt: CKATTR_BOOL ':' TOK_BOOLEAN  */
#line 176 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_bool), sizeof(CK_BBOOL) )!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
#line 1761 "wrappedkey_parser.c"
    break;

  case 20: /* wkeystmt: CKATTR_STR ':' STRING  */
#line 183 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign bytes value.");
			YYERROR;
		    }
		}
#line 1772 "wrappedkey_parser.c"
    break;

  case 21: /* wkeystmt: CKATTR_DATE ':' TOK_DATE  */
#line 190 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_date).as_buffer, sizeof(CK_DATE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 1783 "wrappedkey_parser.c"
    break;

  case 22: /* wkeystmt: CKATTR_DATE ':' STRING  */
#line 197 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 1794 "wrappedkey_parser.c"
    break;

  case 23: /* wkeystmt: CKATTR_KEY ':' KEYTYPE  */
#line 204 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_key), sizeof(CK_KEY_TYPE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
#line 1805 "wrappedkey_parser.c"
    break;

  case 24: /* wkeystmt: CKATTR_CLASS ':' OCLASS  */
#line 211 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_cls), sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
#line 1816 "wrappedkey_parser.c"
    break;

  case 32: /* pkcs1algoheader: pkcs1algoid  */
#line 233 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1828 "wrappedkey_parser.c"
    break;

  case 37: /* oaepalgoheader: oaepalgoid  */
#line 254 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1840 "wrappedkey_parser.c"
    break;

  case 42: /* oaepparam: PARAMHASH '=' HASHALG  */
#line 275 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_hash(ctx, (yyvsp[0].val_hashalg))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1851 "wrappedkey_parser.c"
    break;

  case 43: /* oaepparam: PARAMMGF '=' MGFTYPE  */
#line 282 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_mgf(ctx, (yyvsp[0].val_mgf))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1862 "wrappedkey_parser.c"
    break;

  case 44: /* oaepparam: PARAMLABEL '=' STRING  */
#line 289 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_label(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1873 "wrappedkey_parser.c"
    break;

  case 47: /* cbcpadalgoheader: cbcpadalgoid  */
#line 303 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1885 "wrappedkey_parser.c"
    break;

  case 52: /* cbcpadparam: PARAMIV '=' STRING  */
#line 325 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_iv(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1896 "wrappedkey_parser.c"
    break;

  case 55: /* rfc3394algoheader: rfc3394algoid  */
#line 341 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1908 "wrappedkey_parser.c"
    break;

  case 60: /* rfc5649algoheader: rfc5649algoid  */
#line 364 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1920 "wrappedkey_parser.c"
    break;

  case 65: /* rfc5649param: PARAMFLAVOUR '=' WRAPALG  */
#line 385 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_flavour(ctx, (yyvsp[0].val_wrapalg))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm flavour.");
			YYERROR;
		    }
		}
#line 1931 "wrappedkey_parser.c"
    break;

  case 67: /* $@1: %empty  */
#line 395 "wrappedkey_parser.y"
                {
		    if(++parsing_envelope>1) {
			yyerror(ctx, "Nested envelope() algorithm not allowed.");
			YYERROR;
		    }
		}
#line 1942 "wrappedkey_parser.c"
    break;

  case 68: /* envelopealgo: envelopealgoheader '(' $@1 envelopeparamlist ')'  */
#line 402 "wrappedkey_parser.y"
                    { --parsing_envelope; }
#line 1948 "wrappedkey_parser.c"
    break;

  case 69: /* envelopealgoheader: envelopealgoid  */
#line 406 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1960 "wrappedkey_parser.c"
    break;

  case 74: /* $@2: %empty  */
#line 427 "wrappedkey_parser.y"
                {
		    envelope_keyindex = WRAPPEDKEYCTX_OUTER_KEY_INDEX;
		}
#line 1968 "wrappedkey_parser.c"
    break;

  case 76: /* $@3: %empty  */
#line 432 "wrappedkey_parser.y"
                {
		    envelope_keyindex = WRAPPEDKEYCTX_INNER_KEY_INDEX;
		}
#line 1976 "wrappedkey_parser.c"
    break;

  case 84: /* pubkblock: PUBK  */
#line 453 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_pem(ctx, (yyvsp[0].val_pem))!=rc_ok) {
			yyerror(ctx,"Error when parsing public key information");
			YYERROR;
		    }
                    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1988 "wrappedkey_parser.c"
    break;

  case 87: /* pubkstmt: CKATTR_BOOL ':' TOK_BOOLEAN  */
#line 467 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_bool), sizeof(CK_BBOOL) )!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
#line 1999 "wrappedkey_parser.c"
    break;

  case 88: /* pubkstmt: CKATTR_STR ':' STRING  */
#line 474 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign bytes value.");
			YYERROR;
		    }
		}
#line 2010 "wrappedkey_parser.c"
    break;

  case 89: /* pubkstmt: CKATTR_DATE ':' TOK_DATE  */
#line 481 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_date).as_buffer, sizeof(CK_DATE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 2021 "wrappedkey_parser.c"
    break;

  case 90: /* pubkstmt: CKATTR_DATE ':' STRING  */
#line 488 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 2032 "wrappedkey_parser.c"
    break;

  case 91: /* pubkstmt: CKATTR_KEY ':' KEYTYPE  */
#line 495 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_key), sizeof(CK_KEY_TYPE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
#line 2043 "wrappedkey_parser.c"
    break;

  case 92: /* pubkstmt: CKATTR_CLASS ':' OCLASS  */
#line 502 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_cls), sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
#line 2054 "wrappedkey_parser.c"
    break;

  case 96: /* wrpjobstmt: P_WRAPPINGKEY '=' STRING  */
#line 522 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_key(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
		        yyerror(ctx,"Parsing error with wrapping key identifier.");
                        YYERROR;
                    }
		}
#line 2065 "wrappedkey_parser.c"
    break;

  case 97: /* wrpjobstmt: P_FILENAME '=' STRING  */
#line 529 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_filename(ctx, (yyvsp[0].val_str).val)!=rc_ok) {
		        yyerror(ctx,"Issue when saving filename");
                        YYERROR;
		    }
                }
#line 2076 "wrappedkey_parser.c"
    break;


#line 2080 "wrappedkey_parser.c"

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

#line 538 "wrappedkey_parser.y"

