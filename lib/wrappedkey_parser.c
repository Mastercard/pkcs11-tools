/* A Bison parser, made by GNU Bison 3.6.4.  */

/* Bison implementation for Yacc-like parsers in C

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

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.6.4"

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
    DOTTEDNUMBER = 292             /* DOTTEDNUMBER  */
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

#line 213 "wrappedkey_parser.c"

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
  YYSYMBOL_38_ = 38,                       /* ':'  */
  YYSYMBOL_39_ = 39,                       /* '/'  */
  YYSYMBOL_40_ = 40,                       /* '('  */
  YYSYMBOL_41_ = 41,                       /* ')'  */
  YYSYMBOL_42_ = 42,                       /* ','  */
  YYSYMBOL_43_ = 43,                       /* '='  */
  YYSYMBOL_YYACCEPT = 44,                  /* $accept  */
  YYSYMBOL_wkeyset = 45,                   /* wkeyset  */
  YYSYMBOL_headers = 46,                   /* headers  */
  YYSYMBOL_wkey = 47,                      /* wkey  */
  YYSYMBOL_wkeyblocks = 48,                /* wkeyblocks  */
  YYSYMBOL_innerblock = 49,                /* innerblock  */
  YYSYMBOL_outerblock = 50,                /* outerblock  */
  YYSYMBOL_wkeymeta = 51,                  /* wkeymeta  */
  YYSYMBOL_wkeystmt = 52,                  /* wkeystmt  */
  YYSYMBOL_algo = 53,                      /* algo  */
  YYSYMBOL_pkcs1algo = 54,                 /* pkcs1algo  */
  YYSYMBOL_pkcs1algoheader = 55,           /* pkcs1algoheader  */
  YYSYMBOL_pkcs1algoid = 56,               /* pkcs1algoid  */
  YYSYMBOL_oaepalgo = 57,                  /* oaepalgo  */
  YYSYMBOL_oaepalgoheader = 58,            /* oaepalgoheader  */
  YYSYMBOL_oaepalgoid = 59,                /* oaepalgoid  */
  YYSYMBOL_oaepparamlist = 60,             /* oaepparamlist  */
  YYSYMBOL_oaepparam = 61,                 /* oaepparam  */
  YYSYMBOL_cbcpadalgo = 62,                /* cbcpadalgo  */
  YYSYMBOL_cbcpadalgoheader = 63,          /* cbcpadalgoheader  */
  YYSYMBOL_cbcpadalgoid = 64,              /* cbcpadalgoid  */
  YYSYMBOL_cbcpadparamlist = 65,           /* cbcpadparamlist  */
  YYSYMBOL_cbcpadparam = 66,               /* cbcpadparam  */
  YYSYMBOL_rfc3394algo = 67,               /* rfc3394algo  */
  YYSYMBOL_rfc3394algoheader = 68,         /* rfc3394algoheader  */
  YYSYMBOL_rfc3394algoid = 69,             /* rfc3394algoid  */
  YYSYMBOL_rfc5649algo = 70,               /* rfc5649algo  */
  YYSYMBOL_rfc5649algoheader = 71,         /* rfc5649algoheader  */
  YYSYMBOL_rfc5649algoid = 72,             /* rfc5649algoid  */
  YYSYMBOL_rfc5649paramlist = 73,          /* rfc5649paramlist  */
  YYSYMBOL_rfc5649param = 74,              /* rfc5649param  */
  YYSYMBOL_envelopealgo = 75,              /* envelopealgo  */
  YYSYMBOL_76_1 = 76,                      /* $@1  */
  YYSYMBOL_envelopealgoheader = 77,        /* envelopealgoheader  */
  YYSYMBOL_envelopealgoid = 78,            /* envelopealgoid  */
  YYSYMBOL_envelopeparamlist = 79,         /* envelopeparamlist  */
  YYSYMBOL_envelopeparam = 80,             /* envelopeparam  */
  YYSYMBOL_81_2 = 81,                      /* $@2  */
  YYSYMBOL_82_3 = 82,                      /* $@3  */
  YYSYMBOL_outeralgo = 83,                 /* outeralgo  */
  YYSYMBOL_inneralgo = 84,                 /* inneralgo  */
  YYSYMBOL_pubk = 85,                      /* pubk  */
  YYSYMBOL_pubkblock = 86,                 /* pubkblock  */
  YYSYMBOL_pubkmeta = 87,                  /* pubkmeta  */
  YYSYMBOL_pubkstmt = 88                   /* pubkstmt  */
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
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
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
#define YYFINAL  38
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   171

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  44
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  45
/* YYNRULES -- Number of rules.  */
#define YYNRULES  92
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  163

#define YYMAXUTOK   292


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
      40,    41,     2,     2,    42,     2,     2,    39,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    38,     2,
       2,    43,     2,     2,     2,     2,     2,     2,     2,     2,
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
      35,    36,    37
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   107,   107,   108,   109,   112,   113,   122,   125,   126,
     127,   130,   140,   150,   151,   154,   155,   165,   166,   173,
     180,   187,   194,   201,   208,   219,   220,   221,   222,   223,
     224,   227,   230,   243,   244,   247,   248,   251,   264,   265,
     268,   269,   272,   279,   286,   295,   296,   300,   313,   314,
     318,   319,   322,   333,   334,   338,   351,   352,   357,   358,
     361,   374,   375,   378,   379,   382,   391,   393,   392,   403,
     416,   417,   420,   421,   425,   424,   430,   429,   436,   437,
     440,   441,   442,   447,   450,   460,   461,   464,   471,   478,
     485,   492,   499
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
  "KEYTYPE", "OCLASS", "DOTTEDNUMBER", "':'", "'/'", "'('", "')'", "','",
  "'='", "$accept", "wkeyset", "headers", "wkey", "wkeyblocks",
  "innerblock", "outerblock", "wkeymeta", "wkeystmt", "algo", "pkcs1algo",
  "pkcs1algoheader", "pkcs1algoid", "oaepalgo", "oaepalgoheader",
  "oaepalgoid", "oaepparamlist", "oaepparam", "cbcpadalgo",
  "cbcpadalgoheader", "cbcpadalgoid", "cbcpadparamlist", "cbcpadparam",
  "rfc3394algo", "rfc3394algoheader", "rfc3394algoid", "rfc5649algo",
  "rfc5649algoheader", "rfc5649algoid", "rfc5649paramlist", "rfc5649param",
  "envelopealgo", "$@1", "envelopealgoheader", "envelopealgoid",
  "envelopeparamlist", "envelopeparam", "$@2", "$@3", "outeralgo",
  "inneralgo", "pubk", "pubkblock", "pubkmeta", "pubkstmt", YY_NULLPTR
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
     285,   286,   287,   288,   289,   290,   291,   292,    58,    47,
      40,    41,    44,    61
};
#endif

#define YYPACT_NINF (-36)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int8 yypact[] =
{
      38,   -35,   -17,   -15,    -6,    10,    23,    35,    36,    64,
      12,   -36,   -36,   -36,   -36,   -36,    37,   -36,   -36,    39,
     -36,   -36,    40,   -36,   -36,    41,   -36,   -36,    44,   -36,
      67,    45,    46,    48,    49,    50,    51,    52,   -36,    53,
      54,    55,    56,    57,    58,    59,    61,    62,    28,    -3,
     -36,    43,    75,    63,    66,   -36,   -36,   -36,   -36,   -36,
     -36,   -36,   -36,   -36,    69,    65,     1,    95,    70,    99,
      -4,    71,    72,    73,    74,    76,    77,    78,   -36,     7,
     -36,   -36,   -36,   -36,   104,   105,   -36,    79,    80,    81,
     -10,   -36,    82,     6,   -36,   -36,    83,    25,   -36,    42,
     -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,
      84,   107,     0,    85,    91,   -36,   -36,   -36,   -36,   -36,
     100,    89,   112,   -36,    43,   115,   -36,    75,   103,   -36,
      66,    86,    87,    29,   -36,   -36,   -36,   -36,   -36,   -36,
     -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,
     -36,   -36,    42,    60,    -5,   -36,   -36,   -36,   -36,   -36,
     -36,   -36,   -36
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       0,     0,     0,    33,    38,    48,    56,    61,    70,     0,
       0,     4,    25,    31,    32,    26,    35,    37,    27,    45,
      47,    28,    53,    55,    29,    58,    60,    30,    66,    69,
       0,     0,     0,     0,     0,     0,     0,     0,     1,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     2,     0,
      13,     0,     0,     0,     0,    67,     5,     6,    34,    39,
      49,    57,    62,    71,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     3,     0,
      85,    12,    11,     7,     8,     0,    14,     0,     0,     0,
       0,    40,     0,     0,    50,    54,     0,     0,    63,     0,
      15,    16,    17,    18,    19,    20,    22,    21,    23,    24,
       0,     0,     0,     0,     0,    84,    83,    86,     9,    10,
       0,     0,     0,    36,     0,     0,    46,     0,     0,    59,
       0,     0,     0,     0,    72,    87,    88,    90,    89,    91,
      92,    42,    43,    44,    41,    52,    51,    65,    64,    74,
      76,    68,     0,     0,     0,    73,    78,    79,    75,    80,
      81,    82,    77
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -36,   -36,   -36,   -36,   -36,    47,    68,   -36,    88,    90,
     -22,   -36,   -36,   -20,   -36,   -36,   -36,    11,   -18,   -36,
     -36,   -36,    13,   -16,   -36,   -36,   -13,   -36,   -36,   -36,
       4,   -36,   -36,   -36,   -36,   -36,    -9,   -36,   -36,   -36,
     -36,   -36,   -36,   -36,    92
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     9,    10,    48,    83,    84,    85,    49,    50,    11,
      12,    13,    14,    15,    16,    17,    90,    91,    18,    19,
      20,    93,    94,    21,    22,    23,    24,    25,    26,    97,
      98,    27,    99,    28,    29,   133,   134,   153,   154,   158,
     162,    78,   116,    79,    80
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
      81,    82,   106,    30,    39,    40,   137,    41,    42,     5,
       6,     7,   115,     3,     4,     5,     6,     7,     8,    39,
      40,    31,    41,    42,    32,    43,    44,    45,    46,    47,
     107,   123,   124,    33,   138,    73,    74,    75,    76,    77,
      43,    44,    45,    46,    47,     1,     2,   126,   127,    34,
       3,     4,     5,     6,     7,     8,    73,    74,    75,    76,
      77,    87,    35,    88,    38,    89,   129,   130,   131,   132,
     151,   152,     3,     4,    36,    37,    56,    51,   100,    52,
      53,    54,    57,    58,    55,    59,    60,    61,    62,    63,
      96,    64,    65,    66,    67,    68,    69,    70,    92,    71,
      72,   103,   101,   104,    95,   105,   108,    81,   109,    82,
     142,   110,   111,   136,   112,   113,   114,   135,   143,   141,
     139,   145,   120,   121,   122,   125,   128,   140,   147,   149,
     150,   156,   119,   157,   148,   144,   159,    86,   160,     0,
     146,   161,     0,   155,     0,     0,     0,     0,     0,     0,
       0,     0,   118,     0,     0,     0,   102,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   117
};

static const yytype_int16 yycheck[] =
{
       3,     4,     6,    38,     7,     8,     6,    10,    11,    14,
      15,    16,     5,    12,    13,    14,    15,    16,    17,     7,
       8,    38,    10,    11,    39,    28,    29,    30,    31,    32,
      34,    41,    42,    39,    34,    28,    29,    30,    31,    32,
      28,    29,    30,    31,    32,     7,     8,    41,    42,    39,
      12,    13,    14,    15,    16,    17,    28,    29,    30,    31,
      32,    18,    39,    20,     0,    22,    41,    42,    26,    27,
      41,    42,    12,    13,    39,    39,     9,    40,     9,    40,
      40,    40,    37,    37,    40,    37,    37,    37,    37,    37,
      24,    38,    38,    38,    38,    38,    38,    38,    23,    38,
      38,     6,    37,    33,    41,     6,    35,     3,    36,     4,
      21,    38,    38,     6,    38,    38,    38,    33,     6,    19,
      35,     6,    43,    43,    43,    43,    43,    36,    25,    43,
      43,   153,    85,   153,   130,   124,   154,    49,   154,    -1,
     127,   154,    -1,   152,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    84,    -1,    -1,    -1,    66,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    79
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     7,     8,    12,    13,    14,    15,    16,    17,    45,
      46,    53,    54,    55,    56,    57,    58,    59,    62,    63,
      64,    67,    68,    69,    70,    71,    72,    75,    77,    78,
      38,    38,    39,    39,    39,    39,    39,    39,     0,     7,
       8,    10,    11,    28,    29,    30,    31,    32,    47,    51,
      52,    40,    40,    40,    40,    40,     9,    37,    37,    37,
      37,    37,    37,    37,    38,    38,    38,    38,    38,    38,
      38,    38,    38,    28,    29,    30,    31,    32,    85,    87,
      88,     3,     4,    48,    49,    50,    52,    18,    20,    22,
      60,    61,    23,    65,    66,    41,    24,    73,    74,    76,
       9,    37,    53,     6,    33,     6,     6,    34,    35,    36,
      38,    38,    38,    38,    38,     5,    86,    88,    50,    49,
      43,    43,    43,    41,    42,    43,    41,    42,    43,    41,
      42,    26,    27,    79,    80,    33,     6,     6,    34,    35,
      36,    19,    21,     6,    61,     6,    66,    25,    74,    43,
      43,    41,    42,    81,    82,    80,    54,    57,    83,    62,
      67,    70,    84
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int8 yyr1[] =
{
       0,    44,    45,    45,    45,    46,    46,    47,    48,    48,
      48,    49,    50,    51,    51,    52,    52,    52,    52,    52,
      52,    52,    52,    52,    52,    53,    53,    53,    53,    53,
      53,    54,    55,    56,    56,    57,    57,    58,    59,    59,
      60,    60,    61,    61,    61,    62,    62,    63,    64,    64,
      65,    65,    66,    67,    67,    68,    69,    69,    70,    70,
      71,    72,    72,    73,    73,    74,    75,    76,    75,    77,
      78,    78,    79,    79,    81,    80,    82,    80,    83,    83,
      84,    84,    84,    85,    86,    87,    87,    88,    88,    88,
      88,    88,    88
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
  YYUSE (yyoutput);
  YYUSE (ctx);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yykind < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yykind], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yykind);
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
  YYUSE (yyvaluep);
  YYUSE (ctx);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* The lookahead symbol.  */
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
    yy_state_fast_t yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize;

    /* The state stack.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss;
    yy_state_t *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
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

  yynerrs = 0;
  yystate = 0;
  yyerrstatus = 0;

  yystacksize = YYINITDEPTH;
  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;


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
  case 6:
#line 114 "wrappedkey_parser.y"
                {
		    if(strcmp((yyvsp[0].val_dottednumber),SUPPORTED_GRAMMAR_VERSION)>0) {
			yyerror(ctx,"Grammar version (%s) not supported, max supported is %s please update pkcs11-tools\n", (yyvsp[0].val_dottednumber), SUPPORTED_GRAMMAR_VERSION);
			YYERROR;
		    }
		}
#line 1689 "wrappedkey_parser.c"
    break;

  case 11:
#line 131 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_cryptogram(ctx, (yyvsp[0].val_pem), WRAPPEDKEYCTX_INNER_KEY_INDEX)!=rc_ok) {
			yyerror(ctx,"Error when parsing encrypted key cryptogram (inner)");
			YYERROR;
		    }
                    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1701 "wrappedkey_parser.c"
    break;

  case 12:
#line 141 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_cryptogram(ctx, (yyvsp[0].val_pem), WRAPPEDKEYCTX_OUTER_KEY_INDEX)!=rc_ok) {
			yyerror(ctx,"Error when parsing encrypted key cryptogram (outer)");
			YYERROR;
		    }
                    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1713 "wrappedkey_parser.c"
    break;

  case 16:
#line 156 "wrappedkey_parser.y"
                {
		    if(strcmp((yyvsp[0].val_dottednumber),SUPPORTED_GRAMMAR_VERSION)>0) {
			yyerror(ctx,
				"Grammar version %s not supported (highest supported version is %s)\n"
				"Please update pkcs11-tools\n",
				(yyvsp[0].val_dottednumber), SUPPORTED_GRAMMAR_VERSION);
			YYERROR;
		    }
		}
#line 1727 "wrappedkey_parser.c"
    break;

  case 18:
#line 167 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_key(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
		        yyerror(ctx,"Parsing error with wrapping key identifier.");
                        YYERROR;
                    }
		}
#line 1738 "wrappedkey_parser.c"
    break;

  case 19:
#line 174 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_bool), sizeof(CK_BBOOL) )!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
#line 1749 "wrappedkey_parser.c"
    break;

  case 20:
#line 181 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign bytes value.");
			YYERROR;
		    }
		}
#line 1760 "wrappedkey_parser.c"
    break;

  case 21:
#line 188 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_date).as_buffer, sizeof(CK_DATE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 1771 "wrappedkey_parser.c"
    break;

  case 22:
#line 195 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 1782 "wrappedkey_parser.c"
    break;

  case 23:
#line 202 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_key), sizeof(CK_KEY_TYPE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
#line 1793 "wrappedkey_parser.c"
    break;

  case 24:
#line 209 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_cls), sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
#line 1804 "wrappedkey_parser.c"
    break;

  case 32:
#line 231 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1816 "wrappedkey_parser.c"
    break;

  case 37:
#line 252 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1828 "wrappedkey_parser.c"
    break;

  case 42:
#line 273 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_hash(ctx, (yyvsp[0].val_hashalg))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1839 "wrappedkey_parser.c"
    break;

  case 43:
#line 280 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_mgf(ctx, (yyvsp[0].val_mgf))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1850 "wrappedkey_parser.c"
    break;

  case 44:
#line 287 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_label(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1861 "wrappedkey_parser.c"
    break;

  case 47:
#line 301 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1873 "wrappedkey_parser.c"
    break;

  case 52:
#line 323 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_iv(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1884 "wrappedkey_parser.c"
    break;

  case 55:
#line 339 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1896 "wrappedkey_parser.c"
    break;

  case 60:
#line 362 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1908 "wrappedkey_parser.c"
    break;

  case 65:
#line 383 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_flavour(ctx, (yyvsp[0].val_wrapalg))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm flavour.");
			YYERROR;
		    }
		}
#line 1919 "wrappedkey_parser.c"
    break;

  case 67:
#line 393 "wrappedkey_parser.y"
                {
		    if(++parsing_envelope>1) {
			yyerror(ctx, "Nested envelope() algorithm not allowed.");
			YYERROR;
		    }
		}
#line 1930 "wrappedkey_parser.c"
    break;

  case 68:
#line 400 "wrappedkey_parser.y"
                    { --parsing_envelope; }
#line 1936 "wrappedkey_parser.c"
    break;

  case 69:
#line 404 "wrappedkey_parser.y"
                {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1948 "wrappedkey_parser.c"
    break;

  case 74:
#line 425 "wrappedkey_parser.y"
                {
		    envelope_keyindex = WRAPPEDKEYCTX_OUTER_KEY_INDEX;
		}
#line 1956 "wrappedkey_parser.c"
    break;

  case 76:
#line 430 "wrappedkey_parser.y"
                {
		    envelope_keyindex = WRAPPEDKEYCTX_INNER_KEY_INDEX;
		}
#line 1964 "wrappedkey_parser.c"
    break;

  case 84:
#line 451 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_pem(ctx, (yyvsp[0].val_pem))!=rc_ok) {
			yyerror(ctx,"Error when parsing public key information");
			YYERROR;
		    }
                    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1976 "wrappedkey_parser.c"
    break;

  case 87:
#line 465 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_bool), sizeof(CK_BBOOL) )!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
#line 1987 "wrappedkey_parser.c"
    break;

  case 88:
#line 472 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign bytes value.");
			YYERROR;
		    }
		}
#line 1998 "wrappedkey_parser.c"
    break;

  case 89:
#line 479 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_date).as_buffer, sizeof(CK_DATE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 2009 "wrappedkey_parser.c"
    break;

  case 90:
#line 486 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 2020 "wrappedkey_parser.c"
    break;

  case 91:
#line 493 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_key), sizeof(CK_KEY_TYPE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
#line 2031 "wrappedkey_parser.c"
    break;

  case 92:
#line 500 "wrappedkey_parser.y"
                {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_cls), sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
#line 2042 "wrappedkey_parser.c"
    break;


#line 2046 "wrappedkey_parser.c"

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
  /* Fall through.  */
#endif


/*-----------------------------------------------------.
| yyreturn -- parsing is finished, return the result.  |
`-----------------------------------------------------*/
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

#line 508 "wrappedkey_parser.y"

