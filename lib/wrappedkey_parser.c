/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.4"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* Copy the first part of user declarations.  */
#line 26 "wrappedkey_parser.y" /* yacc.c:339  */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* parsing_envelope will remember if we are parsing inside envelope(...) */
int parsing_envelope= 0;

/* envelope_keyindex will remember, when parsing inside envelope, if we care about inner or outer alg */
int envelope_keyindex=0;


#line 80 "wrappedkey_parser.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 1
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
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
#line 40 "wrappedkey_parser.y" /* yacc.c:355  */


#include "pkcs11lib.h"
#include "wrappedkey_helper.h"

extern void yyerror(wrappedKeyCtx *ctx, const char *s, ...);
extern int yylex(void);


#line 120 "wrappedkey_parser.c" /* yacc.c:355  */

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
#line 53 "wrappedkey_parser.y" /* yacc.c:355  */

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

#line 205 "wrappedkey_parser.c" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (wrappedKeyCtx *ctx);

#endif /* !YY_YY_WRAPPEDKEY_PARSER_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 222 "wrappedkey_parser.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

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

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
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


#if ! defined yyoverflow || YYERROR_VERBOSE

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
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
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
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
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

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   297

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
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
static const yytype_uint16 yyrline[] =
{
       0,   114,   114,   115,   116,   119,   120,   131,   134,   135,
     136,   139,   149,   159,   160,   163,   164,   167,   168,   171,
     172,   184,   185,   196,   197,   200,   207,   216,   223,   232,
     239,   247,   246,   277,   292,   293,   296,   308,   309,   310,
     311,   312,   313,   316,   319,   332,   333,   336,   337,   340,
     353,   354,   357,   358,   361,   368,   375,   386,   387,   391,
     404,   405,   409,   410,   413,   426,   427,   431,   444,   445,
     450,   451,   454,   467,   468,   471,   472,   475,   484,   486,
     485,   496,   509,   510,   513,   514,   518,   517,   523,   522,
     529,   530,   533,   534,   535,   540,   543,   553,   554,   558,
     565,   574,   581,   590,   597,   605,   604,   641,   644,   645,
     648,   657,   666
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 1
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "OUTER", "INNER", "PUBK", "STRING",
  "CTYPE", "GRAMMAR_VERSION", "CTYPE_VAL", "WRAPPING_ALG", "WRAPPING_KEY",
  "PKCS1ALGO", "OAEPALGO", "CBCPADALGO", "RFC3394ALGO", "RFC5649ALGO",
  "ENVELOPEALGO", "PARAMHASH", "PARAMMGF", "MGFTYPE", "PARAMLABEL",
  "PARAMIV", "PARAMFLAVOUR", "PARAMOUTER", "PARAMINNER", "CKATTR_BOOL",
  "CKATTR_STR", "CKATTR_DATE", "CKATTR_KEY", "CKATTR_CLASS",
  "CKATTR_TEMPLATE", "CKATTR_ALLOWEDMECH", "TOK_BOOLEAN", "TOK_DATE",
  "KEYTYPE", "OCLASS", "CKMECH", "DOTTEDNUMBER", "WRAPPINGJOBHEADER",
  "P_WRAPPINGKEY", "P_FILENAME", "P_ALGORITHM", "':'", "'{'", "'}'", "'/'",
  "'('", "')'", "','", "'='", "$accept", "wkeyset", "headers", "wkey",
  "wkeyblocks", "innerblock", "outerblock", "wkeystmts", "wkeystmt",
  "metastmts", "metastmt", "assignstmts", "assignstmt", "$@1",
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
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,    58,   123,   125,    47,    40,    41,    44,
      61
};
# endif

#define YYPACT_NINF -57

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-57)))

#define YYTABLE_NINF -1

#define yytable_value_is_error(Yytable_value) \
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
static const yytype_uint8 yydefact[] =
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
static const yytype_int16 yydefgoto[] =
{
      -1,     4,     5,    26,    61,    62,    63,    27,    28,    29,
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
static const yytype_uint8 yystos[] =
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
static const yytype_uint8 yyr1[] =
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
static const yytype_uint8 yyr2[] =
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


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
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

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



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
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, ctx); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, wrappedKeyCtx *ctx)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (ctx);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, wrappedKeyCtx *ctx)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, ctx);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
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
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule, wrappedKeyCtx *ctx)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              , ctx);
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
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
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


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
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
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
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
            /* Fall through.  */
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

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
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
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
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
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
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
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, wrappedKeyCtx *ctx)
{
  YYUSE (yyvaluep);
  YYUSE (ctx);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
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
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

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

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
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

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

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
| yyreduce -- Do a reduction.  |
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
#line 121 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(strcmp((yyvsp[0].val_dottednumber),SUPPORTED_GRAMMAR_VERSION)>0) {
			yyerror(ctx,"Grammar version (%s) not supported, max supported is %s please update pkcs11-tools\n", (yyvsp[0].val_dottednumber), SUPPORTED_GRAMMAR_VERSION);
			free((yyvsp[0].val_dottednumber));
			YYERROR;
		    }
		    free((yyvsp[0].val_dottednumber));
		}
#line 1466 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 11:
#line 140 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_append_cryptogram(ctx, (yyvsp[0].val_pem), WRAPPEDKEYCTX_INNER_KEY_INDEX)!=rc_ok) {
			yyerror(ctx,"Error when parsing encrypted key cryptogram (inner)");
			YYERROR;
		    }
		    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1478 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 12:
#line 150 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_append_cryptogram(ctx, (yyvsp[0].val_pem), WRAPPEDKEYCTX_OUTER_KEY_INDEX)!=rc_ok) {
			yyerror(ctx,"Error when parsing encrypted key cryptogram (outer)");
			YYERROR;
		    }
		    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1490 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 20:
#line 173 "wrappedkey_parser.y" /* yacc.c:1646  */
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
#line 1506 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 22:
#line 186 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_set_wrapping_key(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Parsing error with wrapping key identifier.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 1519 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 25:
#line 201 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_bool), sizeof(CK_BBOOL) )!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
#line 1530 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 26:
#line 208 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign bytes value.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 1543 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 27:
#line 217 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_date).as_buffer, sizeof(CK_DATE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 1554 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 28:
#line 224 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 1567 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 29:
#line 233 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_key), sizeof(CK_KEY_TYPE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
#line 1578 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 30:
#line 240 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_cls), sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
#line 1589 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 31:
#line 247 "wrappedkey_parser.y" /* yacc.c:1646  */
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
#line 1608 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 32:
#line 262 "wrappedkey_parser.y" /* yacc.c:1646  */
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
#line 1628 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 33:
#line 278 "wrappedkey_parser.y" /* yacc.c:1646  */
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
#line 1645 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 36:
#line 297 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if( _wrappedkey_parser_add_mechanism(ctx, (yyvsp[0].val_mech))!=rc_ok) {
			yyerror(ctx, "Error during parsing, cannot assign mechanism to allowed mechanisms.");
			YYERROR;
		    }
		}
#line 1656 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 44:
#line 320 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1668 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 46:
#line 333 "wrappedkey_parser.y" /* yacc.c:1646  */
    { free((yyvsp[0].val_dottednumber)); }
#line 1674 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 49:
#line 341 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1686 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 51:
#line 354 "wrappedkey_parser.y" /* yacc.c:1646  */
    { free((yyvsp[0].val_dottednumber)); }
#line 1692 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 54:
#line 362 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_hash(ctx, (yyvsp[0].val_mech))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1703 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 55:
#line 369 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_mgf(ctx, (yyvsp[0].val_mgf))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1714 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 56:
#line 376 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_label(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 1727 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 59:
#line 392 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1739 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 61:
#line 405 "wrappedkey_parser.y" /* yacc.c:1646  */
    { free((yyvsp[0].val_dottednumber)); }
#line 1745 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 64:
#line 414 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_iv(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 1758 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 67:
#line 432 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1770 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 69:
#line 445 "wrappedkey_parser.y" /* yacc.c:1646  */
    { free((yyvsp[0].val_dottednumber)); }
#line 1776 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 72:
#line 455 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1788 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 74:
#line 468 "wrappedkey_parser.y" /* yacc.c:1646  */
    { free((yyvsp[0].val_dottednumber)); }
#line 1794 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 77:
#line 476 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_set_wrapping_param_flavour(ctx, (yyvsp[0].val_mech))!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm flavour.");
			YYERROR;
		    }
		}
#line 1805 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 79:
#line 486 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(++parsing_envelope>1) {
			yyerror(ctx, "Nested envelope() algorithm not allowed.");
			YYERROR;
		    }
		}
#line 1816 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 80:
#line 493 "wrappedkey_parser.y" /* yacc.c:1646  */
    { --parsing_envelope; }
#line 1822 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 81:
#line 497 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    int keyidx = parsing_envelope ? envelope_keyindex : WRAPPEDKEYCTX_LONE_KEY_INDEX;
		    if(_wrappedkey_parser_wkey_set_wrapping_alg(ctx, (yyvsp[0].val_wrappingmethod), keyidx)!=rc_ok) {
			yyerror(ctx,"Parsing error with specified wrapping algorithm.");
			YYERROR;
		    }
		}
#line 1834 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 83:
#line 510 "wrappedkey_parser.y" /* yacc.c:1646  */
    { free((yyvsp[0].val_dottednumber)); }
#line 1840 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 86:
#line 518 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    envelope_keyindex = WRAPPEDKEYCTX_OUTER_KEY_INDEX;
		}
#line 1848 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 88:
#line 523 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    envelope_keyindex = WRAPPEDKEYCTX_INNER_KEY_INDEX;
		}
#line 1856 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 96:
#line 544 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_pubk_append_pem(ctx, (yyvsp[0].val_pem))!=rc_ok) {
			yyerror(ctx,"Error when parsing public key information");
			YYERROR;
		    }
		    free((yyvsp[0].val_pem));	/* free up mem */
		}
#line 1868 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 99:
#line 559 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_bool), sizeof(CK_BBOOL) )!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign boolean value.");
			YYERROR;
		    }
		}
#line 1879 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 100:
#line 566 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign bytes value.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 1892 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 101:
#line 575 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_date).as_buffer, sizeof(CK_DATE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			YYERROR;
		    }
		}
#line 1903 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 102:
#line 582 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign date value.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 1916 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 103:
#line 591 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_key), sizeof(CK_KEY_TYPE))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign key type value.");
			YYERROR;
		    }
		}
#line 1927 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 104:
#line 598 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_pubk_append_attr(ctx, (yyvsp[-2].ckattr), &(yyvsp[0].val_cls), sizeof(CK_OBJECT_CLASS))!=rc_ok) {
			yyerror(ctx,"Error during parsing, cannot assign object class value.");
			YYERROR;
		    }
		}
#line 1938 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 105:
#line 605 "wrappedkey_parser.y" /* yacc.c:1646  */
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
#line 1957 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 106:
#line 620 "wrappedkey_parser.y" /* yacc.c:1646  */
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
#line 1977 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 110:
#line 649 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_set_wrapping_key(ctx, (yyvsp[0].val_str).val, (yyvsp[0].val_str).len)!=rc_ok) {
			yyerror(ctx,"Parsing error with wrapping key identifier.");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 1990 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;

  case 111:
#line 658 "wrappedkey_parser.y" /* yacc.c:1646  */
    {
		    if(_wrappedkey_parser_wkey_set_filename(ctx, (yyvsp[0].val_str).val)!=rc_ok) {
			yyerror(ctx,"Issue when saving filename");
			free((yyvsp[0].val_str).val);
			YYERROR;
		    }
		    free((yyvsp[0].val_str).val);
		}
#line 2003 "wrappedkey_parser.c" /* yacc.c:1646  */
    break;


#line 2007 "wrappedkey_parser.c" /* yacc.c:1646  */
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
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (ctx, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (ctx, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
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

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

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

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
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
                  yystos[yystate], yyvsp, ctx);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

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

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (ctx, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

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
                  yystos[*yyssp], yyvsp, ctx);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 669 "wrappedkey_parser.y" /* yacc.c:1906  */

