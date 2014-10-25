/* A Bison parser, made by GNU Bison 2.4.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
   2009, 2010 Free Software Foundation, Inc.
   
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
#define YYBISON_VERSION "2.4.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Copy the first part of user declarations.  */

/* Line 189 of yacc.c  */
#line 39 "policy_parse.y"

/* Add for SETools */
#include <config.h>

#include <sys/types.h>
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <sepol/policydb/expand.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/flask.h>
#include <sepol/policydb/hierarchy.h>
/* Add for SETools libqpol */
#ifdef HAVE_SEPOL_POLICYCAPS
#include <sepol/policydb/polcaps.h>
#endif

#include "queue.h"

/* #include "checkpolicy.h" - Remove for setools and replace with: */
#include <qpol/policy.h>

#include "module_compiler.h"
#include "policy_define.h"

extern policydb_t *policydbp;
extern unsigned int pass;

extern char yytext[];
extern int yylex(void);
extern int yywarn(char *msg);
extern int yyerror(char *msg);

typedef int (* require_func_t)();

/* Add for SETools libqpol */
/* redefine input so we can read from a string */
/* borrowed from O'Reilly lex and yacc pg 157 */
extern char qpol_src_input[];
extern char *qpol_src_inputptr;/* current position in qpol_src_input */
extern char *qpol_src_inputlim;/* end of data */



/* Line 189 of yacc.c  */
#line 127 "policy_parse.c"

/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     PATH = 258,
     FILENAME = 259,
     CLONE = 260,
     COMMON = 261,
     CLASS = 262,
     CONSTRAIN = 263,
     VALIDATETRANS = 264,
     INHERITS = 265,
     SID = 266,
     ROLE = 267,
     ROLEATTRIBUTE = 268,
     ATTRIBUTE_ROLE = 269,
     ROLES = 270,
     TYPEALIAS = 271,
     TYPEATTRIBUTE = 272,
     TYPEBOUNDS = 273,
     TYPE = 274,
     TYPES = 275,
     ALIAS = 276,
     ATTRIBUTE = 277,
     BOOL = 278,
     TUNABLE = 279,
     IF = 280,
     ELSE = 281,
     TYPE_TRANSITION = 282,
     TYPE_MEMBER = 283,
     TYPE_CHANGE = 284,
     ROLE_TRANSITION = 285,
     RANGE_TRANSITION = 286,
     SENSITIVITY = 287,
     DOMINANCE = 288,
     DOM = 289,
     DOMBY = 290,
     INCOMP = 291,
     CATEGORY = 292,
     LEVEL = 293,
     RANGE = 294,
     MLSCONSTRAIN = 295,
     MLSVALIDATETRANS = 296,
     USER = 297,
     NEVERALLOW = 298,
     ALLOW = 299,
     AUDITALLOW = 300,
     AUDITDENY = 301,
     DONTAUDIT = 302,
     SOURCE = 303,
     TARGET = 304,
     SAMEUSER = 305,
     FSCON = 306,
     PORTCON = 307,
     NETIFCON = 308,
     NODECON = 309,
     PIRQCON = 310,
     IOMEMCON = 311,
     IOPORTCON = 312,
     PCIDEVICECON = 313,
     FSUSEXATTR = 314,
     FSUSETASK = 315,
     FSUSETRANS = 316,
     FSUSEPSID = 317,
     GENFSCON = 318,
     U1 = 319,
     U2 = 320,
     U3 = 321,
     R1 = 322,
     R2 = 323,
     R3 = 324,
     T1 = 325,
     T2 = 326,
     T3 = 327,
     L1 = 328,
     L2 = 329,
     H1 = 330,
     H2 = 331,
     NOT = 332,
     AND = 333,
     OR = 334,
     XOR = 335,
     CTRUE = 336,
     CFALSE = 337,
     IDENTIFIER = 338,
     NUMBER = 339,
     EQUALS = 340,
     NOTEQUAL = 341,
     IPV4_ADDR = 342,
     IPV6_ADDR = 343,
     MODULE = 344,
     VERSION_IDENTIFIER = 345,
     REQUIRE = 346,
     OPTIONAL = 347,
     POLICYCAP = 348,
     PERMISSIVE = 349,
     FILESYSTEM = 350,
     DEFAULT_USER = 351,
     DEFAULT_ROLE = 352,
     DEFAULT_TYPE = 353,
     DEFAULT_RANGE = 354,
     LOW_HIGH = 355,
     LOW = 356,
     HIGH = 357
   };
#endif
/* Tokens.  */
#define PATH 258
#define FILENAME 259
#define CLONE 260
#define COMMON 261
#define CLASS 262
#define CONSTRAIN 263
#define VALIDATETRANS 264
#define INHERITS 265
#define SID 266
#define ROLE 267
#define ROLEATTRIBUTE 268
#define ATTRIBUTE_ROLE 269
#define ROLES 270
#define TYPEALIAS 271
#define TYPEATTRIBUTE 272
#define TYPEBOUNDS 273
#define TYPE 274
#define TYPES 275
#define ALIAS 276
#define ATTRIBUTE 277
#define BOOL 278
#define TUNABLE 279
#define IF 280
#define ELSE 281
#define TYPE_TRANSITION 282
#define TYPE_MEMBER 283
#define TYPE_CHANGE 284
#define ROLE_TRANSITION 285
#define RANGE_TRANSITION 286
#define SENSITIVITY 287
#define DOMINANCE 288
#define DOM 289
#define DOMBY 290
#define INCOMP 291
#define CATEGORY 292
#define LEVEL 293
#define RANGE 294
#define MLSCONSTRAIN 295
#define MLSVALIDATETRANS 296
#define USER 297
#define NEVERALLOW 298
#define ALLOW 299
#define AUDITALLOW 300
#define AUDITDENY 301
#define DONTAUDIT 302
#define SOURCE 303
#define TARGET 304
#define SAMEUSER 305
#define FSCON 306
#define PORTCON 307
#define NETIFCON 308
#define NODECON 309
#define PIRQCON 310
#define IOMEMCON 311
#define IOPORTCON 312
#define PCIDEVICECON 313
#define FSUSEXATTR 314
#define FSUSETASK 315
#define FSUSETRANS 316
#define FSUSEPSID 317
#define GENFSCON 318
#define U1 319
#define U2 320
#define U3 321
#define R1 322
#define R2 323
#define R3 324
#define T1 325
#define T2 326
#define T3 327
#define L1 328
#define L2 329
#define H1 330
#define H2 331
#define NOT 332
#define AND 333
#define OR 334
#define XOR 335
#define CTRUE 336
#define CFALSE 337
#define IDENTIFIER 338
#define NUMBER 339
#define EQUALS 340
#define NOTEQUAL 341
#define IPV4_ADDR 342
#define IPV6_ADDR 343
#define MODULE 344
#define VERSION_IDENTIFIER 345
#define REQUIRE 346
#define OPTIONAL 347
#define POLICYCAP 348
#define PERMISSIVE 349
#define FILESYSTEM 350
#define DEFAULT_USER 351
#define DEFAULT_ROLE 352
#define DEFAULT_TYPE 353
#define DEFAULT_RANGE 354
#define LOW_HIGH 355
#define LOW 356
#define HIGH 357




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 214 of yacc.c  */
#line 93 "policy_parse.y"

	unsigned int val;
	uintptr_t valptr;
	void *ptr;
        require_func_t require_func;



/* Line 214 of yacc.c  */
#line 376 "policy_parse.c"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif


/* Copy the second part of user declarations.  */


/* Line 264 of yacc.c  */
#line 388 "policy_parse.c"

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
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
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
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
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
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
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
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
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
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
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

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  9
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   1026

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  113
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  179
/* YYNRULES -- Number of rules.  */
#define YYNRULES  370
/* YYNRULES -- Number of states.  */
#define YYNSTATES  736

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   357

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     108,   109,   112,     2,   107,   110,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   106,   105,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   103,     2,   104,   111,     2,     2,     2,
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
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     5,     7,     8,     9,    10,    28,    30,
      33,    36,    38,    41,    44,    47,    49,    50,    52,    55,
      61,    63,    66,    72,    77,    85,    87,    88,    90,    92,
      94,    96,    99,   102,   105,   108,   113,   118,   123,   128,
     133,   138,   144,   150,   156,   162,   168,   174,   176,   177,
     183,   185,   188,   193,   197,   200,   203,   208,   210,   211,
     213,   216,   221,   225,   227,   230,   236,   240,   242,   245,
     247,   249,   255,   260,   262,   265,   267,   269,   271,   273,
     275,   277,   279,   281,   283,   285,   287,   289,   291,   293,
     295,   297,   299,   301,   303,   305,   307,   309,   311,   313,
     317,   323,   328,   333,   338,   343,   346,   347,   352,   357,
     359,   361,   368,   373,   374,   378,   381,   385,   389,   393,
     397,   401,   403,   405,   408,   409,   411,   413,   415,   424,
     432,   440,   448,   450,   452,   454,   456,   464,   472,   480,
     488,   497,   505,   513,   521,   527,   535,   537,   539,   541,
     543,   545,   553,   561,   569,   577,   585,   589,   595,   600,
     605,   611,   619,   624,   626,   629,   633,   639,   644,   646,
     647,   649,   652,   654,   656,   662,   667,   671,   674,   678,
     682,   684,   688,   692,   696,   697,   702,   703,   708,   709,
     714,   715,   720,   721,   726,   727,   732,   733,   738,   739,
     744,   745,   750,   752,   753,   758,   759,   764,   767,   768,
     773,   774,   779,   783,   787,   791,   795,   799,   803,   805,
     807,   809,   811,   813,   815,   817,   820,   827,   832,   833,
     835,   838,   842,   844,   845,   847,   850,   852,   854,   856,
     858,   862,   866,   872,   876,   882,   886,   888,   889,   891,
     894,   900,   904,   906,   907,   909,   912,   917,   924,   926,
     927,   929,   932,   937,   939,   940,   942,   945,   950,   955,
     957,   958,   960,   963,   968,   973,   978,   982,   984,   985,
     987,   990,   997,   998,  1006,  1011,  1013,  1020,  1023,  1024,
    1028,  1030,  1034,  1036,  1038,  1042,  1044,  1046,  1048,  1050,
    1052,  1055,  1058,  1059,  1064,  1066,  1068,  1070,  1074,  1076,
    1079,  1084,  1086,  1089,  1091,  1093,  1096,  1100,  1102,  1105,
    1107,  1108,  1112,  1114,  1116,  1118,  1120,  1122,  1124,  1126,
    1128,  1132,  1136,  1139,  1144,  1146,  1148,  1150,  1153,  1156,
    1158,  1160,  1162,  1164,  1166,  1168,  1170,  1175,  1178,  1180,
    1183,  1187,  1191,  1193,  1195,  1197,  1199,  1201,  1203,  1205,
    1207,  1209,  1211,  1215,  1216,  1223,  1228,  1229,  1231,  1233,
    1236
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int16 yyrhs[] =
{
     114,     0,    -1,   115,    -1,   274,    -1,    -1,    -1,    -1,
     116,   119,   121,   123,   117,   129,   135,   150,   214,   192,
     118,   217,   226,   239,   242,   229,   219,    -1,   120,    -1,
     119,   120,    -1,     7,   266,    -1,   122,    -1,   121,   122,
      -1,    11,   266,    -1,   124,   127,    -1,   125,    -1,    -1,
     126,    -1,   125,   126,    -1,     6,   266,   103,   261,   104,
      -1,   128,    -1,   127,   128,    -1,     7,   266,   103,   261,
     104,    -1,     7,   266,    10,   266,    -1,     7,   266,    10,
     266,   103,   261,   104,    -1,   130,    -1,    -1,   131,    -1,
     132,    -1,   133,    -1,   134,    -1,   130,   131,    -1,   130,
     132,    -1,   130,   133,    -1,   130,   134,    -1,    96,   254,
      48,   105,    -1,    96,   254,    49,   105,    -1,    97,   254,
      48,   105,    -1,    97,   254,    49,   105,    -1,    98,   254,
      48,   105,    -1,    98,   254,    49,   105,    -1,    99,   254,
      48,   101,   105,    -1,    99,   254,    48,   102,   105,    -1,
      99,   254,    48,   100,   105,    -1,    99,   254,    49,   101,
     105,    -1,    99,   254,    49,   102,   105,    -1,    99,   254,
      49,   100,   105,    -1,   136,    -1,    -1,   137,   140,   141,
     144,   146,    -1,   138,    -1,   137,   138,    -1,    32,   266,
     139,   105,    -1,    32,   266,   105,    -1,    21,   254,    -1,
      33,   266,    -1,    33,   103,   261,   104,    -1,   142,    -1,
      -1,   143,    -1,   142,   143,    -1,    37,   266,   139,   105,
      -1,    37,   266,   105,    -1,   145,    -1,   144,   145,    -1,
      38,   266,   106,   251,   105,    -1,    38,   266,   105,    -1,
     147,    -1,   146,   147,    -1,   148,    -1,   149,    -1,    40,
     254,   254,   197,   105,    -1,    41,   254,   197,   105,    -1,
     151,    -1,   150,   151,    -1,   153,    -1,   152,    -1,   163,
      -1,   286,    -1,   272,    -1,   105,    -1,   183,    -1,   184,
      -1,   186,    -1,   187,    -1,   188,    -1,   191,    -1,   185,
      -1,   154,    -1,   155,    -1,   156,    -1,   157,    -1,   158,
      -1,   160,    -1,   161,    -1,   175,    -1,   176,    -1,   177,
      -1,   273,    -1,    22,   266,   105,    -1,    19,   266,   139,
     159,   105,    -1,    19,   266,   159,   105,    -1,    16,   266,
     139,   105,    -1,    17,   266,   251,   105,    -1,    18,   266,
     251,   105,    -1,   107,   251,    -1,    -1,    23,   266,   162,
     105,    -1,    24,   266,   162,   105,    -1,    81,    -1,    82,
      -1,    25,   165,   103,   167,   104,   164,    -1,    26,   103,
     167,   104,    -1,    -1,   108,   165,   109,    -1,    77,   165,
      -1,   165,    78,   165,    -1,   165,    79,   165,    -1,   165,
      80,   165,    -1,   165,    85,   165,    -1,   165,    86,   165,
      -1,   166,    -1,   266,    -1,   167,   168,    -1,    -1,   169,
      -1,   170,    -1,   280,    -1,    27,   254,   254,   106,   254,
     266,   269,   105,    -1,    27,   254,   254,   106,   254,   266,
     105,    -1,    28,   254,   254,   106,   254,   266,   105,    -1,
      29,   254,   254,   106,   254,   266,   105,    -1,   171,    -1,
     172,    -1,   173,    -1,   174,    -1,    44,   254,   254,   106,
     254,   254,   105,    -1,    45,   254,   254,   106,   254,   254,
     105,    -1,    46,   254,   254,   106,   254,   254,   105,    -1,
      47,   254,   254,   106,   254,   254,   105,    -1,    27,   254,
     254,   106,   254,   266,   269,   105,    -1,    27,   254,   254,
     106,   254,   266,   105,    -1,    28,   254,   254,   106,   254,
     266,   105,    -1,    29,   254,   254,   106,   254,   266,   105,
      -1,    31,   254,   254,   249,   105,    -1,    31,   254,   254,
     106,   254,   249,   105,    -1,   178,    -1,   179,    -1,   180,
      -1,   181,    -1,   182,    -1,    44,   254,   254,   106,   254,
     254,   105,    -1,    45,   254,   254,   106,   254,   254,   105,
      -1,    46,   254,   254,   106,   254,   254,   105,    -1,    47,
     254,   254,   106,   254,   254,   105,    -1,    43,   254,   254,
     106,   254,   254,   105,    -1,    14,   266,   105,    -1,    12,
     266,    20,   254,   105,    -1,    12,   266,   159,   105,    -1,
      33,   103,   189,   104,    -1,    30,   254,   254,   266,   105,
      -1,    30,   254,   254,   106,   254,   266,   105,    -1,    44,
     254,   254,   105,    -1,   190,    -1,   189,   190,    -1,    12,
     260,   105,    -1,    12,   260,   103,   189,   104,    -1,    13,
     266,   251,   105,    -1,   193,    -1,    -1,   194,    -1,   193,
     194,    -1,   195,    -1,   196,    -1,     8,   254,   254,   197,
     105,    -1,     9,   254,   197,   105,    -1,   108,   197,   109,
      -1,    77,   197,    -1,   197,    78,   197,    -1,   197,    79,
     197,    -1,   198,    -1,    64,   212,    65,    -1,    67,   213,
      68,    -1,    70,   212,    71,    -1,    -1,    64,   212,   199,
     258,    -1,    -1,    65,   212,   200,   258,    -1,    -1,    66,
     212,   201,   258,    -1,    -1,    67,   212,   202,   258,    -1,
      -1,    68,   212,   203,   258,    -1,    -1,    69,   212,   204,
     258,    -1,    -1,    70,   212,   205,   258,    -1,    -1,    71,
     212,   206,   258,    -1,    -1,    72,   212,   207,   258,    -1,
      50,    -1,    -1,    48,    12,   208,   258,    -1,    -1,    49,
      12,   209,   258,    -1,    12,   213,    -1,    -1,    48,    19,
     210,   258,    -1,    -1,    49,    19,   211,   258,    -1,    73,
     213,    74,    -1,    73,   213,    76,    -1,    75,   213,    74,
      -1,    75,   213,    76,    -1,    73,   213,    75,    -1,    74,
     213,    76,    -1,    85,    -1,    86,    -1,   212,    -1,    34,
      -1,    35,    -1,    36,    -1,   215,    -1,   214,   215,    -1,
      42,   266,    15,   254,   216,   105,    -1,    38,   250,    39,
     249,    -1,    -1,   218,    -1,   217,   218,    -1,    11,   266,
     247,    -1,   220,    -1,    -1,   221,    -1,   220,   221,    -1,
     222,    -1,   223,    -1,   224,    -1,   225,    -1,    55,   270,
     247,    -1,    56,   270,   247,    -1,    56,   270,   110,   270,
     247,    -1,    57,   270,   247,    -1,    57,   270,   110,   270,
     247,    -1,    58,   270,   247,    -1,   227,    -1,    -1,   228,
      -1,   227,   228,    -1,    51,   270,   270,   247,   247,    -1,
     230,   233,   236,    -1,   231,    -1,    -1,   232,    -1,   231,
     232,    -1,    52,   266,   270,   247,    -1,    52,   266,   270,
     110,   270,   247,    -1,   234,    -1,    -1,   235,    -1,   234,
     235,    -1,    53,   266,   247,   247,    -1,   237,    -1,    -1,
     238,    -1,   237,   238,    -1,    54,   246,   246,   247,    -1,
      54,   271,   271,   247,    -1,   240,    -1,    -1,   241,    -1,
     240,   241,    -1,    59,   267,   247,   105,    -1,    60,   266,
     247,   105,    -1,    61,   266,   247,   105,    -1,    62,   266,
     105,    -1,   243,    -1,    -1,   244,    -1,   243,   244,    -1,
      63,   267,   268,   110,   266,   247,    -1,    -1,    63,   267,
     268,   110,   110,   245,   247,    -1,    63,   267,   268,   247,
      -1,    87,    -1,   266,   106,   266,   106,   266,   248,    -1,
     106,   249,    -1,    -1,   250,   110,   250,    -1,   250,    -1,
     266,   106,   251,    -1,   266,    -1,   266,    -1,   251,   107,
     266,    -1,   111,    -1,   112,    -1,   266,    -1,   262,    -1,
     253,    -1,   252,   266,    -1,   252,   262,    -1,    -1,   266,
     110,   255,   266,    -1,   252,    -1,   253,    -1,   260,    -1,
     103,   259,   104,    -1,   257,    -1,   256,   260,    -1,   256,
     103,   259,   104,    -1,   260,    -1,   259,   260,    -1,    83,
      -1,   266,    -1,   261,   266,    -1,   103,   263,   104,    -1,
     264,    -1,   263,   264,    -1,   266,    -1,    -1,   110,   265,
     266,    -1,   262,    -1,    83,    -1,    95,    -1,    83,    -1,
       3,    -1,     4,    -1,    84,    -1,    88,    -1,    93,   266,
     105,    -1,    94,   266,   105,    -1,   275,   277,    -1,    89,
     266,   276,   105,    -1,    90,    -1,   270,    -1,   246,    -1,
     278,   291,    -1,   278,   279,    -1,   279,    -1,   152,    -1,
     153,    -1,   163,    -1,   280,    -1,   286,    -1,   105,    -1,
      91,   103,   281,   104,    -1,   281,   282,    -1,   282,    -1,
     283,   105,    -1,   284,   285,   105,    -1,     7,   266,   254,
      -1,    12,    -1,    19,    -1,    22,    -1,    14,    -1,    42,
      -1,    23,    -1,    24,    -1,    32,    -1,    37,    -1,   266,
      -1,   285,   107,   266,    -1,    -1,   289,   103,   277,   104,
     287,   288,    -1,   290,   103,   277,   104,    -1,    -1,    92,
      -1,    26,    -1,   215,   291,    -1,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   180,   180,   181,   183,   185,   188,   183,   192,   193,
     195,   198,   199,   201,   204,   206,   207,   209,   210,   212,
     215,   216,   218,   220,   222,   225,   226,   228,   229,   230,
     231,   232,   233,   234,   235,   237,   239,   242,   244,   247,
     249,   252,   254,   256,   258,   260,   262,   265,   266,   268,
     270,   271,   281,   283,   286,   288,   290,   293,   294,   296,
     297,   299,   301,   304,   305,   307,   309,   312,   313,   315,
     316,   318,   321,   324,   325,   327,   328,   329,   330,   331,
     332,   334,   335,   336,   337,   338,   339,   340,   342,   343,
     344,   345,   346,   347,   348,   349,   350,   351,   352,   354,
     357,   359,   362,   365,   368,   371,   372,   374,   377,   380,
     382,   385,   388,   391,   392,   394,   397,   400,   403,   406,
     409,   412,   415,   419,   422,   424,   426,   428,   431,   434,
     437,   440,   444,   446,   448,   450,   453,   457,   461,   465,
     470,   472,   474,   476,   479,   481,   484,   485,   486,   487,
     488,   490,   493,   496,   499,   502,   505,   508,   511,   514,
     516,   518,   521,   524,   526,   529,   531,   534,   537,   538,
     540,   541,   543,   544,   546,   549,   552,   554,   557,   560,
     563,   566,   569,   572,   575,   575,   578,   578,   581,   581,
     584,   584,   587,   587,   590,   590,   593,   593,   596,   596,
     599,   599,   602,   605,   605,   608,   608,   611,   614,   614,
     617,   617,   620,   623,   626,   629,   632,   635,   639,   641,
     644,   646,   648,   650,   653,   654,   656,   659,   660,   662,
     663,   665,   668,   668,   670,   671,   673,   674,   675,   676,
     678,   681,   683,   686,   688,   691,   694,   695,   697,   698,
     700,   703,   705,   706,   708,   709,   711,   713,   716,   717,
     719,   720,   722,   725,   726,   728,   729,   731,   733,   736,
     737,   739,   740,   742,   744,   746,   748,   751,   752,   754,
     755,   757,   759,   759,   761,   764,   767,   769,   770,   772,
     774,   777,   779,   782,   783,   785,   787,   789,   791,   793,
     796,   799,   802,   802,   805,   808,   811,   812,   813,   814,
     815,   817,   818,   820,   823,   824,   826,   828,   828,   830,
     830,   830,   830,   832,   835,   837,   840,   843,   846,   849,
     852,   855,   860,   865,   868,   870,   872,   874,   876,   877,
     879,   880,   881,   882,   883,   884,   886,   888,   889,   891,
     892,   894,   897,   898,   899,   900,   901,   902,   903,   904,
     905,   907,   909,   913,   912,   917,   919,   921,   924,   927,
     928
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "PATH", "FILENAME", "CLONE", "COMMON",
  "CLASS", "CONSTRAIN", "VALIDATETRANS", "INHERITS", "SID", "ROLE",
  "ROLEATTRIBUTE", "ATTRIBUTE_ROLE", "ROLES", "TYPEALIAS", "TYPEATTRIBUTE",
  "TYPEBOUNDS", "TYPE", "TYPES", "ALIAS", "ATTRIBUTE", "BOOL", "TUNABLE",
  "IF", "ELSE", "TYPE_TRANSITION", "TYPE_MEMBER", "TYPE_CHANGE",
  "ROLE_TRANSITION", "RANGE_TRANSITION", "SENSITIVITY", "DOMINANCE", "DOM",
  "DOMBY", "INCOMP", "CATEGORY", "LEVEL", "RANGE", "MLSCONSTRAIN",
  "MLSVALIDATETRANS", "USER", "NEVERALLOW", "ALLOW", "AUDITALLOW",
  "AUDITDENY", "DONTAUDIT", "SOURCE", "TARGET", "SAMEUSER", "FSCON",
  "PORTCON", "NETIFCON", "NODECON", "PIRQCON", "IOMEMCON", "IOPORTCON",
  "PCIDEVICECON", "FSUSEXATTR", "FSUSETASK", "FSUSETRANS", "FSUSEPSID",
  "GENFSCON", "U1", "U2", "U3", "R1", "R2", "R3", "T1", "T2", "T3", "L1",
  "L2", "H1", "H2", "NOT", "AND", "OR", "XOR", "CTRUE", "CFALSE",
  "IDENTIFIER", "NUMBER", "EQUALS", "NOTEQUAL", "IPV4_ADDR", "IPV6_ADDR",
  "MODULE", "VERSION_IDENTIFIER", "REQUIRE", "OPTIONAL", "POLICYCAP",
  "PERMISSIVE", "FILESYSTEM", "DEFAULT_USER", "DEFAULT_ROLE",
  "DEFAULT_TYPE", "DEFAULT_RANGE", "LOW_HIGH", "LOW", "HIGH", "'{'", "'}'",
  "';'", "':'", "','", "'('", "')'", "'-'", "'~'", "'*'", "$accept",
  "policy", "base_policy", "$@1", "$@2", "$@3", "classes", "class_def",
  "initial_sids", "initial_sid_def", "access_vectors", "opt_common_perms",
  "common_perms", "common_perms_def", "av_perms", "av_perms_def",
  "opt_default_rules", "default_rules", "default_user_def",
  "default_role_def", "default_type_def", "default_range_def", "opt_mls",
  "mls", "sensitivities", "sensitivity_def", "alias_def", "dominance",
  "opt_categories", "categories", "category_def", "levels", "level_def",
  "mlspolicy", "mlspolicy_decl", "mlsconstraint_def",
  "mlsvalidatetrans_def", "te_rbac", "te_rbac_decl", "rbac_decl",
  "te_decl", "attribute_def", "type_def", "typealias_def",
  "typeattribute_def", "typebounds_def", "opt_attr_list", "bool_def",
  "tunable_def", "bool_val", "cond_stmt_def", "cond_else", "cond_expr",
  "cond_expr_prim", "cond_pol_list", "cond_rule_def",
  "cond_transition_def", "cond_te_avtab_def", "cond_allow_def",
  "cond_auditallow_def", "cond_auditdeny_def", "cond_dontaudit_def",
  "transition_def", "range_trans_def", "te_avtab_def", "allow_def",
  "auditallow_def", "auditdeny_def", "dontaudit_def", "neverallow_def",
  "attribute_role_def", "role_type_def", "role_attr_def", "role_dominance",
  "role_trans_def", "role_allow_def", "roles", "role_def",
  "roleattribute_def", "opt_constraints", "constraints", "constraint_decl",
  "constraint_def", "validatetrans_def", "cexpr", "cexpr_prim", "$@4",
  "$@5", "$@6", "$@7", "$@8", "$@9", "$@10", "$@11", "$@12", "$@13",
  "$@14", "$@15", "$@16", "op", "role_mls_op", "users", "user_def",
  "opt_mls_user", "initial_sid_contexts", "initial_sid_context_def",
  "opt_dev_contexts", "dev_contexts", "dev_context_def",
  "pirq_context_def", "iomem_context_def", "ioport_context_def",
  "pci_context_def", "opt_fs_contexts", "fs_contexts", "fs_context_def",
  "net_contexts", "opt_port_contexts", "port_contexts", "port_context_def",
  "opt_netif_contexts", "netif_contexts", "netif_context_def",
  "opt_node_contexts", "node_contexts", "node_context_def", "opt_fs_uses",
  "fs_uses", "fs_use_def", "opt_genfs_contexts", "genfs_contexts",
  "genfs_context_def", "$@17", "ipv4_addr_def", "security_context_def",
  "opt_mls_range_def", "mls_range_def", "mls_level_def", "id_comma_list",
  "tilde", "asterisk", "names", "$@18", "tilde_push", "asterisk_push",
  "names_push", "identifier_list_push", "identifier_push",
  "identifier_list", "nested_id_set", "nested_id_list",
  "nested_id_element", "$@19", "identifier", "filesystem", "path",
  "filename", "number", "ipv6_addr", "policycap_def", "permissive_def",
  "module_policy", "module_def", "version_identifier", "avrules_block",
  "avrule_decls", "avrule_decl", "require_block", "require_list",
  "require_decl", "require_class", "require_decl_def", "require_id_list",
  "optional_block", "$@20", "optional_else", "optional_decl", "else_decl",
  "avrule_user_defs", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   123,   125,    59,    58,    44,    40,    41,
      45,   126,    42
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint16 yyr1[] =
{
       0,   113,   114,   114,   116,   117,   118,   115,   119,   119,
     120,   121,   121,   122,   123,   124,   124,   125,   125,   126,
     127,   127,   128,   128,   128,   129,   129,   130,   130,   130,
     130,   130,   130,   130,   130,   131,   131,   132,   132,   133,
     133,   134,   134,   134,   134,   134,   134,   135,   135,   136,
     137,   137,   138,   138,   139,   140,   140,   141,   141,   142,
     142,   143,   143,   144,   144,   145,   145,   146,   146,   147,
     147,   148,   149,   150,   150,   151,   151,   151,   151,   151,
     151,   152,   152,   152,   152,   152,   152,   152,   153,   153,
     153,   153,   153,   153,   153,   153,   153,   153,   153,   154,
     155,   155,   156,   157,   158,   159,   159,   160,   161,   162,
     162,   163,   164,   164,   165,   165,   165,   165,   165,   165,
     165,   165,   166,   167,   167,   168,   168,   168,   169,   169,
     169,   169,   170,   170,   170,   170,   171,   172,   173,   174,
     175,   175,   175,   175,   176,   176,   177,   177,   177,   177,
     177,   178,   179,   180,   181,   182,   183,   184,   185,   186,
     187,   187,   188,   189,   189,   190,   190,   191,   192,   192,
     193,   193,   194,   194,   195,   196,   197,   197,   197,   197,
     197,   198,   198,   198,   199,   198,   200,   198,   201,   198,
     202,   198,   203,   198,   204,   198,   205,   198,   206,   198,
     207,   198,   198,   208,   198,   209,   198,   198,   210,   198,
     211,   198,   198,   198,   198,   198,   198,   198,   212,   212,
     213,   213,   213,   213,   214,   214,   215,   216,   216,   217,
     217,   218,   219,   219,   220,   220,   221,   221,   221,   221,
     222,   223,   223,   224,   224,   225,   226,   226,   227,   227,
     228,   229,   230,   230,   231,   231,   232,   232,   233,   233,
     234,   234,   235,   236,   236,   237,   237,   238,   238,   239,
     239,   240,   240,   241,   241,   241,   241,   242,   242,   243,
     243,   244,   245,   244,   244,   246,   247,   248,   248,   249,
     249,   250,   250,   251,   251,   252,   253,   254,   254,   254,
     254,   254,   255,   254,   256,   257,   258,   258,   258,   258,
     258,   259,   259,   260,   261,   261,   262,   263,   263,   264,
     265,   264,   264,   266,   267,   267,   268,   269,   270,   271,
     272,   273,   274,   275,   276,   276,   276,   277,   278,   278,
     279,   279,   279,   279,   279,   279,   280,   281,   281,   282,
     282,   283,   284,   284,   284,   284,   284,   284,   284,   284,
     284,   285,   285,   287,   286,   288,   288,   289,   290,   291,
     291
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     1,     0,     0,     0,    17,     1,     2,
       2,     1,     2,     2,     2,     1,     0,     1,     2,     5,
       1,     2,     5,     4,     7,     1,     0,     1,     1,     1,
       1,     2,     2,     2,     2,     4,     4,     4,     4,     4,
       4,     5,     5,     5,     5,     5,     5,     1,     0,     5,
       1,     2,     4,     3,     2,     2,     4,     1,     0,     1,
       2,     4,     3,     1,     2,     5,     3,     1,     2,     1,
       1,     5,     4,     1,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     3,
       5,     4,     4,     4,     4,     2,     0,     4,     4,     1,
       1,     6,     4,     0,     3,     2,     3,     3,     3,     3,
       3,     1,     1,     2,     0,     1,     1,     1,     8,     7,
       7,     7,     1,     1,     1,     1,     7,     7,     7,     7,
       8,     7,     7,     7,     5,     7,     1,     1,     1,     1,
       1,     7,     7,     7,     7,     7,     3,     5,     4,     4,
       5,     7,     4,     1,     2,     3,     5,     4,     1,     0,
       1,     2,     1,     1,     5,     4,     3,     2,     3,     3,
       1,     3,     3,     3,     0,     4,     0,     4,     0,     4,
       0,     4,     0,     4,     0,     4,     0,     4,     0,     4,
       0,     4,     1,     0,     4,     0,     4,     2,     0,     4,
       0,     4,     3,     3,     3,     3,     3,     3,     1,     1,
       1,     1,     1,     1,     1,     2,     6,     4,     0,     1,
       2,     3,     1,     0,     1,     2,     1,     1,     1,     1,
       3,     3,     5,     3,     5,     3,     1,     0,     1,     2,
       5,     3,     1,     0,     1,     2,     4,     6,     1,     0,
       1,     2,     4,     1,     0,     1,     2,     4,     4,     1,
       0,     1,     2,     4,     4,     4,     3,     1,     0,     1,
       2,     6,     0,     7,     4,     1,     6,     2,     0,     3,
       1,     3,     1,     1,     3,     1,     1,     1,     1,     1,
       2,     2,     0,     4,     1,     1,     1,     3,     1,     2,
       4,     1,     2,     1,     1,     2,     3,     1,     2,     1,
       0,     3,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     3,     2,     4,     1,     1,     1,     2,     2,     1,
       1,     1,     1,     1,     1,     1,     4,     2,     1,     2,
       3,     3,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     3,     0,     6,     4,     0,     1,     1,     2,
       0
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint16 yydefact[] =
{
       4,     0,     0,     2,     0,     3,     0,   323,     0,     1,
       0,     0,     8,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   367,     0,   345,   340,
     341,    88,    89,    90,    91,    92,    93,    94,   342,    95,
      96,    97,   146,   147,   148,   149,   150,    81,    82,    87,
      83,    84,    85,    86,    98,   332,   370,   339,   343,   344,
       0,   328,   285,   334,   336,   335,     0,    10,     0,     9,
      16,    11,   106,     0,     0,     0,     0,     0,   106,     0,
       0,     0,     0,     0,     0,   121,   122,     0,   295,   296,
       0,   299,     0,   298,   297,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   370,   338,
     337,     0,   333,    13,     0,    12,     5,     0,    15,    17,
       0,     0,     0,     0,   293,   156,     0,     0,     0,     0,
     106,     0,    99,   109,   110,     0,     0,   115,     0,     0,
       0,     0,     0,     0,   124,   320,   322,     0,   317,   319,
     301,   300,     0,   302,     0,     0,     0,     0,     0,     0,
     163,     0,     0,     0,     0,     0,     0,   352,   355,   353,
     354,   357,   358,   359,   360,   356,     0,   348,     0,     0,
     331,     0,   369,     0,     0,    26,     0,    14,    20,    18,
       0,   105,   158,   167,     0,    54,   102,   103,   104,     0,
     101,   107,   108,   114,   116,   117,   118,   119,   120,     0,
       0,   316,   318,     0,     0,     0,     0,     0,     0,     0,
       0,   290,   292,   313,     0,   159,   164,     0,   162,     0,
       0,     0,     0,     0,   346,   347,   349,   361,     0,     0,
     363,     0,     0,     0,     0,     0,    48,    25,    27,    28,
      29,    30,     0,    21,   157,   294,   100,     0,     0,     0,
       0,     0,     0,     0,   113,   123,   125,   126,   132,   133,
     134,   135,   127,   321,     0,   303,     0,     0,     0,   160,
       0,   144,     0,     0,     0,   165,     0,     0,     0,     0,
       0,   351,   350,     0,   228,   366,     0,   314,     0,     0,
       0,     0,     0,     0,    47,     0,    50,    31,    32,    33,
      34,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   111,     0,     0,     0,     0,     0,   289,   291,     0,
       0,     0,     0,     0,     0,   362,     0,     0,   368,   364,
       0,    19,   315,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    80,     0,    73,    76,    75,    77,    79,
      78,     0,    51,    58,    23,     0,     0,     0,     0,     0,
       0,     0,     0,   124,   327,   141,     0,   142,   143,   161,
     145,   166,   155,   151,   152,   153,   154,     0,   226,     0,
      35,    36,    37,    38,    39,    40,     0,     0,     0,     0,
       0,     0,    53,     0,     0,    74,   169,   224,     0,    55,
       0,     0,    57,    59,     0,    22,     0,     0,     0,     0,
       0,     0,     0,     0,   140,     0,     0,    43,    41,    42,
      46,    44,    45,    52,   330,     0,     0,     6,   168,   170,
     172,   173,   225,     0,     0,     0,     0,    63,    60,     0,
       0,     0,     0,     0,     0,     0,     0,   112,   227,   365,
       0,     0,     0,   171,    56,    62,     0,     0,     0,     0,
      64,    49,    67,    69,    70,    24,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   202,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   180,     0,   247,   229,    61,    66,     0,
       0,     0,    68,   129,     0,   130,   131,   136,   137,   138,
     139,     0,   221,   222,   223,   218,   219,   220,   207,   203,
     208,   205,   210,   184,   186,   188,   190,     0,   192,   194,
     196,   198,   200,     0,     0,     0,   177,     0,     0,     0,
     175,     0,     0,   230,   270,   246,   248,     0,     0,     0,
     128,   174,     0,     0,     0,     0,   181,     0,     0,     0,
       0,   182,     0,     0,   183,     0,     0,     0,   212,   216,
     213,   217,   214,   215,   176,   178,   179,   231,     0,     0,
       0,     0,     0,     0,   278,   269,   271,   249,    65,     0,
      72,     0,   304,   305,     0,   308,   204,   306,   209,   206,
     211,   185,   187,   189,   191,   193,   195,   197,   199,   201,
       0,     0,   325,   324,     0,     0,     0,     0,     0,   253,
     277,   279,   272,    71,     0,   311,     0,   309,     0,     0,
       0,     0,     0,   276,     0,     0,   233,   259,   252,   254,
     280,   307,   312,     0,     0,   250,   273,   274,   275,   326,
       0,     0,     0,     0,     0,     0,     7,   232,   234,   236,
     237,   238,   239,     0,   264,   258,   260,   255,   310,   288,
       0,   284,     0,     0,     0,     0,     0,   235,     0,     0,
     251,   263,   265,   261,     0,   286,   282,     0,     0,   256,
     240,     0,   241,     0,   243,   245,     0,   329,     0,     0,
     266,   287,     0,   281,     0,     0,     0,   262,     0,     0,
     283,   257,   242,   244,   267,   268
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     2,     3,     4,   195,   472,    11,    12,    80,    81,
     126,   127,   128,   129,   197,   198,   256,   257,   258,   259,
     260,   261,   313,   314,   315,   316,   137,   373,   421,   422,
     423,   456,   457,   481,   482,   483,   484,   364,   365,    39,
      40,    41,    42,    43,    44,    45,   132,    46,    47,   145,
      48,   331,    94,    95,   219,   275,   276,   277,   278,   279,
     280,   281,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,   169,   170,    63,   447,
     448,   449,   450,   451,   512,   513,   577,   578,   579,   580,
     582,   583,   585,   586,   587,   572,   574,   573,   575,   537,
     538,   416,   118,   347,   515,   516,   676,   677,   678,   679,
     680,   681,   682,   564,   565,   566,   656,   657,   658,   659,
     684,   685,   686,   700,   701,   702,   604,   605,   606,   639,
     640,   641,   722,    74,   597,   705,   230,   231,   133,   100,
     101,   102,   224,   614,   615,   616,   644,   617,   306,   103,
     157,   158,   220,   104,   634,   670,   386,    75,   719,   369,
      64,     5,     6,    76,    65,    66,    67,    68,   186,   187,
     188,   189,   248,    69,   305,   349,    70,   350,   120
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -652
static const yytype_int16 yypact[] =
{
     -24,    26,    79,  -652,   113,  -652,   476,  -652,   313,  -652,
      26,   270,  -652,    26,    26,    26,    26,    26,    26,    26,
      26,    26,    26,   -11,    56,    56,    56,    56,    56,    25,
      56,    56,    56,    56,    56,    40,  -652,    26,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,  -652,   310,  -652,  -652,  -652,
      57,  -652,  -652,  -652,  -652,  -652,   135,  -652,    26,  -652,
     172,  -652,     8,    26,   142,   175,    26,    26,    10,   171,
     212,   212,   -11,   -11,   280,  -652,  -652,    44,  -652,  -652,
      -5,  -652,    56,  -652,    83,    56,    56,    56,    56,   272,
      56,    56,    56,    56,    56,   406,   183,    26,   261,  -652,
    -652,   476,  -652,  -652,    26,  -652,  -652,   301,   330,  -652,
      56,    26,   207,   199,  -652,  -652,    56,   214,   307,   319,
     218,   243,  -652,  -652,  -652,   246,   273,   245,   101,   -11,
     -11,   -11,   -11,   -11,  -652,  -652,  -652,    87,  -652,  -652,
    -652,  -652,   278,  -652,   283,   289,   -38,   -22,   333,    14,
    -652,   305,   267,   315,   321,   326,    26,  -652,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,  -652,    27,  -652,   345,    26,
    -652,   438,  -652,   374,   394,   343,    26,   301,  -652,  -652,
     386,   395,  -652,  -652,    26,  -652,  -652,  -652,  -652,   407,
    -652,  -652,  -652,  -652,   245,   229,   264,  -652,  -652,   117,
      26,  -652,  -652,    56,    26,    56,    56,    56,   411,    56,
     412,   398,   419,  -652,   328,  -652,  -652,    56,  -652,    56,
      56,    56,    56,    56,  -652,  -652,  -652,  -652,   344,    56,
    -652,    26,    56,    56,    56,    56,   492,   343,  -652,  -652,
    -652,  -652,     1,  -652,  -652,  -652,  -652,    56,    56,    56,
      56,    56,    56,    56,   500,  -652,  -652,  -652,  -652,  -652,
    -652,  -652,  -652,  -652,    26,  -652,    26,    26,    26,  -652,
      26,  -652,    26,    26,   272,  -652,    56,    56,    56,    56,
      56,  -652,  -652,    26,   489,   502,    88,  -652,   350,   388,
     397,   418,    26,   768,  -652,   448,  -652,  -652,  -652,  -652,
    -652,    26,    26,    56,    56,    56,    56,    56,    56,    56,
     426,  -652,    20,   430,   440,   445,   452,  -652,   395,    15,
     453,   454,   456,   457,   458,  -652,    26,   459,  -652,  -652,
     450,  -652,  -652,   460,   461,   464,   466,   471,   479,   197,
     262,     9,    26,  -652,   363,  -652,  -652,  -652,  -652,  -652,
    -652,   141,  -652,   493,   485,    90,   497,   498,   499,   501,
     503,   504,   509,  -652,  -652,  -652,   494,  -652,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,  -652,  -652,   559,  -652,   476,
    -652,  -652,  -652,  -652,  -652,  -652,   516,   517,   518,   519,
     520,   521,  -652,   522,   523,  -652,    46,  -652,    26,  -652,
      26,   568,   493,  -652,    26,  -652,    56,    56,    56,    56,
      56,    56,    56,   209,  -652,    26,   527,  -652,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,    56,    56,  -652,   474,  -652,
    -652,  -652,  -652,   144,    16,    26,   306,  -652,  -652,   186,
      26,    26,    26,    56,    56,    56,    56,  -652,  -652,  -652,
      56,   193,   621,  -652,  -652,  -652,   532,   379,    56,    56,
    -652,   446,  -652,  -652,  -652,  -652,    21,   533,   534,   535,
     536,   538,   539,   193,    22,    64,   170,  -652,   425,   425,
     425,    22,   425,   425,   425,   425,   425,    22,    22,    22,
     193,   193,    24,  -652,    26,    29,  -652,  -652,  -652,    26,
      56,   193,  -652,  -652,   540,  -652,  -652,  -652,  -652,  -652,
    -652,   106,  -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,
    -652,  -652,  -652,   581,  -652,  -652,   579,   582,  -652,  -652,
     578,  -652,  -652,   293,   575,   399,  -652,    -4,   193,   193,
    -652,    26,   569,  -652,   403,   601,  -652,   369,   193,   128,
    -652,  -652,   168,   168,   168,   168,  -652,   168,   168,   168,
     168,  -652,   168,   168,  -652,   168,   168,   168,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,  -652,   577,  -652,   550,   569,
      -2,    26,    26,    26,   594,   403,  -652,  -652,  -652,   147,
    -652,   333,  -652,  -652,   146,  -652,  -652,  -652,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,
      26,    26,  -652,  -652,    26,    26,    26,   553,    -2,   607,
     594,  -652,  -652,  -652,   191,  -652,   333,  -652,   554,    26,
     556,   557,   560,  -652,   661,    26,   414,   624,   607,  -652,
    -652,  -652,  -652,   192,    26,  -652,  -652,  -652,  -652,  -652,
     -40,   569,   569,   569,   569,   569,  -652,   414,  -652,  -652,
    -652,  -652,  -652,    26,   620,   624,  -652,  -652,  -652,   580,
      28,  -652,   129,    26,   162,   163,    26,  -652,    26,   427,
    -652,   620,  -652,  -652,    26,  -652,  -652,    26,   569,  -652,
    -652,   569,  -652,   569,  -652,  -652,    26,  -652,   596,   593,
    -652,  -652,    26,  -652,    26,    26,    26,  -652,    26,    26,
    -652,  -652,  -652,  -652,  -652,  -652
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -652,  -652,  -652,  -652,  -652,  -652,  -652,   673,  -652,   605,
    -652,  -652,  -652,   562,  -652,   490,  -652,  -652,   431,   439,
     441,   442,  -652,  -652,  -652,   385,   -83,  -652,  -652,  -652,
     279,  -652,   248,  -652,   221,  -652,  -652,  -652,   341,  -269,
    -251,  -652,  -652,  -652,  -652,  -652,   -50,  -652,  -652,   616,
    -242,  -652,    65,  -652,   325,  -652,  -652,  -652,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,  -652,   415,  -162,  -652,  -652,
    -652,   263,  -652,  -652,  -458,  -652,  -652,  -652,  -652,  -652,
    -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,  -652,    91,
    -191,  -652,  -322,  -652,  -652,   195,  -652,  -652,    35,  -652,
    -652,  -652,  -652,  -652,  -652,   148,  -652,  -652,  -652,    58,
    -652,  -652,    32,  -652,  -652,    13,  -652,  -652,   114,  -652,
    -652,    78,  -652,  -651,  -494,  -652,  -282,  -259,   -84,   -31,
       0,   506,  -652,  -652,  -652,    93,    74,  -167,  -312,   -68,
    -652,   565,  -652,    -1,    92,  -652,   240,  -539,    17,  -652,
    -652,  -652,  -652,  -652,  -117,  -652,   668,  -213,  -652,   551,
    -652,  -652,  -652,  -240,  -652,  -652,  -652,  -652,   622
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -221
static const yytype_int16 yytable[] =
{
       8,   234,   138,   139,   193,   140,   282,   236,   336,    77,
     375,   321,    82,    83,    84,    85,    86,    87,    88,    89,
      90,    91,    96,   599,   384,   384,   168,   168,   130,   156,
     136,   136,   160,   337,   176,   531,   116,   136,   141,   177,
     514,   178,   417,     7,   366,     7,   179,   201,   718,   180,
     181,   182,   556,   557,   445,   446,   532,   533,   534,   183,
     631,     7,   367,   569,   184,     1,    92,   728,   227,   185,
     690,   368,     7,   370,   558,   559,   539,   123,     7,     9,
     562,   632,   134,   540,   229,   134,   134,   397,   117,   156,
     209,    96,    96,   633,   452,   366,   159,    93,    97,   161,
     595,   596,   558,   559,   322,   594,   453,   535,   536,     7,
     609,     7,   459,   367,   412,   131,   191,   131,   235,   391,
      10,   475,   368,   194,   370,   385,   523,     7,   109,   560,
     134,   244,   692,   693,   694,   695,   696,   649,   706,     7,
     650,   651,   652,   115,   267,   268,   269,    97,    96,    96,
      96,    96,    96,   468,   155,   665,   159,   147,   148,    97,
     121,   270,   271,   272,   273,   228,   232,    98,    99,   724,
       7,     7,   725,     7,   726,   243,   691,   236,   124,   149,
     150,   151,   541,    78,   558,   559,   152,   153,   247,   542,
      97,   221,   351,   163,   425,   262,   136,   155,   709,   710,
     712,   714,   715,   265,   716,   494,   558,   559,    35,   338,
     213,   571,     7,   723,   214,   215,   216,   217,   218,   283,
     282,   274,   727,   285,     7,   558,   559,     7,   730,   233,
     731,   732,   733,   610,   734,   735,   267,   268,   269,   708,
     122,   495,   496,   497,   418,     7,     7,   135,   474,   646,
     307,   233,   643,   270,   271,   272,   273,   498,   499,   500,
     501,   502,   503,   504,   505,   506,   507,   508,   509,     7,
     510,   611,   711,   713,   233,   233,   142,    10,   413,    98,
      99,    78,   436,   332,   168,   333,   334,   335,   190,   232,
     485,   232,   134,   143,   144,   661,   688,   406,   407,   408,
      35,   511,   345,   117,   203,   352,   204,   149,   196,   151,
     547,   361,   202,   467,   152,   153,   553,   554,   555,   206,
     374,   307,    13,    14,    15,   131,    16,    17,    18,    19,
     152,   153,    20,    21,    22,    23,   124,    24,    25,    26,
      27,    28,   149,    29,   455,   232,   478,   479,   210,   152,
     153,   211,   117,    30,    31,    32,    33,    34,   149,   150,
     151,   414,   409,   410,   411,   152,   153,   588,   589,   590,
     419,   476,   238,   239,   352,    13,    14,    15,   212,    16,
      17,    18,    19,   154,   223,    20,    21,    22,    23,   225,
      24,    25,    26,    27,    28,   226,    29,    71,   353,   354,
      72,    35,    36,    73,    37,   117,    30,    31,    32,    33,
      34,   237,   207,   176,   204,    38,   233,   307,   177,   454,
     178,   240,   721,   307,   208,   179,   204,   241,   180,   181,
     182,   294,   242,   295,   232,   567,   355,   356,   183,   252,
     253,   254,   255,   184,   645,   357,   358,   647,   185,   302,
     246,   303,   352,   249,   477,    36,   362,    37,   352,   486,
     487,   488,   600,   601,   602,   603,   359,   360,   363,   672,
     673,   674,   675,   592,   608,   593,   204,   662,   250,   645,
     312,   371,   445,   446,   518,   519,   478,   479,    13,    14,
      15,   264,    16,    17,    18,    19,   662,   251,    20,    21,
      22,    23,   204,    24,    25,    26,    27,    28,   292,    29,
     535,   536,   266,   561,    72,   717,   289,   291,   134,    30,
      31,    32,    33,    34,   312,   293,   330,   346,   348,   383,
     420,   105,   106,   107,   108,   387,   110,   111,   112,   113,
     114,   612,   612,   612,   612,   388,   612,   612,   612,   612,
     389,   612,   612,   399,   612,   612,   612,   390,   392,   393,
     598,   394,   395,   396,   398,   400,   401,    35,    36,   402,
      37,   403,   613,   613,   613,   613,   404,   613,   613,   613,
     613,    38,   613,   613,   405,   613,   613,   613,   424,   543,
     544,   545,   546,   548,   549,   550,   551,   552,   435,   434,
     635,   636,   637,   426,   427,   428,   455,   429,   162,   430,
     431,   164,   165,   166,   167,   432,   171,   172,   173,   174,
     175,   437,   438,   439,   440,   441,   442,   443,   444,   648,
     598,   469,   514,   598,   598,   598,   200,   517,   525,   526,
     527,   528,   205,   529,   530,   570,   576,  -220,   598,   584,
     581,   591,   562,    71,   671,   558,   630,   638,   653,   655,
     664,   666,   667,   689,   669,   668,   618,   619,   620,   598,
     621,   622,   623,   624,   699,   625,   626,   683,   627,   628,
     629,   717,   698,    72,    79,   125,   704,   263,   317,   707,
     199,   598,   598,   598,   598,   598,   318,   598,   319,   320,
     372,   458,   522,   232,   480,   415,   598,   146,   433,   339,
     563,   473,   697,   607,   720,   598,   687,   703,   660,   642,
     663,   598,   222,   598,   598,   598,   524,   598,   598,   284,
     654,   286,   287,   288,   119,   290,   729,   245,     0,     0,
     192,     0,     0,   296,     0,   297,   298,   299,   300,   301,
       0,     0,     0,     0,     0,   304,     0,     0,   308,   309,
     310,   311,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   323,   324,   325,   326,   327,   328,   329,
      13,    14,    15,     0,    16,    17,    18,    19,     0,     0,
      20,    21,    22,    23,     0,    24,    25,    26,    27,    28,
       0,    29,   340,   341,   342,   343,   344,     0,     0,     0,
       0,    30,    31,    32,    33,    34,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   376,
     377,   378,   379,   380,   381,   382,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      36,   362,    37,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   363,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   460,   461,   462,   463,   464,   465,   466,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   470,   471,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   489,
     490,   491,   492,     0,     0,     0,   493,     0,     0,     0,
       0,     0,     0,     0,   520,   521,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   568
};

static const yytype_int16 yycheck[] =
{
       1,   168,    86,    87,   121,    88,   219,   169,   290,    10,
     322,    10,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,   562,     4,     4,    12,    12,    20,    97,
      21,    21,   100,   292,     7,   493,    37,    21,    88,    12,
      11,    14,   364,    83,   313,    83,    19,   131,   699,    22,
      23,    24,   510,   511,     8,     9,    34,    35,    36,    32,
     599,    83,   313,   521,    37,    89,    77,   718,   106,    42,
     110,   313,    83,   313,    78,    79,    12,    78,    83,     0,
      51,    83,    83,    19,   106,    86,    87,   346,    42,   157,
     140,    92,    93,    95,   416,   364,    97,   108,   103,   100,
     558,   559,    78,    79,   103,   109,   418,    85,    86,    83,
     568,    83,   424,   364,   105,   107,   117,   107,   104,   104,
       7,   105,   364,   124,   364,   105,   105,    83,   103,   105,
     131,   104,   671,   672,   673,   674,   675,   631,   110,    83,
     634,   635,   636,   103,    27,    28,    29,   103,   149,   150,
     151,   152,   153,   435,   110,   649,   157,    92,    93,   103,
     103,    44,    45,    46,    47,   166,   167,   111,   112,   708,
      83,    83,   711,    83,   713,   176,   670,   339,     6,    78,
      79,    80,    12,    11,    78,    79,    85,    86,   189,    19,
     103,   104,   104,   110,   104,   196,    21,   110,   692,   693,
     694,   695,   696,   204,   698,    12,    78,    79,    91,   293,
     109,   105,    83,   707,   149,   150,   151,   152,   153,   220,
     433,   104,   716,   224,    83,    78,    79,    83,   722,    83,
     724,   725,   726,   105,   728,   729,    27,    28,    29,   110,
     105,    48,    49,    50,   103,    83,    83,   105,   104,   103,
     251,    83,   105,    44,    45,    46,    47,    64,    65,    66,
      67,    68,    69,    70,    71,    72,    73,    74,    75,    83,
      77,   103,   110,   110,    83,    83,   105,     7,   361,   111,
     112,    11,   399,   284,    12,   286,   287,   288,   105,   290,
     104,   292,   293,    81,    82,   104,   104,   100,   101,   102,
      91,   108,   303,    42,   105,   306,   107,    78,     7,    80,
     501,   312,   105,   104,    85,    86,   507,   508,   509,   105,
     321,   322,    12,    13,    14,   107,    16,    17,    18,    19,
      85,    86,    22,    23,    24,    25,     6,    27,    28,    29,
      30,    31,    78,    33,    38,   346,    40,    41,   105,    85,
      86,   105,    42,    43,    44,    45,    46,    47,    78,    79,
      80,   362,   100,   101,   102,    85,    86,    74,    75,    76,
     371,   454,   105,   106,   375,    12,    13,    14,   105,    16,
      17,    18,    19,   103,   106,    22,    23,    24,    25,   106,
      27,    28,    29,    30,    31,   106,    33,    84,    48,    49,
      87,    91,    92,    90,    94,    42,    43,    44,    45,    46,
      47,   106,   105,     7,   107,   105,    83,   418,    12,   420,
      14,   106,   704,   424,   105,    19,   107,   106,    22,    23,
      24,   103,   106,   105,   435,   519,    48,    49,    32,    96,
      97,    98,    99,    37,   611,    48,    49,   614,    42,   105,
     105,   107,   453,    15,   455,    92,    93,    94,   459,   460,
     461,   462,    59,    60,    61,    62,    48,    49,   105,    55,
      56,    57,    58,    74,   105,    76,   107,   644,   104,   646,
      32,    33,     8,     9,   105,   106,    40,    41,    12,    13,
      14,   105,    16,    17,    18,    19,   663,   103,    22,    23,
      24,    25,   107,    27,    28,    29,    30,    31,   110,    33,
      85,    86,   105,   514,    87,    88,   105,   105,   519,    43,
      44,    45,    46,    47,    32,   106,    26,    38,    26,   103,
      37,    25,    26,    27,    28,   105,    30,    31,    32,    33,
      34,   572,   573,   574,   575,   105,   577,   578,   579,   580,
     105,   582,   583,   103,   585,   586,   587,   105,   105,   105,
     561,   105,   105,   105,   105,   105,   105,    91,    92,   105,
      94,   105,   572,   573,   574,   575,   105,   577,   578,   579,
     580,   105,   582,   583,   105,   585,   586,   587,   103,   498,
     499,   500,   501,   502,   503,   504,   505,   506,    39,   105,
     601,   602,   603,   106,   106,   106,    38,   106,   102,   106,
     106,   105,   106,   107,   108,   106,   110,   111,   112,   113,
     114,   105,   105,   105,   105,   105,   105,   105,   105,   630,
     631,   104,    11,   634,   635,   636,   130,   105,   105,   105,
     105,   105,   136,   105,   105,   105,    65,    68,   649,    71,
      68,    76,    51,    84,   655,    78,   106,    63,   105,    52,
     106,   105,   105,   664,     3,   105,   573,   574,   575,   670,
     577,   578,   579,   580,    54,   582,   583,    53,   585,   586,
     587,    88,   683,    87,    11,    80,   106,   197,   257,   690,
     128,   692,   693,   694,   695,   696,   257,   698,   257,   257,
     315,   422,   481,   704,   456,   364,   707,    91,   383,   294,
     515,   448,   677,   565,   701,   716,   658,   685,   640,   605,
     646,   722,   157,   724,   725,   726,   486,   728,   729,   223,
     638,   225,   226,   227,    66,   229,   719,   186,    -1,    -1,
     118,    -1,    -1,   237,    -1,   239,   240,   241,   242,   243,
      -1,    -1,    -1,    -1,    -1,   249,    -1,    -1,   252,   253,
     254,   255,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   267,   268,   269,   270,   271,   272,   273,
      12,    13,    14,    -1,    16,    17,    18,    19,    -1,    -1,
      22,    23,    24,    25,    -1,    27,    28,    29,    30,    31,
      -1,    33,   296,   297,   298,   299,   300,    -1,    -1,    -1,
      -1,    43,    44,    45,    46,    47,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   323,
     324,   325,   326,   327,   328,   329,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      92,    93,    94,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   105,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   426,   427,   428,   429,   430,   431,   432,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   445,   446,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   463,
     464,   465,   466,    -1,    -1,    -1,   470,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   478,   479,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   520
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint16 yystos[] =
{
       0,    89,   114,   115,   116,   274,   275,    83,   266,     0,
       7,   119,   120,    12,    13,    14,    16,    17,    18,    19,
      22,    23,    24,    25,    27,    28,    29,    30,    31,    33,
      43,    44,    45,    46,    47,    91,    92,    94,   105,   152,
     153,   154,   155,   156,   157,   158,   160,   161,   163,   175,
     176,   177,   178,   179,   180,   181,   182,   183,   184,   185,
     186,   187,   188,   191,   273,   277,   278,   279,   280,   286,
     289,    84,    87,    90,   246,   270,   276,   266,    11,   120,
     121,   122,   266,   266,   266,   266,   266,   266,   266,   266,
     266,   266,    77,   108,   165,   166,   266,   103,   111,   112,
     252,   253,   254,   262,   266,   254,   254,   254,   254,   103,
     254,   254,   254,   254,   254,   103,   266,    42,   215,   279,
     291,   103,   105,   266,     6,   122,   123,   124,   125,   126,
      20,   107,   159,   251,   266,   105,    21,   139,   251,   251,
     139,   159,   105,    81,    82,   162,   162,   165,   165,    78,
      79,    80,    85,    86,   103,   110,   262,   263,   264,   266,
     262,   266,   254,   110,   254,   254,   254,   254,    12,   189,
     190,   254,   254,   254,   254,   254,     7,    12,    14,    19,
      22,    23,    24,    32,    37,    42,   281,   282,   283,   284,
     105,   266,   291,   277,   266,   117,     7,   127,   128,   126,
     254,   251,   105,   105,   107,   254,   105,   105,   105,   159,
     105,   105,   105,   109,   165,   165,   165,   165,   165,   167,
     265,   104,   264,   106,   255,   106,   106,   106,   266,   106,
     249,   250,   266,    83,   260,   104,   190,   106,   105,   106,
     106,   106,   106,   266,   104,   282,   105,   266,   285,    15,
     104,   103,    96,    97,    98,    99,   129,   130,   131,   132,
     133,   134,   266,   128,   105,   266,   105,    27,    28,    29,
      44,    45,    46,    47,   104,   168,   169,   170,   171,   172,
     173,   174,   280,   266,   254,   266,   254,   254,   254,   105,
     254,   105,   110,   106,   103,   105,   254,   254,   254,   254,
     254,   254,   105,   107,   254,   287,   261,   266,   254,   254,
     254,   254,    32,   135,   136,   137,   138,   131,   132,   133,
     134,    10,   103,   254,   254,   254,   254,   254,   254,   254,
      26,   164,   266,   266,   266,   266,   249,   250,   251,   189,
     254,   254,   254,   254,   254,   266,    38,   216,    26,   288,
     290,   104,   266,    48,    49,    48,    49,    48,    49,    48,
      49,   266,    93,   105,   150,   151,   152,   153,   163,   272,
     286,    33,   138,   140,   266,   261,   254,   254,   254,   254,
     254,   254,   254,   103,     4,   105,   269,   105,   105,   105,
     105,   104,   105,   105,   105,   105,   105,   250,   105,   103,
     105,   105,   105,   105,   105,   105,   100,   101,   102,   100,
     101,   102,   105,   139,   266,   151,   214,   215,   103,   266,
      37,   141,   142,   143,   103,   104,   106,   106,   106,   106,
     106,   106,   106,   167,   105,    39,   277,   105,   105,   105,
     105,   105,   105,   105,   105,     8,     9,   192,   193,   194,
     195,   196,   215,   261,   266,    38,   144,   145,   143,   261,
     254,   254,   254,   254,   254,   254,   254,   104,   249,   104,
     254,   254,   118,   194,   104,   105,   139,   266,    40,    41,
     145,   146,   147,   148,   149,   104,   266,   266,   266,   254,
     254,   254,   254,   254,    12,    48,    49,    50,    64,    65,
      66,    67,    68,    69,    70,    71,    72,    73,    74,    75,
      77,   108,   197,   198,    11,   217,   218,   105,   105,   106,
     254,   254,   147,   105,   269,   105,   105,   105,   105,   105,
     105,   197,    34,    35,    36,    85,    86,   212,   213,    12,
      19,    12,    19,   212,   212,   212,   212,   213,   212,   212,
     212,   212,   212,   213,   213,   213,   197,   197,    78,    79,
     105,   266,    51,   218,   226,   227,   228,   251,   254,   197,
     105,   105,   208,   210,   209,   211,    65,   199,   200,   201,
     202,    68,   203,   204,    71,   205,   206,   207,    74,    75,
      76,    76,    74,    76,   109,   197,   197,   247,   266,   270,
      59,    60,    61,    62,   239,   240,   241,   228,   105,   197,
     105,   103,   252,   253,   256,   257,   258,   260,   258,   258,
     258,   258,   258,   258,   258,   258,   258,   258,   258,   258,
     106,   270,    83,    95,   267,   266,   266,   266,    63,   242,
     243,   244,   241,   105,   259,   260,   103,   260,   266,   247,
     247,   247,   247,   105,   267,    52,   229,   230,   231,   232,
     244,   104,   260,   259,   106,   247,   105,   105,   105,     3,
     268,   266,    55,    56,    57,    58,   219,   220,   221,   222,
     223,   224,   225,    53,   233,   234,   235,   232,   104,   266,
     110,   247,   270,   270,   270,   270,   270,   221,   266,    54,
     236,   237,   238,   235,   106,   248,   110,   266,   110,   247,
     247,   110,   247,   110,   247,   247,   247,    88,   246,   271,
     238,   249,   245,   247,   270,   270,   270,   247,   246,   271,
     247,   247,   247,   247,   247,   247
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  However,
   YYFAIL appears to be in use.  Nevertheless, it is formally deprecated
   in Bison 2.4.2's NEWS entry, where a plan to phase it out is
   discussed.  */

#define YYFAIL		goto yyerrlab
#if defined YYFAIL
  /* This is here to suppress warnings from the GCC cpp's
     -Wunused-macros.  Normally we don't worry about that warning, but
     some users do, and we want to make it easy for users to remove
     YYFAIL uses, which will produce warnings from Bison 2.5.  */
#endif

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

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
#ifndef	YYINITDEPTH
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
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
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
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
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

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}

/* Prevent warnings from -Wmissing-prototypes.  */
#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */


/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*-------------------------.
| yyparse or yypush_parse.  |
`-------------------------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{


    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.

       Refer to the stacks thru separate pointers, to allow yyoverflow
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
  int yytoken;
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

  yytoken = 0;
  yyss = yyssa;
  yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */
  yyssp = yyss;
  yyvsp = yyvs;

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
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
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
      if (yyn == 0 || yyn == YYTABLE_NINF)
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
  *++yyvsp = yylval;

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
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 4:

/* Line 1464 of yacc.c  */
#line 183 "policy_parse.y"
    { if (define_policy(pass, 0) == -1) return -1; }
    break;

  case 5:

/* Line 1464 of yacc.c  */
#line 185 "policy_parse.y"
    { if (pass == 1) { if (policydb_index_classes(policydbp)) return -1; }
                            else if (pass == 2) { if (policydb_index_others(NULL, policydbp, 0)) return -1; }}
    break;

  case 6:

/* Line 1464 of yacc.c  */
#line 188 "policy_parse.y"
    { if (pass == 1) { if (policydb_index_bools(policydbp)) return -1;}
			   else if (pass == 2) { if (policydb_index_others(NULL, policydbp, 0)) return -1;}}
    break;

  case 10:

/* Line 1464 of yacc.c  */
#line 196 "policy_parse.y"
    {if (define_class()) return -1;}
    break;

  case 13:

/* Line 1464 of yacc.c  */
#line 202 "policy_parse.y"
    {if (define_initial_sid()) return -1;}
    break;

  case 19:

/* Line 1464 of yacc.c  */
#line 213 "policy_parse.y"
    {if (define_common_perms()) return -1;}
    break;

  case 22:

/* Line 1464 of yacc.c  */
#line 219 "policy_parse.y"
    {if (define_av_perms(FALSE)) return -1;}
    break;

  case 23:

/* Line 1464 of yacc.c  */
#line 221 "policy_parse.y"
    {if (define_av_perms(TRUE)) return -1;}
    break;

  case 24:

/* Line 1464 of yacc.c  */
#line 223 "policy_parse.y"
    {if (define_av_perms(TRUE)) return -1;}
    break;

  case 35:

/* Line 1464 of yacc.c  */
#line 238 "policy_parse.y"
    {if (define_default_user(DEFAULT_SOURCE)) return -1; }
    break;

  case 36:

/* Line 1464 of yacc.c  */
#line 240 "policy_parse.y"
    {if (define_default_user(DEFAULT_TARGET)) return -1; }
    break;

  case 37:

/* Line 1464 of yacc.c  */
#line 243 "policy_parse.y"
    {if (define_default_role(DEFAULT_SOURCE)) return -1; }
    break;

  case 38:

/* Line 1464 of yacc.c  */
#line 245 "policy_parse.y"
    {if (define_default_role(DEFAULT_TARGET)) return -1; }
    break;

  case 39:

/* Line 1464 of yacc.c  */
#line 248 "policy_parse.y"
    {if (define_default_type(DEFAULT_SOURCE)) return -1; }
    break;

  case 40:

/* Line 1464 of yacc.c  */
#line 250 "policy_parse.y"
    {if (define_default_type(DEFAULT_TARGET)) return -1; }
    break;

  case 41:

/* Line 1464 of yacc.c  */
#line 253 "policy_parse.y"
    {if (define_default_range(DEFAULT_SOURCE_LOW)) return -1; }
    break;

  case 42:

/* Line 1464 of yacc.c  */
#line 255 "policy_parse.y"
    {if (define_default_range(DEFAULT_SOURCE_HIGH)) return -1; }
    break;

  case 43:

/* Line 1464 of yacc.c  */
#line 257 "policy_parse.y"
    {if (define_default_range(DEFAULT_SOURCE_LOW_HIGH)) return -1; }
    break;

  case 44:

/* Line 1464 of yacc.c  */
#line 259 "policy_parse.y"
    {if (define_default_range(DEFAULT_TARGET_LOW)) return -1; }
    break;

  case 45:

/* Line 1464 of yacc.c  */
#line 261 "policy_parse.y"
    {if (define_default_range(DEFAULT_TARGET_HIGH)) return -1; }
    break;

  case 46:

/* Line 1464 of yacc.c  */
#line 263 "policy_parse.y"
    {if (define_default_range(DEFAULT_TARGET_LOW_HIGH)) return -1; }
    break;

  case 52:

/* Line 1464 of yacc.c  */
#line 282 "policy_parse.y"
    {if (define_mls() | define_sens()) return -1;}
    break;

  case 53:

/* Line 1464 of yacc.c  */
#line 284 "policy_parse.y"
    {if (define_mls() | define_sens()) return -1;}
    break;

  case 55:

/* Line 1464 of yacc.c  */
#line 289 "policy_parse.y"
    {if (define_dominance()) return -1;}
    break;

  case 56:

/* Line 1464 of yacc.c  */
#line 291 "policy_parse.y"
    {if (define_dominance()) return -1;}
    break;

  case 61:

/* Line 1464 of yacc.c  */
#line 300 "policy_parse.y"
    {if (define_category()) return -1;}
    break;

  case 62:

/* Line 1464 of yacc.c  */
#line 302 "policy_parse.y"
    {if (define_category()) return -1;}
    break;

  case 65:

/* Line 1464 of yacc.c  */
#line 308 "policy_parse.y"
    {if (define_level()) return -1;}
    break;

  case 66:

/* Line 1464 of yacc.c  */
#line 310 "policy_parse.y"
    {if (define_level()) return -1;}
    break;

  case 71:

/* Line 1464 of yacc.c  */
#line 319 "policy_parse.y"
    { if (define_constraint((constraint_expr_t*)(yyvsp[(4) - (5)].valptr))) return -1; }
    break;

  case 72:

/* Line 1464 of yacc.c  */
#line 322 "policy_parse.y"
    { if (define_validatetrans((constraint_expr_t*)(yyvsp[(3) - (4)].valptr))) return -1; }
    break;

  case 99:

/* Line 1464 of yacc.c  */
#line 355 "policy_parse.y"
    { if (define_attrib()) return -1;}
    break;

  case 100:

/* Line 1464 of yacc.c  */
#line 358 "policy_parse.y"
    {if (define_type(1)) return -1;}
    break;

  case 101:

/* Line 1464 of yacc.c  */
#line 360 "policy_parse.y"
    {if (define_type(0)) return -1;}
    break;

  case 102:

/* Line 1464 of yacc.c  */
#line 363 "policy_parse.y"
    {if (define_typealias()) return -1;}
    break;

  case 103:

/* Line 1464 of yacc.c  */
#line 366 "policy_parse.y"
    {if (define_typeattribute()) return -1;}
    break;

  case 104:

/* Line 1464 of yacc.c  */
#line 369 "policy_parse.y"
    {if (define_typebounds()) return -1;}
    break;

  case 107:

/* Line 1464 of yacc.c  */
#line 375 "policy_parse.y"
    { if (define_bool_tunable(0)) return -1; }
    break;

  case 108:

/* Line 1464 of yacc.c  */
#line 378 "policy_parse.y"
    { if (define_bool_tunable(1)) return -1; }
    break;

  case 109:

/* Line 1464 of yacc.c  */
#line 381 "policy_parse.y"
    { if (insert_id("T",0)) return -1; }
    break;

  case 110:

/* Line 1464 of yacc.c  */
#line 383 "policy_parse.y"
    { if (insert_id("F",0)) return -1; }
    break;

  case 111:

/* Line 1464 of yacc.c  */
#line 386 "policy_parse.y"
    { if (pass == 2) { if (define_conditional((cond_expr_t*)(yyvsp[(2) - (6)].ptr), (avrule_t*)(yyvsp[(4) - (6)].ptr), (avrule_t*)(yyvsp[(6) - (6)].ptr)) < 0) return -1;  }}
    break;

  case 112:

/* Line 1464 of yacc.c  */
#line 389 "policy_parse.y"
    { (yyval.ptr) = (yyvsp[(3) - (4)].ptr); }
    break;

  case 113:

/* Line 1464 of yacc.c  */
#line 391 "policy_parse.y"
    { (yyval.ptr) = NULL; }
    break;

  case 114:

/* Line 1464 of yacc.c  */
#line 393 "policy_parse.y"
    { (yyval.ptr) = (yyvsp[(2) - (3)].ptr);}
    break;

  case 115:

/* Line 1464 of yacc.c  */
#line 395 "policy_parse.y"
    { (yyval.ptr) = define_cond_expr(COND_NOT, (yyvsp[(2) - (2)].ptr), 0);
			  if ((yyval.ptr) == 0) return -1; }
    break;

  case 116:

/* Line 1464 of yacc.c  */
#line 398 "policy_parse.y"
    { (yyval.ptr) = define_cond_expr(COND_AND, (yyvsp[(1) - (3)].ptr), (yyvsp[(3) - (3)].ptr));
			  if ((yyval.ptr) == 0) return  -1; }
    break;

  case 117:

/* Line 1464 of yacc.c  */
#line 401 "policy_parse.y"
    { (yyval.ptr) = define_cond_expr(COND_OR, (yyvsp[(1) - (3)].ptr), (yyvsp[(3) - (3)].ptr));
			  if ((yyval.ptr) == 0) return   -1; }
    break;

  case 118:

/* Line 1464 of yacc.c  */
#line 404 "policy_parse.y"
    { (yyval.ptr) = define_cond_expr(COND_XOR, (yyvsp[(1) - (3)].ptr), (yyvsp[(3) - (3)].ptr));
			  if ((yyval.ptr) == 0) return  -1; }
    break;

  case 119:

/* Line 1464 of yacc.c  */
#line 407 "policy_parse.y"
    { (yyval.ptr) = define_cond_expr(COND_EQ, (yyvsp[(1) - (3)].ptr), (yyvsp[(3) - (3)].ptr));
			  if ((yyval.ptr) == 0) return  -1; }
    break;

  case 120:

/* Line 1464 of yacc.c  */
#line 410 "policy_parse.y"
    { (yyval.ptr) = define_cond_expr(COND_NEQ, (yyvsp[(1) - (3)].ptr), (yyvsp[(3) - (3)].ptr));
			  if ((yyval.ptr) == 0) return  -1; }
    break;

  case 121:

/* Line 1464 of yacc.c  */
#line 413 "policy_parse.y"
    { (yyval.ptr) = (yyvsp[(1) - (1)].ptr); }
    break;

  case 122:

/* Line 1464 of yacc.c  */
#line 416 "policy_parse.y"
    { (yyval.ptr) = define_cond_expr(COND_BOOL,0, 0);
			  if ((yyval.ptr) == COND_ERR) return   -1; }
    break;

  case 123:

/* Line 1464 of yacc.c  */
#line 420 "policy_parse.y"
    { (yyval.ptr) = define_cond_pol_list((avrule_t *)(yyvsp[(1) - (2)].ptr), (avrule_t *)(yyvsp[(2) - (2)].ptr)); }
    break;

  case 124:

/* Line 1464 of yacc.c  */
#line 422 "policy_parse.y"
    { (yyval.ptr) = NULL; }
    break;

  case 125:

/* Line 1464 of yacc.c  */
#line 425 "policy_parse.y"
    { (yyval.ptr) = (yyvsp[(1) - (1)].ptr); }
    break;

  case 126:

/* Line 1464 of yacc.c  */
#line 427 "policy_parse.y"
    { (yyval.ptr) = (yyvsp[(1) - (1)].ptr); }
    break;

  case 127:

/* Line 1464 of yacc.c  */
#line 429 "policy_parse.y"
    { (yyval.ptr) = NULL; }
    break;

  case 128:

/* Line 1464 of yacc.c  */
#line 432 "policy_parse.y"
    { (yyval.ptr) = define_cond_filename_trans() ;
                          if ((yyval.ptr) == COND_ERR) return -1;}
    break;

  case 129:

/* Line 1464 of yacc.c  */
#line 435 "policy_parse.y"
    { (yyval.ptr) = define_cond_compute_type(AVRULE_TRANSITION) ;
                          if ((yyval.ptr) == COND_ERR) return -1;}
    break;

  case 130:

/* Line 1464 of yacc.c  */
#line 438 "policy_parse.y"
    { (yyval.ptr) = define_cond_compute_type(AVRULE_MEMBER) ;
                          if ((yyval.ptr) ==  COND_ERR) return -1;}
    break;

  case 131:

/* Line 1464 of yacc.c  */
#line 441 "policy_parse.y"
    { (yyval.ptr) = define_cond_compute_type(AVRULE_CHANGE) ;
                          if ((yyval.ptr) == COND_ERR) return -1;}
    break;

  case 132:

/* Line 1464 of yacc.c  */
#line 445 "policy_parse.y"
    { (yyval.ptr) = (yyvsp[(1) - (1)].ptr); }
    break;

  case 133:

/* Line 1464 of yacc.c  */
#line 447 "policy_parse.y"
    { (yyval.ptr) = (yyvsp[(1) - (1)].ptr); }
    break;

  case 134:

/* Line 1464 of yacc.c  */
#line 449 "policy_parse.y"
    { (yyval.ptr) = (yyvsp[(1) - (1)].ptr); }
    break;

  case 135:

/* Line 1464 of yacc.c  */
#line 451 "policy_parse.y"
    { (yyval.ptr) = (yyvsp[(1) - (1)].ptr); }
    break;

  case 136:

/* Line 1464 of yacc.c  */
#line 454 "policy_parse.y"
    { (yyval.ptr) = define_cond_te_avtab(AVRULE_ALLOWED) ;
                          if ((yyval.ptr) == COND_ERR) return -1; }
    break;

  case 137:

/* Line 1464 of yacc.c  */
#line 458 "policy_parse.y"
    { (yyval.ptr) = define_cond_te_avtab(AVRULE_AUDITALLOW) ;
                          if ((yyval.ptr) == COND_ERR) return -1; }
    break;

  case 138:

/* Line 1464 of yacc.c  */
#line 462 "policy_parse.y"
    { (yyval.ptr) = define_cond_te_avtab(AVRULE_AUDITDENY) ;
                          if ((yyval.ptr) == COND_ERR) return -1; }
    break;

  case 139:

/* Line 1464 of yacc.c  */
#line 466 "policy_parse.y"
    { (yyval.ptr) = define_cond_te_avtab(AVRULE_DONTAUDIT);
                          if ((yyval.ptr) == COND_ERR) return -1; }
    break;

  case 140:

/* Line 1464 of yacc.c  */
#line 471 "policy_parse.y"
    {if (define_filename_trans()) return -1; }
    break;

  case 141:

/* Line 1464 of yacc.c  */
#line 473 "policy_parse.y"
    {if (define_compute_type(AVRULE_TRANSITION)) return -1;}
    break;

  case 142:

/* Line 1464 of yacc.c  */
#line 475 "policy_parse.y"
    {if (define_compute_type(AVRULE_MEMBER)) return -1;}
    break;

  case 143:

/* Line 1464 of yacc.c  */
#line 477 "policy_parse.y"
    {if (define_compute_type(AVRULE_CHANGE)) return -1;}
    break;

  case 144:

/* Line 1464 of yacc.c  */
#line 480 "policy_parse.y"
    { if (define_range_trans(0)) return -1; }
    break;

  case 145:

/* Line 1464 of yacc.c  */
#line 482 "policy_parse.y"
    { if (define_range_trans(1)) return -1; }
    break;

  case 151:

/* Line 1464 of yacc.c  */
#line 491 "policy_parse.y"
    {if (define_te_avtab(AVRULE_ALLOWED)) return -1; }
    break;

  case 152:

/* Line 1464 of yacc.c  */
#line 494 "policy_parse.y"
    {if (define_te_avtab(AVRULE_AUDITALLOW)) return -1; }
    break;

  case 153:

/* Line 1464 of yacc.c  */
#line 497 "policy_parse.y"
    {if (define_te_avtab(AVRULE_AUDITDENY)) return -1; }
    break;

  case 154:

/* Line 1464 of yacc.c  */
#line 500 "policy_parse.y"
    {if (define_te_avtab(AVRULE_DONTAUDIT)) return -1; }
    break;

  case 155:

/* Line 1464 of yacc.c  */
#line 503 "policy_parse.y"
    {if (define_te_avtab(AVRULE_NEVERALLOW)) return -1; }
    break;

  case 156:

/* Line 1464 of yacc.c  */
#line 506 "policy_parse.y"
    {if (define_attrib_role()) return -1; }
    break;

  case 157:

/* Line 1464 of yacc.c  */
#line 509 "policy_parse.y"
    {if (define_role_types()) return -1;}
    break;

  case 158:

/* Line 1464 of yacc.c  */
#line 512 "policy_parse.y"
    {if (define_role_attr()) return -1;}
    break;

  case 160:

/* Line 1464 of yacc.c  */
#line 517 "policy_parse.y"
    {if (define_role_trans(0)) return -1; }
    break;

  case 161:

/* Line 1464 of yacc.c  */
#line 519 "policy_parse.y"
    {if (define_role_trans(1)) return -1;}
    break;

  case 162:

/* Line 1464 of yacc.c  */
#line 522 "policy_parse.y"
    {if (define_role_allow()) return -1; }
    break;

  case 163:

/* Line 1464 of yacc.c  */
#line 525 "policy_parse.y"
    { (yyval.ptr) = (yyvsp[(1) - (1)].ptr); }
    break;

  case 164:

/* Line 1464 of yacc.c  */
#line 527 "policy_parse.y"
    { (yyval.ptr) = merge_roles_dom((role_datum_t*)(yyvsp[(1) - (2)].ptr), (role_datum_t*)(yyvsp[(2) - (2)].ptr)); if ((yyval.ptr) == 0) return -1;}
    break;

  case 165:

/* Line 1464 of yacc.c  */
#line 530 "policy_parse.y"
    {(yyval.ptr) = define_role_dom(NULL); if ((yyval.ptr) == 0) return -1;}
    break;

  case 166:

/* Line 1464 of yacc.c  */
#line 532 "policy_parse.y"
    {(yyval.ptr) = define_role_dom((role_datum_t*)(yyvsp[(4) - (5)].ptr)); if ((yyval.ptr) == 0) return -1;}
    break;

  case 167:

/* Line 1464 of yacc.c  */
#line 535 "policy_parse.y"
    {if (define_roleattribute()) return -1;}
    break;

  case 174:

/* Line 1464 of yacc.c  */
#line 547 "policy_parse.y"
    { if (define_constraint((constraint_expr_t*)(yyvsp[(4) - (5)].valptr))) return -1; }
    break;

  case 175:

/* Line 1464 of yacc.c  */
#line 550 "policy_parse.y"
    { if (define_validatetrans((constraint_expr_t*)(yyvsp[(3) - (4)].valptr))) return -1; }
    break;

  case 176:

/* Line 1464 of yacc.c  */
#line 553 "policy_parse.y"
    { (yyval.valptr) = (yyvsp[(2) - (3)].valptr); }
    break;

  case 177:

/* Line 1464 of yacc.c  */
#line 555 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NOT, (yyvsp[(2) - (2)].valptr), 0);
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 178:

/* Line 1464 of yacc.c  */
#line 558 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_AND, (yyvsp[(1) - (3)].valptr), (yyvsp[(3) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 179:

/* Line 1464 of yacc.c  */
#line 561 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_OR, (yyvsp[(1) - (3)].valptr), (yyvsp[(3) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 180:

/* Line 1464 of yacc.c  */
#line 564 "policy_parse.y"
    { (yyval.valptr) = (yyvsp[(1) - (1)].valptr); }
    break;

  case 181:

/* Line 1464 of yacc.c  */
#line 567 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_USER, (yyvsp[(2) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 182:

/* Line 1464 of yacc.c  */
#line 570 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_ROLE, (yyvsp[(2) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 183:

/* Line 1464 of yacc.c  */
#line 573 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_TYPE, (yyvsp[(2) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 184:

/* Line 1464 of yacc.c  */
#line 575 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 185:

/* Line 1464 of yacc.c  */
#line 576 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, CEXPR_USER, (yyvsp[(2) - (4)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 186:

/* Line 1464 of yacc.c  */
#line 578 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 187:

/* Line 1464 of yacc.c  */
#line 579 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, (CEXPR_USER | CEXPR_TARGET), (yyvsp[(2) - (4)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 188:

/* Line 1464 of yacc.c  */
#line 581 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 189:

/* Line 1464 of yacc.c  */
#line 582 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, (CEXPR_USER | CEXPR_XTARGET), (yyvsp[(2) - (4)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 190:

/* Line 1464 of yacc.c  */
#line 584 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 191:

/* Line 1464 of yacc.c  */
#line 585 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, CEXPR_ROLE, (yyvsp[(2) - (4)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 192:

/* Line 1464 of yacc.c  */
#line 587 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 193:

/* Line 1464 of yacc.c  */
#line 588 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_TARGET), (yyvsp[(2) - (4)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 194:

/* Line 1464 of yacc.c  */
#line 590 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 195:

/* Line 1464 of yacc.c  */
#line 591 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_XTARGET), (yyvsp[(2) - (4)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 196:

/* Line 1464 of yacc.c  */
#line 593 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 197:

/* Line 1464 of yacc.c  */
#line 594 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, CEXPR_TYPE, (yyvsp[(2) - (4)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 198:

/* Line 1464 of yacc.c  */
#line 596 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 199:

/* Line 1464 of yacc.c  */
#line 597 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_TARGET), (yyvsp[(2) - (4)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 200:

/* Line 1464 of yacc.c  */
#line 599 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 201:

/* Line 1464 of yacc.c  */
#line 600 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_XTARGET), (yyvsp[(2) - (4)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 202:

/* Line 1464 of yacc.c  */
#line 603 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_USER, CEXPR_EQ);
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 203:

/* Line 1464 of yacc.c  */
#line 605 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 204:

/* Line 1464 of yacc.c  */
#line 606 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, CEXPR_ROLE, CEXPR_EQ);
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 205:

/* Line 1464 of yacc.c  */
#line 608 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 206:

/* Line 1464 of yacc.c  */
#line 609 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_TARGET), CEXPR_EQ);
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 207:

/* Line 1464 of yacc.c  */
#line 612 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_ROLE, (yyvsp[(2) - (2)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 208:

/* Line 1464 of yacc.c  */
#line 614 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 209:

/* Line 1464 of yacc.c  */
#line 615 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, CEXPR_TYPE, CEXPR_EQ);
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 210:

/* Line 1464 of yacc.c  */
#line 617 "policy_parse.y"
    { if (insert_separator(1)) return -1; }
    break;

  case 211:

/* Line 1464 of yacc.c  */
#line 618 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_TARGET), CEXPR_EQ);
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 212:

/* Line 1464 of yacc.c  */
#line 621 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_L1L2, (yyvsp[(2) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 213:

/* Line 1464 of yacc.c  */
#line 624 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_L1H2, (yyvsp[(2) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 214:

/* Line 1464 of yacc.c  */
#line 627 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_H1L2, (yyvsp[(2) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 215:

/* Line 1464 of yacc.c  */
#line 630 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_H1H2, (yyvsp[(2) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 216:

/* Line 1464 of yacc.c  */
#line 633 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_L1H1, (yyvsp[(2) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 217:

/* Line 1464 of yacc.c  */
#line 636 "policy_parse.y"
    { (yyval.valptr) = define_cexpr(CEXPR_ATTR, CEXPR_L2H2, (yyvsp[(2) - (3)].valptr));
			  if ((yyval.valptr) == 0) return -1; }
    break;

  case 218:

/* Line 1464 of yacc.c  */
#line 640 "policy_parse.y"
    { (yyval.valptr) = CEXPR_EQ; }
    break;

  case 219:

/* Line 1464 of yacc.c  */
#line 642 "policy_parse.y"
    { (yyval.valptr) = CEXPR_NEQ; }
    break;

  case 220:

/* Line 1464 of yacc.c  */
#line 645 "policy_parse.y"
    { (yyval.valptr) = (yyvsp[(1) - (1)].valptr); }
    break;

  case 221:

/* Line 1464 of yacc.c  */
#line 647 "policy_parse.y"
    { (yyval.valptr) = CEXPR_DOM; }
    break;

  case 222:

/* Line 1464 of yacc.c  */
#line 649 "policy_parse.y"
    { (yyval.valptr) = CEXPR_DOMBY; }
    break;

  case 223:

/* Line 1464 of yacc.c  */
#line 651 "policy_parse.y"
    { (yyval.valptr) = CEXPR_INCOMP; }
    break;

  case 226:

/* Line 1464 of yacc.c  */
#line 657 "policy_parse.y"
    {if (define_user()) return -1;}
    break;

  case 231:

/* Line 1464 of yacc.c  */
#line 666 "policy_parse.y"
    {if (define_initial_sid_context()) return -1;}
    break;

  case 240:

/* Line 1464 of yacc.c  */
#line 679 "policy_parse.y"
    {if (define_pirq_context((yyvsp[(2) - (3)].val))) return -1;}
    break;

  case 241:

/* Line 1464 of yacc.c  */
#line 682 "policy_parse.y"
    {if (define_iomem_context((yyvsp[(2) - (3)].val),(yyvsp[(2) - (3)].val))) return -1;}
    break;

  case 242:

/* Line 1464 of yacc.c  */
#line 684 "policy_parse.y"
    {if (define_iomem_context((yyvsp[(2) - (5)].val),(yyvsp[(4) - (5)].val))) return -1;}
    break;

  case 243:

/* Line 1464 of yacc.c  */
#line 687 "policy_parse.y"
    {if (define_ioport_context((yyvsp[(2) - (3)].val),(yyvsp[(2) - (3)].val))) return -1;}
    break;

  case 244:

/* Line 1464 of yacc.c  */
#line 689 "policy_parse.y"
    {if (define_ioport_context((yyvsp[(2) - (5)].val),(yyvsp[(4) - (5)].val))) return -1;}
    break;

  case 245:

/* Line 1464 of yacc.c  */
#line 692 "policy_parse.y"
    {if (define_pcidevice_context((yyvsp[(2) - (3)].val))) return -1;}
    break;

  case 250:

/* Line 1464 of yacc.c  */
#line 701 "policy_parse.y"
    {if (define_fs_context((yyvsp[(2) - (5)].val),(yyvsp[(3) - (5)].val))) return -1;}
    break;

  case 256:

/* Line 1464 of yacc.c  */
#line 712 "policy_parse.y"
    {if (define_port_context((yyvsp[(3) - (4)].val),(yyvsp[(3) - (4)].val))) return -1;}
    break;

  case 257:

/* Line 1464 of yacc.c  */
#line 714 "policy_parse.y"
    {if (define_port_context((yyvsp[(3) - (6)].val),(yyvsp[(5) - (6)].val))) return -1;}
    break;

  case 262:

/* Line 1464 of yacc.c  */
#line 723 "policy_parse.y"
    {if (define_netif_context()) return -1;}
    break;

  case 267:

/* Line 1464 of yacc.c  */
#line 732 "policy_parse.y"
    {if (define_ipv4_node_context()) return -1;}
    break;

  case 268:

/* Line 1464 of yacc.c  */
#line 734 "policy_parse.y"
    {if (define_ipv6_node_context()) return -1;}
    break;

  case 273:

/* Line 1464 of yacc.c  */
#line 743 "policy_parse.y"
    {if (define_fs_use(SECURITY_FS_USE_XATTR)) return -1;}
    break;

  case 274:

/* Line 1464 of yacc.c  */
#line 745 "policy_parse.y"
    {if (define_fs_use(SECURITY_FS_USE_TASK)) return -1;}
    break;

  case 275:

/* Line 1464 of yacc.c  */
#line 747 "policy_parse.y"
    {if (define_fs_use(SECURITY_FS_USE_TRANS)) return -1;}
    break;

  case 276:

/* Line 1464 of yacc.c  */
#line 749 "policy_parse.y"
    {if (define_fs_use(SECURITY_FS_USE_PSIDS)) return -1;}
    break;

  case 281:

/* Line 1464 of yacc.c  */
#line 758 "policy_parse.y"
    {if (define_genfs_context(1)) return -1;}
    break;

  case 282:

/* Line 1464 of yacc.c  */
#line 759 "policy_parse.y"
    {insert_id("-", 0);}
    break;

  case 283:

/* Line 1464 of yacc.c  */
#line 760 "policy_parse.y"
    {if (define_genfs_context(1)) return -1;}
    break;

  case 284:

/* Line 1464 of yacc.c  */
#line 762 "policy_parse.y"
    {if (define_genfs_context(0)) return -1;}
    break;

  case 285:

/* Line 1464 of yacc.c  */
#line 765 "policy_parse.y"
    { if (insert_id(yytext,0)) return -1; }
    break;

  case 289:

/* Line 1464 of yacc.c  */
#line 773 "policy_parse.y"
    {if (insert_separator(0)) return -1;}
    break;

  case 290:

/* Line 1464 of yacc.c  */
#line 775 "policy_parse.y"
    {if (insert_separator(0)) return -1;}
    break;

  case 291:

/* Line 1464 of yacc.c  */
#line 778 "policy_parse.y"
    {if (insert_separator(0)) return -1;}
    break;

  case 292:

/* Line 1464 of yacc.c  */
#line 780 "policy_parse.y"
    {if (insert_separator(0)) return -1;}
    break;

  case 297:

/* Line 1464 of yacc.c  */
#line 790 "policy_parse.y"
    { if (insert_separator(0)) return -1; }
    break;

  case 298:

/* Line 1464 of yacc.c  */
#line 792 "policy_parse.y"
    { if (insert_separator(0)) return -1; }
    break;

  case 299:

/* Line 1464 of yacc.c  */
#line 794 "policy_parse.y"
    { if (insert_id("*", 0)) return -1; 
			  if (insert_separator(0)) return -1; }
    break;

  case 300:

/* Line 1464 of yacc.c  */
#line 797 "policy_parse.y"
    { if (insert_id("~", 0)) return -1;
			  if (insert_separator(0)) return -1; }
    break;

  case 301:

/* Line 1464 of yacc.c  */
#line 800 "policy_parse.y"
    { if (insert_id("~", 0)) return -1; 
			  if (insert_separator(0)) return -1; }
    break;

  case 302:

/* Line 1464 of yacc.c  */
#line 802 "policy_parse.y"
    { if (insert_id("-", 0)) return -1; }
    break;

  case 303:

/* Line 1464 of yacc.c  */
#line 803 "policy_parse.y"
    { if (insert_separator(0)) return -1; }
    break;

  case 304:

/* Line 1464 of yacc.c  */
#line 806 "policy_parse.y"
    { if (insert_id("~", 1)) return -1; }
    break;

  case 305:

/* Line 1464 of yacc.c  */
#line 809 "policy_parse.y"
    { if (insert_id("*", 1)) return -1; }
    break;

  case 313:

/* Line 1464 of yacc.c  */
#line 821 "policy_parse.y"
    { if (insert_id(yytext, 1)) return -1; }
    break;

  case 320:

/* Line 1464 of yacc.c  */
#line 830 "policy_parse.y"
    { if (insert_id("-", 0)) return -1; }
    break;

  case 323:

/* Line 1464 of yacc.c  */
#line 833 "policy_parse.y"
    { if (insert_id(yytext,0)) return -1; }
    break;

  case 324:

/* Line 1464 of yacc.c  */
#line 836 "policy_parse.y"
    { if (insert_id(yytext,0)) return -1; }
    break;

  case 325:

/* Line 1464 of yacc.c  */
#line 838 "policy_parse.y"
    { if (insert_id(yytext,0)) return -1; }
    break;

  case 326:

/* Line 1464 of yacc.c  */
#line 841 "policy_parse.y"
    { if (insert_id(yytext,0)) return -1; }
    break;

  case 327:

/* Line 1464 of yacc.c  */
#line 844 "policy_parse.y"
    { yytext[strlen(yytext) - 1] = '\0'; if (insert_id(yytext + 1,0)) return -1; }
    break;

  case 328:

/* Line 1464 of yacc.c  */
#line 847 "policy_parse.y"
    { (yyval.val) = strtoul(yytext,NULL,0); }
    break;

  case 329:

/* Line 1464 of yacc.c  */
#line 850 "policy_parse.y"
    { if (insert_id(yytext,0)) return -1; }
    break;

  case 330:

/* Line 1464 of yacc.c  */
#line 853 "policy_parse.y"
    {if (define_polcap()) return -1;}
    break;

  case 331:

/* Line 1464 of yacc.c  */
#line 856 "policy_parse.y"
    {if (define_permissive()) return -1;}
    break;

  case 332:

/* Line 1464 of yacc.c  */
#line 861 "policy_parse.y"
    { if (end_avrule_block(pass) == -1) return -1;
                          if (policydb_index_others(NULL, policydbp, 0)) return -1;
                        }
    break;

  case 333:

/* Line 1464 of yacc.c  */
#line 866 "policy_parse.y"
    { if (define_policy(pass, 1) == -1) return -1; }
    break;

  case 334:

/* Line 1464 of yacc.c  */
#line 869 "policy_parse.y"
    { if (insert_id(yytext,0)) return -1; }
    break;

  case 335:

/* Line 1464 of yacc.c  */
#line 871 "policy_parse.y"
    { if (insert_id(yytext,0)) return -1; }
    break;

  case 351:

/* Line 1464 of yacc.c  */
#line 895 "policy_parse.y"
    { if (require_class(pass)) return -1; }
    break;

  case 352:

/* Line 1464 of yacc.c  */
#line 897 "policy_parse.y"
    { (yyval.require_func) = require_role; }
    break;

  case 353:

/* Line 1464 of yacc.c  */
#line 898 "policy_parse.y"
    { (yyval.require_func) = require_type; }
    break;

  case 354:

/* Line 1464 of yacc.c  */
#line 899 "policy_parse.y"
    { (yyval.require_func) = require_attribute; }
    break;

  case 355:

/* Line 1464 of yacc.c  */
#line 900 "policy_parse.y"
    { (yyval.require_func) = require_attribute_role; }
    break;

  case 356:

/* Line 1464 of yacc.c  */
#line 901 "policy_parse.y"
    { (yyval.require_func) = require_user; }
    break;

  case 357:

/* Line 1464 of yacc.c  */
#line 902 "policy_parse.y"
    { (yyval.require_func) = require_bool; }
    break;

  case 358:

/* Line 1464 of yacc.c  */
#line 903 "policy_parse.y"
    { (yyval.require_func) = require_tunable; }
    break;

  case 359:

/* Line 1464 of yacc.c  */
#line 904 "policy_parse.y"
    { (yyval.require_func) = require_sens; }
    break;

  case 360:

/* Line 1464 of yacc.c  */
#line 905 "policy_parse.y"
    { (yyval.require_func) = require_cat; }
    break;

  case 361:

/* Line 1464 of yacc.c  */
#line 908 "policy_parse.y"
    { if ((yyvsp[(0) - (1)].require_func) (pass)) return -1; }
    break;

  case 362:

/* Line 1464 of yacc.c  */
#line 910 "policy_parse.y"
    { if ((yyvsp[(0) - (3)].require_func) (pass)) return -1; }
    break;

  case 363:

/* Line 1464 of yacc.c  */
#line 913 "policy_parse.y"
    { if (end_avrule_block(pass) == -1) return -1; }
    break;

  case 364:

/* Line 1464 of yacc.c  */
#line 915 "policy_parse.y"
    { if (end_optional(pass) == -1) return -1; }
    break;

  case 365:

/* Line 1464 of yacc.c  */
#line 918 "policy_parse.y"
    { if (end_avrule_block(pass) == -1) return -1; }
    break;

  case 367:

/* Line 1464 of yacc.c  */
#line 922 "policy_parse.y"
    { if (begin_optional(pass) == -1) return -1; }
    break;

  case 368:

/* Line 1464 of yacc.c  */
#line 925 "policy_parse.y"
    { if (begin_optional_else(pass) == -1) return -1; }
    break;



/* Line 1464 of yacc.c  */
#line 3901 "policy_parse.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yymsg);
	  }
	else
	  {
	    yyerror (YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
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
		      yytoken, &yylval);
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

  /* Do not reclaim the symbols of the rule which action triggered
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
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
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
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  *++yyvsp = yylval;


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

#if !defined(yyoverflow) || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
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
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}



