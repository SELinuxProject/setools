/* A Bison parser, made by GNU Bison 2.4.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C
   
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

/* Line 1685 of yacc.c  */
#line 93 "policy_parse.y"

	unsigned int val;
	uintptr_t valptr;
	void *ptr;
        require_func_t require_func;



/* Line 1685 of yacc.c  */
#line 264 "policy_parse.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;


