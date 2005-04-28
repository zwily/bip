/* A Bison parser, made by GNU Bison 1.875d.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Written by Richard Stallman by simplifying the original so called
   ``semantic'' parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     LEX_IP = 258,
     LEX_EQ = 259,
     LEX_PORT = 260,
     LEX_CSS = 261,
     LEX_SEMICOLON = 262,
     LEX_CONNECTION = 263,
     LEX_NETWORK = 264,
     LEX_LBRA = 265,
     LEX_RBRA = 266,
     LEX_USER = 267,
     LEX_NAME = 268,
     LEX_USERNAME = 269,
     LEX_NICK = 270,
     LEX_SERVER = 271,
     LEX_PASSWORD = 272,
     LEX_SRCIP = 273,
     LEX_HOST = 274,
     LEX_VHOST = 275,
     LEX_SOURCE_PORT = 276,
     LEX_NONE = 277,
     LEX_COMMENT = 278,
     LEX_BUNCH = 279,
     LEX_REALNAME = 280,
     LEX_SSL = 281,
     LEX_CHANNEL = 282,
     LEX_KEY = 283,
     LEX_LOG_ROOT = 284,
     LEX_LOG_FORMAT = 285,
     LEX_LOG_LEVEL = 286,
     LEX_BACKLOG_LINES = 287,
     LEX_NO_BACKLOG = 288,
     LEX_LOG_SYNC_INTERVAL = 289,
     LEX_FOLLOW_NICK = 290,
     LEX_ON_CONNECT_SEND = 291,
     LEX_AWAY_NICK = 292,
     LEX_PID_FILE = 293,
     LEX_IGN_FIRST_NICK = 294,
     LEX_ALWAYS_BACKLOG = 295,
     LEX_LOGIN = 296,
     LEX_BOOL = 297,
     LEX_INT = 298,
     LEX_STRING = 299
   };
#endif
#define LEX_IP 258
#define LEX_EQ 259
#define LEX_PORT 260
#define LEX_CSS 261
#define LEX_SEMICOLON 262
#define LEX_CONNECTION 263
#define LEX_NETWORK 264
#define LEX_LBRA 265
#define LEX_RBRA 266
#define LEX_USER 267
#define LEX_NAME 268
#define LEX_USERNAME 269
#define LEX_NICK 270
#define LEX_SERVER 271
#define LEX_PASSWORD 272
#define LEX_SRCIP 273
#define LEX_HOST 274
#define LEX_VHOST 275
#define LEX_SOURCE_PORT 276
#define LEX_NONE 277
#define LEX_COMMENT 278
#define LEX_BUNCH 279
#define LEX_REALNAME 280
#define LEX_SSL 281
#define LEX_CHANNEL 282
#define LEX_KEY 283
#define LEX_LOG_ROOT 284
#define LEX_LOG_FORMAT 285
#define LEX_LOG_LEVEL 286
#define LEX_BACKLOG_LINES 287
#define LEX_NO_BACKLOG 288
#define LEX_LOG_SYNC_INTERVAL 289
#define LEX_FOLLOW_NICK 290
#define LEX_ON_CONNECT_SEND 291
#define LEX_AWAY_NICK 292
#define LEX_PID_FILE 293
#define LEX_IGN_FIRST_NICK 294
#define LEX_ALWAYS_BACKLOG 295
#define LEX_LOGIN 296
#define LEX_BOOL 297
#define LEX_INT 298
#define LEX_STRING 299




/* Copy the first part of user declarations.  */
#line 1 "conf.y"

/*
 * $Id: conf.y,v 1.26 2005/04/17 15:20:32 nohar Exp $
 *
 * This file is part of the bip proproject
 * Copyright (C) 2004 Arnaud Cornet
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#include <stdlib.h>
#include "util.h"
#include "irc.h"
#include "tuple.h"
extern int yylex (void);
extern char *yytext;
extern int linec;
extern int conf_error;
#define ERRBUFSZ 80
extern char conf_errstr[ERRBUFSZ];

int yywrap()
{
	return 1;
}

int yyerror()
{
	snprintf(conf_errstr, ERRBUFSZ, "Parse error near %s, line %d\n",
			yytext, linec + 1);
	conf_errstr[ERRBUFSZ - 1] = 0;
	conf_error = 1;
	return 1;
}

int yydebug = 1;

list_t *root_list;

struct tuple *tuple_i_new(int type, int i)
{
	struct tuple *t;
	t = malloc(sizeof(struct tuple));
	if (!t)
		fatal("malloc");
	t->type = type;
	t->ndata = i;
	t->tuple_type = TUPLE_INT;
	return t;
}

struct tuple *tuple_p_new(int type, void *p)
{
	struct tuple *t;
	t = malloc(sizeof(struct tuple));
	if (!t)
		fatal("malloc");
	t->type = type;
	t->pdata = p;
	return t;
}

struct tuple *tuple_s_new(int type, void *p)
{
	struct tuple *t = tuple_p_new(type, p);
	t->tuple_type = TUPLE_STR;
	return t;
}

struct tuple *tuple_l_new(int type, void *p)
{
	struct tuple *t = tuple_p_new(type, p);
	t->tuple_type = TUPLE_LIST;
	return t;
}


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

#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 84 "conf.y"
typedef union YYSTYPE {
	int number;
	char *string;
	void *list;
	struct tuple *tuple;
} YYSTYPE;
/* Line 191 of yacc.c.  */
#line 252 "y.tab.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 214 of yacc.c.  */
#line 264 "y.tab.c"

#if ! defined (yyoverflow) || YYERROR_VERBOSE

# ifndef YYFREE
#  define YYFREE free
# endif
# ifndef YYMALLOC
#  define YYMALLOC malloc
# endif

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   define YYSTACK_ALLOC alloca
#  endif
# else
#  if defined (alloca) || defined (_ALLOCA_H)
#   define YYSTACK_ALLOC alloca
#  else
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
# endif
#endif /* ! defined (yyoverflow) || YYERROR_VERBOSE */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (defined (YYSTYPE_IS_TRIVIAL) && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short int yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short int) + sizeof (YYSTYPE))			\
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined (__GNUC__) && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif

#if defined (__STDC__) || defined (__cplusplus)
   typedef signed char yysigned_char;
#else
   typedef short int yysigned_char;
#endif

/* YYFINAL -- State number of the termination state. */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   146

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  45
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  13
/* YYNRULES -- Number of rules. */
#define YYNRULES  51
/* YYNRULES -- Number of states. */
#define YYNSTATES  134

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   299

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
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
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned char yyprhs[] =
{
       0,     0,     3,     4,     8,    12,    16,    20,    24,    28,
      32,    36,    40,    44,    48,    52,    57,    62,    63,    67,
      71,    75,    80,    81,    85,    89,    93,    98,    99,   103,
     107,   111,   115,   119,   123,   127,   131,   135,   139,   143,
     147,   151,   155,   160,   164,   165,   169,   173,   177,   178,
     182,   186
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      46,     0,    -1,    -1,    46,    47,     7,    -1,    29,     4,
      44,    -1,    30,     4,    44,    -1,    31,     4,    43,    -1,
       3,     4,    44,    -1,     5,     4,    43,    -1,     6,     4,
      42,    -1,    32,     4,    43,    -1,    33,     4,    42,    -1,
      40,     4,    42,    -1,    34,     4,    43,    -1,    38,     4,
      44,    -1,     9,    10,    48,    11,    -1,    12,    10,    50,
      11,    -1,    -1,    48,    49,     7,    -1,    13,     4,    44,
      -1,    26,     4,    42,    -1,    16,    10,    56,    11,    -1,
      -1,    50,    51,     7,    -1,    13,     4,    44,    -1,    17,
       4,    44,    -1,     8,    10,    52,    11,    -1,    -1,    52,
      53,     7,    -1,    13,     4,    44,    -1,     9,     4,    44,
      -1,    41,     4,    44,    -1,    15,     4,    44,    -1,    12,
       4,    44,    -1,    25,     4,    44,    -1,    17,     4,    44,
      -1,    20,     4,    44,    -1,    21,     4,    43,    -1,    26,
       4,    42,    -1,    37,     4,    44,    -1,    35,     4,    42,
      -1,    39,     4,    42,    -1,    27,    10,    54,    11,    -1,
      36,     4,    44,    -1,    -1,    54,    55,     7,    -1,    13,
       4,    44,    -1,    28,     4,    44,    -1,    -1,    56,    57,
       7,    -1,    19,     4,    44,    -1,     5,     4,    43,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned char yyrline[] =
{
       0,    99,    99,   100,   104,   105,   107,   108,   109,   110,
     111,   113,   115,   117,   119,   120,   122,   125,   126,   129,
     130,   131,   135,   136,   139,   141,   143,   147,   148,   152,
     153,   155,   156,   157,   158,   160,   162,   163,   165,   166,
     168,   170,   172,   174,   177,   178,   181,   182,   185,   186,
     189,   190
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "LEX_IP", "LEX_EQ", "LEX_PORT",
  "LEX_CSS", "LEX_SEMICOLON", "LEX_CONNECTION", "LEX_NETWORK", "LEX_LBRA",
  "LEX_RBRA", "LEX_USER", "LEX_NAME", "LEX_USERNAME", "LEX_NICK",
  "LEX_SERVER", "LEX_PASSWORD", "LEX_SRCIP", "LEX_HOST", "LEX_VHOST",
  "LEX_SOURCE_PORT", "LEX_NONE", "LEX_COMMENT", "LEX_BUNCH",
  "LEX_REALNAME", "LEX_SSL", "LEX_CHANNEL", "LEX_KEY", "LEX_LOG_ROOT",
  "LEX_LOG_FORMAT", "LEX_LOG_LEVEL", "LEX_BACKLOG_LINES", "LEX_NO_BACKLOG",
  "LEX_LOG_SYNC_INTERVAL", "LEX_FOLLOW_NICK", "LEX_ON_CONNECT_SEND",
  "LEX_AWAY_NICK", "LEX_PID_FILE", "LEX_IGN_FIRST_NICK",
  "LEX_ALWAYS_BACKLOG", "LEX_LOGIN", "LEX_BOOL", "LEX_INT", "LEX_STRING",
  "$accept", "commands", "command", "network", "net_command", "user",
  "usr_command", "connection", "con_command", "channel", "cha_command",
  "server", "ser_command", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const unsigned short int yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    45,    46,    46,    47,    47,    47,    47,    47,    47,
      47,    47,    47,    47,    47,    47,    47,    48,    48,    49,
      49,    49,    50,    50,    51,    51,    51,    52,    52,    53,
      53,    53,    53,    53,    53,    53,    53,    53,    53,    53,
      53,    53,    53,    53,    54,    54,    55,    55,    56,    56,
      57,    57
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     0,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     4,     4,     0,     3,     3,
       3,     4,     0,     3,     3,     3,     4,     0,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     4,     3,     0,     3,     3,     3,     0,     3,
       3,     3
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       2,     0,     1,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      17,    22,     0,     0,     0,     0,     0,     0,     0,     0,
       3,     7,     8,     9,     0,     0,     4,     5,     6,    10,
      11,    13,    14,    12,    15,     0,     0,     0,     0,     0,
      16,     0,     0,     0,     0,    48,     0,    18,    27,     0,
       0,    23,    19,     0,    20,     0,    24,    25,     0,    21,
       0,     0,     0,    26,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    49,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    44,     0,     0,     0,     0,     0,    28,    51,    50,
      30,    33,    29,    32,    35,    36,    37,    34,    38,     0,
      40,    43,    39,    41,    31,    42,     0,     0,     0,     0,
       0,    45,    46,    47
};

/* YYDEFGOTO[NTERM-NUM]. */
static const short int yydefgoto[] =
{
      -1,     1,    16,    34,    48,    35,    53,    65,    88,   119,
     128,    63,    71
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -10
static const yysigned_char yypact[] =
{
     -10,     0,   -10,    13,    14,    17,    12,    15,    20,    22,
      23,    24,    31,    32,    33,    40,    39,     4,     6,    10,
     -10,   -10,     9,    16,    11,    18,    21,    19,    26,    34,
     -10,   -10,   -10,   -10,    -3,     3,   -10,   -10,   -10,   -10,
     -10,   -10,   -10,   -10,   -10,    54,    49,    60,    61,    62,
     -10,    69,    70,    68,    35,   -10,    36,   -10,   -10,    37,
      38,   -10,   -10,    -4,   -10,    30,   -10,   -10,    73,   -10,
      76,    77,    79,   -10,    81,    82,    83,    84,    85,    86,
      87,    88,    89,    90,    91,    92,    93,    94,    95,    50,
      56,   -10,    57,    59,    63,    64,    65,    66,    71,    67,
      74,   -10,    75,    78,    80,    96,    97,   -10,   -10,   -10,
     -10,   -10,   -10,   -10,   -10,   -10,   -10,   -10,   -10,    -9,
     -10,   -10,   -10,   -10,   -10,   -10,   100,   101,    99,    98,
     102,   -10,   -10,   -10
};

/* YYPGOTO[NTERM-NUM].  */
static const yysigned_char yypgoto[] =
{
     -10,   -10,   -10,   -10,   -10,   -10,   -10,   -10,   -10,   -10,
     -10,   -10,   -10
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const unsigned char yytable[] =
{
       2,    68,   125,     3,   126,     4,     5,    69,    44,     6,
      45,    49,     7,    46,    50,    70,    51,    17,    18,   127,
      52,    19,    20,    47,    22,    21,    23,    24,    25,     8,
       9,    10,    11,    12,    13,    26,    27,    28,    14,    72,
      15,    73,    74,    75,    29,    76,    30,    77,    31,    32,
      78,    79,    33,    36,    38,    80,    81,    82,    54,    55,
      37,    39,    41,    40,    56,    83,    84,    85,    57,    86,
      42,    87,    58,    59,    60,    61,    43,    89,    64,    62,
      90,    66,    67,    92,    91,    93,    94,    95,    96,    97,
      98,    99,   100,   108,   102,   103,   104,   105,   106,   101,
     109,   110,   107,   111,   129,   130,   131,   112,   113,   114,
     115,   117,     0,     0,   116,     0,   118,   120,     0,     0,
       0,     0,   121,     0,   122,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   123,     0,
       0,   124,   132,     0,     0,     0,   133
};

static const yysigned_char yycheck[] =
{
       0,     5,    11,     3,    13,     5,     6,    11,    11,     9,
      13,     8,    12,    16,    11,    19,    13,     4,     4,    28,
      17,     4,    10,    26,     4,    10,     4,     4,     4,    29,
      30,    31,    32,    33,    34,     4,     4,     4,    38,     9,
      40,    11,    12,    13,     4,    15,     7,    17,    44,    43,
      20,    21,    42,    44,    43,    25,    26,    27,     4,    10,
      44,    43,    43,    42,     4,    35,    36,    37,     7,    39,
      44,    41,    10,     4,     4,     7,    42,     4,    42,    44,
       4,    44,    44,     4,     7,     4,     4,     4,     4,     4,
       4,     4,     4,    43,     4,     4,     4,     4,     4,    10,
      44,    44,     7,    44,     4,     4,     7,    44,    44,    44,
      44,    44,    -1,    -1,    43,    -1,    42,    42,    -1,    -1,
      -1,    -1,    44,    -1,    44,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    42,    -1,
      -1,    44,    44,    -1,    -1,    -1,    44
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    46,     0,     3,     5,     6,     9,    12,    29,    30,
      31,    32,    33,    34,    38,    40,    47,     4,     4,     4,
      10,    10,     4,     4,     4,     4,     4,     4,     4,     4,
       7,    44,    43,    42,    48,    50,    44,    44,    43,    43,
      42,    43,    44,    42,    11,    13,    16,    26,    49,     8,
      11,    13,    17,    51,     4,    10,     4,     7,    10,     4,
       4,     7,    44,    56,    42,    52,    44,    44,     5,    11,
      19,    57,     9,    11,    12,    13,    15,    17,    20,    21,
      25,    26,    27,    35,    36,    37,    39,    41,    53,     4,
       4,     7,     4,     4,     4,     4,     4,     4,     4,     4,
       4,    10,     4,     4,     4,     4,     4,     7,    43,    44,
      44,    44,    44,    44,    44,    44,    43,    44,    42,    54,
      42,    44,    44,    42,    44,    11,    13,    28,    55,     4,
       4,     7,    44,    44
};

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)		\
   ((Current).first_line   = (Rhs)[1].first_line,	\
    (Current).first_column = (Rhs)[1].first_column,	\
    (Current).last_line    = (Rhs)[N].last_line,	\
    (Current).last_column  = (Rhs)[N].last_column)
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
} while (0)

# define YYDSYMPRINT(Args)			\
do {						\
  if (yydebug)					\
    yysymprint Args;				\
} while (0)

# define YYDSYMPRINTF(Title, Token, Value, Location)		\
do {								\
  if (yydebug)							\
    {								\
      YYFPRINTF (stderr, "%s ", Title);				\
      yysymprint (stderr, 					\
                  Token, Value);	\
      YYFPRINTF (stderr, "\n");					\
    }								\
} while (0)

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_stack_print (short int *bottom, short int *top)
#else
static void
yy_stack_print (bottom, top)
    short int *bottom;
    short int *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (/* Nothing. */; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_reduce_print (int yyrule)
#else
static void
yy_reduce_print (yyrule)
    int yyrule;
#endif
{
  int yyi;
  unsigned int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %u), ",
             yyrule - 1, yylno);
  /* Print the symbols being reduced, and their result.  */
  for (yyi = yyprhs[yyrule]; 0 <= yyrhs[yyi]; yyi++)
    YYFPRINTF (stderr, "%s ", yytname [yyrhs[yyi]]);
  YYFPRINTF (stderr, "-> %s\n", yytname [yyr1[yyrule]]);
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (Rule);		\
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YYDSYMPRINT(Args)
# define YYDSYMPRINTF(Title, Token, Value, Location)
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
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if defined (YYMAXDEPTH) && YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

#endif /* !YYERROR_VERBOSE */



#if YYDEBUG
/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yysymprint (FILE *yyoutput, int yytype, YYSTYPE *yyvaluep)
#else
static void
yysymprint (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  if (yytype < YYNTOKENS)
    {
      YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
# ifdef YYPRINT
      YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
    }
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  switch (yytype)
    {
      default:
        break;
    }
  YYFPRINTF (yyoutput, ")");
}

#endif /* ! YYDEBUG */
/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yydestruct (int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yytype, yyvaluep)
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  switch (yytype)
    {

      default:
        break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM);
# else
int yyparse ();
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
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



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM)
# else
int yyparse (YYPARSE_PARAM)
  void *YYPARSE_PARAM;
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  short int yyssa[YYINITDEPTH];
  short int *yyss = yyssa;
  register short int *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;



#define YYPOPSTACK   (yyvsp--, yyssp--)

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* When reducing, the number of symbols on the RHS of the reduced
     rule.  */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

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
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short int *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	short int *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

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

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

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
      YYDSYMPRINTF ("Next token is", yytoken, &yylval, &yylloc);
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

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %s, ", yytname[yytoken]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;


  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
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
        case 2:
#line 99 "conf.y"
    { yyval.list = root_list = list_new(NULL); }
    break;

  case 3:
#line 100 "conf.y"
    { list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 4:
#line 104 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_LOG_ROOT, yyvsp[0].string); }
    break;

  case 5:
#line 105 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_LOG_FORMAT,
						yyvsp[0].string); }
    break;

  case 6:
#line 107 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_LOG_LEVEL, yyvsp[0].number); }
    break;

  case 7:
#line 108 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_IP, yyvsp[0].string); }
    break;

  case 8:
#line 109 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_PORT, yyvsp[0].number); }
    break;

  case 9:
#line 110 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_CSS, yyvsp[0].number); }
    break;

  case 10:
#line 111 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_BACKLOG_LINES,
      						yyvsp[0].number); }
    break;

  case 11:
#line 113 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_NO_BACKLOG,
       						yyvsp[0].number); }
    break;

  case 12:
#line 115 "conf.y"
    { yyval.tuple = tuple_i_new(
       						LEX_ALWAYS_BACKLOG, yyvsp[0].number); }
    break;

  case 13:
#line 117 "conf.y"
    { yyval.tuple = tuple_i_new(
       						LEX_LOG_SYNC_INTERVAL, yyvsp[0].number); }
    break;

  case 14:
#line 119 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_PID_FILE, yyvsp[0].string); }
    break;

  case 15:
#line 120 "conf.y"
    { yyval.tuple = tuple_l_new(LEX_NETWORK,
       						yyvsp[-1].list); }
    break;

  case 16:
#line 122 "conf.y"
    { yyval.tuple = tuple_l_new(LEX_USER, yyvsp[-1].list); }
    break;

  case 17:
#line 125 "conf.y"
    { yyval.list = list_new(NULL); }
    break;

  case 18:
#line 126 "conf.y"
    { list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 19:
#line 129 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_NAME, yyvsp[0].string); }
    break;

  case 20:
#line 130 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_SSL, yyvsp[0].number); }
    break;

  case 21:
#line 131 "conf.y"
    {
		   	yyval.tuple = tuple_l_new(LEX_SERVER, yyvsp[-1].list); }
    break;

  case 22:
#line 135 "conf.y"
    { yyval.list = list_new(NULL); }
    break;

  case 23:
#line 136 "conf.y"
    { list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 24:
#line 139 "conf.y"
    {
		   yyval.tuple = tuple_s_new(LEX_NAME, yyvsp[0].string); }
    break;

  case 25:
#line 141 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_PASSWORD,
	   	yyvsp[0].string); }
    break;

  case 26:
#line 143 "conf.y"
    {
		  		 yyval.tuple = tuple_l_new(LEX_CONNECTION, yyvsp[-1].list); }
    break;

  case 27:
#line 147 "conf.y"
    { yyval.list = list_new(NULL); }
    break;

  case 28:
#line 148 "conf.y"
    {
	       list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 29:
#line 152 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_NAME, yyvsp[0].string); }
    break;

  case 30:
#line 153 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_NETWORK,
	  		 yyvsp[0].string); }
    break;

  case 31:
#line 155 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_LOGIN, yyvsp[0].string); }
    break;

  case 32:
#line 156 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_NICK, yyvsp[0].string); }
    break;

  case 33:
#line 157 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_USER, yyvsp[0].string); }
    break;

  case 34:
#line 158 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_REALNAME,
	  	 yyvsp[0].string); }
    break;

  case 35:
#line 160 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_PASSWORD,
	  	 yyvsp[0].string); }
    break;

  case 36:
#line 162 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_VHOST, yyvsp[0].string); }
    break;

  case 37:
#line 163 "conf.y"
    {
		   yyval.tuple = tuple_i_new(LEX_SOURCE_PORT, yyvsp[0].number); }
    break;

  case 38:
#line 165 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_SSL, yyvsp[0].number); }
    break;

  case 39:
#line 166 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_AWAY_NICK,
	  					yyvsp[0].string); }
    break;

  case 40:
#line 168 "conf.y"
    {
		   yyval.tuple = tuple_i_new(LEX_FOLLOW_NICK, yyvsp[0].number); }
    break;

  case 41:
#line 170 "conf.y"
    { yyval.tuple = tuple_i_new(
					   LEX_IGN_FIRST_NICK, yyvsp[0].number); }
    break;

  case 42:
#line 172 "conf.y"
    { yyval.tuple = tuple_l_new(
	   					LEX_CHANNEL, yyvsp[-1].list); }
    break;

  case 43:
#line 174 "conf.y"
    { yyval.tuple = tuple_s_new(
	   					LEX_ON_CONNECT_SEND, yyvsp[0].string); }
    break;

  case 44:
#line 177 "conf.y"
    { yyval.list = list_new(NULL); }
    break;

  case 45:
#line 178 "conf.y"
    { list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 46:
#line 181 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_NAME, yyvsp[0].string); }
    break;

  case 47:
#line 182 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_KEY, yyvsp[0].string); }
    break;

  case 48:
#line 185 "conf.y"
    { yyval.list = list_new(NULL); }
    break;

  case 49:
#line 186 "conf.y"
    { list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 50:
#line 189 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_HOST, yyvsp[0].string); }
    break;

  case 51:
#line 190 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_PORT, yyvsp[0].number); }
    break;


    }

/* Line 1010 of yacc.c.  */
#line 1529 "y.tab.c"

  yyvsp -= yylen;
  yyssp -= yylen;


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
#if YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (YYPACT_NINF < yyn && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  int yytype = YYTRANSLATE (yychar);
	  const char* yyprefix;
	  char *yymsg;
	  int yyx;

	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  int yyxbegin = yyn < 0 ? -yyn : 0;

	  /* Stay within bounds of both yycheck and yytname.  */
	  int yychecklim = YYLAST - yyn;
	  int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
	  int yycount = 0;

	  yyprefix = ", expecting ";
	  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	      {
		yysize += yystrlen (yyprefix) + yystrlen (yytname [yyx]);
		yycount += 1;
		if (yycount == 5)
		  {
		    yysize = 0;
		    break;
		  }
	      }
	  yysize += (sizeof ("syntax error, unexpected ")
		     + yystrlen (yytname[yytype]));
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "syntax error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[yytype]);

	      if (yycount < 5)
		{
		  yyprefix = ", expecting ";
		  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
		    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
		      {
			yyp = yystpcpy (yyp, yyprefix);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yyprefix = " or ";
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("syntax error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror ("syntax error");
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* If at end of input, pop the error token,
	     then the rest of the stack, then return failure.  */
	  if (yychar == YYEOF)
	     for (;;)
	       {
		 YYPOPSTACK;
		 if (yyssp == yyss)
		   YYABORT;
		 YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
		 yydestruct (yystos[*yyssp], yyvsp);
	       }
        }
      else
	{
	  YYDSYMPRINTF ("Error: discarding", yytoken, &yylval, &yylloc);
	  yydestruct (yytoken, &yylval);
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

#ifdef __GNUC__
  /* Pacify GCC when the user code never invokes YYERROR and the label
     yyerrorlab therefore never appears in user code.  */
  if (0)
     goto yyerrorlab;
#endif

  yyvsp -= yylen;
  yyssp -= yylen;
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

      YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
      yydestruct (yystos[yystate], yyvsp);
      YYPOPSTACK;
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;


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

#ifndef yyoverflow
/*----------------------------------------------.
| yyoverflowlab -- parser overflow comes here.  |
`----------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}



