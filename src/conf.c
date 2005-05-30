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
     LEX_BACKLOG = 288,
     LEX_LOG = 289,
     LEX_LOG_SYNC_INTERVAL = 290,
     LEX_FOLLOW_NICK = 291,
     LEX_ON_CONNECT_SEND = 292,
     LEX_AWAY_NICK = 293,
     LEX_PID_FILE = 294,
     LEX_IGN_FIRST_NICK = 295,
     LEX_ALWAYS_BACKLOG = 296,
     LEX_LOGIN = 297,
     LEX_BLRESET_ON_TALK = 298,
     LEX_BOOL = 299,
     LEX_INT = 300,
     LEX_STRING = 301
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
#define LEX_BACKLOG 288
#define LEX_LOG 289
#define LEX_LOG_SYNC_INTERVAL 290
#define LEX_FOLLOW_NICK 291
#define LEX_ON_CONNECT_SEND 292
#define LEX_AWAY_NICK 293
#define LEX_PID_FILE 294
#define LEX_IGN_FIRST_NICK 295
#define LEX_ALWAYS_BACKLOG 296
#define LEX_LOGIN 297
#define LEX_BLRESET_ON_TALK 298
#define LEX_BOOL 299
#define LEX_INT 300
#define LEX_STRING 301




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
#line 85 "conf.y"
typedef union YYSTYPE {
	int number;
	char *string;
	void *list;
	struct tuple *tuple;
} YYSTYPE;
/* Line 191 of yacc.c.  */
#line 257 "y.tab.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 214 of yacc.c.  */
#line 269 "y.tab.c"

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
#define YYLAST   130

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  47
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  13
/* YYNRULES -- Number of rules. */
#define YYNRULES  53
/* YYNRULES -- Number of states. */
#define YYNSTATES  140

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   301

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
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned char yyprhs[] =
{
       0,     0,     3,     4,     8,    12,    16,    20,    24,    28,
      32,    36,    40,    44,    48,    52,    56,    60,    65,    70,
      71,    75,    79,    83,    88,    89,    93,    97,   101,   106,
     107,   111,   115,   119,   123,   127,   131,   135,   139,   143,
     147,   151,   155,   159,   163,   168,   172,   173,   177,   181,
     185,   186,   190,   194
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      48,     0,    -1,    -1,    48,    49,     7,    -1,    29,     4,
      46,    -1,    30,     4,    46,    -1,    31,     4,    45,    -1,
       3,     4,    46,    -1,     5,     4,    45,    -1,     6,     4,
      44,    -1,    32,     4,    45,    -1,    33,     4,    44,    -1,
      34,     4,    44,    -1,    41,     4,    44,    -1,    35,     4,
      45,    -1,    39,     4,    46,    -1,    43,     4,    44,    -1,
       9,    10,    50,    11,    -1,    12,    10,    52,    11,    -1,
      -1,    50,    51,     7,    -1,    13,     4,    46,    -1,    26,
       4,    44,    -1,    16,    10,    58,    11,    -1,    -1,    52,
      53,     7,    -1,    13,     4,    46,    -1,    17,     4,    46,
      -1,     8,    10,    54,    11,    -1,    -1,    54,    55,     7,
      -1,    13,     4,    46,    -1,     9,     4,    46,    -1,    42,
       4,    46,    -1,    15,     4,    46,    -1,    12,     4,    46,
      -1,    25,     4,    46,    -1,    17,     4,    46,    -1,    20,
       4,    46,    -1,    21,     4,    45,    -1,    26,     4,    44,
      -1,    38,     4,    46,    -1,    36,     4,    44,    -1,    40,
       4,    44,    -1,    27,    10,    56,    11,    -1,    37,     4,
      46,    -1,    -1,    56,    57,     7,    -1,    13,     4,    46,
      -1,    28,     4,    46,    -1,    -1,    58,    59,     7,    -1,
      19,     4,    46,    -1,     5,     4,    45,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned char yyrline[] =
{
       0,   100,   100,   101,   105,   106,   108,   109,   110,   111,
     112,   114,   116,   117,   119,   121,   122,   125,   127,   130,
     131,   134,   135,   136,   140,   141,   144,   146,   148,   152,
     153,   157,   158,   160,   161,   162,   163,   165,   167,   168,
     170,   171,   173,   175,   177,   179,   182,   183,   186,   187,
     190,   191,   194,   195
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
  "LEX_LOG_FORMAT", "LEX_LOG_LEVEL", "LEX_BACKLOG_LINES", "LEX_BACKLOG",
  "LEX_LOG", "LEX_LOG_SYNC_INTERVAL", "LEX_FOLLOW_NICK",
  "LEX_ON_CONNECT_SEND", "LEX_AWAY_NICK", "LEX_PID_FILE",
  "LEX_IGN_FIRST_NICK", "LEX_ALWAYS_BACKLOG", "LEX_LOGIN",
  "LEX_BLRESET_ON_TALK", "LEX_BOOL", "LEX_INT", "LEX_STRING", "$accept",
  "commands", "command", "network", "net_command", "user", "usr_command",
  "connection", "con_command", "channel", "cha_command", "server",
  "ser_command", 0
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
     295,   296,   297,   298,   299,   300,   301
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    47,    48,    48,    49,    49,    49,    49,    49,    49,
      49,    49,    49,    49,    49,    49,    49,    49,    49,    50,
      50,    51,    51,    51,    52,    52,    53,    53,    53,    54,
      54,    55,    55,    55,    55,    55,    55,    55,    55,    55,
      55,    55,    55,    55,    55,    55,    56,    56,    57,    57,
      58,    58,    59,    59
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     0,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     4,     4,     0,
       3,     3,     3,     4,     0,     3,     3,     3,     4,     0,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     4,     3,     0,     3,     3,     3,
       0,     3,     3,     3
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       2,     0,     1,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    19,    24,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     3,     7,     8,     9,     0,     0,
       4,     5,     6,    10,    11,    12,    14,    15,    13,    16,
      17,     0,     0,     0,     0,     0,    18,     0,     0,     0,
       0,    50,     0,    20,    29,     0,     0,    25,    21,     0,
      22,     0,    26,    27,     0,    23,     0,     0,     0,    28,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    51,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    46,     0,     0,
       0,     0,     0,    30,    53,    52,    32,    35,    31,    34,
      37,    38,    39,    36,    40,     0,    42,    45,    41,    43,
      33,    44,     0,     0,     0,     0,     0,    47,    48,    49
};

/* YYDEFGOTO[NTERM-NUM]. */
static const short int yydefgoto[] =
{
      -1,     1,    18,    38,    54,    39,    59,    71,    94,   125,
     134,    69,    77
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -10
static const yysigned_char yypact[] =
{
     -10,     0,   -10,    13,    14,    17,    12,    15,    20,    22,
      23,    24,    32,    34,    36,    43,    45,    47,    30,     6,
      10,    18,   -10,   -10,    11,    19,    16,    21,    28,    35,
      29,    31,    37,    38,   -10,   -10,   -10,   -10,    -3,     3,
     -10,   -10,   -10,   -10,   -10,   -10,   -10,   -10,   -10,   -10,
     -10,    52,    53,    60,    61,    57,   -10,    72,    74,    73,
      39,   -10,    40,   -10,   -10,    41,    42,   -10,   -10,    -4,
     -10,    33,   -10,   -10,    79,   -10,    82,    83,    85,   -10,
      87,    88,    89,    90,    91,    92,    93,    94,    95,    96,
      97,    98,    99,   100,   101,    54,    63,   -10,    64,    65,
      66,    67,    68,    69,    62,    70,    75,   -10,    76,    71,
      77,    78,    80,   -10,   -10,   -10,   -10,   -10,   -10,   -10,
     -10,   -10,   -10,   -10,   -10,    -9,   -10,   -10,   -10,   -10,
     -10,   -10,   102,   114,   117,    81,    84,   -10,   -10,   -10
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
       2,    74,   131,     3,   132,     4,     5,    75,    50,     6,
      51,    55,     7,    52,    56,    76,    57,    19,    20,   133,
      58,    21,    22,    53,    24,    23,    25,    26,    27,     8,
       9,    10,    11,    12,    13,    14,    28,    34,    29,    15,
      30,    16,    78,    17,    79,    80,    81,    31,    82,    32,
      83,    33,    35,    84,    85,    36,    60,    40,    86,    87,
      88,    42,    37,    61,    62,    41,    43,    64,    63,    89,
      90,    91,    44,    92,    46,    93,    65,    47,    66,    45,
      67,    48,    49,    95,    70,    68,    96,    72,    73,    98,
      97,    99,   100,   101,   102,   103,   104,   105,   106,   114,
     108,   109,   110,   111,   112,   107,   135,   122,   113,   115,
     116,   117,   118,   119,   120,   121,   123,   127,   136,   124,
     126,     0,   129,   128,   137,     0,   130,   138,     0,     0,
     139
};

static const yysigned_char yycheck[] =
{
       0,     5,    11,     3,    13,     5,     6,    11,    11,     9,
      13,     8,    12,    16,    11,    19,    13,     4,     4,    28,
      17,     4,    10,    26,     4,    10,     4,     4,     4,    29,
      30,    31,    32,    33,    34,    35,     4,     7,     4,    39,
       4,    41,     9,    43,    11,    12,    13,     4,    15,     4,
      17,     4,    46,    20,    21,    45,     4,    46,    25,    26,
      27,    45,    44,    10,     4,    46,    45,    10,     7,    36,
      37,    38,    44,    40,    45,    42,     4,    46,     4,    44,
       7,    44,    44,     4,    44,    46,     4,    46,    46,     4,
       7,     4,     4,     4,     4,     4,     4,     4,     4,    45,
       4,     4,     4,     4,     4,    10,     4,    45,     7,    46,
      46,    46,    46,    46,    46,    46,    46,    46,     4,    44,
      44,    -1,    44,    46,     7,    -1,    46,    46,    -1,    -1,
      46
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    48,     0,     3,     5,     6,     9,    12,    29,    30,
      31,    32,    33,    34,    35,    39,    41,    43,    49,     4,
       4,     4,    10,    10,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     7,    46,    45,    44,    50,    52,
      46,    46,    45,    45,    44,    44,    45,    46,    44,    44,
      11,    13,    16,    26,    51,     8,    11,    13,    17,    53,
       4,    10,     4,     7,    10,     4,     4,     7,    46,    58,
      44,    54,    46,    46,     5,    11,    19,    59,     9,    11,
      12,    13,    15,    17,    20,    21,    25,    26,    27,    36,
      37,    38,    40,    42,    55,     4,     4,     7,     4,     4,
       4,     4,     4,     4,     4,     4,     4,    10,     4,     4,
       4,     4,     4,     7,    45,    46,    46,    46,    46,    46,
      46,    46,    45,    46,    44,    56,    44,    46,    46,    44,
      46,    11,    13,    28,    57,     4,     4,     7,    46,    46
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
#line 100 "conf.y"
    { yyval.list = root_list = list_new(NULL); }
    break;

  case 3:
#line 101 "conf.y"
    { list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 4:
#line 105 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_LOG_ROOT, yyvsp[0].string); }
    break;

  case 5:
#line 106 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_LOG_FORMAT,
						yyvsp[0].string); }
    break;

  case 6:
#line 108 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_LOG_LEVEL, yyvsp[0].number); }
    break;

  case 7:
#line 109 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_IP, yyvsp[0].string); }
    break;

  case 8:
#line 110 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_PORT, yyvsp[0].number); }
    break;

  case 9:
#line 111 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_CSS, yyvsp[0].number); }
    break;

  case 10:
#line 112 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_BACKLOG_LINES,
      						yyvsp[0].number); }
    break;

  case 11:
#line 114 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_BACKLOG,
       						yyvsp[0].number); }
    break;

  case 12:
#line 116 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_LOG, yyvsp[0].number); }
    break;

  case 13:
#line 117 "conf.y"
    { yyval.tuple = tuple_i_new(
       						LEX_ALWAYS_BACKLOG, yyvsp[0].number); }
    break;

  case 14:
#line 119 "conf.y"
    { yyval.tuple = tuple_i_new(
       						LEX_LOG_SYNC_INTERVAL, yyvsp[0].number); }
    break;

  case 15:
#line 121 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_PID_FILE, yyvsp[0].string); }
    break;

  case 16:
#line 122 "conf.y"
    {
	       yyval.tuple = tuple_i_new(LEX_BLRESET_ON_TALK, yyvsp[0].number);
	       }
    break;

  case 17:
#line 125 "conf.y"
    { yyval.tuple = tuple_l_new(LEX_NETWORK,
       						yyvsp[-1].list); }
    break;

  case 18:
#line 127 "conf.y"
    { yyval.tuple = tuple_l_new(LEX_USER, yyvsp[-1].list); }
    break;

  case 19:
#line 130 "conf.y"
    { yyval.list = list_new(NULL); }
    break;

  case 20:
#line 131 "conf.y"
    { list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 21:
#line 134 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_NAME, yyvsp[0].string); }
    break;

  case 22:
#line 135 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_SSL, yyvsp[0].number); }
    break;

  case 23:
#line 136 "conf.y"
    {
		   	yyval.tuple = tuple_l_new(LEX_SERVER, yyvsp[-1].list); }
    break;

  case 24:
#line 140 "conf.y"
    { yyval.list = list_new(NULL); }
    break;

  case 25:
#line 141 "conf.y"
    { list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 26:
#line 144 "conf.y"
    {
		   yyval.tuple = tuple_s_new(LEX_NAME, yyvsp[0].string); }
    break;

  case 27:
#line 146 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_PASSWORD,
	   	yyvsp[0].string); }
    break;

  case 28:
#line 148 "conf.y"
    {
		  		 yyval.tuple = tuple_l_new(LEX_CONNECTION, yyvsp[-1].list); }
    break;

  case 29:
#line 152 "conf.y"
    { yyval.list = list_new(NULL); }
    break;

  case 30:
#line 153 "conf.y"
    {
	       list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 31:
#line 157 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_NAME, yyvsp[0].string); }
    break;

  case 32:
#line 158 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_NETWORK,
	  		 yyvsp[0].string); }
    break;

  case 33:
#line 160 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_LOGIN, yyvsp[0].string); }
    break;

  case 34:
#line 161 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_NICK, yyvsp[0].string); }
    break;

  case 35:
#line 162 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_USER, yyvsp[0].string); }
    break;

  case 36:
#line 163 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_REALNAME,
	  	 yyvsp[0].string); }
    break;

  case 37:
#line 165 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_PASSWORD,
	  	 yyvsp[0].string); }
    break;

  case 38:
#line 167 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_VHOST, yyvsp[0].string); }
    break;

  case 39:
#line 168 "conf.y"
    {
		   yyval.tuple = tuple_i_new(LEX_SOURCE_PORT, yyvsp[0].number); }
    break;

  case 40:
#line 170 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_SSL, yyvsp[0].number); }
    break;

  case 41:
#line 171 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_AWAY_NICK,
	  					yyvsp[0].string); }
    break;

  case 42:
#line 173 "conf.y"
    {
		   yyval.tuple = tuple_i_new(LEX_FOLLOW_NICK, yyvsp[0].number); }
    break;

  case 43:
#line 175 "conf.y"
    { yyval.tuple = tuple_i_new(
					   LEX_IGN_FIRST_NICK, yyvsp[0].number); }
    break;

  case 44:
#line 177 "conf.y"
    { yyval.tuple = tuple_l_new(
	   					LEX_CHANNEL, yyvsp[-1].list); }
    break;

  case 45:
#line 179 "conf.y"
    { yyval.tuple = tuple_s_new(
	   					LEX_ON_CONNECT_SEND, yyvsp[0].string); }
    break;

  case 46:
#line 182 "conf.y"
    { yyval.list = list_new(NULL); }
    break;

  case 47:
#line 183 "conf.y"
    { list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 48:
#line 186 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_NAME, yyvsp[0].string); }
    break;

  case 49:
#line 187 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_KEY, yyvsp[0].string); }
    break;

  case 50:
#line 190 "conf.y"
    { yyval.list = list_new(NULL); }
    break;

  case 51:
#line 191 "conf.y"
    { list_add_last(yyvsp[-2].list, yyvsp[-1].tuple); yyval.list = yyvsp[-2].list; }
    break;

  case 52:
#line 194 "conf.y"
    { yyval.tuple = tuple_s_new(LEX_HOST, yyvsp[0].string); }
    break;

  case 53:
#line 195 "conf.y"
    { yyval.tuple = tuple_i_new(LEX_PORT, yyvsp[0].number); }
    break;


    }

/* Line 1010 of yacc.c.  */
#line 1547 "y.tab.c"

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



