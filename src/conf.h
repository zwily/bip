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
     LEX_BOOL = 298,
     LEX_INT = 299,
     LEX_STRING = 300
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
#define LEX_BOOL 298
#define LEX_INT 299
#define LEX_STRING 300




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 85 "conf.y"
typedef union YYSTYPE {
	int number;
	char *string;
	void *list;
	struct tuple *tuple;
} YYSTYPE;
/* Line 1285 of yacc.c.  */
#line 134 "y.tab.h"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;



