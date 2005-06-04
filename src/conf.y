%{
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

%}

%token LEX_IP LEX_EQ LEX_PORT LEX_CSS LEX_SEMICOLON LEX_CONNECTION LEX_NETWORK LEX_LBRA LEX_RBRA LEX_USER LEX_NAME LEX_USERNAME LEX_NICK LEX_SERVER LEX_PASSWORD LEX_SRCIP LEX_HOST LEX_VHOST LEX_SOURCE_PORT LEX_NONE LEX_COMMENT LEX_BUNCH LEX_REALNAME LEX_SSL LEX_CHANNEL LEX_KEY LEX_LOG_ROOT LEX_LOG_FORMAT LEX_LOG_LEVEL LEX_BACKLOG_LINES LEX_BACKLOG LEX_LOG LEX_LOG_SYNC_INTERVAL LEX_FOLLOW_NICK LEX_ON_CONNECT_SEND LEX_AWAY_NICK LEX_PID_FILE LEX_IGN_FIRST_NICK LEX_ALWAYS_BACKLOG LEX_LOGIN LEX_BLRESET_ON_TALK

%union {
	int number;
	char *string;
	void *list;
	struct tuple *tuple;
}

%token <number> LEX_BOOL LEX_INT
%token <string> LEX_STRING

%type <list> commands server network channel user connection
%type <tuple> command ser_command net_command cha_command usr_command con_command
%%

commands:
	{ $$ = root_list = list_new(NULL); }
	| commands command LEX_SEMICOLON { list_add_last($1, $2); $$ = $1; }
	;

command:
       LEX_LOG_ROOT LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_LOG_ROOT, $3); }
       | LEX_LOG_FORMAT LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_LOG_FORMAT,
						$3); }
       | LEX_LOG_LEVEL LEX_EQ LEX_INT { $$ = tuple_i_new(LEX_LOG_LEVEL, $3); }
       | LEX_IP LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_IP, $3); }
       | LEX_PORT LEX_EQ LEX_INT { $$ = tuple_i_new(LEX_PORT, $3); }
       | LEX_CSS LEX_EQ LEX_BOOL { $$ = tuple_i_new(LEX_CSS, $3); }
       | LEX_BACKLOG_LINES LEX_EQ LEX_INT { $$ = tuple_i_new(LEX_BACKLOG_LINES,
      						$3); }
       | LEX_BACKLOG LEX_EQ LEX_BOOL { $$ = tuple_i_new(LEX_BACKLOG,
       						$3); }
       | LEX_LOG LEX_EQ LEX_BOOL { $$ = tuple_i_new(LEX_LOG, $3); }
       | LEX_ALWAYS_BACKLOG LEX_EQ LEX_BOOL { $$ = tuple_i_new(
       						LEX_ALWAYS_BACKLOG, $3); }
       | LEX_LOG_SYNC_INTERVAL LEX_EQ LEX_INT { $$ = tuple_i_new(
       						LEX_LOG_SYNC_INTERVAL, $3); }
       | LEX_PID_FILE LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_PID_FILE, $3); }
       | LEX_BLRESET_ON_TALK LEX_EQ LEX_BOOL {
	       $$ = tuple_i_new(LEX_BLRESET_ON_TALK, $3);
	       }
       | LEX_NETWORK LEX_LBRA network LEX_RBRA { $$ = tuple_l_new(LEX_NETWORK,
       						$3); }
       | LEX_USER LEX_LBRA user LEX_RBRA { $$ = tuple_l_new(LEX_USER, $3); }

network:
	{ $$ = list_new(NULL); }
	| network net_command LEX_SEMICOLON { list_add_last($1, $2); $$ = $1; }

net_command:
	   LEX_NAME LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_NAME, $3); }
	   | LEX_SSL LEX_EQ LEX_BOOL { $$ = tuple_i_new(LEX_SSL, $3); }
	   | LEX_SERVER LEX_LBRA server LEX_RBRA {
		   	$$ = tuple_l_new(LEX_SERVER, $3); }

user:
    { $$ = list_new(NULL); }
    | user usr_command LEX_SEMICOLON { list_add_last($1, $2); $$ = $1; }

usr_command:
	   LEX_NAME LEX_EQ LEX_STRING {
		   $$ = tuple_s_new(LEX_NAME, $3); }
	   | LEX_PASSWORD LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_PASSWORD,
	   	$3); }
       	   | LEX_CONNECTION LEX_LBRA connection LEX_RBRA {
		  		 $$ = tuple_l_new(LEX_CONNECTION, $3); }

connection:
          { $$ = list_new(NULL); }
       	  | connection con_command LEX_SEMICOLON {
	       list_add_last($1, $2); $$ = $1; }

con_command:
	   LEX_NAME LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_NAME, $3); }
	   | LEX_NETWORK LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_NETWORK,
	  		 $3); }
	   | LEX_LOGIN LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_LOGIN, $3); }
	   | LEX_NICK LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_NICK, $3); }
	   | LEX_USER LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_USER, $3); }
	   | LEX_REALNAME LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_REALNAME,
	  	 $3); }
	   | LEX_PASSWORD LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_PASSWORD,
	  	 $3); }
	   | LEX_VHOST LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_VHOST, $3); }
	   | LEX_SOURCE_PORT LEX_EQ LEX_INT {
		   $$ = tuple_i_new(LEX_SOURCE_PORT, $3); }
	   | LEX_AWAY_NICK LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_AWAY_NICK,
	  					$3); }
           | LEX_FOLLOW_NICK LEX_EQ LEX_BOOL {
		   $$ = tuple_i_new(LEX_FOLLOW_NICK, $3); }
           | LEX_IGN_FIRST_NICK LEX_EQ LEX_BOOL { $$ = tuple_i_new(
					   LEX_IGN_FIRST_NICK, $3); }
	   | LEX_CHANNEL LEX_LBRA channel LEX_RBRA { $$ = tuple_l_new(
	   					LEX_CHANNEL, $3); }
	   | LEX_ON_CONNECT_SEND LEX_EQ LEX_STRING { $$ = tuple_s_new(
	   					LEX_ON_CONNECT_SEND, $3); }
channel:
       { $$ = list_new(NULL); }
       | channel cha_command LEX_SEMICOLON { list_add_last($1, $2); $$ = $1; }

cha_command:
	   LEX_NAME LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_NAME, $3); }
	   | LEX_KEY LEX_EQ LEX_STRING { $$ = tuple_s_new(LEX_KEY, $3); }

server:
       { $$ = list_new(NULL); }
       | server ser_command LEX_SEMICOLON { list_add_last($1, $2); $$ = $1; }

ser_command:
	   LEX_HOST LEX_EQ LEX_STRING  { $$ = tuple_s_new(LEX_HOST, $3); }
	   | LEX_PORT LEX_EQ LEX_INT { $$ = tuple_i_new(LEX_PORT, $3); }
