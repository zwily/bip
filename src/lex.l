%{
/*
 * $Id: lex.l,v 1.23 2005/04/12 19:34:35 nohar Exp $
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

#include "conf.h"
int linec = 0;
#define YY_NO_UNPUT
#include "util.h"
extern int conf_error;
extern list_t *root_list;
void yyparse(void);
void free_conf(list_t*);

list_t *parse_conf(FILE *file)
{
	YY_BUFFER_STATE in = yy_create_buffer(file, YY_BUF_SIZE);
	yy_switch_to_buffer(in);
	yyparse();
	if (conf_error) {
		free_conf(root_list);
		return NULL;
	}
	return root_list;
} 
%}
%%
(" "|\t)+
\n                      { linec++; }
"#"[^\n]*$
[0-9]+			{
				yylval.number = atoi(yytext);
				return LEX_INT;
			}
("true"|"false")	{
				yylval.number = strcmp(yytext, "true")
				== 0 ? 1 : 0;
				return LEX_BOOL;
			}
"ip"			{ return LEX_IP; }
"port"			{ return LEX_PORT; }
"client_side_ssl"	{ return LEX_CSS; }
"server"		{ return LEX_SERVER; }
"network"		{ return LEX_NETWORK; }
"host"			{ return LEX_HOST; }
"name"			{ return LEX_NAME; }
"username"		{ return LEX_USERNAME; }
"user"			{ return LEX_USER; }
"login"			{ return LEX_LOGIN; }
"connection"		{ return LEX_CONNECTION; }
"nick"			{ return LEX_NICK; }
"realname"		{ return LEX_REALNAME; }
"source_port"		{ return LEX_SOURCE_PORT; }
"vhost"			{ return LEX_VHOST; }
"password"		{ return LEX_PASSWORD; }
"ssl"		        { return LEX_SSL; }
"key"			{ return LEX_KEY; }
"channel"		{ return LEX_CHANNEL; }
"log_level"		{ return LEX_LOG_LEVEL; }
"log_root"		{ return LEX_LOG_ROOT; }
"log_format"		{ return LEX_LOG_FORMAT; }
"backlog_lines"		{ return LEX_BACKLOG_LINES; }
"no_backlog"		{ return LEX_NO_BACKLOG; }
"always_backlog"	{ return LEX_ALWAYS_BACKLOG; }
"log_sync_interval"	{ return LEX_LOG_SYNC_INTERVAL; }
"follow_nick"		{ return LEX_FOLLOW_NICK; }
"ignore_first_nick"	{ return LEX_IGN_FIRST_NICK; }
"away_nick"		{ return LEX_AWAY_NICK; }
"on_connect_send"	{ return LEX_ON_CONNECT_SEND; }
"pid_file"		{ return LEX_PID_FILE; }
\"[^"]*\" 		{
				size_t len = strlen(yytext) - 2;
				yylval.string = malloc(len + 1);
				if (!yylval.string)
					fatal("malloc");
				memcpy(yylval.string, yytext + 1, len);
				yylval.string[len] = 0;
				return LEX_STRING;
			}
"="			{ return LEX_EQ; }
"{"			{ return LEX_LBRA; }
"}"			{ return LEX_RBRA; }
";"			{ return LEX_SEMICOLON; }
.			{ printf("Parse error line %d, unknown character '%s'\n", linec + 1, yytext);
			return LEX_BUNCH; }
%%