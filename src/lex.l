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
int linec;
#define YY_NO_UNPUT
#include "util.h"
extern list_t *root_list;
void yyparse(void);
void free_conf(list_t*);
int conf_error;
typedef struct bip bip_t;
extern bip_t *_bip;

#if 0
/* SPANK ME WITH A SHOVEL */
static void yyunput(int c, char *buf);
void dummy_lex_FFS(void)
{
	yyunput(0, NULL);
}
#endif
void conf_die(bip_t *, char *, ...);

int yyerror(void)
{
	conf_die(_bip, "Parse error near %s, line %d", yytext, linec + 1);
	conf_error = 1;
	return 1;
}

list_t *parse_conf(FILE *file, int *err)
{
	conf_error = 0;
	linec = 0;

	YY_BUFFER_STATE in = yy_create_buffer(file, YY_BUF_SIZE);
	yy_switch_to_buffer(in);
	yyparse();
	yy_delete_buffer(in);
	*err = conf_error;
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
"user"			{ return LEX_USER; }
"admin"			{ return LEX_ADMIN; }
"connection"		{ return LEX_CONNECTION; }
"nick"			{ return LEX_NICK; }
"realname"		{ return LEX_REALNAME; }
"default_nick"		{ return LEX_DEFAULT_NICK; }
"default_user"		{ return LEX_DEFAULT_USER; }
"default_realname"	{ return LEX_DEFAULT_REALNAME; }
"source_port"		{ return LEX_SOURCE_PORT; }
"vhost"			{ return LEX_VHOST; }
"password"		{ return LEX_PASSWORD; }
"ssl"		        { return LEX_SSL; }
"ssl_check_mode"        { return LEX_SSL_CHECK_MODE; }
"ssl_check_store"       { return LEX_SSL_CHECK_STORE; }
"key"			{ return LEX_KEY; }
"channel"		{ return LEX_CHANNEL; }
"log_level"		{ return LEX_LOG_LEVEL; }
"log_root"		{ return LEX_LOG_ROOT; }
"log_format"		{ return LEX_LOG_FORMAT; }
"backlog_lines"		{ return LEX_BACKLOG_LINES; }
"backlog_no_timestamp"	{ return LEX_BACKLOG_NO_TIMESTAMP; }
"backlog"		{ return LEX_BACKLOG; }
"backlog_always"	{ return LEX_ALWAYS_BACKLOG; }
"backlog_msg_only"	{ return LEX_BL_MSG_ONLY; }
"backlog_reset_on_talk"	{ return LEX_BLRESET_ON_TALK; }
"blreset_on_talk"	{ return LEX_BLRESET_ON_TALK; }
"bl_msg_only"		{ return LEX_BL_MSG_ONLY; }
"always_backlog"	{ return LEX_ALWAYS_BACKLOG; }
"log"			{ return LEX_LOG; }
"log_system"		{ return LEX_LOG_SYSTEM; }
"log_sync_interval"	{ return LEX_LOG_SYNC_INTERVAL; }
"follow_nick"		{ return LEX_FOLLOW_NICK; }
"ignore_first_nick"	{ return LEX_IGN_FIRST_NICK; }
"away_nick"		{ return LEX_AWAY_NICK; }
"on_connect_send"	{ return LEX_ON_CONNECT_SEND; }
"no_client_away_msg"	{ return LEX_NO_CLIENT_AWAY_MSG; }
"pid_file"		{ return LEX_PID_FILE; }
"bip_use_notice"	{ return LEX_BIP_USE_NOTICE; }
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
.			{ conf_die(_bip, "Parse error in config file line %d, unknown character '%s'", linec + 1, yytext); conf_error = 1;
			return LEX_BUNCH; }
%%
