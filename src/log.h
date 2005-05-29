/*
 * $Id: log.h,v 1.26 2005/04/12 19:34:35 nohar Exp $
 *
 * This file is part of the bip project
 * Copyright (C) 2004 Arnaud Cornet and Loïc Gomez
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#ifndef LOG_H
#define LOG_H
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include "util.h"

#define MAX_PATH_LEN 1024
#define LOGLINE_MAXLEN 512

#define S_PRIVATES "privates"

struct list;

typedef struct logfile {
	FILE *file;
	char *filename;
	struct tm last_log;
	size_t backlog_offset;
	size_t len;
} logfile_t;

typedef struct logfilegroup
{
	char *name;
	list_t file_group;
	int skip_advance;

	list_t *memlog;
	int memc;
	list_iterator_t backlog_it;
} logfilegroup_t;

typedef struct log {
	hash_t logfgs;
	char *network;
	char *user;
	char *buffer;
	int connected;
	int backlogging;
	list_iterator_t file_it;
	int lastfile_seeked;
} log_t;

void log_close_all(log_t *logdata);
log_t *log_new(char *user, char *network);
void logdata_free(log_t *logdata);
int log_compare_files(logfile_t *f1, char *f2);

void log_join(log_t *logdata, char *ircmask, char *channel);
void log_part(log_t *logdata, char *ircmask, char *channel, char *message);
void log_kick(log_t *logdata, char *ircmask, char *channel, char *who,
		char *message);
void log_quit(log_t *logdata, char *ircmask, char *channel, char *message);
void log_nick(log_t *logdata, char *ircmask, char *channel, char *newnick);
void log_privmsg(log_t *logdata, char *ircmask, char *destination,
		char *message);
void log_notice(log_t *logdata, char *ircmask, char *channel, char *message);
void log_cli_privmsg(log_t *logdata, char *ircmask, char *destination,
		char *message);
void log_cli_notice(log_t *logdata, char *ircmask, char *channel,
		char *message);
void log_write(log_t *logdata, char *str, char *destination);
void log_mode(log_t *logdata, char *ircmask, char *channel,
		char *modes, char **modargv, unsigned modargc);
void log_topic(log_t *logdata, char *ircmask, char *channel, char *message);
void log_init_topic(log_t *logdata, char *channel, char *message);
void log_init_topic_time(log_t *logdata, char *channel, char *who, char *when);
void log_connected(log_t *logdata);
void log_disconnected(log_t *logdata);
void log_ping_timeout(log_t *logdata);
void log_client_disconnected(log_t *logdata);
void log_client_connected(log_t *logdata);
char *log_backread(log_t *logdata, char *destination);
int log_has_backlog(log_t *logdata, char *destination);
void log_flush_all(void);
void log_client_none_connected(log_t *logdata);
void log_reset(logfilegroup_t *);
#endif
