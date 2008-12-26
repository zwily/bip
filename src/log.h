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
#define LOGLINE_MAXLEN 2048

struct list;

typedef struct logfile
{
	FILE *file;
	char *filename;
	struct tm last_log;
	size_t len;
} logfile_t;

typedef struct logstore
{
	char *name;
	list_t file_group;
	int skip_advance;

	list_t *memlog;
	int memc;
	int track_backlog;
	list_iterator_t file_it;
	size_t file_offset;
} logstore_t;

typedef struct log
{
	hash_t logfgs;
	char *network;
	char *buffer;
	int connected;
	int backlogging;
	int lastfile_seeked;

	struct user *user;
} log_t;

log_t *log_new(struct user *user, const char *network);
void logdata_free(log_t *logdata);

void log_join(log_t *logdata, const char *ircmask, const char *channel);
void log_part(log_t *logdata, const char *ircmask, const char *channel,
		const char *message);
void log_kick(log_t *logdata, const char *ircmask, const char *channel,
		const char *who, const char *message);
void log_quit(log_t *logdata, const char *ircmask, const char *channel,
		const char *message);
void log_nick(log_t *logdata, const char *ircmask, const char *channel,
		const char *newnick);
void log_privmsg(log_t *logdata, const char *ircmask, const char *destination,
		const char *message);
void log_notice(log_t *logdata, const char *ircmask, const char *channel,
		const char *message);
void log_cli_privmsg(log_t *logdata, const char *ircmask,
		const char *destination, const char *message);
void log_cli_notice(log_t *logdata, const char *ircmask, const char *channel,
		const char *message);
void log_write(log_t *logdata, const char *str, const char *destination);
void log_mode(log_t *logdata, const char *ircmask, const char *channel,
		const char *modes, array_t *mode_args);
void log_topic(log_t *logdata, const char *ircmask, const char *channel,
		const char *message);
void log_init_topic(log_t *logdata, const char *channel, const char *message);
void log_init_topic_time(log_t *logdata, const char *channel, const char *who,
		const char *when);
void log_connected(log_t *logdata);
void log_disconnected(log_t *logdata);
void log_ping_timeout(log_t *logdata);
void log_client_disconnected(log_t *logdata);
void log_client_connected(log_t *logdata);
int log_has_backlog(log_t *logdata, const char *destination);
void log_flush_all(void);
void log_client_none_connected(log_t *logdata);
void log_reset(logstore_t *);
void log_reinit_all(log_t *logdata);
void log_free(log_t *log);
int check_dir(char *filename, int is_fatal);

list_t *log_backlogs(log_t *log);
list_t *backlog_lines_from_last_mark(log_t *log, const char *bl);
#endif
