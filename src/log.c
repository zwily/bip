/*
 * $Id: log.c,v 1.56 2005/04/21 06:58:50 nohar Exp $
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

#include "config.h"
#include "log.h"
#include "irc.h"
#include "util.h"
#include <sys/time.h>
#include <stdio.h>

extern int errno;
extern int log_level;
extern char *conf_log_root;
extern char *conf_log_format;
extern int conf_log;

extern FILE *conf_global_log_file;

static int _log_write(log_t *logdata, logstore_t *lf, const char *d,
		const char *str);
static char *_log_wrap(const char *dest, const char *line);
void logfile_free(logfile_t *lf);
void log_drop(log_t *log, const char *storename);
static void log_reset(logstore_t *store);

#define BOLD_CHAR 0x02
#define LAMESTRING "!bip@" P_SERV " PRIVMSG "
#define PMSG_ARROW "\002->\002"

int check_dir(char *filename, int is_fatal)
{
	int err;
	struct stat statbuf;

	err = stat(filename, &statbuf);
	if (err && errno == ENOENT) {
		err = mkdir(filename, 0750);
		if (err) {
			if (is_fatal)
				fatal("mkdir(%s) %s", filename,
						strerror(errno));
			mylog(LOG_ERROR, "mkdir(%s) %s", filename,
					strerror(errno));
			return 1;
		}
	} else if (err) {
		if (is_fatal)
			fatal("stat(%s) %s", filename, strerror(errno));
		mylog(LOG_ERROR, "stat(%s) %s", filename,
				strerror(errno));
		return 1;
	} else if (!(statbuf.st_mode & S_IFDIR)) {
		if (is_fatal)
			fatal("%s is not a directory", filename);
		mylog(LOG_ERROR, "%s is not a directory", filename);
		return 1;
	}

	return 0;
}

int check_dir_r(char *dirname)
{
	int pos, count = 0;
	char *dir, *tmp;
	int len = strlen(dirname);

	mylog(LOG_DEBUGVERB, "Recursive check of %s engaged", dirname);
	tmp = dirname;
	dir = (char *)bip_malloc(len + 1);
	while (*tmp) {
		int slash_ok = 1;
		while (*tmp == '/') {
			if (slash_ok) {
				strncpy(dir + count, "/", 1);
				count++;
				slash_ok = 0;
			}
			tmp++;
		}
		pos = strcspn(tmp, "/");
		strncpy(dir + count, tmp, pos);
		tmp += pos;
		count += pos;
		*(dir + count) = '\0';
		mylog(LOG_DEBUGVERB,"check_dir_r: %s", dir);
		if (check_dir(dir, 0)) {
			free(dir);
			return 1;
		}
	}
	free(dir);
	return 0;
}

void strtolower(char *str)
{
	char *c;

	for (c = str; *c != '\0'; c++)
		*c = tolower(*c);
}

/*
 * Replace all occurences of var in str by value.
 * This function modifies its first argument!
 * Truncate the string after max characters.
 */
void replace_var(char *str, char *var, char *value, unsigned int max)
{
	char *pos;
	unsigned int lenvar = strlen(var);
	unsigned int lenval = strlen(value);

	while((pos = strstr(str, var))) {
		/* Make room */
		if (strlen(str) + lenval - lenvar >= max)
			return;
		memmove(pos + lenval, pos + lenvar, strlen(pos + lenvar) + 1);
		memcpy(pos, value, lenval);
	}
}

char *log_build_filename(log_t *logdata, const char *destination)
{
	char *logfile, year[5], day[3], month[3], *tmp, *logdir;
	struct tm *now;
	time_t s;
	char *dest = bip_strdup(destination);

	strtolower(dest);
	logfile = (char *)bip_malloc(MAX_PATH_LEN + 1);

	time(&s);
	now = localtime(&s);
	snprintf(year, 5, "%04d", now->tm_year + 1900);
	snprintf(day, 3, "%02d", now->tm_mday);
	snprintf(month, 3, "%02d", now->tm_mon + 1);
	snprintf(logfile, MAX_PATH_LEN, "%s/%s", conf_log_root,
			conf_log_format);
	replace_var(logfile, "%u", logdata->user->name, MAX_PATH_LEN);
	replace_var(logfile, "%n", logdata->network, MAX_PATH_LEN);
	replace_var(logfile, "%c", dest, MAX_PATH_LEN);
	replace_var(logfile, "%Y", year, MAX_PATH_LEN);
	replace_var(logfile, "%d", day, MAX_PATH_LEN);
	replace_var(logfile, "%m", month, MAX_PATH_LEN);

	logdir = bip_strdup(logfile);

	/* strrchr works on bytes, not on char (if sizeof(char) != 1) */
	tmp = strrchr(logdir, '/');
	if (tmp)
		*tmp = '\0';

	free(dest);
	if (check_dir_r(logdir)) {
		free(logfile);
		free(logdir);
		return NULL;
	}
	free(logdir);
	return logfile;
}

void log_updatelast(logfile_t *lf)
{
	time_t t;

	time(&t);
	localtime_r(&t, &lf->last_log);
}

static void log_reset(logstore_t *store)
{
	logfile_t *olf;

	store->skip_advance = 0;

	if (store->memlog) {
		while (!list_is_empty(store->memlog))
			free(list_remove_first(store->memlog));
		return;
	}

	while ((olf = list_get_first(&store->file_group)) &&
			olf != list_get_last(&store->file_group)) {
		logfile_free(olf);
		list_remove_first(&store->file_group);
	}

	assert(olf);
	assert(olf->file);

	list_it_init_last(&store->file_group, &store->file_it);

	fseek(olf->file, 0, SEEK_END);
	olf->len = ftell(olf->file);
	store->file_offset = olf->len;
}

void log_reinit(logstore_t *store)
{
	mylog(LOG_ERROR, "%s is inconsistant, droping backlog info",
			store->name);
	log_reset(store);
}

static char *filename_uniq(const char *filename)
{
	struct stat filestat;
	int i;

	if (stat(filename, &filestat) != -1) {
		char *buf = bip_malloc(strlen(filename) + 4 + 1);
		for (i = 0; i < 256; i++) {
			sprintf(buf, "%s.%d", filename, i);
			if (stat(buf, &filestat) == -1)
				return buf;
		}
		free(buf);
	}
	return bip_strdup(filename);
}

static int log_has_file(log_t *logdata, const char *fname)
{
	hash_iterator_t hi;
	list_iterator_t li;
	logstore_t *store;

	for (hash_it_init(&logdata->logfgs, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		store = hash_it_item(&hi);
		for (list_it_init(&store->file_group, &li); list_it_item(&li);
				list_it_next(&li)) {
			logfile_t *lf = list_it_item(&li);
			if (strcmp(fname, lf->filename) == 0)
				return 1;
		}
	}
	return 0;
}

static int log_add_file(log_t *logdata, const char *destination,
		const char *filename)
{
	FILE *f;
	logstore_t *store;
	char *uniq_fname;
	char *canonical_fname = NULL;
	logfile_t *lf = NULL;

	if (conf_log) {
		if (log_has_file(logdata, filename)) {
			canonical_fname = bip_strdup(filename);
			uniq_fname = filename_uniq(filename);
		} else {
			canonical_fname = bip_strdup(filename);
			uniq_fname = bip_strdup(filename);
		}
		f = fopen(uniq_fname, "a+");
		if (!f) {
			mylog(LOG_ERROR, "fopen(%s) %s", uniq_fname,
					strerror(errno));
			free(uniq_fname);
			free(canonical_fname);
			return 0;
		}

		if (fseek(f, 0, SEEK_END) == -1) {
			mylog(LOG_ERROR, "fseek(%s) %s", uniq_fname,
					strerror(errno));
			free(uniq_fname);
			free(canonical_fname);
			fclose(f);
			return 0;
		}

		lf = bip_malloc(sizeof(logfile_t));
		lf->file = f;
		lf->len = ftell(f);
		lf->filename = uniq_fname;
		lf->canonical_filename = canonical_fname;
		log_updatelast(lf);
	}

	store = hash_get(&logdata->logfgs, destination);
	if (!store) {
		store = bip_calloc(sizeof(logstore_t), 1);
		list_init(&store->file_group, NULL);
		store->name = bip_strdup(destination);
		store->skip_advance = 0;
		hash_insert(&logdata->logfgs, destination, store);
	}

	if (!conf_log && logdata->user->backlog) {
		if (!store->memlog)
			store->memlog = list_new(NULL);
	}

	if (lf) {
		list_add_last(&store->file_group, lf);
		if (list_it_item(&store->file_it) == NULL)
			list_it_init_last(&store->file_group, &store->file_it);
		store->file_offset = lf->len;
	}
	return 1;
}

/*
 * XXX: must not free file_group
 */
void logfile_free(logfile_t *lf)
{
	if (!lf)
		return;
	if (lf->file)
		fclose(lf->file);
	if (lf->filename)
		free(lf->filename);
	if (lf->canonical_filename)
		free(lf->canonical_filename);
	free(lf);
}

logstore_t *log_find_file(log_t *logdata, const char *destination)
{
	logfile_t *lf;
	logstore_t *store;
	char *filename = NULL;
	struct link *l;

	store = hash_get(&logdata->logfgs, destination);

	if (store && !conf_log)
		return store;

	if (!store) {
		if (conf_log) {
			filename = log_build_filename(logdata, destination);
			if (!filename)
				return NULL;
			mylog(LOG_DEBUG, "Creating new logfile for %s: %s",
					destination, filename);
		}
		if (!log_add_file(logdata, destination, filename)) {
			free(filename);
			return NULL;
		}
		store = hash_get(&logdata->logfgs, destination);
		assert(store);
		/* ok we are allocating a new store now, let's set it up for
		* backlogging if applicable */
		assert(logdata->user);
		assert(logdata->network);
		l = hash_get(&logdata->user->connections, logdata->network);
		assert(l);

		struct chan_info *ci = hash_get(&l->chan_infos, destination);

		if (ci && !ci->backlog)
			store->track_backlog = 0;
		else
			store->track_backlog = 1;

		if (filename)
			free(filename);
		return store;
	}

	/* This is reached if store already exists */
	lf = list_get_last(&store->file_group);

	time_t t;
	struct tm *ltime;

	time(&t);
	ltime = localtime(&t);
	if (ltime->tm_hour != lf->last_log.tm_hour) {
		logfile_t *oldlf;

		/* day changed, we might want to rotate logfile */
		filename = log_build_filename(logdata, destination);
		if (!filename)
			return NULL;

		if (strcmp(lf->canonical_filename, filename) == 0) {
			/* finally we don't */
			free(filename);
			return store;
		}

		/* we do want to rotate logfiles */
		mylog(LOG_DEBUG, "Rotating logfile for %s %s %s", destination,
				lf->filename, filename);

		oldlf = list_get_last(&store->file_group);
		if (!log_add_file(logdata, destination, filename)) {
			free(filename);
			return NULL;
		}
		free(filename);

		if (!logdata->user->backlog) {
			/* remove oldlf from file_group */
			assert(list_remove_first(&store->file_group) == oldlf);
			logfile_free(oldlf);
			assert(list_get_first(&store->file_group) ==
					list_get_last(&store->file_group));
		} else {
			fclose(oldlf->file);
			oldlf->file = NULL;
		}
	}
	return store;
}

void log_join(log_t *logdata, const char *ircmask, const char *channel)
{
	snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- %s has joined %s", timestamp(), ircmask,
			channel);
	log_write(logdata, channel, logdata->buffer);
}

void log_part(log_t *logdata, const const char *ircmask, const char *channel,
		const const char *message)
{
	if (message)
		snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- %s has left %s [%s]", timestamp(), ircmask,
			channel, message);
	else
		snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- %s has left %s", timestamp(), ircmask,
			channel);
	log_write(logdata, channel, logdata->buffer);
}

void log_kick(log_t *logdata, const char *ircmask, const char *channel,
		const char *who, const char *message)
{
	snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- %s has been kicked by %s [%s]", timestamp(),
			who, ircmask, message);
	log_write(logdata, channel, logdata->buffer);
}

void log_quit(log_t *logdata, const char *ircmask, const char *channel,
		const char *message)
{
	snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- %s has quit [%s]", timestamp(), ircmask,
			message);
	log_write(logdata, channel, logdata->buffer);
}

void log_nick(log_t *logdata, const char *ircmask, const char *channel,
		const char *newnick)
{
	char *oldnick = nick_from_ircmask(ircmask);

	if (hash_includes(&logdata->logfgs, oldnick)) {
		if (hash_includes(&logdata->logfgs, newnick))
			log_drop(logdata, newnick);
		hash_rename_key(&logdata->logfgs, oldnick, newnick);
	}
	free(oldnick);

	snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- %s is now known as %s",
			timestamp(), ircmask, newnick);
	log_write(logdata, channel, logdata->buffer);
}

static void do_log_privmsg(log_t *logdata, const char *storage, int src,
		const char *from, const char *message)
{
	char dir = '<';

	if (!from)
		from = "Server message";
	if (src)
		dir = '>';

	if (strlen(message) > 8 && ((*message == '\001' ||
		((*message == '+' || *message == '-') &&
			 (*(message + 1) == '\001'))) &&
		(*(message + strlen(message) - 1) == '\001'))) {
		char *msg;
		/* hack for freenode and the like */
		const char *real_message = message;

		if (*message == '+' || *message == '-')
			real_message++;

		if (strncmp(real_message, "\001ACTION ", 8) != 0)
			return;
		msg = bip_strdup(real_message);
		*(msg + strlen(msg) - 1) = '\0';
		snprintf(logdata->buffer, LOGLINE_MAXLEN,
					"%s %c * %s %s", timestamp(), dir,
					from, msg + 8);
		free(msg);
	} else {
		snprintf(logdata->buffer, LOGLINE_MAXLEN,
					"%s %c %s: %s", timestamp(), dir,
					from, message);
	}
	log_write(logdata, storage, logdata->buffer);
}

void log_privmsg(log_t *logdata, const char *ircmask, const char *destination,
		const char *message)
{
	if (!ischannel(*destination)) {
		char *nick = nick_from_ircmask(ircmask);
		do_log_privmsg(logdata, nick, 0, ircmask, message);
		free(nick);
	} else {
		do_log_privmsg(logdata, destination, 0, ircmask, message);
	}
}

void log_cli_privmsg(log_t *logdata, const char *ircmask,
		const char *destination, const char *message)
{
	do_log_privmsg(logdata, destination, 1, ircmask, message);
}

void log_notice(log_t *logdata, const char *ircmask, const char *destination,
		const char *message)
{
	if (!ircmask)
		ircmask = P_IRCMASK;
	if (!ischannel(*destination)) {
		char *nick = nick_from_ircmask(ircmask);
		do_log_privmsg(logdata, nick, 0, ircmask, message);
		free(nick);
	} else {
		do_log_privmsg(logdata, destination, 0, ircmask, message);
	}
}

void log_cli_notice(log_t *logdata, const char *ircmask,
		const char *destination, const char *message)
{
	do_log_privmsg(logdata, destination, 1, ircmask, message);
}

void log_topic(log_t *logdata, const char *ircmask, const char *channel,
		const char *message)
{
	snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- %s changed topic of %s to: %s", timestamp(),
			ircmask, channel, message);
	log_write(logdata, channel, logdata->buffer);
}

void log_init_topic(log_t *logdata, const char *channel, const char *message)
{
	snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- Topic for %s: %s", timestamp(), channel,
			message);
	log_write(logdata, channel, logdata->buffer);
}

void log_init_topic_time(log_t *logdata, const char *channel, const char *who,
		const char *when)
{
	struct tm *time;
	char *timestr;
	time_t seconds;

	seconds = atoi(when);
	time = localtime(&seconds);
	timestr = (char *)bip_malloc(50 + 1);
	timestr[0] = '\0';
	if (time)
		strftime(timestr, 50, "%A %d %B %Y, %H:%M:%S", time);
	timestr[50] = '\0';

	snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- Topic set by %s [%s]", timestamp(), who,
			timestr);
	free(timestr);
	log_write(logdata, channel, logdata->buffer);
}

void log_mode(log_t *logdata, const char *ircmask, const char *channel,
		const char *modes, array_t *mode_args)
{
	int i;
	char *tmpbuf = bip_malloc(LOGLINE_MAXLEN + 1);
	char *tmpbuf2 = bip_malloc(LOGLINE_MAXLEN + 1);
	char *tmp;

	snprintf(tmpbuf, LOGLINE_MAXLEN, "%s -!- mode/%s [%s", timestamp(),
			channel, modes);
	if (mode_args) {
		for (i = 0; i < array_count(mode_args); i++) {
			snprintf(tmpbuf2, LOGLINE_MAXLEN, "%s %s", tmpbuf,
					(char *)array_get(mode_args, i));
			tmp = tmpbuf;
			tmpbuf = tmpbuf2;
			tmpbuf2 = tmp;
		}
	}

	snprintf(logdata->buffer, LOGLINE_MAXLEN, "%s] by %s", tmpbuf, ircmask);
	log_write(logdata, channel, logdata->buffer);

	free(tmpbuf);
	free(tmpbuf2);
}

void log_disconnected(log_t *logdata)
{
	hash_iterator_t hi;
	snprintf(logdata->buffer, LOGLINE_MAXLEN, "%s -!- Disconnected"
			" from server...", timestamp());
	for (hash_it_init(&logdata->logfgs, &hi); hash_it_item(&hi);
			hash_it_next(&hi))
		log_write(logdata, hash_it_key(&hi), logdata->buffer);
}

void log_ping_timeout(log_t *logdata)
{
	list_t *l = log_backlogs(logdata);
	char *s;

	snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- Ping timeout with server...", timestamp());
	while ((s = list_remove_first(l))) {
		log_write(logdata, s, logdata->buffer);
		free(s);
	}
	list_free(l);
	log_disconnected(logdata);
}

void log_connected(log_t *logdata)
{
	logstore_t *store;
	hash_iterator_t hi;

	snprintf(logdata->buffer, LOGLINE_MAXLEN, "%s -!- Connected to"
			" server...", timestamp());
	for (hash_it_init(&logdata->logfgs, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		store = hash_it_item(&hi);
		log_write(logdata, hash_it_key(&hi), logdata->buffer);
	}
}

void log_client_disconnected(log_t *logdata)
{
	(void)logdata;
	mylog(LOG_DEBUG, "A client disconnected");
}

void log_store_free(logstore_t *store)
{
	logfile_t *lf;

	log_reset(store);
	while ((lf = list_remove_first(&store->file_group)))
		logfile_free(lf);
	free(store->name);
	if (store->memlog)
		list_free(store->memlog);
	free(store);
}

void log_drop(log_t *log, const char *storename)
{
	logstore_t *store;

	store = hash_remove(&log->logfgs, storename);
	log_store_free(store);
}

void log_reset_all(log_t *logdata)
{
	logstore_t *store;
	hash_iterator_t hi;
	list_t drop;

	list_init(&drop, NULL);

	for (hash_it_init(&logdata->logfgs, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		store = hash_it_item(&hi);
		if (ischannel(*hash_it_key(&hi)))
			log_reset(store);
		else
			list_add_last(&drop, strdup(hash_it_key(&hi)));
	}

	char *name;
	while ((name = list_remove_first(&drop))) {
		log_drop(logdata, name);
		free(name);
	}
}

void log_reset_store(log_t *log, const char *storename)
{
	logstore_t *store;

	store = hash_get(&log->logfgs, storename);
	if (store) {
		log_reset(store);
		if (!ischannel(*storename))
			log_drop(log, storename);
	}
}

void log_client_none_connected(log_t *logdata)
{
	logdata->connected = 0;

	if (logdata->user->always_backlog)
		return;

	log_reset_all(logdata);
}

void log_client_connected(log_t *logdata)
{
	mylog(LOG_DEBUG, "A client connected");
	logdata->connected = 1;
}

void log_advance_backlogs(log_t* ld, logstore_t *store)
{
	int c;

	if (!store->track_backlog)
		return;

	if (!ld->user->backlog || ld->user->backlog_lines == 0)
		return;

	if (store->skip_advance < ld->user->backlog_lines) {
		store->skip_advance++;
		return;
	}

	logfile_t *lf;
	while ((lf = list_it_item(&store->file_it))) {
		if (!lf->file) {
			lf->file = fopen(lf->filename, "r");
			if (!lf->file) {
				mylog(LOG_ERROR, "Can't open %s for reading",
						lf->filename);
				log_reinit(store);
				return;
			}
		}
		if (fseek(lf->file, store->file_offset, SEEK_SET)) {
			log_reinit(store);
			return;
		}

		while ((c = fgetc(lf->file)) != EOF) {
			store->file_offset++;
			if (c == '\n')
				return;
		}
		if (lf == list_get_last(&store->file_group))
			return;
		fclose(lf->file);
		lf->file = NULL;
		list_it_next(&store->file_it);
		store->file_offset = 0;
	}
}

int log_has_backlog(log_t *logdata, const char *destination)
{
	logstore_t *store = hash_get(&logdata->logfgs, destination);

	if (!store)
		return 0;

	if (store->memlog)
		return !list_is_empty(store->memlog);

	if (!store->track_backlog)
		return 0;

	logfile_t *lf;
	lf = list_it_item(&store->file_it);
	if (lf != list_get_last(&store->file_group))
		return 1;

	return store->file_offset != lf->len;
}

/*
query:
09-01-2009 14:16:10 < nohar!~nohar@haruka.t1r.net: repl querytest
09-01-2009 14:16:37 > bip4ever: je dis yo la quand meem
chan:
09-01-2009 14:15:57 > bip4ever: chantest
09-01-2009 14:16:21 < nohar!~nohar@haruka.t1r.net: chantestrepl
*/
char *log_beautify(log_t *logdata, const char *buf, const char *storename,
		const char *dest)
{
	int action = 0;
	char *p;
	/*
	 * so = startov, lo = lengthov
	 * ts = timestamp, n = sender nick, m = message or action
	 */
	const char *sots, *son, *som;
	size_t lots, lon, lom;
	char *ret;
	int out;

	assert(buf);

	p = strchr(buf, ' ');
	if (!p || !p[0] || !p[1])
		return _log_wrap(dest, buf);
	p++;
	sots = p;
	p = strchr(p, ' ');
	if (!p || !p[0] || !p[1])
		return _log_wrap(dest, buf);
	lots = p - sots;
	p++;

	if (strncmp(p, "-!-", 3) == 0) {
		if (logdata->user->bl_msg_only)
			return NULL;
		else
			return _log_wrap(dest, buf);
	}

	if (*p == '>')
		out = 1;
	else if (*p == '<')
		out = 0;
	else
		return _log_wrap(dest, buf);

	p++;
	if (*p != ' ')
		return _log_wrap(dest, buf);
	p++;
	if (*p == '*') {
		action = 1;
		if (!p[1] || !p[2])
			return _log_wrap(dest, buf);
		p += 2;
	}

	son = p;
	while (*p && *p != '!' && *p != ' ' && *p != ':')
		p++;
	if (!p[0])
		return _log_wrap(dest, buf);
	lon = p - son;

	p = strchr(p, ' ');
	if (!p || !p[0] || !p[1])
		return _log_wrap(dest, buf);
	p++;

	if (out && !ischannel(*dest)) {
		son = storename;
		lon = strlen(storename);
	}

	som = p;
	lom = strlen(p);
	if (lom == 0)
		return _log_wrap(dest, buf);

	p = ret = (char *)bip_malloc(
		1 + lon + strlen(LAMESTRING) + strlen(dest) + 2 + lots + 2 +
		lom + 3 + action * (2 + strlen("ACTION ")) +
		out * strlen(PMSG_ARROW));

	*p++ = ':';

	memcpy(p, son, lon);
	p += lon;

	strcpy(p, LAMESTRING);
	p += strlen(LAMESTRING);

	memcpy(p, dest, strlen(dest));
	p += strlen(dest);
	//memcpy(p, sod, lod);
	//p += lod;

	*p++ = ' ';
	*p++ = ':';

	if (action) {
		*p++ = 1;
		strcpy(p, "ACTION ");
		p += strlen("ACTION ");
	}
	if (out && !ischannel(*dest)) {
		strcpy(p, PMSG_ARROW);
		p += strlen(PMSG_ARROW);
	}
	if (logdata->user->backlog_no_timestamp == 0) {
		memcpy(p, sots, lots);
		p += lots;
		*p++ = '>';
		*p++ = ' ';
	}

	memcpy(p, som, lom);
	p += lom;

	if (action)
		*p++ = 1;

	*p++ = '\r';
	*p++ = '\n';
	*p = 0;
	return ret;
}

static time_t compute_time(const char *buf)
{
	struct tm tm;
	int err;
	time_t tv;

	/* this is to fill tm_isdst to current tm, expect brokennes when dst
	 * changes */
	time(&tv);
	tm = *localtime(&tv);

	err = sscanf(buf, "%2d-%2d-%4d %2d:%2d:%2d", &tm.tm_mday, &tm.tm_mon,
			&tm.tm_year, &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
	if (err != 6)
		return (time_t)-1;
	tm.tm_year -= 1900;
	return mktime(&tm);
}

static int log_backread_file(log_t *log, logstore_t *store, logfile_t *lf,
		list_t *res, const char *dest, time_t start)
{
	char *buf, *logbr;
	int close = 0;

	if (!lf->file) {
		lf->file = fopen(lf->filename, "r");
		if (!lf->file) {
			mylog(LOG_ERROR, "Can't open %s for reading",
					lf->filename);
			list_add_last(res, _log_wrap("Error opening logfile",
					store->name));
			return 0;
		}

		close = 1;
	}

	if (!start && list_it_item(&store->file_it) == lf) {
		mylog(LOG_DEBUG, "Seeking %s to %d", lf->filename,
				store->file_offset);
		if (fseek(lf->file, store->file_offset, SEEK_SET)) {
			mylog(LOG_ERROR, "Can't seek in %s", lf->filename);
			list_add_last(res, _log_wrap(store->name,
						"Error seeking in logfile"));
			return 0;
		}
	} else {
		mylog(LOG_DEBUG, "Seeking %s to %d", lf->filename, 0);
		if (fseek(lf->file, 0, SEEK_SET)) {
			mylog(LOG_ERROR, "Can't seek in %s", lf->filename);
			list_add_last(res, _log_wrap(store->name,
						"Error seeking in logfile"));
			return 0;
		}
	}

	buf = bip_malloc(LOGLINE_MAXLEN + 1);
	for(;;) {
		if (!fgets(buf, LOGLINE_MAXLEN, lf->file)) {
			if (ferror(lf->file)) {
				list_add_last(res, _log_wrap("Error reading "
						"logfile", store->name));
			}
			/* error or oef */
			break;
		}
		int slen = strlen(buf);
		if (buf[slen - 1] == '\n')
			buf[slen - 1] = 0;
		if (slen >= 2 && buf[slen] == '\r')
			buf[slen - 2] = 0;
		if (buf[0] == 0 || buf[0] == '\n')
			continue;

		if (start != 0) {
			time_t linetime = compute_time(buf);
			/* parse error, don't backlog */
			if (linetime == (time_t)-1) {
				list_add_last(res, _log_wrap("Error in "
							"timestamp in %s",
							store->name));
				continue;
			}
			/* too old line, don't backlog */
			if (linetime < start)
				continue;
		}
		logbr = log_beautify(log, buf, store->name, dest);
		if (logbr)
			list_add_last(res, logbr);

	}
	if (close) {
		fclose(lf->file);
		lf->file = NULL;
	}
	free(buf);
	return 1;
}

static list_t *log_backread(log_t *log, const char *storename, const char *dest)
{
	list_t *ret;

	if (!log->user->always_backlog && log->connected)
		return NULL;

	logstore_t *store = hash_get(&log->logfgs, storename);
	if (!store)
		return NULL;

	if (!store->track_backlog)
		return NULL;

	if (store->memlog) {
		list_iterator_t li;
		ret = list_new(NULL);

		for (list_it_init(store->memlog, &li); list_it_item(&li);
				list_it_next(&li))
			list_add_last(ret, bip_strdup(list_it_item(&li)));
		return ret;
	}

	if (!conf_log) {
		mylog(LOG_DEBUG, "No conf_log, not backlogging");
		return NULL;
	}

	list_iterator_t file_it = store->file_it;
	logfile_t *logf;

	ret = list_new(NULL);
	for (file_it = store->file_it;
			(logf = list_it_item(&file_it));
			list_it_next(&file_it)) {
		if (!log_backread_file(log, store, logf, ret, dest,
					(time_t)0)) {
			log_reinit(store);
			return ret;
		}
	}
	return ret;
}

static char *_log_wrap(const char *dest, const char *line)
{
	char *buf;
	size_t count;

	buf = bip_malloc(LOGLINE_MAXLEN + 1);
	count = snprintf(buf, LOGLINE_MAXLEN + 1,
			":" P_IRCMASK " PRIVMSG %s :%s\r\n", dest, line);
	if (count >= LOGLINE_MAXLEN + 1) {
		mylog(LOG_DEBUG, "line too long");
		buf[LOGLINE_MAXLEN - 2] = '\r';
		buf[LOGLINE_MAXLEN - 1] = '\n';
		buf[LOGLINE_MAXLEN] = 0;
	}
	return buf;
}

static int _log_write(log_t *logdata, logstore_t *store,
		const char *destination, const char *str)
{
	size_t nbwrite;
	size_t len;
	static char tmpstr[LOGLINE_MAXLEN + 1];

	strncpy(tmpstr, str, LOGLINE_MAXLEN);
	tmpstr[LOGLINE_MAXLEN] = 0;

	if (store->memlog) {
		char *r = log_beautify(logdata, tmpstr, store->name,
				destination);
		if (r != NULL) {
			list_add_last(store->memlog, r);
			if (store->memc == logdata->user->backlog_lines)
				free(list_remove_first(store->memlog));
			else
				store->memc++;
		}
	}

	if (!conf_log)
		return 0;

	logfile_t *lf = list_get_last(&store->file_group);

	len = strlen(tmpstr);
	nbwrite = fwrite(tmpstr, sizeof(char), len, lf->file);
	nbwrite += fwrite("\n", sizeof(char), 1, lf->file);
	log_updatelast(lf);
	if (nbwrite != len + 1)
		mylog(LOG_ERROR, "Error writing to %s logfile", lf->filename);
	lf->len += nbwrite;
	if (!logdata->connected || logdata->user->always_backlog)
		log_advance_backlogs(logdata, store);
	return nbwrite;
}

void log_write(log_t *logdata, const char *destination, const char *str)
{
	logstore_t *store = log_find_file(logdata, destination);

	if (!store) {
		mylog(LOG_ERROR, "Unable to find/create logfile for '%s'",
				destination);
		return;
	}
	_log_write(logdata, store, destination, str);
}

static list_t *log_all_logs = NULL;

void log_flush_all(void)
{
	list_iterator_t li;
	if (!log_all_logs)
		return;

	fflush(conf_global_log_file);
	for (list_it_init(log_all_logs, &li); list_it_item(&li);
			list_it_next(&li)) {
		log_t *log = list_it_item(&li);
		hash_iterator_t hi;
		for (hash_it_init(&log->logfgs, &hi); hash_it_item(&hi);
				hash_it_next(&hi)) {
			logstore_t *store = hash_it_item(&hi);
			list_iterator_t lj;
			for (list_it_init(&store->file_group, &lj);
					list_it_item(&lj); list_it_next(&lj)) {
				logfile_t *lf = list_it_item(&lj);
				if (lf->file)
					fflush(lf->file);
			}
		}
	}
}

log_t *log_new(struct user *user, const char *network)
{
	log_t *logdata;

	logdata = (log_t *)bip_calloc(sizeof(log_t), 1);
	logdata->user = user;
	logdata->network = bip_strdup(network);
	hash_init(&logdata->logfgs, HASH_NOCASE);
	logdata->buffer = (char *)bip_malloc(LOGLINE_MAXLEN + 1);
	logdata->buffer[LOGLINE_MAXLEN - 1] = 0; // debug
	logdata->buffer[LOGLINE_MAXLEN] = 0;
	logdata->connected = 0;
	if (!log_all_logs)
		log_all_logs = list_new(list_ptr_cmp);
	list_add_last(log_all_logs, logdata);
	return logdata;
}

void log_free(log_t *log)
{
	hash_iterator_t it;
	logstore_t *store;

	list_remove(log_all_logs, log);

	free(log->network);
	free(log->buffer);

	for (hash_it_init(&log->logfgs, &it); (store = hash_it_item(&it));
			hash_it_next(&it)) {
		log_reset(store);
		log_store_free(store);
	}
	hash_clean(&log->logfgs);
	free(log);
}

list_t *log_backlogs(log_t *log)
{
	return hash_keys(&log->logfgs);
}

array_t *str_split(const char *str, const char *splt)
{
	const char *p = str;
	const char *start = str;
	int len;
	char *extracted;
	array_t *array = array_new();;

	do {
		if (!*p || strchr(splt, *p)) {
			len = p - start;
			extracted = bip_malloc(len + 1);
			memcpy(extracted, start, len);
			extracted[len] = 0;
			array_push(array, extracted);
			if (!*p)
				return array;
			else
				start = p + 1;
		}
	} while (*p++);
	fatal("never reached");
	return NULL;
}

/* 26-12-2008 08:54:39 */
int log_parse_date(char *strdate, int *year, int *month, int *mday, int *hour,
		int *min, int *sec)
{
	array_t *fields;
	char *sptr;
	int ret = 0;

	fields = str_split(strdate, ":- ");
	if (array_count(fields) == 6) {
		*year = atoi(array_get(fields, 2));
		*month = atoi(array_get(fields, 1));
		*mday = atoi(array_get(fields, 0));
		*hour = atoi(array_get(fields, 3));
		*min = atoi(array_get(fields, 4));
		*sec = atoi(array_get(fields, 5));
		ret = 1;
	}
	int i;
	array_each(fields, i, sptr)
		free(sptr);

	array_free(fields);
	return ret;
}

void logstore_get_file_at(logstore_t *store, time_t at, list_iterator_t *li)
{
	for (list_it_init(&store->file_group, li); list_it_item(li);
			list_it_next(li)) {
		logfile_t *lf = list_it_item(li);

		if (mktime(&lf->last_log) > at)
			return;
	}
}

static list_t *log_backread_hours(log_t *log, const char *storename,
		const char *dest, int hours)
{
	time_t blstarttime;
	struct timeval tv;
	logstore_t *store;
	logfile_t *logf;
	list_t *ret;
	list_iterator_t file_it;

	gettimeofday(&tv, NULL);
	if (tv.tv_sec <= 3600 * 24 * hours)
		return NULL;
	blstarttime = tv.tv_sec - 3600 * 24 * hours;

	store = hash_get(&log->logfgs, storename);

	ret = list_new(NULL);
	for (logstore_get_file_at(store, blstarttime, &file_it);
			(logf = list_it_item(&file_it));
			list_it_next(&file_it)) {
		if (!log_backread_file(log, store, logf, ret, dest,
					blstarttime)) {
			log_reinit(store);
			return ret;
		}
	}
	return ret;
}

list_t *backlog_lines(log_t *log, const char *bl, const char *cli_nick,
		int hours)
{
	list_t *ret;
	struct line l;
	const char *dest;

	ret = NULL;
	if (ischannel(*bl))
		dest = bl;
	else
		dest = cli_nick;

	if (log_has_backlog(log, bl) || hours) {
		if (hours == 0)
			ret = log_backread(log, bl, dest);
		else
			ret = log_backread_hours(log, bl, dest, hours);
		if (ret && !list_is_empty(ret)) {
			/*
			 * This exception is cosmetic, but you want it.
			 * Most of the time, you get backlog from your own nick
			 * for your mode changes only.
			 * Hence opening a query just to say "end of backlog"...
			 */
			if (strcmp(bl, cli_nick) != 0) {
				/* clean this up */
				irc_line_init(&l);
				l.origin = P_IRCMASK;
				if (dest == cli_nick)
					l.origin = (char *)bl;
				_irc_line_append(&l, "PRIVMSG");
				_irc_line_append(&l, dest);
				_irc_line_append(&l, "End of backlog");
				list_add_last(ret, irc_line_to_string(&l));
				_irc_line_deinit(&l);
			}
		}
	}
	return ret;
}

