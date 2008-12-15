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

extern int errno;
extern int log_level;
extern char *conf_log_root;
extern char *conf_log_format;
extern int conf_log;

extern FILE *conf_global_log_file;

int log_set_backlog_offset(log_t *logdata, char *dest);
static int _log_write(log_t *logdata, logfilegroup_t *lf, const char *d,
		const char *str);
void logfile_free(logfile_t *lf);
static char *_log_wrap(const char *dest, const char *line);

#define BOLD_CHAR 0x02
#define LAMESTRING "!bip@bip.bip.bip PRIVMSG "
#define PMSG_ARROW " \002->\002 "


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
		if (strlen(str) + (lenval - lenvar) >= max)
			return;
		memmove(pos + lenval, pos + lenvar,
				(strlen(pos + lenvar) + 1)*sizeof(char));
		memcpy(pos, value, lenval*sizeof(char));
	}
}

char *log_build_filename(log_t *logdata, const char *destination)
{
	char *logfile, year[5], day[3], month[3], *tmp, *logdir;
	int log_format_len;
	struct tm *now;
	time_t s;
	char *dest = bip_strdup(destination);
	strtolower(dest);

	log_format_len = strlen(conf_log_format);
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

void log_reset(logfilegroup_t *lfg)
{
	logfile_t *olf;
	lfg->skip_advance = 0;

	if (lfg->memlog) {
		while (!list_is_empty(lfg->memlog))
			free(list_remove_first(lfg->memlog));
		return;
	}

	while ((olf = list_get_first(&lfg->file_group)) !=
			list_get_last(&lfg->file_group)) {
		logfile_free(olf);
		list_remove_first(&lfg->file_group);
	}
	if (!olf)
		return;

	if (!olf->file)
		fatal("internal, (NULL logfile)");
	fseek(olf->file, 0, SEEK_END);
	olf->len = ftell(olf->file);
	olf->backlog_offset = olf->len;
}

void log_reinit(logfilegroup_t *lfg)
{
	mylog(LOG_ERROR, "%s is inconsistant, droping backlog info",
			lfg->name);
	log_reset(lfg);
}

static int log_add_file(log_t *logdata, const char *destination, const char *filename)
{
	FILE *f;
	logfile_t *lf = NULL;
	logfilegroup_t *lfg;

	if (conf_log) {
		f = fopen(filename, "a+");
		if (!f) {
			mylog(LOG_ERROR, "fopen(%s) %s", filename,
					strerror(errno));
			return 0;
		}

		lf = bip_malloc(sizeof(logfile_t));
		lf->file = f;
		lf->filename = bip_strdup(filename);

		fseek(lf->file, 0, SEEK_END);
		if (ftell(f) < 0)
			fatal("ftell");
		lf->len = ftell(f);
		lf->backlog_offset = lf->len;
		log_updatelast(lf);
	}

	lfg = hash_get(&logdata->logfgs, destination);

	if (!lfg) {
		lfg = bip_calloc(sizeof(logfilegroup_t), 1);
		list_init(&lfg->file_group, NULL);
		lfg->name = bip_strdup(destination);
		lfg->skip_advance = 0;
		hash_insert(&logdata->logfgs, destination, lfg);
	}

	if (!conf_log && logdata->user->backlog) {
		if (!lfg->memlog)
			lfg->memlog = list_new(NULL);
	}

	if (lf)
		list_add_last(&lfg->file_group, lf);
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
	free(lf);
}

logfilegroup_t *log_find_file(log_t *logdata, const char *destination)
{
	logfile_t *lf;
	logfilegroup_t *lfg;
	char *filename = NULL;
	time_t t;
	struct tm *ltime;
	struct link *l;

	if (!ischannel(*destination))
		destination = "privates";

	lfg = hash_get(&logdata->logfgs, destination);

	if (lfg && !conf_log)
		return lfg;

	if (!lfg) {
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
		lfg = hash_get(&logdata->logfgs, destination);
		if (!lfg)
			fatal("internal log_find_file");
		/* ok we are allocating a new lfg now, let's set it up for
		 * backlogging if applicable */
		if (!logdata->user)
			fatal("log_find_file: no user associated to logdata");
		if (!logdata->network)
			fatal("log_find_file: no network id associated to "
					"logdata");
		l = hash_get(&logdata->user->connections, logdata->network);
		if (!l)
			fatal("log_beautify: no connection associated to "
					"logdata");
		struct chan_info *ci = hash_get(&l->chan_infos, destination);
		if (ci && !ci->backlog) {
			lfg->track_backlog = 0;
		} else {
			lfg->track_backlog = 1;
		}

		if (filename)
			free(filename);
		return lfg;
	}

	/* This is reached if lfg already exists */
	time(&t);
	ltime = localtime(&t);
	lf = list_get_last(&lfg->file_group);
	if (ltime->tm_mday != lf->last_log.tm_mday) {
		logfile_t *oldlf;

		/* day changed, we might want to rotate logfile */
		filename = log_build_filename(logdata, destination);
		if (!filename)
			return NULL;

		if (strcmp(lf->filename, filename) == 0) {
			/* finally we don't */
			free(filename);
			return lfg;
		}

		/* we do want do rotate logfiles */
		mylog(LOG_DEBUG, "Rotating logfile for %s from", destination);
		oldlf = list_get_last(&lfg->file_group);
		if (!log_add_file(logdata, destination, filename)) {
			free(filename);
			return NULL;
		}
		free(filename);

		if (!logdata->user->backlog) {
			/* remove oldlf from file_group */
			if (list_remove_first(&lfg->file_group) != oldlf)
				fatal("internal log_find_file 2");
			logfile_free(oldlf);
			if (list_get_first(&lfg->file_group)
					!= list_get_last(&lfg->file_group))
				fatal("internal log_find_file 3");
		} else {
			fclose(oldlf->file);
			oldlf->file = NULL;
		}
	}
	return lfg;
}

/*
 * Da log routines
 * There are a lot of snprintf's here without enforcing the last \0 in the
 * buffer, but _log_write takes care of this for us.
 */
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
	snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- %s is now known as %s",
			timestamp(), ircmask, newnick);
	log_write(logdata, channel, logdata->buffer);
}

static void _log_privmsg(log_t *logdata, const char *ircmask, int src,
		const char *destination, const char *message)
{
	char dir = '<';
	if (!ircmask)
		ircmask = "Server message";

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
		if (ischannel(*destination) || strchr(destination, '@')) {
			snprintf(logdata->buffer, LOGLINE_MAXLEN,
					"%s %c * %s %s", timestamp(), dir,
					ircmask, msg + 8);
		} else {
			snprintf(logdata->buffer, LOGLINE_MAXLEN,
					"%s (%s) %c * %s %s", timestamp(),
					destination, dir, ircmask, msg + 8);
		}
		free(msg);
	} else {
		if (ischannel(*destination) || strchr(destination, '@')) {
			snprintf(logdata->buffer, LOGLINE_MAXLEN,
					"%s %c %s: %s", timestamp(), dir,
					ircmask, message);
		} else {
			snprintf(logdata->buffer, LOGLINE_MAXLEN,
					"%s %c %s (%s): %s", timestamp(),
					dir, ircmask, destination, message);
		}
	}
	log_write(logdata, destination, logdata->buffer);
}

void log_privmsg(log_t *logdata, const char *ircmask, const char *destination,
		const char *message)
{
	_log_privmsg(logdata, ircmask, 0, destination, message);
}

void log_cli_privmsg(log_t *logdata, const char *ircmask,
		const char *destination, const char *message)
{
	_log_privmsg(logdata, ircmask, 1, destination, message);
}

static void _log_notice(log_t *logdata, const char *ircmask, int src,
		const char *destination, const char *message)
{
	char dir = '<';

	if (!ircmask)
		ircmask = "Server message";
	if (src)
		dir = '>';
	if (*message == '\001' && *(message + strlen(message) - 1) == '\001')
		return;
	if (ischannel(*destination) || strchr(destination, '@')) {
		snprintf(logdata->buffer, LOGLINE_MAXLEN, "%s %c %s: %s",
				timestamp(), dir, ircmask, message);
	} else {
		snprintf(logdata->buffer, LOGLINE_MAXLEN,
				"%s %c %s (%s): %s", timestamp(),
				dir, ircmask, destination, message);
	}
	log_write(logdata, destination, logdata->buffer);
}

void log_notice(log_t *logdata, const char *ircmask, const char *destination,
		const char *message)
{
	_log_notice(logdata, ircmask, 0, destination, message);
}

void log_cli_notice(log_t *logdata, const char *ircmask,
		const char *destination, const char *message)
{
	_log_notice(logdata, ircmask, 1, destination, message);
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
		const char *modes, const const char **modargv, int modargc)
{
	int i;
	char *tmpbuf = bip_malloc(LOGLINE_MAXLEN + 1);
	char *tmpbuf2 = bip_malloc(LOGLINE_MAXLEN + 1);
	char *tmp;

	snprintf(tmpbuf, LOGLINE_MAXLEN, "%s -!- mode/%s [%s", timestamp(),
			channel, modes);
	for (i = 0; i < modargc; i++) {
		snprintf(tmpbuf2, LOGLINE_MAXLEN, "%s %s", tmpbuf, modargv[i]);
		tmp = tmpbuf;
		tmpbuf = tmpbuf2;
		tmpbuf2 = tmp;
	}

	snprintf(logdata->buffer, LOGLINE_MAXLEN, "%s] by %s", tmpbuf,
			ircmask);
	log_write(logdata, channel, logdata->buffer);

	free(tmpbuf);
	free(tmpbuf2);
}

void log_disconnected(log_t *logdata)
{
	logfilegroup_t *lfg;
	hash_iterator_t hi;
	snprintf(logdata->buffer, LOGLINE_MAXLEN, "%s -!- Disconnected"
			" from server...", timestamp());
	for (hash_it_init(&logdata->logfgs, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		lfg = hash_it_item(&hi);
		_log_write(logdata, lfg, hash_it_key(&hi), logdata->buffer);
	}
}

void log_ping_timeout(log_t *logdata)
{
	snprintf(logdata->buffer, LOGLINE_MAXLEN,
			"%s -!- Ping timeout with server...", timestamp());
	log_write(logdata, "privates", logdata->buffer);
	log_disconnected(logdata);
}

void log_connected(log_t *logdata)
{
	logfilegroup_t *lfg;
	hash_iterator_t hi;
	snprintf(logdata->buffer, LOGLINE_MAXLEN, "%s -!- Connected to"
			" server...", timestamp());
	for (hash_it_init(&logdata->logfgs, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		lfg = hash_it_item(&hi);
		_log_write(logdata, lfg, hash_it_key(&hi), logdata->buffer);
	}
}

void log_client_disconnected(log_t *logdata)
{
	(void)logdata;
	mylog(LOG_DEBUG, "A client disconnected");
}

void log_reinit_all(log_t *logdata)
{
	logfilegroup_t *lfg;
	hash_iterator_t hi;

	for (hash_it_init(&logdata->logfgs, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		lfg = hash_it_item(&hi);
		log_reset(lfg);
	}
}

void log_client_none_connected(log_t *logdata)
{
	logdata->connected = 0;

	if (logdata->user->always_backlog)
		return;

	log_reinit_all(logdata);
}

void log_client_connected(log_t *logdata)
{
	mylog(LOG_DEBUG, "A client connected");
	logdata->connected = 1;
}

void log_advance_backlogs(log_t* ld, logfilegroup_t *lfg)
{
	int c;

	if (!lfg->track_backlog)
		return;

	if (!ld->user->backlog || ld->user->backlog_lines == 0)
		return;

	if (lfg->skip_advance < ld->user->backlog_lines) {
		lfg->skip_advance++;
		return;
	}

	logfile_t *lf;
	while ((lf = list_get_first(&lfg->file_group))) {
		if (!lf->file) {
			lf->file = fopen(lf->filename, "r");
			if (!lf->file) {
				mylog(LOG_ERROR, "Can't open %s for reading",
						lf->filename);
				log_reinit(lfg);
				return;
			}
		}
		if (fseek(lf->file, lf->backlog_offset, SEEK_SET)) {
			log_reinit(lfg);
			return;
		}

		while ((c = fgetc(lf->file)) != EOF) {
			lf->backlog_offset++;
			if (c == '\n')
				return;
		}
		if (lf == list_get_last(&lfg->file_group))
			return;
		fclose(lf->file);
		lf->file = NULL;
		list_remove_first(&lfg->file_group);
		logfile_free(lf);
	}
}

int log_has_backlog(log_t *logdata, char *destination)
{
	logfilegroup_t *lfg = hash_get(&logdata->logfgs, destination);

	if (!lfg)
		return 0;

	if (lfg->memlog)
		return !list_is_empty(lfg->memlog);

	if (!lfg->track_backlog)
		return 0;

	logfile_t *lf;
	lf = list_get_first(&lfg->file_group);
	if (lf != list_get_last(&lfg->file_group))
		return 1;

	return lf->backlog_offset != lf->len;
}


/*
 * chan:
 * 13-05-2005 12:14:29 > nohar: coucou
 * 13-05-2005 12:14:30 < nohar!~nohar@je.suis.t1r.net: coucou
 *
 * private:
 * 13-05-2005 12:14:53 > nohar (jj): 1 luv PHP
 * 13-05-2005 12:14:55 < jj!john@thebox.ofjj.net (nohar): t00 s3xy
 * 01-08-2005 10:46:11 < * jj!john@thebox.ofjj.net
 */

char *log_beautify(log_t *logdata, const char *buf, const char *dest)
{
	int action = 0;
	char *p;
	/*
	 * so = startov, lo = lengthov
	 * ts = timestamp, n = sender nick, m = message or action
	 */
	const char *sots, *son, *som, *sod = NULL;
	size_t lots, lon, lom, lod;
	char *ret;
	int out;
	int done;

	if (!buf)
		fatal("BUG log_beautify not called correctly!");

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
	if (!p || !p[0])
		return _log_wrap(dest, buf);

	done = ((p[-1] == ':') || (action && (p[1] != '(')));
	p++;

	/*
	 * TODO add a : before the action text in the log files
	 * otherwise "/me (bla) blabla" on a chan is logged exactly as
	 * "/me blabla" in a query with bla.
	 */
	if (!done) {
		p++;
		if (!p[0] || !p[1] || p[0] == ')')
			return _log_wrap(dest, buf);
		sod = p;
		while (*p && *p != ')' && *p != ' ' && *p != '!')
			p++;
		lod = p - sod;

		if (*p == '!')
			while (*p && *p != ')' && *p != ' ')
				p++;

		if (!p[0] || p[0] != ')' || !p[1] || p[1] != ':' ||
				!p[2] || p[2] != ' ' || !p[3])
			return _log_wrap(dest, buf);
		p += 3;
	} else {
		sod = dest;
		lod = strlen(dest);
	}

	if (out && strcmp(dest, "privates") == 0) {
		const char *stmp;
		size_t ltmp;

		stmp = sod;
		ltmp = lod;

		sod = son;
		lod = lon;

		son = stmp;
		lon = ltmp;
	}

	som = p;
	lom = strlen(p);
	if (lom == 0)
		return _log_wrap(dest, buf);

	p = ret = (char *)bip_malloc(
		1 + lon + strlen(LAMESTRING) + lod + 2 + lots +	2 + lom + 3
		+ action * (2 + strlen("ACTION ")) + out * strlen(PMSG_ARROW));

	*p++ = ':';

	memcpy(p, son, lon);
	p += lon;

	strcpy(p, LAMESTRING);
	p += strlen(LAMESTRING);

	memcpy(p, sod, lod);
	p += lod;

	*p++ = ' ';
	*p++ = ':';

	if (action) {
		*p++ = 1;
		strcpy(p, "ACTION ");
		p += strlen("ACTION ");
	}
	if (out) {
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

char *log_backread(log_t *logdata, char *destination, int *skip)
{
	char *buf;
	size_t pos = 0;
	logfile_t *lf;
	logfilegroup_t *lfg;
	int c;
	char *ret;

	*skip = 0;

	if (!logdata->user->always_backlog && logdata->connected)
		return NULL;

	lfg = hash_get(&logdata->logfgs, destination);
	if (!lfg)
		return NULL;

	if (!lfg->track_backlog)
		return NULL;

	if (!logdata->backlogging) {
		logdata->backlogging = 1;
		mylog(LOG_DEBUG, "backlogging!");
		if (lfg->memlog)
			list_it_init(lfg->memlog, &lfg->backlog_it);
		else
			list_it_init(&lfg->file_group, &logdata->file_it);
	}

	if (lfg->memlog) {
		char *ptr;
		ptr = list_it_item(&lfg->backlog_it);
		if (!ptr) {
			logdata->backlogging = 0;
			return NULL;
		}
		list_it_next(&lfg->backlog_it);
		return bip_strdup(ptr);
	}

	if (!conf_log) {
		mylog(LOG_DEBUG, "No conf_log, not backlogging");
		return NULL;
	}

	buf = (char *)bip_malloc(LOGLINE_MAXLEN + 1);

next_file:
	/* check the files containing data to backlog */
	lf = list_it_item(&logdata->file_it);
	if (lf != list_get_last(&lfg->file_group)) {
		mylog(LOG_DEBUGVERB, "%s not last file!", lf->filename);
		/* if the file is not the current open for logging
		 * (it is an old file that has been rotated)
		 * open if necessary, backlog line per line, and close */
		if (!lf->file) {
			mylog(LOG_DEBUGVERB, "opening: %s!", lf->filename);
			lf->file = fopen(lf->filename, "r");
			if (!lf->file) {
				mylog(LOG_ERROR, "Can't open %s for reading",
						lf->filename);
				log_reinit(lfg);
				free(buf);
				return _log_wrap("Error reading logfile",
						destination);
			}
			mylog(LOG_DEBUGVERB, "seeking: %d!",
					lf->backlog_offset);
			if (fseek(lf->file, lf->backlog_offset, SEEK_SET)) {
				log_reinit(lfg);
				free(buf);
				return _log_wrap(destination,
						"Error reading in logfile");
			}
		}
		for(;;) {
			c = fgetc(lf->file);
			if (!logdata->user->always_backlog)
				lf->backlog_offset++;
			if (c == EOF || c == '\n' || pos == LOGLINE_MAXLEN) {
				/* change file if we reach EOF, if pos == maxlen
				 * then the log file is corrupted so we also
				 * drop this file */
				if (pos == LOGLINE_MAXLEN)
					mylog(LOG_DEBUG, "logline too long");
				if (c == EOF || pos == LOGLINE_MAXLEN) {
					mylog(LOG_DEBUGVERB, "EOF: %s (%d)!",
						lf->filename,
						logdata->user->always_backlog);

					list_it_next(&logdata->file_it);
					if (!logdata->user->always_backlog) {
						list_remove_first(
							&lfg->file_group);
						logfile_free(lf);
					} else {
						fclose(lf->file);
						lf->file = NULL;
					}

					pos = 0;
					goto next_file;
				}
				buf[pos] = 0;
				if (pos == 0) {
					*skip = 1;
					return buf;
				}
				ret = log_beautify(logdata, buf, destination);
				if (ret == NULL) {
					pos = 0;
					continue;
				}
				free(buf);
				return ret;
			}
			buf[pos++] = c;
		}
	}

	/* the logfile to read is the one open for writing */
	if (!logdata->lastfile_seeked) {
		if (fseek(lf->file, lf->backlog_offset, SEEK_SET)) {
			log_reinit(lfg);
			return _log_wrap(destination,
					"Error reading in logfile");
		}
		logdata->lastfile_seeked = 1;
		mylog(LOG_DEBUG, "last file seeked!");
	}

	c = fgetc(lf->file);
	if (c == EOF) {
		mylog(LOG_DEBUG, "Nothing more to backlog");
		logdata->lastfile_seeked = 0;
		logdata->backlogging = 0;
		free(buf);
		return NULL;
	}
	if (!logdata->user->always_backlog)
		lf->backlog_offset++;

	if (c != '\n')
		buf[pos++] = c;
	for(;;) {
		c = fgetc(lf->file);
		if (!logdata->user->always_backlog)
			lf->backlog_offset++;
		if (c == EOF || c == '\n' || pos == LOGLINE_MAXLEN) {
			if (pos == LOGLINE_MAXLEN) {
				mylog(LOG_DEBUG, "logline too long");
				fseek(lf->file, 0, SEEK_END);
				/* in the corruption case we alwayse reset
				 * backlog offset */
				lf->backlog_offset = ftell(lf->file);
				free(buf);
				return NULL;
			}

			if (!logdata->user->always_backlog && c == EOF)
				lf->backlog_offset--;
			buf[pos] = 0;
			if (pos == 0) {
				*skip = 1;
				return buf;
			}
			ret = log_beautify(logdata, buf, destination);
			if (ret == NULL) {
				mylog(LOG_DEBUGVERB, "Line not backlogged");
				pos = 0;
				continue;
			}
			mylog(LOG_DEBUGVERB, "backlog: %s", ret);
			free(buf);
			return ret;
		}
		buf[pos++] = c;
	}
	/* unreachable */
	fatal("internal error 12");
	return NULL;
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

static int _log_write(log_t *logdata, logfilegroup_t *lfg,
		const char *destination, const char *str)
{
	size_t nbwrite;
	size_t len;
	static char tmpstr[LOGLINE_MAXLEN + 1];

	strncpy(tmpstr, str, LOGLINE_MAXLEN);
	tmpstr[LOGLINE_MAXLEN] = 0;

	if (lfg->memlog) {
		char *r = log_beautify(logdata, tmpstr, destination);
		if (r != NULL) {
			list_add_last(lfg->memlog, r);
			if (lfg->memc == logdata->user->backlog_lines)
				free(list_remove_first(lfg->memlog));
			else
				lfg->memc++;
		}
	}

	if (!conf_log)
		return 0;

	logfile_t *lf = list_get_last(&lfg->file_group);

	len = strlen(tmpstr);
	nbwrite = fwrite(tmpstr, sizeof(char), len, lf->file);
	nbwrite += fwrite("\n", sizeof(char), 1, lf->file);
	log_updatelast(lf);
	if (nbwrite != len + 1)
		mylog(LOG_ERROR, "Error writing to %s logfile", lf->filename);
	lf->len += nbwrite;
	if (!logdata->connected || logdata->user->always_backlog)
		log_advance_backlogs(logdata, lfg);
	return nbwrite;
}

void log_write(log_t *logdata, const char *destination, const char *str)
{
	logfilegroup_t *lfg = log_find_file(logdata, destination);

	if (!lfg) {
		mylog(LOG_ERROR, "Unable to find/create logfile for '%s'",
				destination);
		return;
	}
	_log_write(logdata, lfg, destination, str);
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
			logfilegroup_t *lfg = hash_it_item(&hi);
			list_iterator_t lj;
			for (list_it_init(&lfg->file_group, &lj);
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
	logfilegroup_t *lfg;
	logfile_t *lf;

	list_remove(log_all_logs, log);

	free(log->network);
	free(log->buffer);

	for (hash_it_init(&log->logfgs, &it); (lfg = hash_it_item(&it));
			hash_it_next(&it)) {
		log_reset(lfg);
		if ((lf = list_remove_first(&lfg->file_group)))
			logfile_free(lf);
	}
	hash_clean(&log->logfgs);
	free(log);
}

