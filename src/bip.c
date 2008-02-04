/*
 * $Id: bip.c,v 1.39 2005/04/21 06:58:50 nohar Exp $
 *
 * This file is part of the bip project
 * Copyright (C) 2004 2005 Arnaud Cornet and Loïc Gomez
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "irc.h"
#include "conf.h"
#include "tuple.h"
#include "log.h"
#include "bip.h"
#include "line.h"
#include "version.h"
#include "defaults.h"

int sighup = 0;

char *conf_log_root;
char *conf_log_format;
int conf_log_level;
char *conf_ip;
unsigned short conf_port;
int conf_css;
#ifdef HAVE_LIBSSL
char *conf_ssl_certfile;
#endif
int conf_daemonize;
char *conf_pid_file;
char *conf_biphome;

/* log options, for sure the trickiest :) */
int conf_log = DEFAULT_LOG;
int conf_log_system = DEFAULT_LOG_SYSTEM;
int conf_log_sync_interval = DEFAULT_LOG_SYNC_INTERVAL;

list_t *parse_conf(FILE *file, int *err);
void conf_die(bip_t *bip, char *fmt, ...);
#ifdef HAVE_LIBSSL
int adm_trust(struct link_client *ic, struct line *line);
#endif
static char *get_tuple_pvalue(list_t *tuple_l, int lex);
void bip_notify(struct link_client *ic, char *fmt, ...);
void adm_list_connections(struct link_client *ic, struct user *bu);
void free_conf(list_t *l);

#ifdef HAVE_OIDENTD
#define OIDENTD_FILENAME ".oidentd.conf"
#endif

static void hash_binary(char *hex, unsigned char **password, unsigned int *seed)
{
	unsigned char *md5;
	unsigned int buf;
	int i;

	if (strlen(hex) != 40)
		fatal("Incorrect password format %s\n", hex);

	md5 = malloc(20);
	for (i = 0; i < 20; i++) {
		sscanf(hex + 2 * i, "%02x", &buf);
		md5[i] = buf;
	}

	*seed = 0;
	sscanf(hex, "%02x", &buf);
	*seed |= buf << 24;
	sscanf(hex + 2, "%02x", &buf);
	*seed |= buf << 16;
	sscanf(hex + 2 * 2, "%02x", &buf);
	*seed |= buf << 8;
	sscanf(hex + 2 * 3, "%02x", &buf);
	*seed |= buf;

	*password = md5;
}

static int add_server(bip_t *bip, struct server *s, list_t *data)
{
	struct tuple *t;

	s->port = 6667; /* default port */

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_HOST:
			MOVE_STRING(s->host, t->pdata);
			break;
		case LEX_PORT:
			s->port = t->ndata;
			break;
		default:
			fatal("Config error in server block (%d)", t->type);
		}
		if (t->tuple_type == TUPLE_STR && t->pdata)
			free(t->pdata);
		free(t);
	}
	if (!s->host) {
		free(s);
		conf_die(bip, "Server conf: host not set");
		return 0;
	}
	return 1;
}

#define ERRBUFSZ 128

extern list_t *root_list;
int yyparse();

void conf_die(bip_t *bip, char *fmt, ...)
{
	va_list ap;
	int size = ERRBUFSZ;
	int n;
	char *error = malloc(size);

	for (;;) {
		va_start(ap, fmt);
		n = vsnprintf(error, size, fmt, ap);
		va_end(ap);
		if (n > -1 && n < size) {
			list_add_last(&bip->errors, error);
			break;
		}
		if (n > -1)
			size = n + 1;
		else
			size *= 2;
		error = realloc(error, size);
	}
	va_start(ap, fmt);
	_mylog(LOG_ERROR, fmt, ap);
	va_end(ap);
}

FILE *conf_global_log_file;

static pid_t daemonize(void)
{
	switch (fork()) {
	case -1:
		fatal("Fork failed");
		break;
	case 0:
		break;
	default:
		_exit(0);
	}

	if (setsid() < 0)
		fatal("setsid() failed");

	switch (fork()) {
	case -1:
		fatal("Fork failed");
		break;
	case 0:
		break;
	default:
		_exit(0);
	}

	close(0);
	close(1);
	close(2);
	/* This better be the very last action since fatal makes use of
	 * conf_global_log_file */
	return getpid();
}

/* RACE CONDITION! */
int do_pid_stuff(void)
{
	char hname[1024];
	char longpath[1024];
	FILE *f;
try_again:
	f = fopen(conf_pid_file, "r");
	if (f)
		goto pid_is_there;
	if (gethostname(hname, 1023) == -1)
		fatal("%s %s", "gethostname", strerror(errno));
	snprintf(longpath, 1023, "%s.%s.%ld", conf_pid_file, hname,
			(long unsigned int)getpid());
	int fd;
	if ((fd = open(longpath, O_CREAT|O_WRONLY, S_IWUSR|S_IRUSR)) == -1)
		fatal("Cannot write to PID file (%s) %s", longpath,
				strerror(errno));
	if (link(longpath, conf_pid_file) ==  -1) {
		struct stat buf;
		if (stat(longpath, &buf) == -1) {
			if (buf.st_nlink != 2) {
				f = fopen(conf_pid_file, "r");
				goto pid_is_there;
			}
		}
	}
	unlink(longpath);
	return fd;
pid_is_there:
	{
		pid_t pid;
		long unsigned int p;
		if (f) {
			int c = fscanf(f, "%ld", &p);
			pid = p;
			if (c != 1 || p == 0) {
				mylog(LOG_INFO, "pid file found but invalid "
						"data inside. Continuing...\n");
				if (unlink(conf_pid_file)) {
					fatal("Cannot delete pid file '%s', "
							"check permissions.\n",
							conf_pid_file);
				}
				goto try_again;
			}
		} else
			pid = 0;
		int kr = kill(pid, 0);
		if (kr == -1 && (errno == ESRCH || errno == EPERM)) {
			/* that's not bip! */
			fclose(f);
			if (unlink(conf_pid_file)) {
				fatal("Cannot delete pid file '%s', check "
						"permissions.\n",
						conf_pid_file);
			}
			goto try_again;
		}
		if (pid)
			mylog(LOG_INFO, "pid file found (pid %ld).", pid);
		mylog(LOG_FATAL, "Another instance of bip is certainly runing.");
		mylog(LOG_FATAL, "If you are sure this is not the case remove"
					" %s.", conf_pid_file);
		exit(2);
	}
	return 0;
}

#define S_CONF "/.bip/bip.conf"

static void usage(char *name)
{
	printf(
"Usage: %s [-f config_file] [-h] [-n]\n"
"	-f config_file: Use config_file as the configuration file\n"
"		If no config file is given %s will try to open ~" S_CONF "\n"
"	-n: Don't daemonize, log in stderr\n"
"	-v: Print version and exit\n"
"	-h: This help\n", name, name);
	exit(1);
}

static void version()
{
	printf(
"Bip IRC Proxy - %s\n"
"Copyright © Arnaud Cornet and Loïc Gomez (2004 - 2008)\n"
"Distributed under the GNU Public License Version 2\n", BIP_VERSION);
}

bip_t *_bip;

void reload_config(int i)
{
	(void)i;
	sighup = 1;
	_bip->reloading_client = NULL;
}

void rlimit_cpu_reached(int i)
{
	(void)i;
	mylog(LOG_WARN, "This process has reached the CPU time usage limit. "
		"It means bip will be killed by the Operating System soon.");
}

void rlimit_bigfile_reached(int i)
{
	(void)i;
	mylog(LOG_WARN, "A file has reached the max size this process is "
		"allowed to create. The file will not be written correctly, "
		"an error message should follow. This is not fatal.");
}

void bad_quit(int i)
{
	list_iterator_t it;
	for (list_it_init(&_bip->link_list, &it); list_it_item(&it);
			list_it_next(&it)) {
		struct link *l = list_it_item(&it);
		struct link_server *ls = l->l_server;
		if (ls && l->s_state == IRCS_CONNECTED) {
			write_line_fast(CONN(ls), "QUIT :Coyote finally "
					"caught me\r\n");
		}
	}
	unlink(conf_pid_file);
	exit(i);
}

static int add_network(bip_t *bip, list_t *data)
{
	struct tuple *t;
	struct network *n;
	int i;
	int r;

	char *name = get_tuple_pvalue(data, LEX_NAME);

	if (name == NULL) {
		conf_die(bip, "Network with no name");
		return 0;
	}
	n = hash_get(&bip->networks, name);
	if (n) {
		for (i = 0; i < n->serverc; i++)
			free(n->serverv[i].host);
		free(n->serverv);
		n->serverv = NULL;
		n->serverc = 0;
	} else {
		n = calloc(sizeof(struct network), 1);
		hash_insert(&bip->networks, name, n);
	}

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_NAME:
			MOVE_STRING(n->name, t->pdata);
			break;
#ifdef HAVE_LIBSSL
		case LEX_SSL:
			n->ssl = t->ndata;
			break;
#endif
		case LEX_SERVER:
			n->serverv = realloc(n->serverv, (n->serverc + 1)
						* sizeof(struct server));
			n->serverc++;
			memset(&n->serverv[n->serverc - 1], 0,
					sizeof(struct server));
			r = add_server(bip, &n->serverv[n->serverc - 1],
					t->pdata);
			if (!r) {
				n->serverc--;
				return 0;
			}
			free(t->pdata);
			t->pdata = NULL;
			break;
		default:
			conf_die(bip, "unknown keyword in network statement");
			return 0;
			break;
		}
		if (t->tuple_type == TUPLE_STR && t->pdata)
			free(t->pdata);
		free(t);
	}
	return 1;
}

void adm_bip_delconn(bip_t *bip, struct link_client *ic, char *conn_name)
{
	struct user *user = LINK(ic)->user;
	struct link *l;

	if (!(l = hash_get(&user->connections, conn_name))) {
		bip_notify(ic, "cannot find this connection");
		return;
	}

	bip_notify(ic, "deleting");
	link_kill(bip, l);
}

void adm_bip_addconn(bip_t *bip, struct link_client *ic, char *conn_name,
		char *network_name)
{
	struct user *user = LINK(ic)->user;
	struct network *network;

	/* check name uniqueness */
	if (hash_get(&user->connections, conn_name)) {
		bip_notify(ic, "connection name already exists for this user.");
		return;
	}

	/* check we know about this network */
	network = hash_get(&bip->networks, network_name);
	if (!network) {
		bip_notify(ic, "no such network name");
		return;
	}

	struct link *l;
	l = irc_link_new();
	l->name = strdup(conn_name);
	hash_insert(&user->connections, conn_name, l);
	list_add_last(&bip->link_list, l);
	l->user = user;
	l->network = network;
	l->log = log_new(user, conn_name);
#ifdef HAVE_LIBSSL
	l->ssl_check_mode = user->ssl_check_mode;
	l->untrusted_certs = sk_X509_new_null();
#endif


#define SCOPY(member) l->member = (LINK(ic)->member ? strdup(LINK(ic)->member) : NULL)
#define ICOPY(member) l->member = LINK(ic)->member

	SCOPY(connect_nick);
	SCOPY(username);
	SCOPY(realname);
	/* we don't copy server password */
	SCOPY(vhost);
	ICOPY(follow_nick);
	ICOPY(ignore_first_nick);
	SCOPY(away_nick);
	SCOPY(no_client_away_msg);
	/* we don't copy on_connect_send */
#ifdef HAVE_LIBSSL
	ICOPY(ssl_check_mode);
#endif
#undef SCOPY
#undef ICOPY
	bip_notify(ic, "connection added, you should soon be able to connect");
}

static int add_connection(bip_t *bip, struct user *user, list_t *data)
{
	struct tuple *t, *t2;
	struct link *l;
	struct chan_info *ci;
	char *name = get_tuple_pvalue(data, LEX_NAME);

	if (name == NULL) {
		conf_die(bip, "Connection with no name");
		return 0;
	}
	l = hash_get(&user->connections, name);
	if (!l) {
		l = irc_link_new();
		hash_insert(&user->connections, name, l);
		list_add_last(&bip->link_list, l);
		l->user = user;
		l->log = log_new(user, name);
#ifdef HAVE_LIBSSL
		l->ssl_check_mode = user->ssl_check_mode;
		l->untrusted_certs = sk_X509_new_null();
#endif
	} else {
		l->network = NULL;
		log_reinit_all(l->log);
	}

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_NAME:
			MOVE_STRING(l->name, t->pdata);
			break;
		case LEX_NETWORK:
			l->network = hash_get(&bip->networks, t->pdata);
			if (!l->network) {
				conf_die(bip, "Undefined network %s.\n",
						t->pdata);
				return 0;
			}
			break;
		case LEX_NICK:
			if (!is_valid_nick(t->pdata)) {
				conf_die(bip, "Invalid nickname %s.", t->pdata);
				return 0;
			}
			MOVE_STRING(l->connect_nick, t->pdata);
			break;
		case LEX_USER:
			MOVE_STRING(l->username, t->pdata);
			break;
		case LEX_REALNAME:
			MOVE_STRING(l->realname, t->pdata);
			break;
		case LEX_PASSWORD:
			MOVE_STRING(l->s_password, t->pdata);
			break;
		case LEX_VHOST:
			MOVE_STRING(l->vhost, t->pdata);
			break;
		case LEX_CHANNEL:
			name = get_tuple_pvalue(t->pdata, LEX_NAME);
			if (name == NULL) {
				conf_die(bip, "Channel with no name");
				return 0;
			}

			ci = hash_get(&l->chan_infos, name);
			if (!ci) {
				ci = chan_info_new();
				hash_insert(&l->chan_infos, name, ci);
				/* FIXME: this order is not reloaded */
				list_add_last(&l->chan_infos_order, ci);
				ci->backlog = 1;
			}

			while ((t2 = list_remove_first(t->pdata))) {
				switch (t2->type) {
				case LEX_NAME:
					MOVE_STRING(ci->name, t2->pdata);
					break;
				case LEX_KEY:
					MOVE_STRING(ci->key, t2->pdata);
					break;
				case LEX_BACKLOG:
					ci->backlog = t2->ndata;
					break;
				}
				if (t2->tuple_type == TUPLE_STR && t2->pdata)
					free(t2->pdata);
				free(t2);
			}
			list_free(t->pdata);
			break;
		case LEX_FOLLOW_NICK:
			l->follow_nick = t->ndata;
			break;
		case LEX_IGN_FIRST_NICK:
			l->ignore_first_nick = t->ndata;
			break;
		case LEX_AWAY_NICK:
			MOVE_STRING(l->away_nick, t->pdata);
			break;
		case LEX_NO_CLIENT_AWAY_MSG:
			MOVE_STRING(l->no_client_away_msg, t->pdata);
			break;
		case LEX_ON_CONNECT_SEND:
			list_add_last(&l->on_connect_send, t->pdata);
			t->pdata = NULL;
			break;
#ifdef HAVE_LIBSSL
		case LEX_SSL_CHECK_MODE:
			if (strcmp(t->pdata, "basic") == 0)
				l->ssl_check_mode = SSL_CHECK_BASIC;
			if (strcmp(t->pdata, "ca") == 0)
				l->ssl_check_mode = SSL_CHECK_CA;
			break;
#else
		case LEX_SSL_CHECK_MODE:
			mylog(LOG_WARN, "Found SSL option whereas bip is "
					"not built with SSL support.");
			break;
#endif
		default:
			conf_die(bip, "Unknown keyword in connection "
					"statement");
			return 0;
		}
		if (t->tuple_type == TUPLE_STR && t->pdata)
			free(t->pdata);
		free(t);
	}
	/* checks that can only be here, or must */
	if (!l->network) {
		conf_die(bip, "Missing network in connection block");
		return 0;
	}
	if (!l->connect_nick) {
		if (!user->default_nick) {
			conf_die(bip, "No nick set and no default nick.");
			return 0;
		}
		l->connect_nick = strdup(user->default_nick);
	}
	if (!l->username) {
		if (!user->default_username) {
			conf_die(bip, "No username set and no default "
					"username.");
			return 0;
		}
		l->username = strdup(user->default_username);
	}
	if (!l->realname) {
		if (!user->default_realname) {
			conf_die(bip, "No realname set and no default "
					"realname.");
			return 0;
		}
		l->realname = strdup(user->default_realname);
	}

	l->in_use = 1;
	return 1;
}

static char *get_tuple_pvalue(list_t *tuple_l, int lex)
{
	struct tuple *t;
	list_iterator_t it;

	for (list_it_init(tuple_l, &it); (t = list_it_item(&it));
			list_it_next(&it)) {
		if (t->type == lex)
			return t->pdata;
	}
	return NULL;
}

static int get_tuple_nvalue(list_t *tuple_l, int lex)
{
	struct tuple *t;
	list_iterator_t it;

	for (list_it_init(tuple_l, &it); (t = list_it_item(&it));
			list_it_next(&it)) {
		if (t->type == lex)
			return t->ndata;
	}
	return -1;
}

struct historical_directives {
	int always_backlog;
	int backlog;
	int bl_msg_only;
	int backlog_lines;
	int backlog_no_timestamp;
	int blreset_on_talk;
};

static int add_user(bip_t *bip, list_t *data, struct historical_directives *hds)
{
	int r;
	struct tuple *t;
	struct user *u;
	char *name = get_tuple_pvalue(data, LEX_NAME);
	list_t connection_list, *cl;

	list_init(&connection_list, NULL);

	if (name == NULL) {
		conf_die(bip, "User with no name");
		return 0;
	}
	u = hash_get(&bip->users, name);
	if (!u) {
		u = calloc(sizeof(struct user), 1);
		hash_insert(&bip->users, name, u);
		hash_init(&u->connections, HASH_NOCASE);
		u->admin = 0;
		u->backlog = DEFAULT_BACKLOG;
		u->always_backlog = DEFAULT_ALWAYS_BACKLOG;
		u->bl_msg_only = DEFAULT_BL_MSG_ONLY;
		u->backlog_lines = DEFAULT_BACKLOG_LINES;
		u->backlog_no_timestamp = DEFAULT_BACKLOG_NO_TIMESTAMP;
		u->blreset_on_talk = DEFAULT_BLRESET_ON_TALK;
		u->bip_use_notice = DEFAULT_BIP_USE_NOTICE;
	} else {
		FREE(u->name);
		FREE(u->password);
		FREE(u->default_nick);
		FREE(u->default_username);
		FREE(u->default_realname);
#ifdef HAVE_LIBSSL
		FREE(u->ssl_check_store);
		FREE(u->ssl_client_certfile);
#endif
	}

	u->backlog = hds->backlog;
	u->always_backlog = hds->always_backlog;
	u->bl_msg_only = hds->bl_msg_only;
	u->backlog_lines = hds->backlog_lines;
	u->backlog_no_timestamp = hds->backlog_no_timestamp;
	u->blreset_on_talk = hds->blreset_on_talk;

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_NAME:
			MOVE_STRING(u->name, t->pdata);
			break;
		case LEX_ADMIN:
			u->admin = t->ndata;
			break;
		case LEX_PASSWORD:
			hash_binary(t->pdata, &u->password, &u->seed);
			free(t->pdata);
			t->pdata = NULL;
			break;
		case LEX_DEFAULT_NICK:
			MOVE_STRING(u->default_nick, t->pdata);
			break;
		case LEX_DEFAULT_USER:
			MOVE_STRING(u->default_username, t->pdata);
			break;
		case LEX_DEFAULT_REALNAME:
			MOVE_STRING(u->default_realname, t->pdata);
			break;
		case LEX_ALWAYS_BACKLOG:
			u->always_backlog = t->ndata;
			break;
		case LEX_BACKLOG:
			u->backlog = t->ndata;
			break;
		case LEX_BL_MSG_ONLY:
			u->bl_msg_only = t->ndata;
			break;
		case LEX_BACKLOG_LINES:
			u->backlog_lines = t->ndata;
			break;
		case LEX_BACKLOG_NO_TIMESTAMP:
			u->backlog_no_timestamp = t->ndata;
			break;
		case LEX_BLRESET_ON_TALK:
			u->blreset_on_talk = t->ndata;
			break;
		case LEX_BIP_USE_NOTICE:
			u->bip_use_notice = t->ndata;
			break;
		case LEX_CONNECTION:
			list_add_last(&connection_list, t->pdata);
			t->pdata = NULL;
			break;
#ifdef HAVE_LIBSSL
		case LEX_SSL_CHECK_MODE:
			if (!strncmp(t->pdata, "basic", 5))
				u->ssl_check_mode = SSL_CHECK_BASIC;
			if (!strncmp(t->pdata, "ca", 2))
				u->ssl_check_mode = SSL_CHECK_CA;
			free(t->pdata);
			t->pdata = NULL;
			break;
		case LEX_SSL_CHECK_STORE:
			MOVE_STRING(u->ssl_check_store, t->pdata);
			break;
		case LEX_SSL_CLIENT_CERTFILE:
			MOVE_STRING(u->ssl_client_certfile, t->pdata);
			break;
#else
		case LEX_SSL_CLIENT_CERTFILE:
		case LEX_SSL_CHECK_MODE:
		case LEX_SSL_CHECK_STORE:
			mylog(LOG_WARN, "Found SSL option whereas bip is "
					"not built with SSL support.");
			break;
#endif
		default:
			conf_die(bip, "Uknown keyword in user statement");
			return 0;
		}
		if (t->tuple_type == TUPLE_STR && t->pdata)
			free(t->pdata);
		free(t);
	}
	if (!u->password) {
		conf_die(bip, "Missing password in user block");
		return 0;
	}

	while ((cl = list_remove_first(&connection_list))) {
		r = add_connection(bip, u, cl);
		free(cl);
		if (!r)
			return 0;
	}

	u->in_use = 1;
	return 1;
}

static int validate_config(bip_t *bip)
{
	/* nick username realname or default_{nick,username,realname} in user */
	hash_iterator_t it, sit, cit;
	struct user *user;
	struct link *link;
	struct chan_info *ci;
	int r = 1;

	for (hash_it_init(&bip->users, &it); (user = hash_it_item(&it));
			hash_it_next(&it)) {
		if (!user->default_nick || !user->default_username ||
				!user->default_realname) {
			for (hash_it_init(&user->connections, &sit);
					(link = hash_it_item(&sit));
					hash_it_next(&sit)) {
				if ((!link->username &&
						!user->default_username) ||
						(!link->connect_nick &&
						 !user->default_nick) ||
						(!link->realname &&
						 !user->default_realname))
					link_kill(bip, link);

#ifdef HAVE_LIBSSL
				if (link->network->ssl &&
				    !link->ssl_check_mode) {
					conf_die(bip, "user %s, "
						"connection %s: you should "
						"define a ssl_check_mode.",
						user->name, link->name);
					return 0;
				}
#endif

				r = 0;

				for (hash_it_init(&link->chan_infos, &cit);
						(ci = hash_it_item(&cit));
						hash_it_next(&cit)) {
					if (!ci->name) {
						conf_die(bip, "user %s, "
							"connection "
							"%s: channel must have"
							"a name.", user->name,
							link->name);
						return 0;
					}
				}
			}
		}

		if (user->backlog && !conf_log && user->backlog_lines == 0) {
			conf_die(bip, "If conf_log = false, you must set "
				"backlog_"
				"lines to a non-nul value for each user with"
				"backlog = true. Faulty user is %s",
				user->name);
			return 0;
		}
	}

	if (strstr(conf_log_format, "%u") == NULL)
		mylog(LOG_WARN, "log_format does not contain %%u, all users'"
			" logs will be mixed !");
	return r;
}

void clear_marks(bip_t *bip)
{
	list_iterator_t lit;
	hash_iterator_t hit;

	for (list_it_init(&bip->link_list, &lit); list_it_item(&lit);
			list_it_next(&lit))
		((struct link *)list_it_item(&lit))->in_use = 0;
	for (hash_it_init(&bip->users, &hit); hash_it_item(&hit);
			hash_it_next(&hit))
		((struct user *)hash_it_item(&hit))->in_use = 0;
}

void user_kill(bip_t *bip, struct user *user)
{
	(void)bip;
	if (!hash_is_empty(&user->connections))
		fatal("user_kill, user still has connections");
	free(user->name);
	free(user->password);
	MAYFREE(user->default_nick);
	MAYFREE(user->default_username);
	MAYFREE(user->default_realname);

#ifdef HAVE_LIBSSL
	MAYFREE(user->ssl_check_store);
	MAYFREE(user->ssl_client_certfile);
#endif
	free(user);
}

void sweep(bip_t *bip)
{
	list_iterator_t lit;
	hash_iterator_t hit;

	for (list_it_init(&bip->link_list, &lit); list_it_item(&lit);
			list_it_next(&lit)) {
		struct link *l = ((struct link *)list_it_item(&lit));
		if (!l->in_use) {
			mylog(LOG_INFO, "Administratively killing %s/%s",
					l->user->name, l->name);
			link_kill(bip, l);
			list_remove_if_exists(&bip->conn_list, l);
			list_it_remove(&lit);
		}
	}
	for (hash_it_init(&bip->users, &hit); hash_it_item(&hit);
			hash_it_next(&hit)) {
		struct user *u = (struct user *)hash_it_item(&hit);
		if (!u->in_use) {
			hash_it_remove(&hit);
			user_kill(bip, u);
		}
	}
}

int fireup(bip_t *bip, FILE *conf)
{
	int r;
	struct tuple *t;
	int err = 0;
	struct historical_directives hds;
	char *l;

	clear_marks(bip);
	while ((l = list_remove_first(&bip->errors)))
		free(l);
	parse_conf(conf, &err);
	if (err) {
		free_conf(root_list);
		root_list = NULL;
		return 0;
	}

#define SET_HV(d, n) do {\
	int __gtv = get_tuple_nvalue(root_list, LEX_##n);\
	if (__gtv != -1) \
		d = __gtv;\
	else\
		d = DEFAULT_##n;\
	} while(0);
	SET_HV(hds.always_backlog, ALWAYS_BACKLOG);
	SET_HV(hds.backlog, BACKLOG);
	SET_HV(hds.bl_msg_only, BL_MSG_ONLY);
	SET_HV(hds.backlog_lines, BACKLOG_LINES);
	SET_HV(hds.backlog_no_timestamp, BACKLOG_NO_TIMESTAMP);
	SET_HV(hds.blreset_on_talk, BLRESET_ON_TALK);
#undef SET_HV

	while ((t = list_remove_first(root_list))) {
		switch (t->type) {
		case LEX_LOG_SYNC_INTERVAL:
			conf_log_sync_interval = t->ndata;
			break;
		case LEX_LOG:
			conf_log = t->ndata;
			break;
		case LEX_LOG_SYSTEM:
			conf_log_system = t->ndata;
			break;
		case LEX_LOG_ROOT:
			MOVE_STRING(conf_log_root, t->pdata);
			break;
		case LEX_LOG_FORMAT:
			MOVE_STRING(conf_log_format, t->pdata);
			break;
		case LEX_LOG_LEVEL:
			conf_log_level = t->ndata;
			break;
		case LEX_IP:
			MOVE_STRING(conf_ip, t->pdata);
			break;
		case LEX_PORT:
			conf_port = t->ndata;
			break;
#ifdef HAVE_LIBSSL
		case LEX_CSS:
			conf_css = t->ndata;
			break;
		case LEX_CSS_PEM:
			MOVE_STRING(conf_ssl_certfile, t->pdata);
			break;
#else
		case LEX_CSS:
		case LEX_CSS_PEM:
			mylog(LOG_WARN, "Found SSL option whereas bip is "
					"not built with SSL support.");
			break;
#endif
		case LEX_PID_FILE:
			MOVE_STRING(conf_pid_file, t->pdata);
			break;
		case LEX_ALWAYS_BACKLOG:
			hds.always_backlog = t->ndata;
			break;
		case LEX_BACKLOG:
			hds.backlog = t->ndata;
			break;
		case LEX_BL_MSG_ONLY:
			hds.bl_msg_only = t->ndata;
			break;
		case LEX_BACKLOG_LINES:
			hds.backlog_lines = t->ndata;
			break;
		case LEX_BACKLOG_NO_TIMESTAMP:
			hds.backlog_no_timestamp = t->ndata;
			break;
		case LEX_BLRESET_ON_TALK:
			hds.blreset_on_talk = t->ndata;
			break;
		case LEX_NETWORK:
			r = add_network(bip, t->pdata);
			list_free(t->pdata);
			if (!r)
				goto out_conf_error;
			break;
		case LEX_USER:
			r = add_user(bip, t->pdata, &hds);
			list_free(t->pdata);
			if (!r)
				goto out_conf_error;
			break;
		default:
			conf_die(bip, "Config error in base config (%d)",
					t->type);
			goto out_conf_error;
		}
		if (t->tuple_type == TUPLE_STR && t->pdata)
			free(t->pdata);
		free(t);
	}
	free(root_list);
	root_list = NULL;

	if (validate_config(bip)) {
		sweep(bip);
		return 1;
	} else {
		return 0;
	}
out_conf_error:
	free_conf(root_list);
	root_list = NULL;
	return 0;
}

static void log_file_setup(void)
{
	char buf[4096];

	if (conf_log_system && conf_daemonize) {
		if (conf_global_log_file && conf_global_log_file != stderr)
			fclose(conf_global_log_file);
		snprintf(buf, 4095, "%s/bip.log", conf_log_root);
		FILE *f = fopen(buf, "a");
		if (!f)
			fatal("Can't open %s: %s", buf, strerror(errno));
		conf_global_log_file = f;
	} else {
		conf_global_log_file = stderr;
	}
}

void check_rlimits()
{
	int r, cklim;
	struct rlimit lt;

	cklim = 0;

	r = getrlimit(RLIMIT_AS, &lt);
	if (r) {
		mylog(LOG_ERROR, "getrlimit(): failed with %s",
				strerror(errno));
	} else {
		if (lt.rlim_max != RLIM_INFINITY) {
			mylog(LOG_WARN, "virtual memory rlimit active, "
				"bip may be KILLED by the system");
			cklim = 1;
		}
	}

	r = getrlimit(RLIMIT_CPU, &lt);
	if (r) {
		mylog(LOG_ERROR, "getrlimit(): failed with %s",
				strerror(errno));
	} else {
		if (lt.rlim_max != RLIM_INFINITY) {
			mylog(LOG_WARN, "CPU rlimit active, bip may "
				"be OFTEN KILLED by the system");
			cklim = 1;
		}
	}

	r = getrlimit(RLIMIT_FSIZE, &lt);
	if (r) {
		mylog(LOG_ERROR, "getrlimit(): failed with %s",
				strerror(errno));
	} else {
		if (lt.rlim_max != RLIM_INFINITY) {
			mylog(LOG_WARN, "FSIZE rlimit active, bip will "
				"fail to create files of size greater than "
				"%d bytes.", (int)lt.rlim_max);
			cklim = 1;
		}
	}

	r = getrlimit(RLIMIT_NOFILE, &lt);
	if (r) {
		mylog(LOG_ERROR, "getrlimit(): failed with %s",
				strerror(errno));
	} else {
		if (lt.rlim_max != RLIM_INFINITY && lt.rlim_max < 256) {
			mylog(LOG_WARN, "opened files count rlimit "
				"active, bip will not be allowed to open more "
				"than %d files at a time", (int)lt.rlim_max);
			cklim = 1;
		}
	}

	r = getrlimit(RLIMIT_STACK, &lt);
	if (r) {
		mylog(LOG_ERROR, "getrlimit(): failed with %s",
				strerror(errno));
	} else {
		if (lt.rlim_max != RLIM_INFINITY) {
			mylog(LOG_WARN, "stack rlimit active, "
				"bip may be KILLED by the system");
			cklim = 1;
		}
	}

	if (cklim)
		mylog(LOG_WARN, "You can check your limits with `ulimit -a'");
}

int main(int argc, char **argv)
{
	FILE *conf = NULL;
	char *confpath = NULL;
	int ch;
	int r, fd;
	char buf[30];
	bip_t bip;
	char *home;

	bip_init(&bip);
	_bip = &bip;

	conf_ip = strdup("0.0.0.0");
	conf_port = 7778;
	conf_css = 0;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, reload_config);
	signal(SIGINT, bad_quit);
	signal(SIGQUIT, bad_quit);
	signal(SIGTERM, bad_quit);
	signal(SIGXFSZ, rlimit_bigfile_reached);
	signal(SIGXCPU, rlimit_cpu_reached);

	conf_log_root = NULL;
	conf_log_format = strdup(DEFAULT_LOG_FORMAT);
	conf_log_level = DEFAULT_LOG_LEVEL;
	conf_daemonize = 1;
	conf_global_log_file = stderr;
	conf_pid_file = NULL;
#ifdef HAVE_LIBSSL
	conf_ssl_certfile = NULL;
#endif

	while ((ch = getopt(argc, argv, "hvnf:s:")) != -1) {
		switch (ch) {
		case 'f':
			confpath = strdup(optarg);
			break;
		case 'n':
			conf_daemonize = 0;
			break;
		case 's':
			conf_biphome = strdup(optarg);
			break;
		case 'v':
			version();
			exit(0);
			break;
		default:
			version();
			usage(argv[0]);
		}
	}

	umask(0027);

	check_rlimits();

	home = getenv("HOME");
	if (!home) {
		conf_die(&bip, "no $HOME !, do you live in a trailer ?");
		return 0;
	}

	if (confpath) {
		conf = fopen(confpath, "r");
		if (!conf)
			fatal("config file not found");
	}
	if (!conf) {
		confpath = malloc(strlen(home) + 1 + strlen(S_CONF) + 1);
		*confpath = 0;
		strcat(confpath, home);
		strcat(confpath, "/");
		strcat(confpath, S_CONF);
		conf = fopen(confpath, "r");
		if (!conf)
			fatal("%s config file not found", confpath);
	}

#ifdef HAVE_OIDENTD
	bip.oidentdpath = malloc(strlen(home) + 1 +
			strlen(OIDENTD_FILENAME) + 1);
	strcpy(bip.oidentdpath, home);
	strcat(bip.oidentdpath, "/");
	strcat(bip.oidentdpath, OIDENTD_FILENAME);
#endif

	r = fireup(&bip, conf);
	fclose(conf);
	if (!r)
		fatal("Not starting: error in config file.");

	if (!conf_biphome) {
		conf_biphome = malloc(strlen(home) + strlen("/.bip") + 1);
		strcpy(conf_biphome, home);
		strcat(conf_biphome, "/.bip");
	}
	if (!conf_log_root) {
		char *ap = "/logs";
		conf_log_root = malloc(strlen(conf_biphome) + strlen(ap) + 1);
		strcpy(conf_log_root, conf_biphome);
		strcat(conf_log_root, ap);
		mylog(LOG_INFO, "Default log root: %s", conf_log_root);
	}
	if (!conf_pid_file) {
		char *pid = "/bip.pid";
		conf_pid_file = malloc(strlen(conf_biphome) + strlen(pid) + 1);
		strcpy(conf_pid_file, conf_biphome);
		strcat(conf_pid_file, pid);
		mylog(LOG_INFO, "Default pid file: %s", conf_pid_file);
	}

#ifdef HAVE_LIBSSL
	if (conf_css) {
		int e, fd;
		struct stat fs;

		if (!conf_ssl_certfile) {
			char *ap = "/bip.pem";
			conf_ssl_certfile = malloc(strlen(conf_biphome) +
					strlen(ap) + 1);
			strcpy(conf_ssl_certfile, conf_biphome);
			strcat(conf_ssl_certfile, ap);
			mylog(LOG_INFO, "Using default SSL certificate file: "
					"%s", conf_ssl_certfile);
		}

		if ((fd = open(conf_ssl_certfile, O_RDONLY)) == -1)
			fatal("Unable to open PEM file %s for reading",
				conf_ssl_certfile);
		else
			close(fd);

		e = stat(conf_ssl_certfile, &fs);
		if (e)
			mylog(LOG_WARN, "Unable to check PEM file, stat(%s): "
				"%s", conf_ssl_certfile, strerror(errno));
		else if ((fs.st_mode & S_IROTH) | (fs.st_mode & S_IWOTH))
			mylog(LOG_ERROR, "PEM file %s should not be world "
				"readable / writable. Please fix the modes.",
				conf_ssl_certfile);
	}
#endif

	check_dir(conf_log_root, 1);
	fd = do_pid_stuff();
	pid_t pid = 0;

	log_file_setup();
	if (conf_daemonize)
		pid = daemonize();
	else
		pid = getpid();
	snprintf(buf, 29, "%ld\n", (long unsigned int)pid);
	write(fd, buf, strlen(buf));
	close(fd);

	bip.listener = listen_new(conf_ip, conf_port, conf_css);
	if (!bip.listener)
		fatal("Could not create listening socket");

	for (;;) {
		irc_main(&bip);

		sighup = 0;

		conf = fopen(confpath, "r");
		if (!conf)
			fatal("%s config file not found", confpath);
		fireup(&bip, conf);
		fclose(conf);

		/* re-open to allow logfile rotate */
		log_file_setup();
	}
	return 1;
}

#define RET_STR_LEN 256
#define LINE_SIZE_LIM 70
void adm_print_connection(struct link_client *ic, struct link *lnk,
		struct user *bu)
{
	hash_iterator_t lit;
	char buf[RET_STR_LEN + 1];
	int t_written = 0;

	if (!bu)
		bu = lnk->user;

	bip_notify(ic, "* %s to %s as \"%s\" (%s!%s) :", lnk->name,
		lnk->network->name,
		(lnk->realname ? lnk->realname : bu->default_realname),
		(lnk->connect_nick ? lnk->connect_nick : bu->default_nick),
		(lnk->username ? lnk->username : bu->default_username));

	t_written = snprintf(buf, RET_STR_LEN, "  Options:");
	if (t_written >= RET_STR_LEN)
		goto noroom;
	if (lnk->follow_nick) {
		t_written += snprintf(buf + t_written,
			RET_STR_LEN - t_written, " follow_nick");
		if (t_written >= RET_STR_LEN)
			goto noroom;
	}
	if (lnk->ignore_first_nick) {
		t_written += snprintf(buf + t_written,
			RET_STR_LEN - t_written, " ignore_first_nick");
		if (t_written >= RET_STR_LEN)
			goto noroom;
	}
	if (lnk->away_nick) {
		t_written += snprintf(buf + t_written,
			RET_STR_LEN - t_written, " away_nick=%s",
			lnk->away_nick);
		if (t_written >= RET_STR_LEN)
			goto noroom;
	}
	if (lnk->no_client_away_msg) {
		t_written += snprintf(buf + t_written,
			RET_STR_LEN - t_written, " no_client_away_msg=%s",
			lnk->no_client_away_msg);
		if (t_written >= RET_STR_LEN)
			goto noroom;
	}
	if (lnk->vhost) {
		t_written += snprintf(buf + t_written,
			RET_STR_LEN - t_written, " vhost=%s",
			lnk->vhost);
		if (t_written >= RET_STR_LEN)
			goto noroom;
	}
	if (lnk->bind_port) {
		t_written += snprintf(buf + t_written,
			RET_STR_LEN - t_written, " bind_port=%u",
			lnk->bind_port);
		if (t_written >= RET_STR_LEN)
			goto noroom;
	}
noroom: /* that means the line is larger that RET_STR_LEN. We're not likely to
	   even read such a long line */
	buf[RET_STR_LEN] = 0;
	bip_notify(ic, buf);

	// TODO: on_connect_send

	// TODO : check channels struct
	t_written = snprintf(buf, RET_STR_LEN, "  Channels (* with key, ` no backlog)");
	if (t_written >= RET_STR_LEN)
		goto noroomchan;
	for (hash_it_init(&lnk->chan_infos, &lit); hash_it_item(&lit);
			hash_it_next(&lit)) {
		struct chan_info *ch = hash_it_item(&lit);

		t_written += snprintf(buf + t_written, RET_STR_LEN - t_written, " %s%s%s",
			ch->name, (ch->key ? "*" : ""),
			(ch->backlog ? "" : "`"));
		if (t_written > LINE_SIZE_LIM) {
			buf[RET_STR_LEN] = 0;
			bip_notify(ic, buf);
			t_written = 0;
		}
	}
noroomchan:
	buf[RET_STR_LEN] = 0;
	bip_notify(ic, buf);

	t_written = snprintf(buf, RET_STR_LEN, "  Status: ");
	if (t_written >= RET_STR_LEN)
		goto noroomstatus;
	switch (lnk->s_state) {
	case  IRCS_NONE:
		t_written += snprintf(buf + t_written, RET_STR_LEN - t_written,
			"not started");
		if (t_written >= RET_STR_LEN)
			goto noroomstatus;
		break;
	case  IRCS_CONNECTING:
		t_written += snprintf(buf + t_written, RET_STR_LEN - t_written,
			"connecting... attempts: %d, last: %s",
			lnk->s_conn_attempt,
			hrtime(lnk->last_connection_attempt));
		if (t_written >= RET_STR_LEN)
			goto noroomstatus;
		break;
	case  IRCS_CONNECTED:
		t_written += snprintf(buf + t_written, RET_STR_LEN - t_written,
			"connected !");
		if (t_written >= RET_STR_LEN)
			goto noroomstatus;
		break;
	case  IRCS_WAS_CONNECTED:
		t_written += snprintf(buf + t_written, RET_STR_LEN - t_written,
			"disconnected, attempts: %d, last: %s",
			lnk->s_conn_attempt,
			hrtime(lnk->last_connection_attempt));
		if (t_written >= RET_STR_LEN)
			goto noroomstatus;
		break;
	case  IRCS_RECONNECTING:
		t_written += snprintf(buf + t_written, RET_STR_LEN - t_written,
			"reconnecting... attempts: %d, last: %s",
			lnk->s_conn_attempt,
			hrtime(lnk->last_connection_attempt));
		if (t_written >= RET_STR_LEN)
			goto noroomstatus;
		break;
	case  IRCS_TIMER_WAIT:
		t_written += snprintf(buf + t_written, RET_STR_LEN - t_written,
			"waiting to reconnect, attempts: %d, last: %s",
			lnk->s_conn_attempt,
			hrtime(lnk->last_connection_attempt));
		if (t_written >= RET_STR_LEN)
			goto noroomstatus;
		break;
	default:
		t_written += snprintf(buf + t_written, RET_STR_LEN - t_written,
			"unknown");
		if (t_written >= RET_STR_LEN)
			goto noroomstatus;
		break;
		// s_conn_attempt recon_timer last_connection_attempt
	}
noroomstatus:
	buf[RET_STR_LEN] = 0;
	bip_notify(ic, buf);
}

void adm_list_all_links(struct link_client *ic)
{
	list_iterator_t it;

	bip_notify(ic, "-- All links");
	for (list_it_init(&_bip->link_list, &it); list_it_item(&it);
			list_it_next(&it)) {
		struct link *l = list_it_item(&it);
		if (l)
			adm_print_connection(ic, l, NULL);
	}
	bip_notify(ic, "-- End of All links");
}

void adm_list_all_connections(struct link_client *ic)
{
	hash_iterator_t it;

	bip_notify(ic, "-- All connections");
	for (hash_it_init(&_bip->users, &it); hash_it_item(&it);
			hash_it_next(&it)) {
		struct user *u = hash_it_item(&it);
		if (u)
			adm_list_connections(ic, u);
	}
	bip_notify(ic, "-- End of All connections");
}

#define STRORNULL(s) ((s) == NULL ? "unset" : (s))

void adm_info_user(struct link_client *ic, char *name)
{
	struct user *u;
	char buf[RET_STR_LEN + 1];
	int t_written = 0;

	bip_notify(ic, "-- User '%s' info", name);
	u = hash_get(&_bip->users, name);
	if (!u) {
		bip_notify(ic, "Unknown user");
		return;
	}

	t_written += snprintf(buf + t_written, RET_STR_LEN - t_written,
			      "user: %s", u->name);
	if (t_written >= RET_STR_LEN)
		goto noroom;
	if (u->admin) {
		t_written += snprintf(buf + t_written, RET_STR_LEN - t_written,
				", is bip admin");
		if (t_written >= RET_STR_LEN)
			goto noroom;
	}

noroom:
	buf[RET_STR_LEN] = 0;
	bip_notify(ic, buf);
	t_written = 0;

#ifdef HAVE_LIBSSL
	bip_notify(ic, "SSL check mode '%s', stored into '%s'",
		   checkmode2text(u->ssl_check_mode),
		   STRORNULL(u->ssl_check_store));
	if (u->ssl_client_certfile)
		bip_notify(ic, "SSL client certificate stored into '%s'",
				u->ssl_client_certfile);
#endif
	bip_notify(ic, "Defaults nick: %s, user: %s, realname: %s",
		   STRORNULL(u->default_nick), STRORNULL(u->default_username),
		   STRORNULL(u->default_realname));
	if (u->backlog) {
		bip_notify(ic, "Backlog enabled, lines: %d, no timestamp: %s,"
			"  messages only: %s", u->backlog_lines,
			bool2text(u->backlog_no_timestamp),
			bool2text(u->bl_msg_only));
		bip_notify(ic, "always backlog: %s, reset on talk: %s",
			bool2text(u->always_backlog),
			bool2text(u->blreset_on_talk));
	} else {
		bip_notify(ic, "Backlog disabled");
	}
	adm_list_connections(ic, u);
	bip_notify(ic, "-- End of User '%s' info", name);
}

void adm_list_users(struct link_client *ic)
{
	hash_iterator_t it;
	hash_iterator_t lit;
	char buf[RET_STR_LEN + 1];
	connection_t *c;

	c = CONN(ic);

	bip_notify(ic, "-- User list");
	for (hash_it_init(&_bip->users, &it); hash_it_item(&it);
			hash_it_next(&it)) {
		struct user *u = hash_it_item(&it);
		int first = 1;
		int t_written = 0;

		buf[RET_STR_LEN] = 0;
		t_written += snprintf(buf, RET_STR_LEN, "* %s%s:", u->name,
				(u->admin ? "(admin)": ""));
		if (t_written >= RET_STR_LEN)
			goto noroom;
		for (hash_it_init(&u->connections, &lit); hash_it_item(&lit);
				hash_it_next(&lit)) {
			struct link *lnk = hash_it_item(&lit);
			if (first) {
				first = 0;
			} else {
				t_written += snprintf(buf + t_written, RET_STR_LEN
					- t_written, ",");
				if (t_written >= RET_STR_LEN)
					goto noroom;
			}

			t_written += snprintf(buf + t_written,
					RET_STR_LEN - t_written,
					" %s", lnk->name);
			if (t_written >= RET_STR_LEN)
				goto noroom;
			if (t_written > LINE_SIZE_LIM) {
				buf[RET_STR_LEN] = 0;
				bip_notify(ic, buf);
				t_written = 0;
			}
		}
noroom:
		buf[RET_STR_LEN] = 0;
		bip_notify(ic, buf);
	}
	bip_notify(ic, "-- End of User list");
}

void adm_list_networks(struct link_client *ic)
{
	hash_iterator_t it;
	char buf[RET_STR_LEN + 1];
	connection_t *c;

	c = CONN(ic);

	bip_notify(ic, "-- Network list (* means SSL):");
	for (hash_it_init(&_bip->networks, &it); hash_it_item(&it);
			hash_it_next(&it)) {
		struct network *n = hash_it_item(&it);
		int t_written = 0;
		int i;

		buf[RET_STR_LEN] = 0;
#ifdef HAVE_LIBSSL
		if (n->ssl) {
			t_written += snprintf(buf, RET_STR_LEN, "- %s*:",
					n->name);
			if (t_written >= RET_STR_LEN)
				goto noroom;
		} else {
#endif
			t_written += snprintf(buf, RET_STR_LEN, "- %s:", n->name);
			if (t_written >= RET_STR_LEN)
				goto noroom;
#ifdef HAVE_LIBSSL
		}
#endif
		for (i = 0; i < n->serverc; i++) {
			struct server *serv = i+n->serverv;
			t_written += snprintf(buf + t_written, RET_STR_LEN
				- t_written, " %s:%d", serv->host,
				serv->port);
			if (t_written >= RET_STR_LEN)
				goto noroom;
			if (t_written > LINE_SIZE_LIM) {
				buf[RET_STR_LEN] = 0;
				bip_notify(ic, buf);
				t_written = 0;
			}
		}
noroom:
		buf[RET_STR_LEN] = 0;
		bip_notify(ic, buf);
	}
	bip_notify(ic, "-- End of Network list");
}

void adm_list_connections(struct link_client *ic, struct user *bu)
{
	hash_iterator_t it;
	connection_t *c;

	c = CONN(ic);
	if (!bu) {
		bip_notify(ic, "-- Your connections:");
		bu = LINK(ic)->user;
	} else {
		bip_notify(ic, "-- User %s's connections:", bu->name);
	}

	for (hash_it_init(&bu->connections, &it); hash_it_item(&it);
			hash_it_next(&it)) {
		struct link *lnk= hash_it_item(&it);
		adm_print_connection(ic, lnk, bu);
	}
	bip_notify(ic, "-- End of Connection list");
}

#ifdef HAVE_LIBSSL
int link_add_untrusted(struct link_server *ls, X509 *cert)
{
	int i;

	/* Check whether the cert is already in the stack */
	for (i = 0; i < sk_X509_num(LINK(ls)->untrusted_certs); i++) {
		if (!X509_cmp(cert,
				sk_X509_value(LINK(ls)->untrusted_certs, i)))
			return 1;
	}

	return sk_X509_push(LINK(ls)->untrusted_certs, cert);
}

int ssl_check_trust(struct link_client *ic)
{
	X509 *trustcert = NULL;
	char subject[270];
	char issuer[270];
	unsigned char fp[EVP_MAX_MD_SIZE];
	char fpstr[EVP_MAX_MD_SIZE * 3 + 20];
	unsigned int fplen;
	int i;

	if(!LINK(ic)->untrusted_certs ||
			sk_X509_num(LINK(ic)->untrusted_certs) <= 0)
		return 0;

	trustcert = sk_X509_value(LINK(ic)->untrusted_certs, 0);
	strcpy(subject, "Subject: ");
	strcpy(issuer, "Issuer:  ");
	strcpy(fpstr, "MD5 fingerprint: ");
	X509_NAME_oneline(X509_get_subject_name(trustcert), subject + 9, 256);
	X509_NAME_oneline(X509_get_issuer_name(trustcert), issuer + 9, 256);

	X509_digest(trustcert, EVP_md5(), fp, &fplen);
	for(i = 0; i < (int)fplen; i++)
		sprintf(fpstr + 17 + (i * 3), "%02X%c",
				fp[i], (i == (int)fplen - 1) ? '\0' : ':');

	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
			"This server SSL certificate was not "
			"accepted because it is not in your store "
			"of trusted certificates:");

	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm", subject);
	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm", issuer);
	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm", fpstr);

	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
			"WARNING: if you've already trusted a "
			"certificate for this server before, that "
			"probably means it has changed.");

	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
			"If so, YOU MAY BE SUBJECT OF A "
			"MAN-IN-THE-MIDDLE ATTACK! PLEASE DON'T TRUST "
			"THIS CERTIFICATE IF YOU'RE NOT SURE THIS IS "
			"NOT THE CASE.");

	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
			"Type /QUOTE BIP TRUST OK to trust this "
			"certificate, /QUOTE BIP TRUST NO to discard it.");

	return 1;
}

#if 0
static int ssl_trust_next_cert(struct link_client *ic)
{
	(void)ic;
}

static int ssl_discard_next_cert(struct link_client *ic)
{
	(void)ic;
}
#endif /* 0 */
#endif

#ifdef HAVE_LIBSSL
int adm_trust(struct link_client *ic, struct line *line)
{
	if (ic->allow_trust != 1) {
		mylog(LOG_ERROR, "User attempted TRUST command without "
				"being allowed to!");
		unbind_from_link(ic);
		return OK_CLOSE;
	}

	if(!LINK(ic)->untrusted_certs ||
			sk_X509_num(LINK(ic)->untrusted_certs) <= 0) {
		/* shouldn't have been asked to /QUOTE BIP TRUST but well... */
		WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
				"No untrusted certificates.");
		return ERR_PROTOCOL;
	}

	if (line->elemc != 3)
		return ERR_PROTOCOL;

	if (!strcasecmp(line->elemv[2], "OK")) {
		/* OK, attempt to trust the cert! */
		BIO *bio = BIO_new_file(LINK(ic)->user->ssl_check_store, "a+");
		X509 *trustcert = sk_X509_shift(LINK(ic)->untrusted_certs);

		if(!bio || !trustcert ||
				PEM_write_bio_X509(bio, trustcert) <= 0)
			write_line_fast(CONN(ic), ":irc.bip.net NOTICE pouet "
					":==== Error while trusting test!\r\n");
		else
			write_line_fast(CONN(ic), ":irc.bip.net NOTICE pouet "
					":==== Certificate now trusted.\r\n");

		BIO_free_all(bio);
		X509_free(trustcert);
	} else if (!strcasecmp(line->elemv[2], "NO")) {
		/* NO, discard the cert! */
		write_line_fast(CONN(ic), ":irc.bip.net NOTICE pouet "
				":==== Certificate discarded.\r\n");

		X509_free(sk_X509_shift(LINK(ic)->untrusted_certs));
	} else
		return ERR_PROTOCOL;

	if (!ssl_check_trust(ic)) {
		write_line_fast(CONN(ic), ":irc.bip.net NOTICE pouet "
				":No more certificates waiting awaiting "
				"user trust, thanks!\r\n");
		write_line_fast(CONN(ic), ":irc.bip.net NOTICE pouet "
				":If the certificate is trusted, bip should "
				"be able to connect to the server on the "
				"next retry. Please wait a while and try "
				"connecting your client again.\r\n");

		LINK(ic)->recon_timer = 1; /* Speed up reconnection... */
		unbind_from_link(ic);
		return OK_CLOSE;
	}
	return OK_FORGET;
}
#endif

void _bip_notify(struct link_client *ic, char *fmt, va_list ap)
{
	char *nick;
	char str[4096];

	if (LINK(ic)->l_server)
		nick = LINK(ic)->l_server->nick;
	else
		nick = LINK(ic)->prev_nick;

	vsnprintf(str, 4095, fmt, ap);
	str[4095] = 0;
	WRITE_LINE2(CONN(ic), P_IRCMASK, (LINK(ic)->user->bip_use_notice ?
				"NOTICE" : "PRIVMSG"), nick, str);
}

void bip_notify(struct link_client *ic, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_bip_notify(ic, fmt, ap);
	va_end(ap);
}

void adm_blreset(struct link_client *ic)
{
	log_reinit_all(LINK(ic)->log);
	bip_notify(ic, "backlog resetted for this network.");
}

void adm_follow_nick(struct link_client *ic, char *val)
{
	struct link *link = LINK(ic);
	if (strcasecmp(val, "TRUE") == 0) {
		link->follow_nick = 1;
		bip_notify(ic, "follow_nick is now true.");
	} else {
		link->follow_nick = 0;
		bip_notify(ic, "follow_nick is now false.");
	}
}

void adm_ignore_first_nick(struct link_client *ic, char *val)
{
	struct link *link = LINK(ic);
	if (strcasecmp(val, "TRUE") == 0) {
		link->ignore_first_nick = 1;
		bip_notify(ic, "ignore_first_nick is now true.");
	} else {
		link->ignore_first_nick = 0;
		bip_notify(ic, "ignore_first_nick is now false.");
	}
}

void set_on_connect_send(struct link_client *ic, char *val)
{
	struct link *link = LINK(ic);
	char *s;

	if (val != NULL) {
		list_add_last(&link->on_connect_send, strdup(val));
		bip_notify(ic, "added to on_connect_send.");
	} else {
		s = list_remove_last(&link->on_connect_send);
		if (s)
			free(s);
		bip_notify(ic, "last on_connect_send string deleted.");
	}
}

#define ON_CONNECT_MAX_STRSIZE 1024
void adm_on_connect_send(struct link_client *ic, struct line *line,
		unsigned int privmsg)
{
	char buf[ON_CONNECT_MAX_STRSIZE];
	int t_written = 0;
	unsigned int i;

	if (!line) {
		set_on_connect_send(ic, NULL);
		return;
	}

	if (line->elemc < 3)
		return;

	for (i = privmsg + 2; i < line->elemc; i++) {
		if (t_written) {
			t_written += snprintf(buf,
					ON_CONNECT_MAX_STRSIZE - 1 - t_written,
					" %s", line->elemv[i]);
			if (t_written >= ON_CONNECT_MAX_STRSIZE)
				goto noroom;
		} else {
			t_written = snprintf(buf, ON_CONNECT_MAX_STRSIZE - 1,
					"%s", line->elemv[i]);
			if (t_written >= ON_CONNECT_MAX_STRSIZE)
				goto noroom;
		}
	}
ok:
	buf[ON_CONNECT_MAX_STRSIZE - 1] = 0;
	set_on_connect_send(ic, buf);
	return;
noroom:
	bip_notify(ic, "on connect send string too big, truncated");
	goto ok;
}

void adm_away_nick(struct link_client *ic, char *val)
{
	struct link *link = LINK(ic);
	if (link->away_nick) {
		free(link->away_nick);
		link->away_nick = NULL;
	}
	if (val != NULL) {
		link->away_nick = strdup(val);
		bip_notify(ic, "away_nick set.");
	} else {
		bip_notify(ic, "away_nick cleared.");
	}
}

void adm_bip_help(struct link_client *ic, int admin, char *subhelp)
{
	if (subhelp == NULL) {
		if (admin) {
			bip_notify(ic, "/BIP RELOAD # Re-read bip configuration "
				"and apply changes. /!\\ VERY UNSTABLE !");
			bip_notify(ic, "/BIP INFO user <username> # show a user's "
				"configuration");
			bip_notify(ic, "/BIP LIST networks|users|connections|all_links"
				"|all_connections");
			bip_notify(ic, "/BIP ADD_CONN <connection name> <network>");
			bip_notify(ic, "/BIP DEL_CONN <connection name>");
		} else {
			bip_notify(ic, "/BIP LIST networks|connections");
		}
		bip_notify(ic, "/BIP JUMP # jump to next server (in same network)");
		bip_notify(ic, "/BIP BLRESET # reset backlog (this connection only). Add -q flag and the operation is quiet.");
#ifdef HAVE_LIBSSL
		bip_notify(ic, "/BIP TRUST # trust this server certificate");
#endif
		bip_notify(ic, "/BIP HELP [subhelp] # show this help...");
		bip_notify(ic, "## Temporary changes for this connection:");
		bip_notify(ic, "/BIP FOLLOW_NICK|IGNORE_FIRST_NICK TRUE|FALSE");
		bip_notify(ic, "/BIP ON_CONNECT_SEND <str> # Adds a string to "
			"send on connect");
		bip_notify(ic, "/BIP ON_CONNECT_SEND # Clears on_connect_send");
		bip_notify(ic, "/BIP AWAY_NICK <nick> # Set away nick");
		bip_notify(ic, "/BIP AWAY_NICK # clear away nick");
	} else if (admin && strcasecmp(subhelp, "RELOAD") == 0) {
		bip_notify(ic, "/BIP RELOAD (admin only) :");
		bip_notify(ic, "  Reloads bip configuration file and apply "
			"changes.");
		bip_notify(ic, "  Please note that changes to 'user' or "
			"'realname' will not be applied without a JUMP.");
	} else if (admin && strcasecmp(subhelp, "INFO") == 0) {
		bip_notify(ic, "/BIP INFO USER <user> (admin only) :");
		bip_notify(ic, "  Show <user>'s current configuration.");
		bip_notify(ic, "  That means it may be different from the "
			"configuration stored in bip.conf");
	} else if (admin && strcasecmp(subhelp, "ADD_CONN") == 0) {
		bip_notify(ic, "/BIP ADD_CONN <connection name> <network> "
			"(admin only) :");
		bip_notify(ic, "  Add a connection named <connection name> to "
			"the network <network> to your connection list");
		bip_notify(ic, "  <network> should already exist in bip's "
			"configuration.");
	} else if (admin && strcasecmp(subhelp, "DEL_CONN") == 0) {
		bip_notify(ic, "/BIP DEL_CONN <connection name> (admin only) "
			":");
		bip_notify(ic, "  Remove the connection named <connection "
			"name> from your connection list.");
		bip_notify(ic, "  Removing a connection will cause "
			"its disconnection.");
	} else if (strcasecmp(subhelp, "JUMP") == 0) {
		bip_notify(ic, "/BIP JUMP :");
		bip_notify(ic, "  Jump to next server in current network.");
	} else if (strcasecmp(subhelp, "BLRESET") == 0) {
		bip_notify(ic, "/BIP BLRESET :");
		bip_notify(ic, "  Reset backlog on this network.");
	} else if (strcasecmp(subhelp, "TRUST") == 0) {
		bip_notify(ic, "/BIP TRUST");
		bip_notify(ic, "  Trust current server's certificate.");
	} else if (strcasecmp(subhelp, "FOLLOW_NICK") == 0) {
		bip_notify(ic, "/BIP FOLLOW_NICK TRUE|FALSE :");
		bip_notify(ic, "  Change the value of the follow_nick option "
			"for this connection.");
		bip_notify(ic, "  If set to true, when you change nick, "
			"BIP stores the new nickname as the new default "
			"nickname value.");
		bip_notify(ic, "  Thus, if you are disconnected from the "
			"server, BIP will restore the correct nickname.");
	} else if (strcasecmp(subhelp, "IGNORE_FIRST_NICK") == 0) {
		bip_notify(ic, "/BIP IGNORE_FIRST_NICK TRUE|FALSE :");
		bip_notify(ic, "  Change the value of the ignore_first_nick "
			"option for this connection.");
		bip_notify(ic, "  If set to TRUE, BIP will ignore the nickname"
			"sent by the client upon connect.");
		bip_notify(ic, "  Further nickname changes will be processed "
			"as usual.");
	} else if (strcasecmp(subhelp, "ON_CONNECT_SEND") == 0) {
		bip_notify(ic, "/BIP ON_CONNECT_SEND [some text] :");
		bip_notify(ic, "  BIP will send the text as is to the server "
			"upon connection.");
		bip_notify(ic, "  You can call this command more than once.");
		bip_notify(ic, "  If [some text] is empty, this command will "
			"remove any on_connect_send defined for this connection.");
	} else if (strcasecmp(subhelp, "AWAY_NICK") == 0) {
		bip_notify(ic, "/BIP AWAY_NICK [some_nick] :");
		bip_notify(ic, "  If [some_nick] is set, BIP will change "
			"nickname to [some_nick] if there are no more client "
			"attached");
		bip_notify(ic, "  If [some_nick] is empty, this command will "
			"unset current connection's away_nick.");
	} else if (strcasecmp(subhelp, "LIST") == 0) {
		bip_notify(ic, "/BIP LIST <section> :");
		bip_notify(ic, "  List information from a these sections :");
		bip_notify(ic, "  - networks: list all available networks");
		bip_notify(ic, "  - connections: list all your configured "
			"connections and their state.");
		if (admin) {
			bip_notify(ic, "  - users: list all users (admin)");
			bip_notify(ic, "  - all_links: list all connected "
				"sockets from and to BIP (admin)");
			bip_notify(ic, "  - all_connections: list all users' "
				"configured connections (admin)");
		}
	} else {
		bip_notify(ic, "-- No sub-help for '%s'", subhelp);
	}
}

int adm_bip(bip_t *bip, struct link_client *ic, struct line *line,
		unsigned int privmsg)
{
	int admin = LINK(ic)->user->admin;

	if (privmsg) {
		char *linestr = line->elemv[2];
		char *ptr = line->elemv[2], *eptr;
		int slen;

		if (line->elemc != 3)
			return OK_FORGET;

		line->elemc--;

		while((eptr = strstr(ptr, " "))) {
			slen = eptr - ptr;
			if (slen == 0) {
				ptr++;
				continue;
			}
			line->elemv = realloc(line->elemv,
					(line->elemc + 1) * sizeof(char *));
			line->elemv[line->elemc] = malloc(slen + 1);
			memcpy(line->elemv[line->elemc], ptr, slen);
			line->elemv[line->elemc][slen] = 0;
			line->elemc++;
			ptr = eptr + 1;
		}
		eptr = ptr + strlen(ptr);
		slen = eptr - ptr;
		if (slen != 0) {
			line->elemv = realloc(line->elemv,
				      (line->elemc + 1) * sizeof(char *));
			slen = eptr - ptr;
			line->elemv[line->elemc] = malloc(slen + 1);
			memcpy(line->elemv[line->elemc], ptr, slen);
			line->elemv[line->elemc][slen] = 0;
			line->elemc++;
		}
		free(linestr);
	}

	if (line->elemc < privmsg + 2)
		return OK_FORGET;

	mylog(LOG_INFO, "/BIP %s from %s", line->elemv[privmsg + 1],
			LINK(ic)->user->name);
	if (strcasecmp(line->elemv[privmsg + 1], "RELOAD") == 0) {
		if (!admin) {
			bip_notify(ic, "-- You're not allowed to reload bip");
			return OK_FORGET;
		}
		bip_notify(ic, "-- Reloading bip...");
		bip->reloading_client = ic;
		sighup = 1;
	} else if (strcasecmp(line->elemv[privmsg + 1], "LIST") == 0) {
		if (line->elemc != privmsg + 3) {
			bip_notify(ic, "-- LIST command needs one argument");
			return OK_FORGET;
		}

		if (admin && strcasecmp(line->elemv[privmsg + 2],
					"users") == 0) {
			adm_list_users(ic);
		} else if (strcasecmp(line->elemv[privmsg + 2],
					"networks") == 0) {
			adm_list_networks(ic);
		} else if (strcasecmp(line->elemv[privmsg + 2],
					"connections") == 0) {
			adm_list_connections(ic, NULL);
		} else if (admin && strcasecmp(line->elemv[privmsg + 2],
					"all_connections") == 0) {
			adm_list_all_connections(ic);
		} else if (admin && strcasecmp(line->elemv[privmsg + 2],
					"all_links") == 0) {
			adm_list_all_links(ic);
		} else {
			bip_notify(ic, "-- Invalid LIST request");
		}
	} else if (strcasecmp(line->elemv[privmsg + 1], "INFO") == 0) {
		if (line->elemc < privmsg + 3) {
			bip_notify(ic, "-- INFO command needs at least one argument");
			return OK_FORGET;
		}

		if (admin && strcasecmp(line->elemv[privmsg + 2],
					"user") == 0) {
			if (line->elemc == privmsg + 4) {
				adm_info_user(ic, line->elemv[privmsg + 3]);
			} else {
				bip_notify(ic, "-- INFO USER command needs one"
					" argument");
			}
#if 0
			TODO
		} else if (strcasecmp(line->elemv[privmsg + 2],
				      "network") == 0) {
			if (line->elemc == privmsg + 4) {
				adm_info_network(ic, line->elemv[privmsg + 3]);
			} else {
				bip_notify(ic, "/BIP INFO network needs one "
					"argument");
			}
#endif
		} else {
			bip_notify(ic, "-- Invalid INFO request");
		}
	} else if (strcasecmp(line->elemv[privmsg + 1], "JUMP") == 0) {
		if (LINK(ic)->l_server) {
			WRITE_LINE1(CONN(LINK(ic)->l_server), NULL, "QUIT",
					"jumpin' jumpin'");
			connection_close(CONN(LINK(ic)->l_server));
		}
		bip_notify(ic, "-- Jumping to next server");
	} else if (strcasecmp(line->elemv[privmsg + 1], "BLRESET") == 0) {
		if (line->elemc == privmsg + 3 &&
				strcmp(line->elemv[privmsg + 2], "-q") == 0) {
			log_reinit_all(LINK(ic)->log);
		} else {
			adm_blreset(ic);
		}
	} else if (strcasecmp(line->elemv[privmsg + 1], "HELP") == 0) {
		if (line->elemc == privmsg + 2)
			adm_bip_help(ic, admin, NULL);
		else if (line->elemc == privmsg + 3)
			adm_bip_help(ic, admin, line->elemv[privmsg + 2]);
		else
			bip_notify(ic,
				"-- HELP command needs at most one argument");
	} else if (strcasecmp(line->elemv[privmsg + 1], "FOLLOW_NICK") == 0) {
		if (line->elemc != privmsg + 3) {
			bip_notify(ic,
				"-- FOLLOW_NICK command needs one argument");
			return OK_FORGET;
		}
		adm_follow_nick(ic, line->elemv[privmsg + 2]);
	} else if (strcasecmp(line->elemv[privmsg + 1],
				"IGNORE_FIRST_NICK") == 0) {
		if (line->elemc != privmsg + 3) {
			bip_notify(ic, "-- IGNORE_FIRST_NICK "
				"command needs one argument");
			return OK_FORGET;
		}
		adm_ignore_first_nick(ic, line->elemv[privmsg + 2]);
	} else if (strcasecmp(line->elemv[privmsg + 1],
				"ON_CONNECT_SEND") == 0) {
		if (line->elemc == privmsg + 2) {
			adm_on_connect_send(ic, NULL, 0);
		} else if (line->elemc >= privmsg + 3) {
			adm_on_connect_send(ic, line, privmsg);
		} else {
			bip_notify(ic, "-- ON_CONNECT_SEND command needs at "
				"least one argument");
		}
	} else if (strcasecmp(line->elemv[privmsg + 1], "AWAY_NICK") == 0) {
		if (line->elemc == privmsg + 2) {
			adm_away_nick(ic, NULL);
		} else if (line->elemc == privmsg + 3) {
			adm_away_nick(ic, line->elemv[privmsg + 2]);
		} else {
			bip_notify(ic, "-- AWAY_NICK command needs zero or one"
				" argument");
		}
	} else if (admin &&
			strcasecmp(line->elemv[privmsg + 1], "ADD_CONN") == 0) {
		if (line->elemc != privmsg + 4) {
			bip_notify(ic, "/BIP ADD_CONN <connection name> "
					"<network name>");
		} else {
			adm_bip_addconn(bip, ic, line->elemv[privmsg + 2],
					line->elemv[privmsg + 3]);
		}
	} else if (admin &&
			strcasecmp(line->elemv[privmsg + 1], "DEL_CONN") == 0) {
		if (line->elemc != privmsg + 3) {
			bip_notify(ic, "/BIP DEL_CONN <connection name>");
		} else {
			adm_bip_delconn(bip, ic, line->elemv[privmsg + 2]);
		}
#ifdef HAVE_LIBSSL
	} else if (strcasecmp(line->elemv[privmsg + 1], "TRUST") == 0) {
		return adm_trust(ic, line);
#endif
	} else {
		bip_notify(ic, "Unknown command.");
	}
	return OK_FORGET;
}

void free_conf(list_t *l)
{
	struct tuple *t;
	list_iterator_t li;

	for (list_it_init(l, &li); (t = list_it_item(&li)); list_it_next(&li)) {
		switch (t->tuple_type) {
		case TUPLE_STR:
			free(t->pdata);
			break;
		case TUPLE_INT:
			break;
		case TUPLE_LIST:
			free_conf(t->pdata);
			break;
		default:
			fatal("internal error free_conf");
			break;
		}
		free(t);
	}
	free(l);
}

