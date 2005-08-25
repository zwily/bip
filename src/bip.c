/*
 * $Id: bip.c,v 1.39 2005/04/21 06:58:50 nohar Exp $
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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include "irc.h"
#include "conf.h"
#include "tuple.h"
#include "log.h"
#include "irc.h"
#include "bip.h"
#include "line.h"

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
hash_t conf_networks;
hash_t conf_users;
char *conf_biphome;
hash_t adm_users;

/* log options, for sure the trickiest :) */
/* no backlog at all */
int conf_backlog;
int conf_memlog;
int conf_log;
/* number of lines in backlog */
int conf_backlog_lines = 10;
/* backlog even lines already backlogged */
int conf_always_backlog;
int conf_log_sync_interval;
int conf_blreset_on_talk = 0;

list_t *parse_conf(FILE *file);
static void conf_die(char *fmt, ...);
#ifdef HAVE_LIBSSL
static int adm_trust(struct link_client *ic, struct line *line);
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

void server_free(struct server *s)
{
	free(s->host);
	free(s);
}

static int add_server(list_t *serverl, list_t *data)
{
	struct tuple *t;
	struct server *s;

	s = calloc(sizeof(struct server), 1);
	s->port = 6667; /* default port */

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_HOST:
			s->host = t->pdata;
			break;
		case LEX_PORT:
			s->port = t->ndata;
			break;
		default:
			fatal("Config error in server block (%d)", t->type);
		}
	}
	if (!s->host) {
		free(s);
		conf_die("Server conf: host not set");
		return 0;
	}
	list_add_last(serverl, s);
	return 1;
}

#define ERRBUFSZ 128

extern list_t *root_list;
int yyparse();
int conf_error;
char conf_errstr[ERRBUFSZ];

static void conf_start(void)
{
	conf_error = 0;
}

static void conf_die(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	vsnprintf(conf_errstr, ERRBUFSZ, fmt, ap);
	conf_errstr[ERRBUFSZ - 1] = 0;
	conf_error = 1;

	va_end(ap);
}


FILE *conf_global_log_file;

static pid_t daemonize(void)
{
	char buf[4096];
	switch (fork()) {
	case -1:
		fatal("Fork failed");
		break;
	case 0:
		break;
	default:
		exit(0);
	}
	if (setsid() < 0)
		fatal("setsid() failed");

	if (conf_log) {
		snprintf(buf, 4095, "%s/bip.log", conf_log_root);
		FILE *f = fopen(buf, "a");
		if (!f)
			fatal("Can't open %s: %s", buf, strerror(errno));
		conf_global_log_file = f;
	} else {
		conf_global_log_file = stderr;
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
		fatal("%s %s", "open", strerror(errno));
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
		mylog(LOG_INFO, "Another instance of bip is certainly runing.");
		mylog(LOG_INFO, "If you are sure this is not the case remove"
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
"	-h: This help\n", name, name);
	exit(1);
}

void reload_config(int i)
{
	(void)i;
	sighup = 1;
}

extern list_t *_connections;

void bad_quit(int i)
{
	list_iterator_t it;
	for (list_it_init(_connections, &it); list_it_item(&it);
			list_it_next(&it)) {
		connection_t *c = list_it_item(&it);
		struct link_any *la = c->user_data;
		if (c->connected == CONN_OK && la &&
				TYPE(la) == IRC_TYPE_SERVER) {
			write_line_fast(CONN(la), "QUIT :Coyote finally "
					"caught me\r\n");
		}
	}
	unlink(conf_pid_file);
	exit(i);
}

void c_network_free(struct c_network *on)
{
	struct server *s;
	free(on->name);
	s = list_remove_first(&on->serverl);
	free(s->host);
	free(on);
}

static int add_network(list_t *data)
{
	struct tuple *t;
	struct c_network *n;
	struct c_network *old_n;
	int r;

	n = calloc(sizeof(struct c_network), 1);
	list_init(&n->serverl, NULL);

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_NAME:
			n->name = t->pdata;
			break;
#ifdef HAVE_LIBSSL
		case LEX_SSL:
			n->ssl = t->ndata;
			break;
#endif
		case LEX_SERVER:
			r = add_server(&n->serverl, t->pdata);
			free(t->pdata);
			if (!r)
				return 0;
			break;
		default:
			conf_die("uknown keyword in network statement");
			if (t->type == TUPLE_STR)
				free(t->pdata);
			return 0;
			break;
		}
		free(t);
	}
	if (!n->name) {
		conf_die("Network with no name");
		return 0;
	}

	old_n = hash_get(&conf_networks, n->name);
	if (old_n) {
		hash_remove(&conf_networks, n->name);
		c_network_free(old_n);
	}
	hash_insert(&conf_networks, n->name, n);
	return 1;
}

static int add_channel(list_t *channell, list_t *data)
{
	struct tuple *t;
	struct c_channel *c;

	c = calloc(sizeof(struct c_channel), 1);

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_NAME:
			c->name = t->pdata;
			break;
		case LEX_KEY:
			c->key = t->pdata;
			break;
		default:
			conf_die("uknown keyword in channel statement");
			if (t->type == TUPLE_STR)
				free(t->pdata);
			return 0;
			break;
		}
		free(t);
	}
	if (!c->name)
		conf_die("channel wo a name !");
	list_add_last(channell, c);
	return 1;
}

void c_connection_free(struct c_connection *c)
{
	/* XXX network free! */
	free(c->user);
	free(c->password);
	free(c->vhost);

	struct c_channel *chan;
	while ((chan = list_remove_first(&c->channell))) {
		free(chan->name);
		if (chan->key)
			free(chan->key);
		free(chan);
	}

	free(c->away_nick);
	free(c->on_connect_send);
}

static int add_connection(list_t *connectionl, list_t *data,
		list_t *old_c_connl)
{
	struct tuple *t;
	struct c_connection *c, *old_c = NULL;
	int r;

	c = calloc(sizeof(struct c_connection), 1);
	list_init(&c->channell, NULL);

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_NAME:
			c->name = t->pdata;
			break;
		case LEX_NETWORK:
			c->network = hash_get(&conf_networks, t->pdata);
			if (!c->network) {
				free(c);
				conf_die("networkd:%s used but not defined\n",
						t->pdata);
				return 0;
			}
			break;
		case LEX_NICK:
			if (!is_valid_nick(t->pdata))
				conf_die("Invalid nickname (%s)", t->pdata);
			c->nick = t->pdata;
			break;
		case LEX_USER:
			c->user = t->pdata;
			break;
		case LEX_REALNAME:
			c->realname = t->pdata;
			break;
		case LEX_PASSWORD:
			c->password = t->pdata;
			break;
		case LEX_CHANNEL:
			r = add_channel(&c->channell, t->pdata);
			free(t->pdata);
			if (!r)
				return 0;
			break;
		case LEX_FOLLOW_NICK:
			c->follow_nick = t->ndata;
			break;
		case LEX_IGN_FIRST_NICK:
			c->ignore_first_nick = t->ndata;
			break;
		case LEX_AWAY_NICK:
			c->away_nick = t->pdata;
			break;
		case LEX_ON_CONNECT_SEND:
			c->on_connect_send = t->pdata;
			break;
		default:
			conf_die("uknown keyword in connection statement");
			if (t->type == TUPLE_STR)
				free(t->pdata);
			return 0;
		}
		free(t);
	}
	/* checks that can only be here, or must */
	if (!c->network) {
		conf_die("Missing network in connection block");
		return 0;
	}
	list_add_last(connectionl, c);
	if (old_c_connl) {
		old_c = list_remove_first(old_c_connl);
		if (old_c)
			c_connection_free(old_c);
	}
	return 1;
}

void c_user_free(struct c_user *cu)
{
	free(cu->name);
	free(cu->password);
#ifdef HAVE_LIBSSL
	free(cu->ssl_check_store);
#endif
	struct c_connection *con;
	while ((con = list_remove_first(&cu->connectionl)))
		c_connection_free(con);
	free(cu);
}

static int add_user(list_t *data)
{
	int r;
	struct tuple *t;
	struct c_user *u;
	struct c_user *old_u = 0;

	u = calloc(sizeof(struct c_user), 1);
	list_init(&u->connectionl, NULL);

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_NAME:
			u->name = t->pdata;
			old_u = hash_get(&conf_users, u->name);
			break;
		case LEX_PASSWORD:
			hash_binary(t->pdata, &u->password, &u->seed);
			free(t->pdata);
			break;
		case LEX_DEFAULT_NICK:
			u->default_nick = t->pdata;
			break;
		case LEX_DEFAULT_USER:
			u->default_user = t->pdata;
			break;
		case LEX_DEFAULT_REALNAME:
			u->default_realname = t->pdata;
			break;
		case LEX_CONNECTION:
			if (!u->name)
				conf_die("name statement must be first in user"
						"block");
			if (!old_u)
				r = add_connection(&u->connectionl, t->pdata,
						NULL);
			else
				r = add_connection(&u->connectionl, t->pdata, 
						&old_u->connectionl);
			free(t->pdata);
			if (!r)
				return 0;
			break;
#ifdef HAVE_LIBSSL
		case LEX_SSL_CHECK_MODE:
			if (!strncmp(t->pdata, "basic", 5))
				u->ssl_check_mode = SSL_CHECK_BASIC;
			if (!strncmp(t->pdata, "ca", 2))
				u->ssl_check_mode = SSL_CHECK_CA;
			free(t->pdata);
			break;
		case LEX_SSL_CHECK_STORE:
			u->ssl_check_store = t->pdata;
			break;
#endif
		default:
			conf_die("Uknown keyword in user statement");
			if (t->type == TUPLE_STR)
				free(t->pdata);
			break;
		}
		free(t);
	}
	if (!u->name) {
		conf_die("User w/o a name!");
		return 0;
	}
	if (!u->password) {
		conf_die("Missing password in user block");
		return 0;
	}

	if (old_u) {
		hash_remove(&conf_users, u->name);
		c_user_free(old_u);
	}
	hash_insert(&conf_users, u->name, u);
	return 1;
}

int fireup(FILE *conf)
{
	struct tuple *t;
	list_t *l;
	int r;

	conf_start();

	l = parse_conf(conf);
	if (conf_error)
		return 0;

	while ((t = list_remove_first(l))) {
		switch (t->type) {
		case LEX_LOG_SYNC_INTERVAL:
			conf_log_sync_interval = t->ndata;
			break;
		case LEX_ALWAYS_BACKLOG:
			conf_always_backlog = t->ndata;
			break;
		case LEX_BACKLOG:
			conf_backlog = t->ndata;
			break;
		case LEX_LOG:
			conf_log = t->ndata;
			break;
		case LEX_BACKLOG_LINES:
			conf_backlog_lines = t->ndata;
			break;
		case LEX_LOG_ROOT:
			if (conf_log_root)
				free(conf_log_root);
			conf_log_root = t->pdata;
			break;
		case LEX_LOG_FORMAT:
			if (conf_log_format)
				free(conf_log_format);
			conf_log_format = t->pdata;
			break;
		case LEX_LOG_LEVEL:
			conf_log_level = t->ndata;
			break;
		case LEX_IP:
			if (conf_ip)
				free(conf_ip);
			conf_ip = t->pdata;
			break;
		case LEX_PORT:
			conf_port = t->ndata;
			break;
		case LEX_CSS:
			conf_css = t->ndata;
			break;
		case LEX_PID_FILE:
			if (conf_pid_file)
				free(conf_pid_file);
			conf_pid_file = t->pdata;
			break;
		case LEX_BLRESET_ON_TALK:
			conf_blreset_on_talk = t->ndata;
			break;
		case LEX_NETWORK:
			r = add_network(t->pdata);
			list_free(t->pdata);
			if (!r)
				return 0;
			break;
		case LEX_USER:
			r = add_user(t->pdata);
			list_free(t->pdata);
			if (!r)
				return 0;
			break;
		default:
			if (t->type == TUPLE_STR)
				free(t->pdata);
			conf_die("Config error in base config (%d)", t->type);
			return 0;
		}
		free(t);
	}
	free(root_list);
	root_list = NULL;

	if (conf_backlog && !conf_log) {
		if (conf_backlog_lines == 0) {
			conf_die("You must set conf_backlog_lines if "
					"conf_log = false and "
					"conf_backlog = true");
			return 0;
		}
	}

	if (!conf_log)
		conf_memlog = 1;
	else
		conf_memlog = 0;

	/*
	check_networks(networkl);
	check_clients(userl);
	*/

	if (!conf_biphome) {
		char *home = getenv("HOME");
		if (!home)
			conf_die("no $HOME !, do you live in a trailer ?");
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
	conf_ssl_certfile = NULL;	/* Make into a config option */
	if (!conf_ssl_certfile) {
		char *home = getenv("HOME");
		char *ap = "/.bip/bip.pem";
		if (!home)
			fatal("no $HOME !, do you live in a trailer ?");
		if (conf_ssl_certfile) {
			free(conf_ssl_certfile);
			conf_ssl_certfile = NULL;
		}
		conf_ssl_certfile = malloc(strlen(home) + strlen(ap) + 1);
		strcpy(conf_ssl_certfile, home);
		strcat(conf_ssl_certfile, ap);
		mylog(LOG_INFO, "Default SSL certificate file: %s",
				conf_ssl_certfile);
	}
#endif
	if (!conf_log_format)
		conf_log_format = "%u/%n/%Y-%m/%c.%d.log";

	return 1;
}

void ircize(list_t *ll)
{
	hash_iterator_t it;
	for (hash_it_init(&conf_users, &it); hash_it_item(&it);
			hash_it_next(&it)) {
		struct c_user *u = hash_it_item(&it);

		hash_t *adm_conn = hash_get(&adm_users, u->name);
		if (!adm_conn) {
			adm_conn = hash_new(HASH_NOCASE);
			hash_insert(&adm_users, u->name, adm_conn);
			mylog(LOG_DEBUG, "new user: \"%s\"", u->name);
		} else {
			mylog(LOG_DEBUG, "old user: \"%s\"", u->name);
		}

		/*
		 * TODO: keep track of removed connection on sighup
		 */
		/*
		 * A user has multiple connections.
		 * For each connections create a irc_client and a irc_server
		 * instance and register them in connection structure;
		 */
		list_iterator_t cit;
		for (list_it_init(&u->connectionl, &cit); list_it_item(&cit);
				list_it_next(&cit)) {
			struct c_connection *c = list_it_item(&cit);
			struct link *link;
			int i;

			if (!c->name)
				fatal("no name for a connection");

			link = hash_get(adm_conn, c->name);
			if (!link) {
				mylog(LOG_DEBUG, "new connection: \"%s\"",
						c->name);
				link = irc_link_new();
				hash_insert(adm_conn, c->name, link);
				link->name = strmaydup(c->name);
				link->log = log_new(u->name, link->name);

				list_iterator_t chit;
				for (list_it_init(&c->channell, &chit);
						list_it_item(&chit);
						list_it_next(&chit)) {
					struct c_channel *chan =
						list_it_item(&chit);
					struct chan_info *ci = chan_info_new();
					printf("%s\n",chan->name);
					ci->name = strdup(chan->name);
					ci->key = strmaydup(chan->key);
					hash_insert(&link->chan_infos,
							ci->name, ci);
					list_add_last(&link->chan_infos_order,
							ci);
				}
				list_add_last(ll, link);
			} else {
				mylog(LOG_DEBUG, "old connection: \"%s\"",
						c->name);
#define MAYFREE(a) do { \
		if (a) { \
			free(a); \
			(a) = NULL; \
		} \
	} while(0);
				MAYFREE(link->away_nick);
				MAYFREE(link->password);
				MAYFREE(link->user);
				MAYFREE(link->real_name);
				MAYFREE(link->s_password);
				MAYFREE(link->connect_nick);
				MAYFREE(link->vhost);
#ifdef HAVE_LIBSSL
				MAYFREE(link->ssl_check_store);
				sk_X509_free(link->untrusted_certs);
#endif
				

				for (i = 0; i < link->serverc; i++)
					server_free(link->serverv[i]);
				free(link->serverv);
				link->serverv = NULL;
				link->serverc = 0;
			}

			link->follow_nick = c->follow_nick;
			link->ignore_first_nick = c->ignore_first_nick;
			link->on_connect_send = strmaydup(c->on_connect_send);
			link->away_nick = strmaydup(c->away_nick);

			link->username = strmaydup(u->name);
			link->password = malloc(20);
			memcpy(link->password, u->password, 20);
			link->seed = u->seed;

			list_iterator_t seit;
			for (list_it_init(&c->network->serverl, &seit);
					list_it_item(&seit);
					list_it_next(&seit)) {
				struct server *s = list_it_item(&seit);
				link->serverv = realloc(link->serverv,
						(link->serverc + 1)
						* sizeof(struct server *));
				link->serverv[link->serverc] = server_new();
				/* XXX: wrong */
				link->serverv[link->serverc]->host
					= strmaydup(s->host);
				link->serverv[link->serverc]->port = s->port;
				link->serverc++;
			}

			link->user = strmaydup(c->user);
			if (!link->user)
				link->user = strmaydup(u->default_user);
			link->real_name = strmaydup(c->realname);
			if (!link->real_name)
				link->real_name =
						strmaydup(u->default_realname);
			link->s_password = strmaydup(c->password);
			link->connect_nick = strmaydup(c->nick);
			if (!link->connect_nick)
				link->connect_nick = strmaydup(u->default_nick);

			link->vhost = strmaydup(c->vhost);
			link->bind_port = c->source_port;
#ifdef HAVE_LIBSSL
			link->s_ssl = c->network->ssl;
			link->ssl_check_mode = u->ssl_check_mode;
			link->ssl_check_store = strmaydup(u->ssl_check_store);
			link->untrusted_certs = sk_X509_new_null();
#endif

			if (!link->user)
				link->user = strmaydup("bip");
			if (!link->connect_nick)
				link->connect_nick = strmaydup("bip");
			if (!link->real_name)
				link->real_name = strmaydup("bip");

		}
	}
}

int main(int argc, char **argv)
{
	FILE *conf = NULL;
	char *confpath = NULL;
	list_t *ll = list_new(NULL);
	int ch;
	int r,fd;
	char buf[30];

	conf_ip = strdup("0.0.0.0");
	conf_port = 7778;
	conf_css = 0;

	hash_init(&adm_users, HASH_NOCASE);

	hash_init(&conf_users, HASH_NOCASE);
	hash_init(&conf_networks, HASH_NOCASE);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, reload_config);
	signal(SIGINT, bad_quit);
	signal(SIGQUIT, bad_quit);
	signal(SIGTERM, bad_quit);

	conf_log_root = NULL;
	conf_log_format = NULL;
	conf_log_level = LOG_ERROR;
	conf_backlog = 1;
	conf_log = 1;
	conf_backlog_lines = 100;
	conf_log_sync_interval = 5;
	conf_daemonize = 1;
	conf_global_log_file = stderr;
	conf_pid_file = NULL;

	while ((ch = getopt(argc, argv, "hnf:")) != -1) {
		switch (ch) {
		case 'f':
			confpath = strdup(optarg);
			break;
		case 'n':
			conf_daemonize = 0;
			break;
		default:
			usage(argv[0]);
		}
	}
	if (confpath) {
		conf = fopen(confpath, "r");
		if (!conf)
			fatal("config file not found");
	}
	if (!conf) {
		char *home;
		home = getenv("HOME");
		if (!home)
			fatal("no home");
		confpath = malloc(strlen(home) + 1 + strlen(S_CONF) + 1);
		*confpath = 0;
		strcat(confpath, home);
		strcat(confpath, "/");
		strcat(confpath, S_CONF);
		conf = fopen(confpath, "r");
		if (!conf)
			fatal("%s config file not found", confpath);
	}

	r = fireup(conf);
	fclose(conf);
	if (!r) {
		fatal("%s", conf_errstr);
		exit(28);
	}

	fd = do_pid_stuff();
	pid_t pid = 0;
	if (conf_daemonize)
		pid = daemonize();
	else
		pid = getpid();
	snprintf(buf, 29, "%ld\n", (long unsigned int)pid);
	write(fd, buf, strlen(buf));
	close(fd);

	connection_t *inc;
	inc = listen_new(conf_ip, conf_port, conf_css);
	if (!inc)
		fatal("Could not create listening socket");

	for (;;) {
		if (r)
			ircize(ll);
		if (conf_error)
			mylog(LOG_ERROR, "conf error: %s", conf_errstr);

		irc_main(inc, ll);

		sighup = 0;

		conf = fopen(confpath, "r");
		if (!conf)
			fatal("%s config file not found", confpath);
		r = fireup(conf);
		fclose(conf);
	}
	return 1;
}

void write_user_list(connection_t *c, char *dest)
{
	hash_iterator_t it;
	list_iterator_t lit;
	
	WRITE_LINE2(c, P_IRCMASK, "PRIVMSG", dest, "bip user list:");
	for (hash_it_init(&conf_users, &it); hash_it_item(&it);
			hash_it_next(&it)) {
		struct c_user *u = hash_it_item(&it);

		WRITE_LINE2(c, P_IRCMASK, "PRIVMSG", dest, u->name);
		for (list_it_init(&u->connectionl, &lit); list_it_item(&lit);
				list_it_next(&lit)) {
			struct c_connection *con = list_it_item(&lit);
			WRITE_LINE2(c, P_IRCMASK, "PRIVMSG", dest, con->name);
		}
	}
	WRITE_LINE2(c, P_IRCMASK, "PRIVMSG", dest,
			"end of bip user list");
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
static int adm_trust(struct link_client *ic, struct line *line)
{
	if (ic->allow_trust != 1) {
		mylog(LOG_ERROR, "User attempted TRUST command without "
				"being allowed to!");
		unbind_from_link(ic);
		return OK_CLOSE;
	}

	if(!LINK(ic)->untrusted_certs ||
			sk_X509_num(LINK(ic)->untrusted_certs) <= 0) {
		/* shouldn't have been asked to /QUOTE TRUST but well... */
		WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
				"No untrusted certificates.");
		return ERR_PROTOCOL;
	}

	if (line->elemc != 3)
		return ERR_PROTOCOL;

	if (!strcasecmp(line->elemv[2], "OK")) {
		/* OK, attempt to trust the cert! */
		BIO *bio = BIO_new_file(LINK(ic)->ssl_check_store, "a+");
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

extern struct link_client *reloading_client;
void adm_blreset(struct link_client *ic)
{
	hash_iterator_t it;
	for (hash_it_init(&LINK(ic)->log->logfgs, &it);
			hash_it_item(&it);
			hash_it_next(&it)) {
		logfilegroup_t *lfg = hash_it_item(&it);
		log_reset(lfg);
	}
}

int adm_bip(struct link_client *ic, struct line *line);
int adm_bip(struct link_client *ic, struct line *line)
{
	char *nick;
	if (LINK(ic)->l_server)
		nick = LINK(ic)->l_server->nick;
	else
		nick = LINK(ic)->prev_nick;
	if (line->elemc < 2)
		return OK_FORGET;
	
	if (strcasecmp(line->elemv[1], "RELOAD") == 0) {
		reloading_client = ic;
		sighup = 1;
	} else if (strcasecmp(line->elemv[1], "LIST") == 0) {
		write_user_list(CONN(ic), nick);
	} else if (strcasecmp(line->elemv[1], "JUMP") == 0) {
		if (LINK(ic)->l_server) {
			WRITE_LINE1(CONN(LINK(ic)->l_server), NULL, "QUIT",
					"jumpin' jumpin'");
			connection_close(CONN(LINK(ic)->l_server));
		}
	} else if (strcasecmp(line->elemv[1], "BLRESET") == 0) {
		adm_blreset(ic);
	} else if (strcasecmp(line->elemv[1], "HELP") == 0) {
		WRITE_LINE2(CONN(ic), P_IRCMASK, "PRIVMSG", nick,
			"/BIP (RELOAD|LIST|JUMP|BLRESET|HELP)");
#ifdef HAVE_LIBSSL
	} else if (strcasecmp(line->elemv[1], "TRUST") == 0) {
		return adm_trust(ic, line);
#endif
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
			free(t->pdata);	/* no break, for the style */
		case TUPLE_INT:	
			free(t);
			break;
		case TUPLE_LIST:
			free_conf(t->pdata);
			break;
		default:
			fatal("internal error free_conf");
			break;
		}
	}
}
