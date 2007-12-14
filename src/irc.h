/*
 * $Id: irc.h,v 1.43 2005/04/21 06:58:50 nohar Exp $
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

#ifndef IRC_H
#define IRC_H
#include "connection.h"
#include "line.h"


#define ERR_PROTOCOL (-1)
#define ERR_AUTH (-2)
#define OK_COPY (1)
#define OK_FORGET (2)
#define OK_CLOSE (3)
#define OK_COPY_CLI (4)
#define OK_COPY_WHO (5)

#define P_SERV "bip.bip.bip"
#define S_PING "BIPPING"
#define P_IRCMASK "-bip!bip@bip.bip.bip"

struct server {
	char *host;
	unsigned short port;
};

#define server_new() calloc(sizeof(struct server), 1)

#define NICKOP 1
#define NICKVOICED 2

struct nick {
	char *name;
	int ovmask;
};

struct channel {
	char *name;
	char *mode;
	char *key;
	char *topic;
	int limit;
	char type;
	char *creator;
	char *create_ts;
	hash_t nicks;
	int running_names;
};

#define IRC_TYPE_CLIENT (0)
#define IRC_TYPE_SERVER (1)
#define IRC_TYPE_LOGING_CLIENT (2)
#define IRC_TYPE_TRUST_CLIENT (3)

struct user {
	/** client connection static data **/

	char *name;
	unsigned char *password;
	unsigned int seed;
	int admin;
	int bip_use_notice;

	/* common link options */

	char *default_nick;
	char *default_username;
	char *default_realname;

	/* backlog options */
	int backlog;
	int backlog_lines;
	int always_backlog;
	int bl_msg_only;
	int backlog_no_timestamp;
	int blreset_on_talk;

#ifdef HAVE_LIBSSL
	int ssl_check_mode;
	char *ssl_check_store;
#endif

	hash_t connections;
	int in_use; /* for mark and sweep on reload */
};

struct network
{
	char *name;
#ifdef HAVE_LIBSSL
	int ssl;
#endif
	int serverc;
	struct server *serverv;
};

struct link {
	char *name;	/* id */

	/** link live data **/
	struct link_server *l_server;
	int l_clientc;
	struct link_client **l_clientv;

	struct log *log;

	/* we honnor the /who from clients one client at a time, this is the
	 * client that is /who-ing. Now for bans too */
	struct link_client *who_client;

	/* server related live stuff */
	int s_state;
	int s_conn_attempt;
	char *prev_nick; /* XXX del me */
	char *cli_nick;
	list_t init_strings;

	/* connection state (reconnecting, was_connected ...) */
	int recon_timer;
	time_t last_connection_attempt;

	/** link options */

	int follow_nick;
	int ignore_first_nick;
	list_t on_connect_send;
	char *no_client_away_msg;
	char *away_nick;
	hash_t chan_infos;		/* channels we want */
	list_t chan_infos_order;	/* for order only */

	struct user *user;

	/** server connection static data **/
	/* server list */
	struct network *network;
	int cur_server;

	char *username;
	char *realname;
	char *s_password;
	char *connect_nick;

	/* socket creation info */
	char *vhost;
	int bind_port;

#ifdef HAVE_LIBSSL
	int ssl_check_mode;
	STACK_OF(X509) *untrusted_certs;
#endif
	int in_use; /* for mark and sweep on reload */
};

struct link_connection {
	int type;
	connection_t *conn;
	struct link *link;
};

struct link_any {
	struct link_connection _link_c;
};

#define LINK(s) ((s)->_link_c.link)
#define CONN(s) ((s)->_link_c.conn)
#define TYPE(s) ((s)->_link_c.type)

#define IRCC_NONE (0)
#define IRCC_NICK (1)
#define IRCC_USER (1<<1)
#define IRCC_PASS (1<<2)
#define IRCC_READY (IRCC_NICK|IRCC_PASS|IRCC_USER)

struct link_client {
	struct link_connection _link_c;

	char *init_nick;
	char *init_pass;
	int state;
	int logging_timer;

	list_t who_queue;
	int who_count;
	time_t whoc_tstamp;

#ifdef HAVE_LIBSSL
	int allow_trust;
#endif
};

#define IRCS_NONE (0)
#define IRCS_CONNECTING (1)
#define IRCS_CONNECTED (2)
#define IRCS_WAS_CONNECTED (3)
#define IRCS_RECONNECTING (4)
#define IRCS_TIMER_WAIT (5)

struct log;

struct chan_info {
	char *name;
	char *key;
	int backlog;
};

#define chan_info_new() calloc(sizeof(struct chan_info), 1)

struct link_server {
	struct link_connection _link_c;

	char *nick;

	/* channels we are in */
	hash_t channels;

	char *user_mode;
	int user_mode_len;

	/* init stuff */
	int lag;
	int laginit_ts;
	int lagtest_timeout;
};

typedef struct bip {
	connection_t *listener;
	/* all connected tcp connections */
	list_t conn_list;
	/* all links */
	list_t link_list;
	/* connecting clients */
	list_t connecting_client_list;

	hash_t networks;
	hash_t users;
	list_t errors;
	struct link_client *reloading_client;
} bip_t;

void bip_init(bip_t *bip);
struct link_client *irc_client_new(void);
struct link_server *irc_server_new(struct link *link, connection_t *conn);
void irc_server_free(struct link_server *is);
struct client *client_new();
void irc_main(bip_t *);
int ischannel(char p);
void irc_client_close(struct link_client *);
void irc_client_free(struct link_client *);
struct link *irc_link_new();
void link_kill(bip_t *bip, struct link *);
void unbind_from_link(struct link_client *ic);
#endif

