/*
 * $Id: bip.h,v 1.6 2005/04/12 19:34:35 nohar Exp $
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

#ifndef BIP_H
#define BIP_H

#if 0
struct c_connection
{
	char *name;
	struct c_network *network;
	char *realname, *user, *nick;
	char *password;	/* server pass */
	char *vhost;
	unsigned short source_port;
	list_t channell;

	int follow_nick;
	int ignore_first_nick;
	char *away_nick;
	list_t on_connect_send;
	char *no_client_away_msg;

	struct client *client;
	struct c_user *bipuser;
};

struct c_channel
{
	char *name;
	char *key;
};
#endif

#ifdef HAVE_LIBSSL
int adm_trust(struct link_client *ic, struct line *line);
#endif
int adm_bip(struct link_client *ic, struct line *line, unsigned int privmsg);
int ssl_check_trust(struct link_client *ic);
void adm_blreset(struct link_client *ic);

#endif
