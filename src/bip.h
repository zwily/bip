/*
 * $Id: bip.h,v 1.6 2005/04/12 19:34:35 nohar Exp $
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

#ifndef BIP_H
#define BIP_H

struct c_network
{
	char *name;
#ifdef HAVE_LIBSSL
	int ssl;
#endif
	list_t serverl;
};

struct c_user
{
	char *name;
	unsigned char *password;
	unsigned int seed;
	list_t connectionl;
};

struct c_connection
{
	char *name;
	struct c_network *network;
	char *realname, *user, *nick; 
	char *login; 		/* connection id for a user */
	char *password; 	/* server pass */
	char *vhost;
	unsigned short source_port;
	list_t channell;

	int follow_nick;
	int ignore_first_nick;
	char *away_nick;
	char *on_connect_send;

	struct client *client;
};

struct c_channel
{
	char *name;
	char *key;
};

#endif
