/*
 * $Id: connection.h,v 1.40 2005/04/12 19:34:35 nohar Exp $
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

#ifndef CONNECTION_H
#define CONNECTION_H
#include "util.h"
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>

#ifdef HAVE_LIBSSL
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#endif

#define CONN_BUFFER_SIZE 2048

#define CONN_OK 1
#define CONN_TIMEOUT 2
#define CONN_ERROR 3
#define CONN_INPROGRESS 4
#define CONN_DISCONN 5
#define CONN_EXCEPT 6
#define CONN_NEW 7
#define CONN_NEED_SSLIZE 8
#define CONN_UNTRUSTED 9

#define WRITE_OK 0
#define WRITE_ERROR -1
#define WRITE_KEEP -2

#ifdef HAVE_LIBSSL
#define SSL_CHECK_NONE (0)
#define SSL_CHECK_BASIC (1)
#define SSL_CHECK_CA (2)
#endif

struct connecting_data;
typedef struct connection {
	int anti_flood;
	int ssl;
	unsigned long lasttoken;
	unsigned token;
	int handle;
	int connected;
	int listening;
	int client;
	time_t connect_time;
	time_t timeout;
	char *incoming;
	unsigned incoming_end;
	list_t *outgoing;
	list_t *incoming_lines;
	void *user_data;
	list_t *ip_list;
	struct connecting_data *connecting_data;
#ifdef HAVE_LIBSSL
	SSL_CTX *ssl_ctx_h;
	SSL *ssl_h;
	int ssl_check_mode;
	X509 *cert;
#endif
	char *localip, *remoteip;
	uint16_t localport, remoteport;
} connection_t;

connection_t *connection_new(char *dsthostname, int dstport, char *srchostname,
		int srcport, int ssl, int ssl_check_mode,
		char *ssl_check_store,int timeout);
connection_t *listen_new(char *hostname, int port, int ssl);
connection_t *accept_new(connection_t *cn);
void connection_free(connection_t *cn);
void connection_close(connection_t *cn);

void write_line(connection_t *cn, char *line);
void write_line_fast(connection_t *cn, char *line);
list_t *read_lines(connection_t *cn, int *error);
list_t *wait_event(list_t *cn_list, int *msec, int *nc);

int cn_is_connected(connection_t *cn);
int cn_is_listening(connection_t *cn);

int connection_localport(connection_t *cn);
int connection_remoteport(connection_t *cn);
char *connection_localip(connection_t *cn);
char *connection_remoteip(connection_t *cn);
#endif
