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

#ifdef HAVE_LIBSSL
int adm_trust(struct link_client *ic, struct line *line);
#endif
int adm_bip(bip_t *bip, struct link_client *ic, struct line *line, int privmsg);
int ssl_check_trust(struct link_client *ic);
void adm_blreset(struct link_client *ic);
void bip_notify(struct link_client *ic, char *fmt, ...);

#endif
