/*
 * $Id$
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
#include "line.h"

void irc_line_init(struct line *l)
{
	memset(l, 0, sizeof(struct line));
}

struct line *irc_line_new()
{
	struct line *l;
	l = malloc(sizeof(struct line));
	if (!l)
		fatal("malloc");
	irc_line_init(l);
	return l;
}

void irc_line_clear(struct line *l)
{
	unsigned i;
	for (i = 0; i < l->elemc; i++)
		free(l->elemv[i]);
	free(l->elemv);
	if (l->origin)
		free(l->origin);
	memset(l, 0, sizeof(struct line));
}

void irc_line_write(struct line *l, connection_t *c)
{
	char *bytes = irc_line_to_string(l);
	write_line(c, bytes);
	free(bytes);
}

struct line *irc_line_dup(struct line *line)
{
	unsigned i;
	struct line *nl = irc_line_new();
	nl->origin = line->origin ? strdup(line->origin) : NULL;
	nl->elemc = line->elemc;
	nl->elemv = malloc(sizeof(char *) * line->elemc);
	for (i = 0; i < line->elemc; i++)
		nl->elemv[i] = strdup(line->elemv[i]);
	nl->colon = line->colon;
	return nl;
}

void _irc_line_append(struct line *l, char *s)
{
	l->elemc++;
	l->elemv = realloc(l->elemv, l->elemc * sizeof(char *));
	if (!l)
		fatal("realloc");
	l->elemv[l->elemc - 1] = s;
}

void irc_line_append(struct line *l, char *s)
{
	_irc_line_append(l, strdup(s));
}

char *irc_line_to_string(struct line *l)
{
	size_t len = 0;
	unsigned i;
	char *ret;

	if (l->origin)
		len = strlen(l->origin) + 2;
	for (i = 0; i < l->elemc; i++)
		len += strlen(l->elemv[i]) + 1;
	len += 1; /* remove one trailing space and add \r\n */
	len++; /* last args ":" */
	ret = malloc(len + 1);
	ret[0] = 0;

	if (l->origin) {
		strcat(ret, ":");
		strcat(ret, l->origin);
		strcat(ret, " ");
	}
	for (i = 0; i < l->elemc - 1; i++) {
		strcat(ret, l->elemv[i]);
		strcat(ret, " ");
	}
	if (strchr(l->elemv[i], ' ') || l->colon)
		strcat(ret, ":");

	strcat(ret, l->elemv[i]);
	strcat(ret, "\r\n");
	return ret;
}

/*
 * takes a null terminated string as input w/o \r\n
 */
struct line *irc_line(char *str)
{
	struct line *line;
	char *space;
	size_t len;
	int curelem = 0;

	line = calloc(sizeof(struct line), 1);
	if (!line)
		fatal("calloc");
	if (str[0] == ':') {
		space = str + 1;

		while (*space && *space != ' ')
			space++;
		if (!*space)
			return NULL;
		len = space - str - 1; /* leading ':' */
		line->origin = malloc(len + 1);
		if (!line->origin)
			fatal("malloc");
		memcpy(line->origin, str + 1, len);
		line->origin[len] = 0;
		str = space;
	}

	while (*str == ' ')
		str++;

	while (*str) {
		char *tmp;

		line->elemc++;
		line->elemv = realloc(line->elemv,
				line->elemc * sizeof(char *));
		if (!line->elemv)
			fatal("realloc");

		space = str;
		if (*space == ':') {
			line->colon = 1;
			str++;
			while (*space)
				space++;
		} else {
			while (*space && *space != ' ')
				space++;
		}
		len = space - str;
		tmp = line->elemv[curelem] = malloc(len + 1);
		if (!tmp)
			fatal("malloc");
		memcpy(tmp, str, len);
		tmp[len] = 0;
		if (curelem == 0)
			strucase(line->elemv[curelem]);

		curelem++;

		str = space;
		while (*str == ' ')
			str++;
	}
	return line;
}

void irc_line_free(struct line *l)
{
	unsigned i;
	for (i = 0; i < l->elemc; i++)
		free(l->elemv[i]);
	free(l->elemv);
	if (l->origin)
		free(l->origin);
	free(l);
}
