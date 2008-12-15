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
	l = bip_malloc(sizeof(struct line));
	irc_line_init(l);
	return l;
}

void irc_line_write(struct line *l, connection_t *c)
{
	char *bytes = irc_line_to_string(l);
	write_line(c, bytes);
	free(bytes);
}

struct line *irc_line_dup(struct line *line)
{
	int i;
	struct line *nl = irc_line_new();
	nl->origin = line->origin ? bip_strdup(line->origin) : NULL;
	nl->elemc = line->elemc;
	nl->elemv = bip_malloc(sizeof(char *) * line->elemc);
	for (i = 0; i < line->elemc; i++)
		nl->elemv[i] = bip_strdup(line->elemv[i]);
	nl->colon = line->colon;
	return nl;
}

char *irc_line_pop(struct line *l)
{
	char *ret;

	if (irc_line_count(l) == 0)
		return NULL;
	ret = (char *)l->elemv[l->elemc - 1];
	l->elemc--;

	return ret;
}

void _irc_line_append(struct line *l, const char *s)
{
	l->elemc++;
	l->elemv = bip_realloc(l->elemv, l->elemc * sizeof(char *));
	l->elemv[l->elemc - 1] = (char *)s;
}

void irc_line_append(struct line *l, const char *s)
{
	_irc_line_append(l, bip_strdup(s));
}

char *irc_line_to_string(struct line *l)
{
	size_t len = 0;
	int i;
	char *ret;

	if (l->origin)
		len = strlen(l->origin) + 2;
	for (i = 0; i < l->elemc; i++)
		len += strlen(l->elemv[i]) + 1;
	len += 1; /* remove one trailing space and add \r\n */
	len++; /* last args ":" */
	ret = bip_malloc(len + 1);
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

int irc_line_count(struct line *line)
{
	return line->elemc;
}

int irc_line_include(struct line *line, int elem)
{
	if (elem < 0)
		fatal("internal error: irc_line_elem got negative elem");
	return elem < line->elemc;
}

const char *irc_line_elem(struct line *line, int elem)
{
	if (!irc_line_include(line, elem))
		fatal("internal error: irc_line_elem got too large elem");
	return line->elemv[elem];
}

int irc_line_elem_equals(struct line *line, int elem, const char *cmp)
{
	return !strcmp(irc_line_elem(line, elem), cmp);
}

int irc_line_elem_case_equals(struct line *line, int elem, const char *cmp)
{
	return !strcasecmp(irc_line_elem(line, elem), cmp);
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

	line = bip_calloc(sizeof(struct line), 1);
	if (str[0] == ':') {
		space = str + 1;

		while (*space && *space != ' ')
			space++;
		if (!*space)
			return NULL;
		len = space - str - 1; /* leading ':' */
		line->origin = bip_malloc(len + 1);
		memcpy(line->origin, str + 1, len);
		line->origin[len] = 0;
		str = space;
	}

	while (*str == ' ')
		str++;

	while (*str) {
		char *tmp;

		line->elemc++;
		line->elemv = bip_realloc(line->elemv,
				line->elemc * sizeof(char *));

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
		tmp = bip_malloc(len + 1);
		memcpy(tmp, str, len);
		tmp[len] = 0;
		if (curelem == 0)
			strucase(tmp);
		line->elemv[curelem] = (const char *)tmp;

		curelem++;

		str = space;
		while (*str == ' ')
			str++;
	}
	return line;
}

void irc_line_free(struct line *l)
{
	int i;

	for (i = 0; i < l->elemc; i++)
		free((char *)l->elemv[i]);
	free(l->elemv);
	if (l->origin)
		free(l->origin);
	free(l);
}
