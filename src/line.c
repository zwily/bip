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
#include "util.h"

void irc_line_init(struct line *l)
{
	memset(l, 0, sizeof(struct line));
	array_init(&l->words);
}

void _irc_line_deinit(struct line *l)
{
	array_deinit(&l->words);
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
	char *ptr;

	nl->origin = line->origin ? bip_strdup(line->origin) : NULL;
	array_each(&line->words, i, ptr)
		array_set(&nl->words, i, bip_strdup(ptr));
	nl->colon = line->colon;
	return nl;
}

char *irc_line_pop(struct line *l)
{
	return (char *)array_pop(&l->words);
}

void _irc_line_append(struct line *l, const char *s)
{
	array_push(&l->words, (char *)s);
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
	for (i = 0; i < array_count(&l->words); i++)
		len += strlen(array_get(&l->words, i)) + 1;
	len += 1; /* remove one trailing space and add \r\n */
	len++; /* last args ":" */
	ret = bip_malloc(len + 1);
	ret[0] = 0;

	if (l->origin) {
		strcat(ret, ":");
		strcat(ret, l->origin);
		strcat(ret, " ");
	}
	for (i = 0; i < array_count(&l->words) - 1; i++) {
		strcat(ret, array_get(&l->words, i));
		strcat(ret, " ");
	}
	if (strchr(array_get(&l->words, i), ' ') || l->colon)
		strcat(ret, ":");

	strcat(ret, array_get(&l->words, i));
	strcat(ret, "\r\n");
	return ret;
}

char *irc_line_to_string_to(struct line *line, char *nick)
{
	char *tmp;
	char *l;

	tmp = (char *)irc_line_elem(line, 1);
	array_set(&line->words, 1, nick);
	l = irc_line_to_string(line);
	array_set(&line->words, 1, tmp);

	return l;
}

int irc_line_count(struct line *line)
{
	return array_count(&line->words);
}

int irc_line_includes(struct line *line, int elem)
{
	return array_includes(&line->words, elem);
}

const char *irc_line_elem(struct line *line, int elem)
{
	return array_get(&line->words, elem);
}

void irc_line_drop(struct line *line, int elem)
{
	free(array_drop(&line->words, elem));
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
struct line *irc_line_new_from_string(char *str)
{
	struct line *line;
	char *space;
	size_t len;

	line = irc_line_new();
	if (str[0] == ':') {
		space = str + 1;

		while (*space && *space != ' ')
			space++;
		if (!*space) {
			irc_line_free(line);
			return NULL;
		}
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
		if (array_count(&line->words) == 0)
			strucase(tmp);
		array_push(&line->words, tmp);

		str = space;
		while (*str == ' ')
			str++;
	}
	return line;
}

void irc_line_free(struct line *l)
{
	int i;

	for (i = 0; i < array_count(&l->words); i++)
		free(array_get(&l->words, i));
	array_deinit(&l->words);
	if (l->origin)
		free(l->origin);
	free(l);
}

void irc_line_free_args(char **elemv, int elemc)
{
	int i;

	if (elemc == 0)
		return;
	for (i = 0; i < elemc; i++)
		free(elemv[i]);
	free(elemv);
}

