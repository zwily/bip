/*
 * $Id: util.c,v 1.60 2005/04/12 19:34:35 nohar Exp $
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
#include "connection.h"
#include "util.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

extern int conf_log_level;
extern int conf_log_system;
extern int errno;
extern FILE *conf_global_log_file;

void memory_fatal(void)
{
	fflush(conf_global_log_file);
#define OOMMSG "Out of memory.\n"
	fwrite(OOMMSG, 1, strlen(OOMMSG), conf_global_log_file);
#undef OOMMSG
	fflush(conf_global_log_file);
	exit(28);
}

void *bip_malloc(size_t size)
{
	void *r;

	assert(size < INT_MAX / 4);

	r = malloc(size);
	if (!r)
		memory_fatal();
	return r;
}

void *bip_calloc(size_t nmemb, size_t size)
{
	void *r = calloc(nmemb, size);
	if (!r)
		memory_fatal();
	return r;
}

void *bip_realloc(void *ptr, size_t size)
{
	void *r;

	assert(size < INT_MAX / 4);

	r = realloc(ptr, size);
	if (size > 0 && r == NULL)
		memory_fatal();
	return r;
}

char *bip_strdup(const char *str)
{
	char *r = strdup(str);
	if (!r)
		memory_fatal();
	return r;
}

/*
 * <nick> ::= <letter> { <letter> | <number> | <special> }
 * <special> ::= '-' | '[' | ']' | '\' | '`' | '^' | '{' | '}'
 */
int is_valid_nick(char *str)
{
	char *tmp;
	if (!str || !isalpha(*str))
		return 0;

	tmp = str;
	while (*tmp != '\0' && (isalnum(*tmp) || *tmp == '-' || *tmp == '[' ||
			*tmp == ']' || *tmp == '\\' || *tmp == '`' ||
			*tmp == '^' || *tmp == '{' || *tmp == '}' ||
			*tmp == '|' || *tmp == '_' ))
		tmp++;
	return (*tmp == '\0');
}

int is_valid_username(char *str)
{
	char *tmp;
	if (!str || *str == '\0' || *str == ' ' || *str == '\n' || *str == '\r')
		return 0;

	tmp = str;
	while (*tmp != '\0' && *tmp != ' ' && *tmp != '\0' && *tmp != '\r' &&
			*tmp != '\n')
		tmp++;
	return (*tmp == '\0');
}

char *timestamp(void)
{
	static char ts[20];
	time_t tv;
	struct tm *tm;

	time(&tv);
	tm = localtime(&tv);

	snprintf(ts, 20, "%02d-%02d-%04d %02d:%02d:%02d", tm->tm_mday,
			tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour,
			tm->tm_min, tm->tm_sec);
	return ts;
}

char *hrtime(time_t s)
{
	static char ts[20];
	struct tm *tm;

	if (s == 0)
		return "never";
	tm = localtime(&s);

	snprintf(ts, 20, "%02d-%02d-%04d %02d:%02d:%02d", tm->tm_mday,
			tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour,
			tm->tm_min, tm->tm_sec);
	return ts;
}

#ifdef HAVE_LIBSSL
char *checkmode2text(int v)
{
	switch (v) {
	case SSL_CHECK_BASIC:
		return "basic";
	case SSL_CHECK_CA:
		return "ca";
	default:
		return "none";
	}
}
#endif

void _mylog(int level, char *fmt, va_list ap)
{
	char *prefix;

	if (!conf_log_system)
		return;

	if (level > conf_log_level)
		return;

	switch (level) {
		case LOG_FATAL:
			prefix = "FATAL: ";
			break;
		case LOG_DEBUGVERB:
			prefix = "DEBUGVERB: ";
			break;
		case LOG_DEBUG:
			prefix = "DEBUG: ";
			break;
		case LOG_ERROR:
			prefix = "ERROR: ";
			break;
		case LOG_WARN:
			prefix = "WARNING: ";
			break;
		case LOG_INFO:
			prefix = "";
			break;
		default:
			prefix = "";
			break;
	}

	fprintf(conf_global_log_file, "%s %s", timestamp(), prefix);
	vfprintf(conf_global_log_file, fmt, ap);
	fprintf(conf_global_log_file, "\n");
#ifdef DEBUG
	fflush(conf_global_log_file);
#endif
}

void mylog(int level, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_mylog(level, fmt, ap);
	va_end(ap);
}

#ifdef HAVE_BACKTRACE
#include <execinfo.h>

void print_trace(void)
{
	void *array[32];
	size_t size;
	size_t i;

	size = backtrace(array, 32);
	fflush(conf_global_log_file);
	backtrace_symbols_fd(array, size, fileno(conf_global_log_file));
}
#endif

extern char *conf_pid_file;
void fatal(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_mylog(LOG_FATAL, fmt, ap);
	va_end(ap);

#ifdef HAVE_BACKTRACE
	print_trace();
#endif

	exit(200);
}

/*
 * list handling functions
 */

struct list_item {
	struct list_item *next;
	struct list_item *prev;
	void *ptr;
};

int list_ptr_cmp(const void *a, const void *b)
{
	if (a == b)
		return 0;
	return -1;
}

void list_init(list_t *l, int (*cmp)(const void *, const void *))
{
	l->first = NULL;
	l->last = NULL;
	l->cmp = cmp;
}

list_t *list_new(int (*cmp)(const void *, const void *))
{
	list_t *l;
	l = bip_malloc(sizeof(list_t));
	list_init(l, cmp);
	return l;
}

static struct list_item *list_item(void *ptr)
{
	struct list_item *l;
	l = bip_malloc(sizeof(struct list_item));
	l->ptr = ptr;
	l->next = NULL;
	l->prev = NULL;
	return l;
}

void list_add_first(list_t *list, void *ptr)
{
	struct list_item *li;

	if (!ptr)
		fatal("Cannot add NULL ptr to list.");
	li = list_item(ptr);
	if (!list->first) {
		list->first = list->last = li;
		return;
	}
	li->next = list->first;
	list->first = li;
	li->next->prev = li;
}

void list_add_first_uniq(list_t *list, void *ptr)
{
	if (!ptr)
		fatal("Cannot add NULL ptr to list.");
	if (list_get(list, ptr))
		return;
	list_add_first(list, ptr);
}

void list_add_last(list_t *list, void *ptr)
{
	struct list_item *li;

	if (!ptr)
		fatal("Cannot add NULL ptr to list.");
	li = list_item(ptr);
	if (!list->first) {
		list->first = list->last = li;
		return;
	}
	li->prev = list->last;
	list->last = li;
	li->prev->next = li;
}

void *list_get_first(list_t *list)
{
	if (!list->first)
		return NULL;
	return list->first->ptr;
}

void *list_get_last(list_t *list)
{
	if (!list->last)
		return NULL;
	return list->last->ptr;
}

void *list_remove_first(list_t *list)
{
	struct list_item *l;
	void *ptr = list_get_first(list);

	if (!ptr)
		return NULL;
	l = list->first;
	list->first = list->first->next;
	if (list->first == NULL)
		list->last = NULL;
	free(l);
	return ptr;
}

void *list_remove_last(list_t *list)
{
	struct list_item *l;
	void *ptr = list_get_last(list);

	if (!ptr)
		return NULL;
	l = list->last;
	list->last = list->last->prev;
	if (list->last == NULL)
		list->first = NULL;
	free(l);
	return ptr;
}

void *list_remove_if_exists(list_t *list, const void *ptr)
{
	list_iterator_t li;
	int debug = 0;
	void *ret = 0;

	if (!list->cmp)
		fatal("list_remove: list does not have a cmp function\n");

	for (list_it_init(list, &li); list_it_item(&li); list_it_next(&li)) {
		if (list->cmp(list_it_item(&li), ptr) == 0) {
			if (debug == 1)
				fatal("%x appears twice in list\n", ptr);
			ret = list_it_remove(&li);
			debug = 1;
		}
	}
	if (debug)
		return ret;
	return NULL;
}

void *list_remove(list_t *list, const void *ptr)
{
	void *ret;
	if (!(ret = list_remove_if_exists(list, ptr)))
		fatal("list_remove: item not found");
	return ret;
}

void *list_get(list_t *list, const void *ptr)
{
	struct list_item *it;

	if (!list->cmp)
		fatal("list_get: list does not have a cmp function\n");

	for (it = list->first; it; it = it->next) {
		if (list->cmp(it->ptr, ptr) == 0)
			return it->ptr;
	}
	return NULL;
}

int list_is_empty(list_t *l)
{
	return (l->first ? 0 : 1);
}

void list_it_init(list_t *list, list_iterator_t *ti)
{
	ti->list = list;
	ti->cur = list->first;
	ti->next = NULL;
}

void list_it_next(list_iterator_t *ti)
{
	if (ti->cur) {
		if (ti->next)
			fatal("list_it_next: inconsistent interator state");
		ti->cur = ti->cur->next;
	} else if (ti->next) {
		ti->cur = ti->next;
		ti->next = NULL;
	}
}

void *list_it_item(list_iterator_t *ti)
{
	if (!ti->cur)
		return NULL;
	return ti->cur->ptr;
}

void *list_it_remove(list_iterator_t *li)
{
	if (!li->cur)
		return NULL;

	if (li->cur->prev)
		li->cur->prev->next = li->cur->next;
	else
		li->list->first = li->cur->next;

	if (li->cur->next)
		li->cur->next->prev = li->cur->prev;
	else
		li->list->last = li->cur->prev;

	void *ptr = li->cur->ptr;
	struct list_item *item = li->cur;
	li->next = li->cur->next;
	li->cur = NULL;
	free(item);
	return ptr;
}

void list_free(list_t *t)
{
	if (t->first != NULL)
		fprintf(stderr, "Warning, freeing non empty list\n");
	free(t);
}

void list_append(list_t *dest, list_t *src)
{
	if (src->last == NULL)
		return;
	if (dest->first == NULL) {
		dest->first = src->first;
		dest->last = src->last;
		src->first = src->last = NULL;
		return;
	}
	src->first->prev = dest->last;
	dest->last->next = src->first;
	dest->last = src->last;
	src->first = src->last = NULL;
}

/*
 * Hash stuff
 */

struct hash_item {
	char *key;
	void *item;
};

static int hash_item_nocase_cmp(const struct hash_item *a, const char *b)
{
	return strcasecmp(a->key, b);
}

static int hash_item_cmp(struct hash_item *a, char *b)
{
	return strcmp(a->key, b);
}

void hash_init(hash_t *h, int options)
{
	int i;

	memset(h, 0, sizeof(hash_t));
	for (i = 0; i < 256; i++) {
		switch (options) {
		case HASH_NOCASE:
			list_init(&h->lists[i],
				(int (*)(const void*, const void*))
					hash_item_nocase_cmp);
			break;
		case HASH_DEFAULT:
			list_init(&h->lists[i],
				(int (*)(const void*,const void*))
					hash_item_cmp);
			break;
		default:
			fatal("wrong hash option %d", options);
		}
	}
}

void hash_clean(hash_t *h)
{
	int i;
	struct hash_item *hi;

	for (i = 0; i < 256; i++) {
		while ((hi = list_remove_first(&h->lists[i]))) {
			free(hi->key);
			free(hi);
		}
	}
}

void hash_free(hash_t *h)
{
	hash_clean(h);
	free(h);
}

hash_t *hash_new(int options)
{
	hash_t *h;
	h = bip_malloc(sizeof(hash_t));
	hash_init(h, options);
	return h;
}

/* Now we have a real hash, but we use only the last byte of it :p */
static unsigned char hash_func(const char *pkey)
{
	char c;
	unsigned long hash = 5381; /* 5381 & 0xff makes more sense */

	while ((c = *pkey++))
		hash = ((hash << 5) + hash) ^ toupper(c);
	return (unsigned char)hash;
}

void hash_insert(hash_t *hash, const char *key, void *ptr)
{
	struct hash_item *it;

	if (hash_get(hash, key))
		fatal("Element with key %s already in hash %x\n", key, hash);

	it = bip_malloc(sizeof(struct hash_item));
	it->key = bip_strdup(key);
	it->item = ptr;
	list_add_first(&hash->lists[hash_func(key)], it);
}

int hash_includes(hash_t *hash, const char *key)
{
	struct hash_item *hi;
	list_t *list = &hash->lists[hash_func(key)];
	hi = list_get(list, key);
	return hi != NULL;
}

void *hash_get(hash_t *hash, const char *key)
{
	struct hash_item *hi;
	list_t *list = &hash->lists[hash_func(key)];
	hi = list_get(list, key);
	if (!hi)
		return NULL;
	return hi->item;
}

void *hash_remove_if_exists(hash_t *hash, const char *key)
{
	if (hash_get(hash, key) == NULL)
		return NULL;
	return hash_remove(hash, key);
}

void *hash_remove(hash_t *hash, const char *key)
{
	struct hash_item *it;
	void *ptr;
	it = (struct hash_item *)list_remove(&hash->lists[hash_func(key)], key);
	if (!it)
		return NULL;
	ptr = it->item;
	free(it->key);
	free(it);
	return ptr;
}

int hash_is_empty(hash_t *h)
{
	int i;

	for (i = 0; i < 256; i++) {
		if (!list_is_empty(&h->lists[i]))
			return 0;
	}
	return 1;
}

void hash_it_init(hash_t *h, hash_iterator_t *hi)
{
	memset(hi, 0, sizeof(hash_iterator_t));
	hi->hash = h;

	while (hi->list < 256 && list_is_empty(&h->lists[hi->list]))
		hi->list++;
	if (hi->list < 256)
		list_it_init(&h->lists[hi->list], &hi->lit);
}

void hash_it_next(hash_iterator_t *hi)
{
	list_it_next(&hi->lit);
	if (!list_it_item(&hi->lit)) {
		do {
			hi->list++;
			if (hi->list == 256)
				return;
		} while (list_is_empty(&hi->hash->lists[hi->list]));
		list_it_init(&hi->hash->lists[hi->list], &hi->lit);
	}
}

void *hash_it_item(hash_iterator_t *h)
{
	struct hash_item *hi;

	hi = list_it_item(&h->lit);
	if (!hi)
		return NULL;
	return hi->item;
}

const char *hash_it_key(hash_iterator_t *h)
{
	struct hash_item *hi;
	hi = list_it_item(&h->lit);
	if (!hi)
		return NULL;
	return hi->key;
}

void *hash_it_remove(hash_iterator_t *hi)
{
	struct hash_item *hitem;
	void *ptr;

	hitem = list_it_remove(&hi->lit);

	ptr = hitem->item;
	free(hitem->key);
	free(hitem);
	return ptr;
}

void hash_dump(hash_t *h)
{
	hash_iterator_t it;
	for (hash_it_init(h, &it); hash_it_key(&it) ;hash_it_next(&it))
		printf("%s => %p\n", hash_it_key(&it), hash_it_item(&it));
}

list_t *hash_keys(hash_t *hash)
{
	hash_iterator_t hi;
	list_t *ret;

	ret = list_new(NULL);

	for (hash_it_init(hash, &hi); hash_it_item(&hi); hash_it_next(&hi))
		list_add_last(ret, bip_strdup(hash_it_key(&hi)));

	return ret;
}

void hash_rename_key(hash_t *h, const char *oldk, const char *newk)
{
	hash_insert(h, newk, hash_remove(h, oldk));
}

char *bip_strmaydup(char *s)
{
	if (!s)
		return s;
	return bip_strdup(s);
}

void strucase(char *s)
{
	while (*s) {
		*s = toupper(*s);
		s++;
	}
}

int ischannel(char p)
{
	return (p == '#' || p == '&' || p == '+' || p == '!');
}

void array_init(array_t *a)
{
	memset(a, 0, sizeof(array_t));
}

array_t *array_new(void)
{
	array_t *a;

	a = bip_malloc(sizeof(array_t));
	array_init(a);
	return a;
}

void array_ensure(array_t *a, int index)
{
	assert(index >= 0);

	if (array_includes(a, index))
		return;
	a->elemv = bip_realloc(a->elemv, sizeof(void *) * (index + 1));
	memset(a->elemv + a->elemc, 0, sizeof(void *) * (index + 1 - a->elemc));
	a->elemc = index + 1;
}

array_t *array_extract(array_t *a, int index, int upto)
{
	array_t *ret;
	int i;

	assert(array_includes(a, index));
	if (upto == -1)
		upto = a->elemc;
	assert((index == 0 && upto == 0) || array_includes(a, upto - 1));
	assert(index <= upto);

	ret = array_new();
	if (index == upto)
		return ret;

	/* here we have index < upto */
	array_ensure(ret, upto - index - 1);
	for (i = 0; i < ret->elemc; i++)
		ret->elemv[i] = a->elemv[i + index];
	return ret;
}

void array_deinit(array_t *a)
{
	if (a->elemv)
		free(a->elemv);
	array_init(a);
}

void array_free(array_t *a)
{
	if (a->elemv)
		free(a->elemv);
	free(a);
}
