/*
 * $Id: util.h,v 1.35 2005/04/12 19:34:35 nohar Exp $
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
#ifndef UTIL_H
#define UTIL_H
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>

/* Warning: must be in order, 0 = less output */
#define LOG_FATAL 0
#define LOG_ERROR 1
#define LOG_WARN 2
#define LOG_INFO 3
#define LOG_DEBUG 4
#define LOG_DEBUGVERB 5
#define LOG_DEBUGTOOMUCH 6

#define HASH_NOCASE 1
#define HASH_DEFAULT 0

void mylog(int level, char *fmt, ...);
void _mylog(int level, char *fmt, va_list ap);
void fatal(char *fmt, ...);
char *timestamp(void);
struct list_item;
struct hash_item;

typedef struct list {
	struct list_item *first;
	struct list_item *last;
	int (*cmp)();
} list_t;

typedef struct list_iterator {
	list_t *list;
	struct list_item *cur;
	struct list_item *next;
} list_iterator_t;

typedef struct hash {
	list_t lists[256];
} hash_t;

typedef struct hash_iterator {
	int list;
	list_iterator_t lit;
	struct hash_item *cur;
	hash_t *hash;
} hash_iterator_t;

typedef struct array {
	int elemc;
	void **elemv;
} array_t;

#define MOVE_STRING(dest, src) do {\
	if (dest)\
		free(dest);\
	(dest) = (src);\
	(src) = NULL;\
} while(0)

#define FREE(a) free(a); (a) = NULL;

#define MAYFREE(a) do { \
		if (a) { \
			free(a); \
			(a) = NULL; \
		} \
	} while(0);

#define assert(condition) \
	do { \
		if (!(condition)) \
			fatal("Failed assetion in " __FILE__ "(%d): " \
				#condition, __LINE__); \
	} while(0)

#define assert_msg(condition, msg) \
	do { \
		if (!(condition)) \
			fatal(msg); \
	} while(0)

void list_init(list_t *list, int (*cmp)(const void*, const void*));
int list_ptr_cmp(const void *a, const void *b);
list_t *list_new(int (*cmp)(const void *, const void *));
void *list_remove(list_t *list, const void *ptr);
void *list_remove_if_exists(list_t *list, const void *ptr);
void *list_get(list_t *list, const void *ptr);
void list_add_first(list_t *list, void *ptr);
void list_add_first_uniq(list_t *list, void *ptr);
void list_add_last(list_t *list, void *ptr);
void *list_get_first(list_t *list);
void *list_get_last(list_t *list);
void *list_remove_first(list_t *list);
void *list_remove_last(list_t *list);
void list_it_init(list_t *list, list_iterator_t *ti);
void list_it_next(list_iterator_t *ti);
void *list_it_item(list_iterator_t *ti);
void *list_it_remove(list_iterator_t *li);
void list_free(list_t *t);
void list_append(list_t *dest, list_t *src);
int list_is_empty(list_t *l);

void hash_init(hash_t *h, int);
void hash_free(hash_t *h);
void hash_clean(hash_t *h);
hash_t *hash_new(int options);
void hash_insert(hash_t *hash, const char *key, void *ptr);
int hash_includes(hash_t *hash, const char *key);
void *hash_get(hash_t *, const char *key);
void *hash_remove(hash_t *hash, const char *key);
void *hash_remove_if_exists(hash_t *hash, const char *key);
int hash_is_empty(hash_t *h);
void hash_it_init(hash_t *hash, hash_iterator_t *i);
void hash_it_next(hash_iterator_t *hi);
void *hash_it_item(hash_iterator_t *h);
const char *hash_it_key(hash_iterator_t *h);
void *hash_it_remove(hash_iterator_t *li);
list_t *hash_keys(hash_t *hash);
void hash_rename_key(hash_t *h, const char *oldk, const char *newk);

int is_valid_nick(char *str);
int is_valid_username(char *str);
char *bip_strmaydup(char *s);

void strucase(char *s);
int ischannel(char p);
char *hrtime(time_t t);
#ifdef HAVE_LIBSSL
char *checkmode2text(int v);
#endif
#define bool2text(v) ((v) ? "true" : "false")
void *bip_malloc(size_t size);
void *bip_calloc(size_t nmemb, size_t size);
void *bip_realloc(void *ptr, size_t size);
char *bip_strdup(const char *str);
#define array_each(a, idx, ptr) for ((idx) = 0; \
		(idx) < (a)->elemc && (((ptr) = array_get((a), (idx))) || 1); \
		(idx)++)

void array_init(array_t *a);
array_t *array_new(void);
void array_ensure(array_t *a, int index);
array_t *array_extract(array_t *a, int index, int upto);
void array_deinit(array_t *a);
void array_free(array_t *a);
static inline int array_count(array_t *a)
{
	return a->elemc;
}

static inline int array_includes(array_t *a, int index)
{
	assert(index >= 0);
	return a->elemc > index;
}

static inline void array_set(array_t *a, int index, void *ptr)
{
	array_ensure(a, index);
	a->elemv[index] = ptr;
}

static inline void *array_get(array_t *a, int index)
{
	assert(array_includes(a, index));
	return a->elemv[index];
}

static inline void array_push(array_t *a, void *ptr)
{
	int idx = a->elemc;

	array_ensure(a, idx);
	a->elemv[idx] = ptr;
}

static inline void *array_pop(array_t *a)
{
	if (a->elemc == 0)
		return NULL;
	if (a->elemc == 1) {
		void *ptr = a->elemv[0];
		free(a->elemv);
		a->elemv = NULL;
		a->elemc = 0;
		return ptr;
	}
	return a->elemv[--a->elemc];
}

#endif
