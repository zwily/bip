/*
 * $Id: util.h,v 1.35 2005/04/12 19:34:35 nohar Exp $
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
#ifndef UTIL_H
#define UTIL_H
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

/* Warning: must be in order, 0 = less output */
#define LOG_FATAL 0
#define LOG_ERROR 1
#define LOG_WARN 2
#define LOG_INFO 3
#define LOG_DEBUG 4
#define LOG_STD 4
#define LOG_DEBUGVERB 5
#define LOG_DEBUGTOOMUCH 6

#define HASH_NOCASE 1
#define HASH_DEFAULT 0

void mylog(int level, char *fmt, ...);
void fatal(char *fmt, ...);
char *timestamp(void);
struct list_item;

typedef struct list {
	struct list_item *first;
	struct list_item *last;
	int (*cmp)();
} list_t;

typedef struct list_iterator {
	list_t *list;
	struct list_item *cur;
} list_iterator_t;

/* our hash is also a list */
typedef struct hash {
	list_t lists[256];
} hash_t;

typedef struct hash_iterator {
	int list;
	struct list_item *cur;
	hash_t *hash;
} hash_iterator_t;

void list_init(list_t *list, int (*cmp)(void*,void*));
int list_ptr_cmp(void *a, void *b);
list_t *list_new(int (*cmp)(void *, void *));
void *list_remove(list_t *list, void *ptr);
void *list_remove_if_exists(list_t *list, void *ptr);
void *list_get(list_t *list, void *ptr);
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
void list_free_force(list_t *t);
void list_copy(list_t *src, list_t *dest);
void list_append(list_t *src, list_t *dest);
int list_is_empty(list_t *l);

void hash_init(hash_t *h, int);
void hash_free(hash_t *h);
void hash_clean(hash_t *h);
hash_t *hash_new(int options);
void hash_insert(hash_t *hash, char *key, void *ptr);
void *hash_get(hash_t *, char *key);
void *hash_remove(hash_t *hash, char *key);
void *hash_remove_if_exists(hash_t *hash, char *key);
void hash_it_init(hash_t *hash, hash_iterator_t *i);
void hash_it_next(hash_iterator_t *hi);
void *hash_it_item(hash_iterator_t *h);
char *hash_it_key(hash_iterator_t *h);

int is_valid_nick(char *str);
int is_valid_username(char *str);
char *strmaydup(char *s);

int ident_spoof(char *user);
int ident_nospoof();
void strucase(char *s);
int ischannel(char p);
#endif
