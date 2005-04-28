#ifndef IRC_LINE_H
#define IRC_LINE_H

#include "connection.h"

#define WRITE_LINE1(con, org, com, a) \
	do  { \
		struct line l; \
		irc_line_init(&l); \
		l.origin = org; \
		_irc_line_append(&l, com); \
		_irc_line_append(&l, a); \
		irc_line_write(&l, con); \
		free(l.elemv); \
	} while(0)

#define WRITE_LINE2(con, org, com, a1, a2) \
	do  { \
		struct line l; \
		irc_line_init(&l); \
		l.origin = org; \
		_irc_line_append(&l, com); \
		_irc_line_append(&l, a1); \
		_irc_line_append(&l, a2); \
		irc_line_write(&l, con); \
		free(l.elemv); \
	} while(0)

#define WRITE_LINE3(con, org, com, a1, a2, a3) \
	do  { \
		struct line l; \
		irc_line_init(&l); \
		l.origin = org; \
		_irc_line_append(&l, com); \
		_irc_line_append(&l, a1); \
		_irc_line_append(&l, a2); \
		_irc_line_append(&l, a3); \
		irc_line_write(&l, con); \
		free(l.elemv); \
	} while(0)

#define WRITE_LINE4(con, org, com, a1, a2, a3, a4) \
	do  { \
		struct line l; \
		irc_line_init(&l); \
		l.origin = org; \
		_irc_line_append(&l, com); \
		_irc_line_append(&l, a1); \
		_irc_line_append(&l, a2); \
		_irc_line_append(&l, a3); \
		_irc_line_append(&l, a4); \
		irc_line_write(&l, con); \
		free(l.elemv); \
	} while(0)

struct line {
	char *origin;
	unsigned int elemc;
	char **elemv;
	int colon;
};

void irc_line_init(struct line *l);
struct line *irc_line_new();
void irc_line_clear(struct line *l);
void irc_line_write(struct line *l, connection_t *c);
void irc_line_append(struct line *l, char *s);
struct line *irc_line(char *str);
char *irc_line_to_string(struct line *l);
void irc_line_free(struct line *l);
struct line *irc_line_dup(struct line *line);
void _irc_line_append(struct line *l, char *s);

#endif
