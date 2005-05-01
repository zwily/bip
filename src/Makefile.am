bin_PROGRAMS = bip genpwent
bip_SOURCES = conf.y lex.l bip.c connection.c irc.c line.c log.c md5.c util.c
genpwent_SOURCES = genpwent.c md5.c util.c
AM_YFLAGS= -d
if DEBUG
	AM_CFLAGS=-Wall -g
	AM_LDFLAGS=-g
else
	AM_CFLAGS=-Wall
endif
