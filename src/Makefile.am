bin_PROGRAMS = bip bipmkpw
bip_SOURCES = conf.y lex.l bip.c connection.c irc.c line.c log.c md5.c util.c
bipmkpw_SOURCES = bipmkpw.c md5.c util.c
AM_YFLAGS= -d
BUILT_SOURCES = conf.h
if DEBUG
	AM_CFLAGS+=-Wall -g
	AM_LDFLAGS+=-g
else
	AM_CFLAGS+=-Wall
endif
