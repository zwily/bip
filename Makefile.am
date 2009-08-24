bin_PROGRAMS = src/bip src/bipmkpw
src_bip_SOURCES = src/conf.y src/lex.l src/bip.c src/connection.c src/irc.c src/line.c src/log.c src/md5.c src/util.c
src_bipmkpw_SOURCES = src/bipmkpw.c src/md5.c src/util.c
AM_YFLAGS= -d
BUILT_SOURCES = src/conf.c src/conf.h src/lex.c
if DEBUG
	AM_CFLAGS+=-Wall -g
	AM_LDFLAGS+=-g
else
	AM_CFLAGS+=-Wall
endif


man_MANS = bip.1 bip.conf.5

examplesdir = $(prefix)/share/doc/bip/examples/
examples_DATA = samples/bip.conf samples/bip.vim
