LOCALBASE?=/usr/local
CFLAGS+= -Wall -I${LOCALBASE}/include
LDFLAGS+=-s
EXTRA_LIBS=-L${LOCALBASE}/lib -Liniparse -lpcre2-8 -liniparser
CC?=gcc
AR?=ar

BRUTEBLOCK_OBJS=bruteblock.o utils.o ipfw2.o
BRUTEBLOCKD_OBJS=bruteblockd.o utils.o ipfw2.o pidfile.o
INIPARSE_SRC=iniparse/dictionary.c iniparse/iniparser.c iniparse/strlib.c
INIPARSE_H=iniparse/dictionary.h iniparse/iniparser.h iniparse/strlib.h

all: bruteblock bruteblockd

iniparse/libiniparser.a: $(INIPARSE_SRC) $(INIPARSE_H)
	@cd iniparse  && make

bruteblock: $(BRUTEBLOCK_OBJS) iniparse/libiniparser.a
	$(CC) $(LDFLAGS) -o $@ $(BRUTEBLOCK_OBJS) $(EXTRA_LIBS)

bruteblockd: $(BRUTEBLOCKD_OBJS) iniparse/libiniparser.a pidfile.h
	$(CC) $(LDFLAGS) -o $@ $(BRUTEBLOCKD_OBJS) $(EXTRA_LIBS)

clean:
	@rm -f *.o *~  bruteblockd bruteblock *.core
	@cd iniparse && make clean

