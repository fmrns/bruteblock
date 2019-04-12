LOCALBASE?=/usr/local
CFLAGS+=-Os -Wall -I${LOCALBASE}/include
LDFLAGS+=-s
EXTRA_LIBS=-L${LOCALBASE}/lib -Liniparse -lpcre -liniparser
CC?=clang
AR?=ar

BRUTEBLOCK_OBJS=bruteblock.o ipfw2_nodelete.o
BRUTEBLOCKD_OBJS=bruteblockd.o ipfw2.o pidfile.o
INIPARSE_SRC=iniparse/dictionary.c iniparse/iniparser.c iniparse/strlib.c
INIPARSE_H=iniparse/dictionary.h iniparse/iniparser.h iniparse/strlib.h

all: bruteblock bruteblockd

iniparse/libiniparser.a: $(INIPARSE_SRC) $(INIPARSE_H)
	@cd iniparse  && make ARFLAGS=-rc

pidfile.o: pidfile.c pidfile.h

%.o: %.c bruteblock.h

ipfw2_nodelete.o: ipfw2.c bruteblock.h
	${CC} ${CFLAGS} -DNO_DELETE_IPFWTABLELIST -o $@ -c ipfw2.c

bruteblock: $(BRUTEBLOCK_OBJS) iniparse/libiniparser.a
	$(CC) $(LDFLAGS) -o $@ $(BRUTEBLOCK_OBJS) $(EXTRA_LIBS)

bruteblockd: $(BRUTEBLOCKD_OBJS) iniparse/libiniparser.a
	$(CC) $(LDFLAGS) -o $@ $(BRUTEBLOCKD_OBJS) $(EXTRA_LIBS)

clean:
	@rm -f *.o *~  bruteblockd bruteblock *.core
	@rm -rf .diff
	@cd iniparse && make clean


ORIG_DIR=../bruteblock-orig
TRUNK_DIR=${ORIG_DIR}/bruteblock-trunk
R005_DIR=${ORIG_DIR}/bruteblock-0.0.5

gettrunk:
	mkdir -p ${TRUNK_DIR}
	svn checkout http://svn.code.sf.net/p/bruteblock/code/trunk ${TRUNK_DIR}

get005:
	mkdir -p ${ORIG_DIR}
	fetch -o - 'http://downloads.sourceforge.net/project/bruteblock/bruteblock/bruteblock-0.0.5/bruteblock-0.0.5.tar.gz' | tar -C ${ORIG_DIR} -xvf -

${TRUNK_DIR}/RELEASE: gettrunk

${R005_DIR}/RELEASE:  get005

diff: ${TRUNK_DIR}/RELEASE ${R005_DIR}/RELEASE
	rm -f *.udiff
	make clean
	mkdir .diff
	-diff -ruwN --exclude=.diff --exclude=.git --exclude=.svn ${TRUNK_DIR} . >.diff/bruteblock-ipv6-for-trunk.udiff
	-diff -ruwN --exclude=.diff --exclude=.git                ${R005_DIR}  . >.diff/bruteblock-ipv6-for-0.0.5.udiff
	mv .diff/bruteblock-ipv6-for-trunk.udiff .
	mv .diff/bruteblock-ipv6-for-0.0.5.udiff .
	rmdir .diff
