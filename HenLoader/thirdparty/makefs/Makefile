#	$NetBSD: Makefile,v 1.36 2013/08/05 14:41:57 reinoud Exp $
#
CFLAGS=`pkg-config --cflags libbsd-overlay`
LDFLAGS=`pkg-config --libs libbsd-overlay`
WARNS?=	5

# .include <bsd.own.mk>

PROG=	makefs
SRCS=	udf.c strstuff.c \
	makefs.c \
	walk.c
MAN=	makefs.8
#CC=	clang
DESTDIR ?= /usr/local

MKNODSRC=	${NETBSDSRCDIR}/sbin/mknod
MTREESRC=	${NETBSDSRCDIR}/usr.sbin/mtree

CPPFLAGS+=	-I${.CURDIR} -I${MKNODSRC} -I${MTREESRC} -DMAKEFS
#CPPFLAGS+=	-DMSDOSFS_DEBUG
#PATH:		${MKNODSRC} ${MTREESRC}

#.include "${.CURDIR}/cd9660/Makefile.inc"
#.include "${.CURDIR}/chfs/Makefile.inc"
#.include "${.CURDIR}/ffs/Makefile.inc"
#.include "${.CURDIR}/v7fs/Makefile.inc"
#.include "${.CURDIR}/msdos/Makefile.inc"

SRCS+= udf_core.c udf_osta.c

#if !defined(HOSTPROG)
DPADD+= ${LIBUTIL} ${LIBM}
LDADD+= -lutil -lm
#endif

prog:
	${CC} -o $(PROG) $(SRCS) $(LDFLAGS) -D_GNU_SOURCE -std=c11 -lm -I./udf -static

install:
	install -D $(PROG) $(DESTDIR)/bin/$(PROG)

#.include <bsd.prog.mk>
# DO NOT DELETE
