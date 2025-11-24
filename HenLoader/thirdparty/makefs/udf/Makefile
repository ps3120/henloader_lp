#	$NetBSD: Makefile.inc,v 1.2 2013/08/05 18:45:00 reinoud Exp $
#

UDF=	${NETBSDSRCDIR}/sys/fs/udf
UDF_NEWFS=	${NETBSDSRCDIR}/sbin/newfs_udf
FSCK=	${NETBSDSRCDIR}/sbin/fsck	# use progress meter.

.PATH:	${.CURDIR}/udf ${UDF} ${UDF_NEWFS} ${FSCK}

CPPFLAGS+= -I${UDF} -I${UDF_NEWFS} -I${FSCK}

SRCS += udf_create.c udf_write.c udf_osta.c newfs_udf.c

objs:
	$(CC)  -o udf_osta.o udf_osta.c
	$(CC)  -o udf_create.o udf_create.c
	$(CC)  -o udf_write.o udf_write.c
	ar rs libudf.a *.o

