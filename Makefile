PROG=	jdk-ca-certs

SRCS+=	jdk-ca-certs.c

SRCS+=	bs_ber.c
SRCS+=	bs_cbb.c
SRCS+=	bs_cbs.c

LDADD+=	-lcrypto
DPADD+= ${LIBCRYPTO}

CFLAGS+= -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith
CFLAGS+= -Wsign-compare

.include <bsd.prog.mk>
