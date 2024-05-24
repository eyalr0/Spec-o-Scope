TARGET=aes
SRCS=test_aes.c aes_core.c
OBJS=${SRCS:.c=.o}

CFLAGS=-g -O3 -I../../../include
LDFLAGS=-g 

all: ${TARGET}

aes: ${OBJS}
	cc -o $@ ${OBJS} ${LDFLAGS}


clean:
	rm -f ${OBJS} ${TARGET}

# aes.o: aes.h
# aes_core.o: aes.h
