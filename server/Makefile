CROSS_CC?=$(CROSS_COMPILE)
CC?=$(CROSS_CC)gcc
CFLAGS?=-g -Wall -Werror -Wextra
OBJECTS=aesdsocket.o aesdsocketpthreadutils.o aesdsocketpthreadclient.o
HEADERS=aesdsocketTypes.h
LDFLAGS?=-lpthread
all: aesdsocket aesdsocket.o aesdsocket.c aesdsocketpthreadclient.c aesdsocketpthreadutils.c aesdsocketTypes.h
aesdsocket: $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@ 
aesdsocketpthreadutils.o: aesdsocketpthreadutils.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@
aesdsocketpthreadclient.o: aesdsocketpthreadclient.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@
aesdsocket.o: aesdsocket.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f aesdsocketpthreadclient.o aesdsocketpthreadutils.o aesdsocket.o aesdsocket
