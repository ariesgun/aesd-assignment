PROGS := aesdsocket
CFLAGS := -g -Wall -Werror -pthread

all: $(PROGS)

aesdsocket: aesdsocket.c aesdsocket.h
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $@ $(LDFLAGS) $^

clean:
	rm -f *.o
	rm -f $(PROGS)
