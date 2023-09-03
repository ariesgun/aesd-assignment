PROGS := aesdsocket
CFLAGS := -g -Wall -Werror

all: $(PROGS)

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $@ $(LDFLAGS) $^

clean:
	rm -f *.o
	rm -f $(PROGS)
