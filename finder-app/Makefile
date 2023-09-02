PROGS := writer
CC := $(CROSS_COMPILE)gcc

all: $(PROGS)

writer: writer.c
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $@ $(LDFLAGS) $^

clean:
	rm -f *.o
	rm -f $(PROGS)
