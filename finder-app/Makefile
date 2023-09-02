PROGS := writer
CC := $(CROSS_COMPILE)gcc

all: $(PROGS)

writer: writer.c
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o
	rm -f $(PROGS)
