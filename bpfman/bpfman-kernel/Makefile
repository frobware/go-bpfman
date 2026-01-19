.PHONY: all clean

BINARY := bpfman-kernel

CFLAGS := -Wall -Wextra -O2 $(shell pkg-config --cflags libbpf)
LDFLAGS := $(shell pkg-config --libs libbpf) -lelf -lz

all: $(BINARY)

$(BINARY): main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BINARY)
