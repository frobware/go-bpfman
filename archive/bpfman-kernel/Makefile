.PHONY: all clean

BINARY := bpfman-kernel
SRCS := main.c cJSON.c

CFLAGS := -Wall -Wextra -O2 $(shell pkg-config --cflags libbpf)
LDFLAGS := $(shell pkg-config --libs libbpf) -lelf -lz -lm

all: $(BINARY)

$(BINARY): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(BINARY)
