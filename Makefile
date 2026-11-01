CLANG ?= clang
ARCH  ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
	-I/usr/include/$(shell uname -m)-linux-gnu

all: drop_ipv4_opt.o

drop_ipv4_opt.o: src/drop_ipv4_opt.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f drop_ipv4_opt.o

.PHONY: all clean
