PREFIX ?= /usr/local
DESTDIR ?=

BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib

ALGORITHMS = rc4 trivium hc128

.PHONY: build test install uninstall

build:
	cargo build --workspace

test: build
	cargo test -p tests

install:
	cargo build --release --workspace
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 target/release/etc $(DESTDIR)$(BINDIR)/etc
	install -d $(DESTDIR)$(LIBDIR)
	for alg in $(ALGORITHMS); do \
		install -m 0644 target/release/lib$${alg}.so $(DESTDIR)$(LIBDIR)/lib$${alg}.so; \
	done

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/etc
	for alg in $(ALGORITHMS); do \
		rm -f $(DESTDIR)$(LIBDIR)/lib$${alg}.so; \
	done
