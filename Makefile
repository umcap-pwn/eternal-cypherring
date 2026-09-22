PREFIX ?= /usr/local
DESTDIR ?=

BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib

ALGORITHMS = rc4 trivium hc128

.PHONY: build release test install uninstall clean

clean: 
	cargo clean
build:
	cargo build --workspace

release:
	cargo build --release --workspace

test: build
	cargo test -p tests

# Build artifacts as a regular user (`make release`), then install as root
# (`sudo make install`): root has no cargo/rustup in PATH, so the install
# target only copies files and never invokes the toolchain.
install:
	@test -x target/release/etc || { \
		echo "error: release artifacts missing - run 'make release' as your user first" >&2; exit 1; }
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
