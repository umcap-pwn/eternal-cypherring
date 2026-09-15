.PHONY: build test

build:
	cargo build --workspace

test: build
	cargo test -p tests
