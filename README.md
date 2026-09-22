# eternal-cypherring

etc (EThernal Cyphering) is a small project directed towards learning cryptography.
It implements the RC4, Trivium and HC-128 stream ciphers as shared libraries and
loads them at runtime from a small CLI.

## Requirements

Rust 1.88 or newer (edition 2024, let-chains).

## Build and run

```
cargo build --workspace

./target/debug/etc -a rc4 -m gen-key -s key.bin
./target/debug/etc -a rc4 -m encrypt -k key.bin -i plain.txt -o cipher.bin
./target/debug/etc -a rc4 -m decrypt -k key.bin -i cipher.bin -o plain.txt
```

Available algorithms: `rc4`, `trivium`, `hc128`.

## Tests

```
make test                            # build + cargo test -p tests
cargo test -p tests -- --ignored     # long HC-128 test vector
```

## Install

```
make release                         # build as your user (cargo lives in ~/.cargo/bin)
sudo make install                    # then install as root; PREFIX=/usr/local by default
make install PREFIX=~/.local         # no sudo needed for a user-local prefix
sudo make uninstall
```

The install target only copies files, so the release build must be done first
as a regular user.

The ciphers are installed as shared libraries into `$(PREFIX)/lib`, the CLI into
`$(PREFIX)/bin`; `etc` finds them next to itself at runtime.
