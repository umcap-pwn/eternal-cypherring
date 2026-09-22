# eternal-cypherring

etc (EThernal Cyphering) is a small project directed towards learning cryptography.
It implements the RC4, Trivium and HC-128 stream ciphers as shared libraries and
loads them at runtime from a small CLI.

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
cargo test -p tests
```

## Install

```
make install                         
make uninstall
```
