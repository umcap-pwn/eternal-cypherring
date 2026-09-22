fn main() {
    println!("ABI test suite: run `cargo test -p tests` (or `make test`)");
}

#[cfg(test)]
mod tests {
    use loader::{Cipher, load_algorithm};

    fn load(name: &str) -> Cipher {
        match load_algorithm(name) {
            Ok(cipher) => cipher,
            Err(e) => panic!("failed to load '{name}': {e}. Run `cargo build --workspace` first"),
        }
    }

    fn test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 251) as u8).collect()
    }

    fn roundtrip(name: &str, key: &[u8]) {
        let cipher = load(name);

        for size in [0, 1, 15, 16, 17, 63, 64, 65, 512, 100_000] {
            let plaintext = test_data(size);
            let encrypted = cipher.encrypt(key, &plaintext).unwrap();
            let decrypted = cipher.decrypt(key, &encrypted).unwrap();

            assert_eq!(
                plaintext, decrypted,
                "{name}: roundtrip failed for {size} bytes"
            );

            if size > 0 {
                let again = cipher.encrypt(key, &plaintext).unwrap();
                assert_ne!(
                    encrypted, again,
                    "{name}: two encryptions produced the same output"
                );
            }
        }
    }

    #[test]
    fn algorithm_info() {
        let cases = [
            ("rc4", 32usize, 16usize),
            ("trivium", 10, 10),
            ("hc128", 16, 16),
        ];

        for (name, key_size, iv_size) in cases {
            let cipher = load(name);

            assert_eq!(cipher.algorithm_name().unwrap(), name);
            assert_eq!(cipher.key_size().unwrap(), key_size);
            assert_eq!(cipher.output_size(100, 0).unwrap(), 100 + iv_size);
            assert_eq!(cipher.output_size(100, 1).unwrap(), 100 - iv_size);
        }
    }

    #[test]
    fn rc4_roundtrip() {
        roundtrip("rc4", &[0x11; 32]);
    }

    #[test]
    fn trivium_roundtrip() {
        roundtrip("trivium", &[0x22; 10]);
    }

    #[test]
    fn hc128_roundtrip() {
        roundtrip("hc128", &[0x33; 16]);
    }

    #[test]
    fn unknown_algorithm_is_an_error() {
        assert!(load_algorithm("definitely-not-a-cipher").is_err());
    }

    #[test]
    fn decrypt_rejects_short_input() {
        let cases: [(&str, &[u8]); 3] = [
            ("rc4", &[0x11; 32]),
            ("trivium", &[0x22; 10]),
            ("hc128", &[0x33; 16]),
        ];

        for (name, key) in cases {
            let cipher = load(name);
            let short = [0u8; 4];

            assert!(
                cipher.decrypt(key, &short).is_err(),
                "{name}: decrypting input shorter than the IV must fail"
            );
        }
    }

    fn hc128_keystream(key: &[u8; 16], iv: &[u8; 16], size: usize) -> Vec<u8> {
        let cipher = load("hc128");

        // decrypt() XORs the keystream with the data after the IV, so zeroes
        // return the raw keystream.
        let mut input = vec![0u8; 16 + size];
        input[..16].copy_from_slice(iv);

        cipher.decrypt(key, &input).unwrap()
    }

    fn words_to_bytes(words: &[u32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    // Test vectors from Appendix A of the HC-128 paper
    #[test]
    fn hc128_kat_zero_key_zero_iv() {
        let expected: [u32; 16] = [
            0x73150082, 0x3bfd03a0, 0xfb2fd77f, 0xaa63af0e, 0xde122fc6, 0xa7dc29b6, 0x62a68527,
            0x8b75ec68, 0x9036db1e, 0x81896005, 0x00ade078, 0x491fbf9a, 0x1cdc3013, 0x6c3d6e24,
            0x90f664b2, 0x9cd57102,
        ];

        assert_eq!(
            hc128_keystream(&[0; 16], &[0; 16], 64),
            words_to_bytes(&expected)
        );
    }
}
