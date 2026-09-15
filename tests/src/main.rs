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

    #[test]
    fn hc128_kat_iv0_is_one() {
        let mut iv = [0u8; 16];
        iv[0] = 1;
        let expected: [u32; 16] = [
            0xc01893d5, 0xb7dbe958, 0x8f65ec98, 0x64176604, 0x36fc6724, 0xc82c6eec, 0x1b1c38a7,
            0xc9b42a95, 0x323ef123, 0x0a6a908b, 0xce757b68, 0x9f14f7bb, 0xe4cde011, 0xaeb5173f,
            0x89608c94, 0xb5cf46ca,
        ];

        assert_eq!(
            hc128_keystream(&[0; 16], &iv, 64),
            words_to_bytes(&expected)
        );
    }

    #[test]
    fn hc128_kat_k0_is_0x55() {
        let mut key = [0u8; 16];
        key[0] = 0x55;
        let expected: [u32; 16] = [
            0x518251a4, 0x04b4930a, 0xb02af931, 0x0639f032, 0xbcb4a47a, 0x5722480b, 0x2bf99f72,
            0xcdc0e566, 0x310f0c56, 0xd3cc83e8, 0x663db8ef, 0x62dfe07f, 0x593e1790, 0xc5ceaa9c,
            0xab03806f, 0xc9a6e5a0,
        ];

        assert_eq!(
            hc128_keystream(&key, &[0; 16], 64),
            words_to_bytes(&expected)
        );
    }

    // XORs the keystream words at every position over 2^20 blocks of 16 words.
    // Exercises the Q phase and the counter wrap-around.
    #[test]
    #[ignore = "generates 64 MiB of keystream; run with --ignored"]
    fn hc128_kat_2_20_blocks() {
        let keystream = hc128_keystream(&[0; 16], &[0; 16], (1 << 20) * 64);

        let mut folded = [0u32; 16];
        for block in keystream.chunks(64) {
            for (j, word) in folded.iter_mut().enumerate() {
                *word ^= u32::from_le_bytes(block[j * 4..j * 4 + 4].try_into().unwrap());
            }
        }

        let expected: [u32; 16] = [
            0xa4eac026, 0x7e491126, 0x6a2a384f, 0x5c4e1329, 0xda407fa1, 0x55e6b1ae, 0x05c6fdf3,
            0xbbdc8a86, 0x7a699aa0, 0x1a4dc117, 0x63658ccc, 0xd3e62474, 0x9cf8236f, 0x0131be21,
            0xc3a51de9, 0xd12290de,
        ];

        assert_eq!(folded, expected);
    }
}
