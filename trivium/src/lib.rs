use common::*;
use getrandom;
use std::slice;

const TRIVIUM_IV_SIZE: usize = 10;

struct TriviumState {
    a: [u8; 93],
    b: [u8; 84],
    c: [u8; 111],
}

#[unsafe(no_mangle)] // Safe to use; no edgecases
pub extern "C" fn get_output_size(input_size: usize, operation_type: i32) -> usize {
    match operation_type {
        0 => input_size + TRIVIUM_IV_SIZE,
        _ => input_size - TRIVIUM_IV_SIZE,
    }
}

#[unsafe(no_mangle)]
/// Do not mutate the `algorithm_name` field as it is immutable. Safe otherwise
pub extern "C" fn get_algorithm_info() -> *const AlgorithmInfo {
    static NAME: &[u8] = b"trivium\0";
    static INFO: AlgorithmInfo = AlgorithmInfo {
        algorithm_name: NAME.as_ptr(),
        key_size: 10,
    };
    &INFO
}

/// All buffers must contain valid non-null pointers and actual buffer sizes.
/// Output must be at least `get_output_size(input.size)` bytes long
#[unsafe(no_mangle)]
pub unsafe extern "C" fn encrypt(
    key: ConstBuffer,
    input: ConstBuffer,
    output: *mut MutBuffer,
) -> i32 {
    let data: &[u8] = unsafe { slice::from_raw_parts(input.data, input.size) };
    let key: &[u8] = unsafe { slice::from_raw_parts(key.data, key.size) };

    let mut iv = [0u8; TRIVIUM_IV_SIZE];
    getrandom::fill(&mut iv).expect("Error getting random value");

    let mut state = init(key, &iv);
    let result: Vec<u8> = data
        .iter()
        .map(|&b| b ^ keystream_byte(&mut state))
        .collect();
    let mut full: Vec<u8> = Vec::with_capacity(result.len() + TRIVIUM_IV_SIZE);
    full.extend_from_slice(&iv);
    full.extend_from_slice(&result);

    unsafe {
        let out = &mut *output;
        std::ptr::copy_nonoverlapping(full.as_ptr(), out.data, full.len());
        out.size = full.len();
    }

    0
}

/// All buffers must contain valid non-null pointers and actual buffer sizes.
/// Output must be at least `get_output_size(input.size)` bytes long
#[unsafe(no_mangle)]
pub unsafe extern "C" fn decrypt(
    key: ConstBuffer,
    input: ConstBuffer,
    output: *mut MutBuffer,
) -> i32 {
    let data: &[u8] = unsafe {
        slice::from_raw_parts(
            input.data.add(TRIVIUM_IV_SIZE),
            input.size - TRIVIUM_IV_SIZE,
        )
    };
    let key: &[u8] = unsafe { slice::from_raw_parts(key.data, key.size) };
    let iv: &[u8] = unsafe { slice::from_raw_parts(input.data, TRIVIUM_IV_SIZE) };

    let mut state = init(key, iv);
    let result: Vec<u8> = data
        .iter()
        .map(|&b| b ^ keystream_byte(&mut state))
        .collect();

    unsafe {
        let out = &mut *output;
        std::ptr::copy_nonoverlapping(result.as_ptr(), out.data, result.len());
        out.size = result.len();
    }
    0
}

fn init(key: &[u8], iv: &[u8]) -> TriviumState {
    let mut s = TriviumState {
        a: [0u8; 93],
        b: [0u8; 84],
        c: [0u8; 111],
    };
    assert_eq!(key.len(), 10);
    assert_eq!(iv.len(), 10);

    for (n, byte) in key.iter().enumerate() {
        for bit in 0..8 {
            s.a[n * 8 + bit] = (byte >> bit) & 1;
        }
    }
    for (n, byte) in iv.iter().enumerate() {
        for bit in 0..8 {
            s.b[n * 8 + bit] = (byte >> bit) & 1;
        }
    }

    (s.c[108], s.c[109], s.c[110]) = (1, 1, 1);

    for _ in 0..1153 {
        tick(&mut s);
    }
    s
}

fn tick(s: &mut TriviumState) -> u8 {
    let t1 = s.a[65] ^ s.a[92];
    let t2 = s.b[68] ^ s.b[83];
    let t3 = s.c[65] ^ s.c[110];

    let z = t1 ^ t2 ^ t3;

    let t1 = t1 ^ (s.a[90] & s.a[91]) ^ s.b[77];
    let t2 = t2 ^ (s.b[81] & s.b[82]) ^ s.c[86];
    let t3 = t3 ^ (s.c[108] & s.c[109]) ^ s.a[68];

    s.a.rotate_right(1);
    s.a[0] = t3;
    s.b.rotate_right(1);
    s.b[0] = t1;
    s.c.rotate_right(1);
    s.c[0] = t2;

    z
}

fn keystream_byte(state: &mut TriviumState) -> u8 {
    let mut byte: u8 = 0;
    for i in 0..8 {
        byte |= tick(state) << i;
    }
    byte
}
