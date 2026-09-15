use common::*;
use getrandom;
use std::slice;

const KEY_SIZE: usize = 16;
const IV_SIZE: usize = 16;

struct Hc128State {
    p: [u32; 512],
    q: [u32; 512],
    counter: usize,
}

impl Hc128State {
    fn new() -> Self {
        Self {
            p: [0; 512],
            q: [0; 512],
            counter: 0,
        }
    }
}

fn idx(i: usize, offset: usize) -> usize {
    (i + 512 - offset) & 511
}

fn f1(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn f2(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

fn g1(x: u32, y: u32, z: u32) -> u32 {
    (x.rotate_right(10) ^ z.rotate_right(23)).wrapping_add(y.rotate_right(8))
}

fn g2(x: u32, y: u32, z: u32) -> u32 {
    (x.rotate_left(10) ^ z.rotate_left(23)).wrapping_add(y.rotate_left(8))
}

fn h1(q: &[u32; 512], x: u32) -> u32 {
    let x0 = (x & 0xff) as usize;
    let x2 = ((x >> 16) & 0xff) as usize;

    q[x0].wrapping_add(q[256 + x2])
}

fn h2(p: &[u32; 512], x: u32) -> u32 {
    let x0 = (x & 0xff) as usize;
    let x2 = ((x >> 16) & 0xff) as usize;

    p[x0].wrapping_add(p[256 + x2])
}

fn hc128_init(state: &mut Hc128State, key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE]) {
    let mut w = [0u32; 1280];

    for i in 0..4 {
        let k = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
        let v = u32::from_le_bytes(iv[4 * i..4 * i + 4].try_into().unwrap());

        w[i] = k;
        w[4 + i] = k;
        w[8 + i] = v;
        w[12 + i] = v;
    }

    for i in 16..1280 {
        w[i] = f2(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(f1(w[i - 15]))
            .wrapping_add(w[i - 16])
            .wrapping_add(i as u32);
    }

    state.p.copy_from_slice(&w[256..768]);
    state.q.copy_from_slice(&w[768..1280]);
    state.counter = 0;

    for _ in 0..1024 {
        hc128_warmup_step(state);
    }
}

/// Runs the cipher 1024 steps without producing keystream: the outputs are
/// folded back into P and Q.
fn hc128_warmup_step(state: &mut Hc128State) {
    let j = state.counter & 511;

    if state.counter < 512 {
        let x = state.p[idx(j, 3)];
        let y = state.p[idx(j, 10)];
        let z = state.p[idx(j, 511)];
        let h = h1(&state.q, state.p[idx(j, 12)]);

        state.p[j] = state.p[j].wrapping_add(g1(x, y, z)) ^ h;
    } else {
        let x = state.q[idx(j, 3)];
        let y = state.q[idx(j, 10)];
        let z = state.q[idx(j, 511)];
        let h = h2(&state.p, state.q[idx(j, 12)]);

        state.q[j] = state.q[j].wrapping_add(g2(x, y, z)) ^ h;
    }

    state.counter = (state.counter + 1) & 1023;
}

fn hc128_step(state: &mut Hc128State) -> u32 {
    let j = state.counter & 511;

    let output = if state.counter < 512 {
        let x = state.p[idx(j, 3)];
        let y = state.p[idx(j, 10)];
        let z = state.p[idx(j, 511)];

        state.p[j] = state.p[j].wrapping_add(g1(x, y, z));

        h1(&state.q, state.p[idx(j, 12)]) ^ state.p[j]
    } else {
        let x = state.q[idx(j, 3)];
        let y = state.q[idx(j, 10)];
        let z = state.q[idx(j, 511)];

        state.q[j] = state.q[j].wrapping_add(g2(x, y, z));

        h2(&state.p, state.q[idx(j, 12)]) ^ state.q[j]
    };

    state.counter = (state.counter + 1) & 1023;

    output
}

fn hc128_process(state: &mut Hc128State, data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut word = 0u32;
    let mut remaining = 0;

    for &byte in data {
        if remaining == 0 {
            word = hc128_step(state);
            remaining = 4;
        }

        result.push(byte ^ word as u8);
        word >>= 8;
        remaining -= 1;
    }

    result
}

#[unsafe(no_mangle)] // Safe to use; no edgecases
pub extern "C" fn get_output_size(input_size: usize, operation_type: i32) -> usize {
    match operation_type {
        0 => input_size + IV_SIZE,
        _ => input_size.saturating_sub(IV_SIZE),
    }
}

#[unsafe(no_mangle)]
/// Do not mutate the `algorithm_name` field as it is immutable. Safe otherwise
pub extern "C" fn get_algorithm_info() -> *const AlgorithmInfo {
    static NAME: &[u8] = b"hc128\0";
    static INFO: AlgorithmInfo = AlgorithmInfo {
        algorithm_name: NAME.as_ptr(),
        key_size: KEY_SIZE,
    };
    &INFO
}

/// All buffers must contain valid non-null pointers and actual buffer sizes.
/// Output must be at least `get_output_size(input.size, 0)` bytes long
#[unsafe(no_mangle)]
pub unsafe extern "C" fn encrypt(
    key: ConstBuffer,
    input: ConstBuffer,
    output: *mut MutBuffer,
) -> i32 {
    let data: &[u8] = unsafe { slice::from_raw_parts(input.data, input.size) };
    let key: &[u8; KEY_SIZE] = unsafe { slice::from_raw_parts(key.data, key.size) }
        .try_into()
        .expect("invalid key size");

    let mut iv = [0u8; IV_SIZE];
    getrandom::fill(&mut iv).expect("Error getting random value");

    let mut state = Hc128State::new();
    hc128_init(&mut state, key, &iv);
    let result: Vec<u8> = hc128_process(&mut state, data);

    let mut full: Vec<u8> = Vec::with_capacity(result.len() + IV_SIZE);
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
/// Output must be at least `get_output_size(input.size, 1)` bytes long
#[unsafe(no_mangle)]
pub unsafe extern "C" fn decrypt(
    key: ConstBuffer,
    input: ConstBuffer,
    output: *mut MutBuffer,
) -> i32 {
    if input.size < IV_SIZE {
        return 1;
    }

    let iv: &[u8; IV_SIZE] = unsafe { slice::from_raw_parts(input.data, IV_SIZE) }
        .try_into()
        .expect("invalid IV size");
    let data: &[u8] =
        unsafe { slice::from_raw_parts(input.data.add(IV_SIZE), input.size - IV_SIZE) };
    let key: &[u8; KEY_SIZE] = unsafe { slice::from_raw_parts(key.data, key.size) }
        .try_into()
        .expect("invalid key size");

    let mut state = Hc128State::new();
    hc128_init(&mut state, key, iv);
    let result: Vec<u8> = hc128_process(&mut state, data);

    unsafe {
        let out = &mut *output;
        std::ptr::copy_nonoverlapping(result.as_ptr(), out.data, result.len());
        out.size = result.len();
    }
    0
}
