use std::{ptr::swap, slice};

use common::*;

const RC4_IV_SIZE: usize = 16;
const S_BOX_SIZE: usize = 256;

#[unsafe(no_mangle)] // Safe to use; no edgecases
pub extern "C" fn get_output_size(input_size: usize, _operation_type: i32) -> usize {
    input_size + RC4_IV_SIZE
}

#[unsafe(no_mangle)]
/// Do not mutate the `algorithm_name` field as it is immutable. Safe otherwise
pub extern "C" fn get_algorithm_info() -> *const AlgorithmInfo {
    static NAME: &[u8] = b"rc4\0";
    static INFO: AlgorithmInfo = AlgorithmInfo {
        algorithm_name: NAME.as_ptr(),
        key_size: 32,
    };
    &INFO
}

#[unsafe(no_mangle)]
/// All buffers must contain valid non-null pointers and actual buffer sizes.
/// Output must be at least `get_output_size(input.size)` bytes long
pub extern "C" fn encrypt(key: ConstBuffer, input: ConstBuffer, output: *mut MutBuffer) -> i32 {
    let data: &[u8] = unsafe { slice::from_raw_parts(input.data, input.size) };
    let key: &[u8] = unsafe { slice::from_raw_parts(input.data, input.size) };
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt);
    let temp = [&mut salt, key].concat();
    let mut S = ksa(&temp);
    let result = prga(&mut S, data);
    unsafe {
        let out = &mut *output;
        std::ptr::copy_nonoverlapping(result.as_ptr(), out.data, result.len());
        out.size = result.len();
    }
    0
}

fn ksa(key: &[u8]) -> [u8; S_BOX_SIZE] {
    let mut s: [u8; S_BOX_SIZE] = std::array::from_fn(|i| i as u8);
    let mut j: usize = 0;
    for i in 0..S_BOX_SIZE {
        j = (j + s[i] as usize + key[i % key.len()] as usize & S_BOX_SIZE);
        s.swap(i, j);
    }
    s
}

fn prga(s: &mut [u8; S_BOX_SIZE], data: &[u8]) -> Vec<u8> {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut res = Vec::<u8>::new();
    for byte in data {
        i = (i + 1) % S_BOX_SIZE;
        j = (j + s[i] as usize) % S_BOX_SIZE;
        s.swap(i, j);
        let t = (s[i] as usize + s[j] as usize) % 256;
        res.push(byte ^ s[t]);
    }
    res
}
