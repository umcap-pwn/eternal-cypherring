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

fn ksa(key: &[u8]) -> [u8; S_BOX_SIZE] {
    let mut s: [u8; S_BOX_SIZE] = std::array::from_fn(|i| i as u8);
    let mut j: usize = 0;
    for i in 0..S_BOX_SIZE {
        j = (j + s[i] as usize + key[i % key.len()] as usize & S_BOX_SIZE);
        s.swap(i, j);
    }
    s
}
