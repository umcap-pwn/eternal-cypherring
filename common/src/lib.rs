#[repr(C)]
pub struct ConstBuffer {
    pub data: *const u8,
    pub size: usize,
}

#[repr(C)]
pub struct MutBuffer {
    pub data: *mut u8,
    pub size: usize,
}

#[repr(C)]
pub struct AlgorithmInfo {
    pub algorithm_name: *const u8,
    pub key_size: usize,
}

// AlgorithmInfo is a fully immutable so sharing is safe
unsafe impl Sync for AlgorithmInfo {}
