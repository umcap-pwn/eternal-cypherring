use std::error::Error;
use std::ffi::{CStr, c_char};
use std::path::{Path, PathBuf};

use libloading::{Library, Symbol};

use common::{AlgorithmInfo, ConstBuffer, MutBuffer};

type GetOutputSizeFn = unsafe extern "C" fn(usize, i32) -> usize;
type GetAlgorithmInfoFn = unsafe extern "C" fn() -> *const AlgorithmInfo;
type CryptFn = unsafe extern "C" fn(ConstBuffer, ConstBuffer, *mut MutBuffer) -> i32;

const OP_ENCRYPT: i32 = 0;
const OP_DECRYPT: i32 = 1;

pub struct Cipher {
    library: Library,
}

impl Cipher {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        let path = path.as_ref().canonicalize()?;
        let library = unsafe { Library::new(path.as_os_str())? };

        unsafe {
            library.get::<GetOutputSizeFn>(b"get_output_size")?;
            library.get::<GetAlgorithmInfoFn>(b"get_algorithm_info")?;
            library.get::<CryptFn>(b"encrypt")?;
            library.get::<CryptFn>(b"decrypt")?;
        }

        Ok(Self { library })
    }

    pub fn algorithm_name(&self) -> Result<String, Box<dyn Error>> {
        let info = self.info()?;
        if info.algorithm_name.is_null() {
            return Err("algorithm_name is null".into());
        }

        let name = unsafe { CStr::from_ptr(info.algorithm_name.cast::<c_char>()) };
        Ok(name.to_string_lossy().into_owned())
    }

    pub fn key_size(&self) -> Result<usize, Box<dyn Error>> {
        Ok(self.info()?.key_size)
    }

    pub fn output_size(&self, input_size: usize, operation: i32) -> Result<usize, Box<dyn Error>> {
        let get_output_size = self.symbol::<GetOutputSizeFn>(b"get_output_size")?;
        Ok(unsafe { (*get_output_size)(input_size, operation) })
    }

    pub fn encrypt(&self, key: &[u8], input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.run(key, input, OP_ENCRYPT, "encrypt")
    }

    pub fn decrypt(&self, key: &[u8], input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.run(key, input, OP_DECRYPT, "decrypt")
    }

    fn info(&self) -> Result<AlgorithmInfo, Box<dyn Error>> {
        let get_info = self.symbol::<GetAlgorithmInfoFn>(b"get_algorithm_info")?;
        let ptr = unsafe { (*get_info)() };

        if ptr.is_null() {
            return Err("get_algorithm_info returned a null pointer".into());
        }

        Ok(unsafe { ptr.read() })
    }

    fn run(
        &self,
        key: &[u8],
        input: &[u8],
        operation: i32,
        name: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let out_len = self.output_size(input.len(), operation)?;
        let mut output = vec![0u8; out_len];

        let mut out_buffer = MutBuffer {
            data: output.as_mut_ptr(),
            size: output.len(),
        };
        let key_buffer = ConstBuffer {
            data: key.as_ptr(),
            size: key.len(),
        };
        let input_buffer = ConstBuffer {
            data: input.as_ptr(),
            size: input.len(),
        };

        let f = self.symbol::<CryptFn>(name.as_bytes())?;
        let code = unsafe { (*f)(key_buffer, input_buffer, &mut out_buffer) };

        if code != 0 {
            return Err(format!("{name} returned error code {code}").into());
        }

        output.truncate(out_buffer.size);
        Ok(output)
    }

    pub fn symbol<T: Copy>(&self, name: &[u8]) -> Result<Symbol<'_, T>, Box<dyn Error>> {
        let symbol = unsafe { self.library.get::<T>(name)? };
        Ok(symbol)
    }
}

pub fn load_algorithm(name: &str) -> Result<Cipher, Box<dyn Error>> {
    let direct = Path::new(name);
    if direct.is_file() {
        return Cipher::load(direct);
    }

    let filename = library_filename(name);
    let mut candidates = vec![PathBuf::from(&filename)];
    candidates.push(PathBuf::from("target/debug").join(&filename));
    candidates.push(PathBuf::from("target/release").join(&filename));

    // Locate libraries next to the running executable as well, so the CLI and
    // the test harness do not depend on the current working directory.
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join(&filename));
        if let Some(parent) = dir.parent() {
            candidates.push(parent.join(&filename));
        }
    }

    for path in candidates {
        if path.is_file() {
            return Cipher::load(path);
        }
    }

    Err(format!("cipher library '{name}' not found").into())
}

fn library_filename(name: &str) -> String {
    use std::env::consts::{DLL_PREFIX, DLL_SUFFIX};

    if name.ends_with(DLL_SUFFIX) {
        return name.to_string();
    }

    format!("{DLL_PREFIX}{name}{DLL_SUFFIX}")
}
