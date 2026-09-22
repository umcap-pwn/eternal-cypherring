use getrandom;
use lexopt::Arg::*;
use lexopt::ValueExt;
use loader::Cipher;
use std::error::Error;
use std::io::IsTerminal;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

struct Args {
    algorithm: String,
    mode: Mode,
    key_source: KeySource,
    input: DataSource,
    output: DataDest,
    save_key: Option<PathBuf>,
}

#[derive(PartialEq, Eq)]
enum Mode {
    Encrypt,
    Decrypt,
    GenerateKey,
}

enum KeySource {
    File(PathBuf),
    Generate,
}

enum DataSource {
    File(PathBuf),
    Stdin,
}

enum DataDest {
    File(PathBuf),
    Stdout,
}

fn main() {
    match parse_args() {
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
        Ok(None) => print_help(),
        Ok(Some(args)) => {
            if let Err(e) = dispatch(args) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn dispatch(args: Args) -> Result<(), Box<dyn Error>> {
    match args.mode {
        Mode::GenerateKey => {
            let cipher = loader::load_algorithm(&args.algorithm)?;
            let key = generate_key(&cipher)?;
            write_key(&args, &key)?;
            Ok(())
        }
        Mode::Encrypt => run_crypto(&args, true),
        Mode::Decrypt => run_crypto(&args, false),
    }
}

fn write_key(args: &Args, key: &[u8]) -> Result<(), Box<dyn Error>> {
    match &args.save_key {
        Some(path) => std::fs::write(path, key)?,
        None => return Err("no key output file; use --save-key <FILE>".into()),
    }
    Ok(())
}

fn generate_key(cipher: &Cipher) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut key = vec![0u8; cipher.key_size()?];
    getrandom::fill(&mut key)?;
    Ok(key)
}

fn run_crypto(args: &Args, encrypt: bool) -> Result<(), Box<dyn Error>> {
    let cipher = loader::load_algorithm(&args.algorithm)?;

    let input = match &args.input {
        DataSource::File(path) => std::fs::read(path)?,
        DataSource::Stdin => {
            let action = if encrypt { "encrypt" } else { "decrypt" };
            println!("Enter text to {action}, then press ^D to continue: ");
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input)?;
            input
        }
    };

    let key_size = cipher.key_size()?;
    let key = match &args.key_source {
        KeySource::File(path) => std::fs::read(path)?,
        KeySource::Generate => {
            let t = generate_key(&cipher)?;
            write_key(args, &t)?;
            t
        }
    };
    if key.len() != key_size {
        return Err(format!("provided key is {} bytes, expected {key_size}", key.len()).into());
    }

    let res = if encrypt {
        cipher.encrypt(&key, &input)
    } else {
        cipher.decrypt(&key, &input)
    }?;

    match &args.output {
        DataDest::File(path) => std::fs::write(path, res)?,
        DataDest::Stdout => write_stdout(&args, &res)?,
    };

    Ok(())
}

fn parse_args() -> Result<Option<Args>, Box<dyn Error>> {
    let mut parser = lexopt::Parser::from_env();

    let mut algorithm: Option<String> = None;
    let mut mode: Option<Mode> = None;
    let mut key_source: Option<KeySource> = None;
    let mut input: Option<DataSource> = None;
    let mut output: Option<DataDest> = None;
    let mut save_key: Option<PathBuf> = None;

    while let Some(arg) = parser.next()? {
        match arg {
            Long("help") | Short('h') => return Ok(None),
            Long("algorithm") | Short('a') => {
                algorithm = Some(parser.value()?.parse()?);
            }
            Long("mode") | Short('m') => {
                mode = Some(match parser.value()?.to_str() {
                    Some("encrypt") => Mode::Encrypt,
                    Some("decrypt") => Mode::Decrypt,
                    Some("gen-key") => Mode::GenerateKey,
                    _ => return Err("--mode must be one of: encrypt, decrypt, gen-key".into()),
                })
            }
            Long("key") | Short('k') => {
                key_source = Some(KeySource::File(parser.value()?.parse()?));
            }
            Long("input") | Short('i') => {
                input = Some(DataSource::File(parser.value()?.parse()?));
            }
            Long("output") | Short('o') => {
                output = Some(DataDest::File(parser.value()?.parse()?));
            }
            Long("save-key") | Short('s') => {
                save_key = Some(parser.value()?.parse()?);
            }
            other => return Err(other.unexpected().into()),
        };
    }

    let algorithm = algorithm.ok_or("missing required option --algorithm")?;
    let mode = mode.ok_or("missing required option --mode")?;

    let ret = Args {
        algorithm: algorithm,
        mode: mode,
        key_source: key_source.unwrap_or(KeySource::Generate),
        input: input.unwrap_or(DataSource::Stdin),
        output: output.unwrap_or(DataDest::Stdout),
        save_key: save_key,
    };
    validate(&ret)?;
    Ok(Some(ret))
}

fn validate(args: &Args) -> Result<(), String> {
    if args.algorithm.is_empty() {
        return Err("--algorithm must not be empty".to_string());
    }

    match &args.mode {
        Mode::GenerateKey => {
            if args.save_key.is_none() {
                return Err("--mode gen-key requires --save-key <FILE>".to_string());
            }
        }
        Mode::Encrypt | Mode::Decrypt => {
            if let KeySource::Generate = &args.key_source {
                if args.save_key.is_none() {
                    return Err("--save-key <FILE> is required when generating a key".to_string());
                }
            }
        }
    }

    Ok(())
}

fn print_help() {
    println!(
        "\
eternal-cypherring — educational stream cipher CLI

Usage:
etc -a <ALGORITHM> -m <MODE> [OPTIONS]

Options:
    -a, --algorithm <ALGORITHM>   Cipher to use: rc4, trivium, hc128
    -m, --mode <MODE>             Mode: encrypt, decrypt, gen-key
    -k, --key <FILE>              Read key from FILE (default: generate one)
    -i, --input <FILE>            Read input from FILE (default: stdin)
    -o, --output <FILE>           Write output to FILE (default: stdout)
    -s, --save-key <FILE>         Write generated key to FILE (required when generating)
    -h, --help                    Show this help

Examples:
    etc -a rc4 -m gen-key -s key.bin
    etc -a rc4 -m encrypt -k key.bin -i plain.txt -o cipher.bin
    etc -a rc4 -m decrypt -k key.bin -i cipher.bin -o plain.dec
"
    )
}

fn write_stdout(args: &Args, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let stdout = std::io::stdout();
    if stdout.is_terminal() && !(args.mode == Mode::Decrypt) {
        return Err("refusing to write binary data to a terminal; use -o FILE or redirect".into());
    }

    stdout.lock().write_all(data)?;
    Ok(())
}
