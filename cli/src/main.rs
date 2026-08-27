mod loader;
use getrandom;
use lexopt::Arg::*;
use lexopt::ValueExt;
use loader::*;
use std::error::Error;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::result;

use crate::KeySource::File;

struct Args {
    algorithm: String,
    mode: Mode,
    key_source: KeySource,
    input: DataSource,
    output: DataDest,
    save_key: Option<PathBuf>,
}

enum Mode {
    Encrypt,
    Decrypt,
    GenerateKey,
}

enum KeySource {
    File(PathBuf),
    Stdin,
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
        Mode::GenerateKey => generate_key(&args),
        Mode::Encrypt => run_crypto(&args, true),
        Mode::Decrypt => run_crypto(&args, false),
    }
}

fn generate_key(args: &Args) -> Result<(), Box<dyn Error>> {
    let cipher = loader::load_algorithm(&args.algorithm)?;
    let key_len = cipher.symbol::<usize>(b"key_size")?;
    let mut key = vec![0u8; *key_len];
    getrandom::fill(&mut key)?;
    if let Some(path) = &args.save_key {
        std::fs::write(path, key)?;
    }
    Ok(())
}

fn run_crypto(args: &Args, encrypt: bool) -> Result<(), Box<dyn Error>> {
    let cipher = loader::load_algorithm(&args.algorithm)?;
    let key = match &args.key_source {
        KeySource::File(path) => std::fs::read(path)?,
        KeySource::Stdin => {
            let key_len = cipher.key_size()?;
            let mut key = vec![0u8; key_len];
            std::io::stdin().read_exact(&mut key)?;
            key
        }
        KeySource::Generate => {
            let key_len = cipher.key_size()?;
            let mut key = vec![0u8; key_len];
            getrandom::fill(&mut key)?;
            key
        }
    };

    let input = match &args.input {
        DataSource::File(path) => std::fs::read(path)?,
        DataSource::Stdin => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input)?;
            input
        }
    };

    let res = if (encrypt) {
        cipher.encrypt(&key, &input)
    } else {
        cipher.decrypt(&key, &input)
    }?;

    match &args.output {
        DataDest::File(path) => std::fs::write(path, res)?,
        DataDest::Stdout => {
            std::io::stdout().write_all(&res)?;
        }
    };

    Ok(())
}

fn parse_args() -> Result<Option<Args>, lexopt::Error> {
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
                    _ => return Ok(None),
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
            _ => return Ok(None),
        };
    }

    let ret = Args {
        algorithm: algorithm.unwrap(),
        mode: mode.unwrap(),
        key_source: key_source.unwrap_or(KeySource::Stdin),
        input: input.unwrap_or(DataSource::Stdin),
        output: output.unwrap_or(DataDest::Stdout),
        save_key,
    };
    Ok(Some(ret))
}

fn validate(args: &Args) -> Result<(), String> {
    todo!()
}

fn print_help() {}
