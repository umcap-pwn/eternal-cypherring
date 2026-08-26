// mod loader;
use lexopt::Arg::*;
use lexopt::ValueExt;
use std::path::PathBuf;

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
        }
        Ok(None) => print_help(),
        Ok(Some(args)) => todo!(),
    }
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
