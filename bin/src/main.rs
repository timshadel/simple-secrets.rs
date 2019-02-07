//
// Used modules
//

#[macro_use]
extern crate failure;

use exitfailure::ExitFailure;
use failure::Error;
use serde_json::Value as JsonValue;
use simple_secrets::Sender;
use std::io::prelude::*;
use structopt::StructOpt;

//
// App commands and options
//

#[derive(Debug, StructOpt)]
#[structopt(name = "secrets", author = "")]
struct App {
    /// Environment variable name containing the 256-bit key value in hex
    #[structopt(short = "e", long = "env", default_value = "SECRET_KEY")]
    env_name: String,

    /// Keychain service name containing the 256-bit key value in hex
    #[structopt(short = "s", long = "service")]
    key_service: Option<String>,

    /// Keychain account name containing the 256-bit key value in hex
    #[structopt(short = "a", long = "account")]
    key_account: Option<String>,

    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Encrypt a JSON file to a websafe string
    #[structopt(name = "encrypt", author = "")]
    Encrypt {
        /// Encrypt input bytes directly, without expecting JSON
        #[structopt(short = "r", long = "raw")]
        raw: bool,

        /// JSON input file to encrypt, "-" to read from STDIN
        #[structopt(name = "json_file")]
        input: String,
    },

    /// Decrypt a websafe string into a JSON object
    #[structopt(name = "decrypt", author = "")]
    Decrypt {
        /// Decrypt directly to raw bytes, without interpreting as JSON
        #[structopt(short = "r", long = "raw")]
        raw: bool,

        /// Text file to decrypt, "-" to read from STDIN
        #[structopt(name = "websafe_text_file")]
        input: String,
    },
}

fn main() -> Result<(), ExitFailure> {
    let app = App::from_args();
    let sender = create_sender_from_keychain(&app)
        .unwrap_or_else(|| create_sender_from_env(&app.env_name))?;
    match app.cmd {
        Command::Encrypt { raw, input } => {
            if raw {
                let mut bytes = read_bytes(input)?;
                println!("{}", sender.pack_raw(&mut bytes)?);
            } else {
                let json = read_json(input)?;
                println!("{}", sender.pack(&json)?);
            }
        }
        Command::Decrypt { raw, input } => {
            let text = read_text(input)?;
            let text = text.trim();
            if raw {
                let result = sender.unpack_raw(text)?;
                std::io::stdout().write(&result)?;
            } else {
                let json: JsonValue = sender.unpack(text)?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
        }
    }
    Ok(())
}

//
// Helpers
//

fn create_sender_from_env(name: &str) -> Result<Sender, Error> {
    use std::env::{var, VarError};
    match var(name) {
        Ok(value) => Ok(Sender::new(value)?),
        Err(VarError::NotPresent) => Err(AppError::MissingKeyName {
            name: name.to_owned(),
        }
        .into()),
        Err(VarError::NotUnicode(val)) => Err(AppError::InvalidKeyValue {
            value: val.to_string_lossy().to_string(),
            name: name.to_owned(),
        }
        .into()),
    }
}

fn create_sender_from_keychain(app: &App) -> Option<Result<Sender, Error>> {
    let service = app.key_service.as_ref()?;
    let account = app.key_account.as_ref()?;
    Some(
        keyring::Keyring::new(service, account)
            .get_password()
            .map_err(|e| AppError::KeyringError(e.to_string()).into())
            .and_then(|password| Ok(Sender::new(password)?)),
    )
}

fn read_json(path: String) -> Result<JsonValue, Error> {
    let contents = read_text(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn read_text(path: String) -> Result<String, Error> {
    let bytes = read_bytes(path)?;
    Ok(String::from_utf8(bytes)?)
}

fn read_bytes(path: String) -> Result<Vec<u8>, Error> {
    if path == "-" {
        let mut buffer = vec![];
        std::io::stdin().read_to_end(&mut buffer)?;
        return Ok(buffer);
    }

    let file_path = std::path::Path::new(&path);
    if file_path.exists() {
        return std::fs::read(file_path).map_err(|e| e.into());
    }

    // Try to decode the literal string passed
    return Ok(path.into());
}

//
// Errors
//

#[derive(Debug, Fail)]
enum AppError {
    #[fail(
        display = "The key is missing. Expected 256-bit hex value in environment variable {}.",
        name
    )]
    MissingKeyName { name: String },

    #[fail(
        display = "The key is invalid. Expected 256-bit hex value, but found '{}' in {}.",
        value, name
    )]
    InvalidKeyValue { value: String, name: String },

    #[fail(display = "{}", 0)]
    KeyringError(String),
}
