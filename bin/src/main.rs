
//
// Used modules
//

#[macro_use] extern crate failure;

use exitfailure::ExitFailure;
use failure::Error;
use keyring::Keyring;
use serde_json::Value;
use simple_secrets::Sender;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
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
        /// JSON input file to encrypt
        #[structopt(parse(from_os_str))]
        json_file: PathBuf,
    },

    /// Decrypt a websafe string into a JSON object
    #[structopt(name = "decrypt", author = "")]
    Decrypt {
        /// Text file to decrypt
        #[structopt(parse(from_os_str))]
        text_file: PathBuf
    }

}


fn main() -> Result<(), ExitFailure> {
    let app = App::from_args();
    let mut result = create_sender_from_env(app.env_name);
    if let (Some(key_name), Some(service_name)) = (app.key_account, app.key_service) {
        result = create_sender_from_keychain(service_name, key_name);
    }
    let sender = result?;
    match app.cmd {
        Command::Encrypt { json_file } => {
            let json = read_json(json_file)?;
            println!("{}", sender.pack(&json)?);
        },
        Command::Decrypt { text_file } => {
            let text = read_text(text_file)?;
            let value: Value = sender.unpack(text)?;
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
    }
    Ok(())
}


//
// Helpers
//

fn create_sender_from_env(name: String) -> Result<Sender, Error> {
    let val = env::var(&name);
    match val {
        Ok(value) => Ok(Sender::new(value)?),
        Err(err) => match err {
            env::VarError::NotPresent =>
                Err(AppError::MissingKeyName { name: name }.into()),
            env::VarError::NotUnicode(val) =>
                Err(AppError::InvalidKeyValue {
                    value: val.to_string_lossy().to_string(),
                    name: name
                }.into())
        }
    }
}

fn create_sender_from_keychain(service: String, account: String) -> Result<Sender, Error> {
    let keyring = Keyring::new(&service, &account);
    let password = keyring.get_password()?;
    Ok(Sender::new(password)?)
}

fn read_json(path: PathBuf) -> Result<Value, Error> {
    let contents = read_text(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn read_text(path: PathBuf) -> Result<String, Error> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}


//
// Errors
//

#[derive(Debug, Fail)]
enum AppError {
    #[fail(display = "The key is missing. Expected 256-bit hex value in environment variable {}.", name)]
    MissingKeyName {
        name: String,
    },
    #[fail(display = "The key is invalid. Expected 256-bit hex value, but found '{}' in {}.", value, name)]
    InvalidKeyValue {
        value: String,
        name: String
    },
}
