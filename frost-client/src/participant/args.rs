// Remove after https://github.com/rust-lang/rust/issues/147648 is fixed
#![allow(unused_assignments)]

use std::{
    env,
    error::Error,
    io::{BufRead, Write},
};

use clap::Parser;
use eyre::eyre;
use frost_core::{
    keys::{KeyPackage, SecretShare},
    Ciphersuite,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::input::read_from_file_or_stdin;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short = 'C', long, default_value = "ed25519")]
    pub ciphersuite: String,

    /// CLI mode. If enabled, it will prompt for inputs from stdin
    /// and print values to stdout, ignoring other flags.
    /// If false, socket communication is enabled.
    #[arg(long, default_value_t = false)]
    pub cli: bool,

    /// Public key package to use. Can be a file with a JSON-encoded
    /// package, or "". If the file does not exist or if "" is specified,
    /// then it will be read from standard input.
    #[arg(short = 'k', long, default_value = "key-package-1.json")]
    pub key_package: String,

    /// IP to connect to, if using online comms
    #[arg(short, long, default_value = "127.0.0.1")]
    pub ip: String,

    /// Port to connect to, if using online comms
    #[arg(short, long, default_value_t = 443)]
    pub port: u16,

    /// Optional Session ID
    #[arg(short, long, default_value = "")]
    pub session_id: String,
}

#[derive(Clone, Zeroize)]
pub struct ProcessedArgs<C: Ciphersuite> {
    /// Key package to use.
    pub key_package: KeyPackage<C>,
}

impl<C> ZeroizeOnDrop for ProcessedArgs<C> where C: Ciphersuite {}

impl<C: Ciphersuite + 'static> ProcessedArgs<C> {
    /// Create a ProcessedArgs from a Args.
    ///
    /// Validates inputs and reads/parses arguments.
    pub fn new(
        args: &Args,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
    ) -> Result<Self, Box<dyn Error>> {
        let bytes = read_from_file_or_stdin(input, output, "key package", &args.key_package)?;

        let key_package = if let Ok(secret_share) = serde_json::from_str::<SecretShare<C>>(&bytes) {
            KeyPackage::try_from(secret_share)?
        } else {
            // TODO: Improve error
            serde_json::from_str::<KeyPackage<C>>(&bytes)?
        };

        Ok(ProcessedArgs { key_package })
    }
}

pub fn read_password(password_env_name: &str) -> Result<String, Box<dyn Error>> {
    if password_env_name.is_empty() {
        Ok(
            rpassword::prompt_password("Password: ")
                .map_err(|_| eyre!("Error reading password"))?,
        )
    } else {
        Ok(env::var(password_env_name).map_err(|_| eyre!("The password argument must specify the name of a environment variable containing the password"))?)
    }
}
