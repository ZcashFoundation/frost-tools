use frost_core::{self as frost, Ciphersuite};

use frost::keys::{PublicKeyPackage, SecretShare};
use frost::Error;
use frost::Identifier;
use itertools::Itertools;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, Write};

use super::args::Args;

#[derive(Debug, PartialEq, Clone)]
pub struct Config {
    pub min_signers: u16,
    pub max_signers: u16,
    pub secret: Vec<u8>,
}

fn validate_inputs<C: Ciphersuite>(config: &Config) -> Result<(), Error<C>> {
    if config.min_signers < 2 {
        return Err(Error::<C>::InvalidMinSigners);
    }

    if config.max_signers < 2 {
        return Err(Error::<C>::InvalidMaxSigners);
    }

    if config.min_signers > config.max_signers {
        return Err(Error::<C>::InvalidMinSigners);
    }

    Ok(())
}

pub fn request_inputs<C: Ciphersuite + 'static>(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<Config, Box<dyn std::error::Error>> {
    let config = if args.cli {
        writeln!(logger, "The minimum number of signers: (2 or more)")?;

        let mut min = String::new();
        input.read_line(&mut min)?;

        let min_signers = min
            .trim()
            .parse::<u16>()
            .map_err(|_| Error::<C>::InvalidMinSigners)?;

        writeln!(logger, "The maximum number of signers: ")?;

        let mut max = String::new();
        input.read_line(&mut max)?;
        let max_signers = max
            .trim()
            .parse::<u16>()
            .map_err(|_| Error::<C>::InvalidMaxSigners)?;

        writeln!(
            logger,
            "Secret key (press enter to randomly generate a fresh one): "
        )?;

        let mut secret_input = String::new();
        input.read_line(&mut secret_input)?;
        let secret =
            hex::decode(secret_input.trim()).map_err(|_| Error::<C>::MalformedSigningKey)?;

        Config {
            min_signers,
            max_signers,
            secret,
        }
    } else {
        let secret = hex::decode(args.key.clone().unwrap_or("".to_string()))
            .map_err(|_| Error::<C>::MalformedSigningKey)?;
        eprintln!(
            "Generating {} shares with threshold {}...",
            args.num_signers, args.threshold
        );
        Config {
            min_signers: args.threshold,
            max_signers: args.num_signers,
            secret,
        }
    };

    validate_inputs::<C>(&config)?;

    Ok(config)
}

pub fn print_values<C: Ciphersuite>(
    args: &Args,
    keys: &BTreeMap<Identifier<C>, SecretShare<C>>,
    pubkeys: &PublicKeyPackage<C>,
    logger: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.cli {
        writeln!(
            logger,
            "Public key package:\n{}",
            serde_json::to_string(pubkeys)?
        )?;

        for (k, v) in keys.iter().sorted_by_key(|x| x.0) {
            writeln!(logger, "Participant: {}", hex::encode(k.serialize()))?;
            writeln!(
                logger,
                "Secret share:\n{}",
                serde_json::to_string(v).unwrap()
            )?;
        }
    } else {
        fs::write(&args.public_key_package, serde_json::to_vec(pubkeys)?)?;
        eprintln!("Public key package written to {}", args.public_key_package);

        for (i, (k, v)) in keys.iter().sorted_by_key(|x| x.0).enumerate() {
            let path = str::replace(&args.key_package, "{}", format!("{}", i + 1).as_str());
            fs::write(&path, serde_json::to_vec(v)?)?;
            eprintln!(
                "Key package for participant {} written to {}",
                hex::encode(k.serialize()),
                path
            );
        }
    }

    Ok(())
}
