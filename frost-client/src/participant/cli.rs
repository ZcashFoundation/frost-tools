use super::args::{Args, ProcessedArgs};

use super::comms::cli::CLIComms;
use super::comms::http::HTTPComms;
use super::comms::socket::SocketComms;

use super::comms::Comms;

use crate::api::SendSigningPackageArgs;
use frost_core::Ciphersuite;
use frost_core::{self as frost};
use frost_core::{
    keys::KeyPackage,
    round1::SigningNonces,
    round2::{self, SignatureShare},
    Error,
};
use frost_ed25519::Ed25519Sha512;
use frost_rerandomized::RandomizedCiphersuite;
use rand::thread_rng;
use reddsa::frost::redpallas::PallasBlake2b512;
use std::io::{BufRead, Write};
use zeroize::Zeroizing;

pub fn generate_signature<C: frost_rerandomized::RandomizedCiphersuite>(
    config: SendSigningPackageArgs<C>,
    key_package: &KeyPackage<C>,
    signing_nonces: &[SigningNonces<C>],
) -> Result<Vec<SignatureShare<C>>, Error<C>> {
    let signatures = config
        .signing_package
        .iter()
        .zip(signing_nonces.iter())
        .map(|(signing_package, signing_nonces)| {
            if !config.randomizer.is_empty() {
                frost_rerandomized::sign::<C>(
                    signing_package,
                    signing_nonces,
                    key_package,
                    config.randomizer[0],
                )
            } else {
                round2::sign(signing_package, signing_nonces, key_package)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(signatures)
}

pub fn print_values_round_2<C: Ciphersuite>(
    signature: SignatureShare<C>,
    logger: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(logger, "Please send the following to the Coordinator")?;
    writeln!(
        logger,
        "SignatureShare:\n{}",
        serde_json::to_string(&signature).unwrap()
    )?;

    Ok(())
}

pub async fn cli<C: RandomizedCiphersuite + 'static>(
    args: &Args,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let pargs = ProcessedArgs::<C>::new(args, reader, logger)?;
    cli_for_processed_args(pargs, reader, logger).await
}

pub async fn cli_for_processed_args<C: RandomizedCiphersuite + 'static>(
    pargs: ProcessedArgs<C>,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut comms: Box<dyn Comms<C>> = if pargs.cli {
        Box::new(CLIComms::new())
    } else if pargs.http {
        Box::new(HTTPComms::new(&pargs)?)
    } else {
        Box::new(SocketComms::new(&pargs))
    };

    // Round 1

    let key_package = &pargs.key_package;

    let message_count = comms.get_message_count(input, logger).await?;

    let mut rng = thread_rng();
    let (nonces, commitments): (Vec<_>, Vec<_>) = (0..message_count)
        .map(|_| frost::round1::commit(key_package.signing_share(), &mut rng))
        .unzip();
    let nonces = Zeroizing::new(nonces);

    // Round 2 - Sign

    let rerandomized = if C::ID == Ed25519Sha512::ID {
        false
    } else if C::ID == PallasBlake2b512::ID {
        true
    } else {
        panic!("invalid ciphersuite");
    };

    let round_2_config = comms
        .get_signing_package(
            input,
            logger,
            &commitments,
            *key_package.identifier(),
            rerandomized,
        )
        .await?;

    comms
        .confirm_message(input, logger, &round_2_config)
        .await?;

    let signatures = generate_signature(round_2_config, key_package, &nonces)?;

    comms
        .send_signature_share(*key_package.identifier(), &signatures)
        .await?;

    if pargs.cli {
        for signature in &signatures {
            print_values_round_2(*signature, logger)?;
        }
    }
    writeln!(logger, "Done")?;

    Ok(())
}
