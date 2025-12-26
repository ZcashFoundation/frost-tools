use super::args::{Args, ProcessedArgs};

use super::comms::cli::CLIComms;

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

// Use implementations from participant::round2

pub async fn cli<C: RandomizedCiphersuite + 'static>(
    args: &Args,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let pargs = ProcessedArgs::<C>::new(args, reader, logger)?;
    let mut comms = CLIComms::new(reader, logger);
    participant(&mut comms, pargs).await
}

pub async fn participant<C: RandomizedCiphersuite + 'static>(
    comms: &mut dyn Comms<C>,
    pargs: ProcessedArgs<C>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Round 1

    let key_package = &pargs.key_package;

    let message_count = comms.get_message_count().await?;

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
        .get_signing_package(&commitments, *key_package.identifier(), rerandomized)
        .await?;

    comms.confirm_message(&round_2_config).await?;

    let signatures = generate_signature(round_2_config, key_package, &nonces)?;

    comms
        .send_signature_share(*key_package.identifier(), &signatures)
        .await?;

    Ok(())
}
