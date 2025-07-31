use eyre::eyre;
use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::{self as frost, Ciphersuite, Identifier};

use crate::cipher::PublicKey;
use rand::thread_rng;
use reddsa::frost::redpallas::keys::EvenY;
use std::collections::HashMap;
use std::error::Error;
use std::io::{BufRead, Write};
use zeroize::Zeroizing;

use super::args::ProcessedArgs;
use super::comms::cli::CLIComms;
use super::comms::http::HTTPComms;
use super::comms::Comms;
use super::inputs::request_inputs;

// The redpallas ciphersuite, when used for generating Orchard spending key
// signatures, requires ensuring public key have an even Y coordinate. Since the
// code uses generics, this trait is used to convert if needed depending on the
// ciphersuite.
//
// If you are adding a new ciphersuite to this tool which does note require
// this, just implement it and the default implementation (which does nothing)
// will suffice. See below.
pub trait MaybeIntoEvenY: Ciphersuite {
    fn into_even_y(
        key_packages: (KeyPackage<Self>, PublicKeyPackage<Self>),
    ) -> (KeyPackage<Self>, PublicKeyPackage<Self>) {
        key_packages
    }
}

// A ciphersuite that does not need the conversion.
impl MaybeIntoEvenY for frost_ed25519::Ed25519Sha512 {}

impl MaybeIntoEvenY for frost_secp256k1_tr::Secp256K1Sha256TR {}

impl MaybeIntoEvenY for reddsa::frost::redpallas::PallasBlake2b512 {
    fn into_even_y(
        (key_package, public_key_package): (KeyPackage<Self>, PublicKeyPackage<Self>),
    ) -> (KeyPackage<Self>, PublicKeyPackage<Self>) {
        let is_even = public_key_package.has_even_y();
        (
            key_package.into_even_y(Some(is_even)),
            public_key_package.into_even_y(Some(is_even)),
        )
    }
}

pub async fn cli<C: Ciphersuite + 'static + MaybeIntoEvenY>(
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = request_inputs::<C>(reader, logger)?;
    let pargs = ProcessedArgs::<C>::new(&config);

    let (key_package, public_key_package, _) =
        cli_for_processed_args(pargs, reader, logger).await?;

    writeln!(
        logger,
        "Participant key package:\n\n{}\n",
        serde_json::to_string(&key_package)?,
    )?;
    writeln!(
        logger,
        "Participant public key package:\n\n{}\n",
        serde_json::to_string(&public_key_package)?,
    )?;

    Ok(())
}

pub async fn cli_for_processed_args<C: Ciphersuite + 'static + MaybeIntoEvenY>(
    pargs: ProcessedArgs<C>,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<
    (
        KeyPackage<C>,
        PublicKeyPackage<C>,
        HashMap<PublicKey, Identifier<C>>,
    ),
    Box<dyn Error>,
> {
    let mut comms: Box<dyn Comms<C>> = if pargs.cli {
        Box::new(CLIComms::new(&pargs))
    } else if pargs.http {
        Box::new(HTTPComms::new(&pargs)?)
    } else {
        return Err(eyre!("either --cli or --http must be specified").into());
    };

    // We put the main logic on a block to be able to cleanup if an error is
    // returned anywhere in it.
    let doit = async {
        let rng = thread_rng();

        let (identifier, max_signers) = comms.get_identifier_and_max_signers(input, logger).await?;

        let (round1_secret_package, round1_package) =
            frost::keys::dkg::part1(identifier, max_signers, pargs.min_signers, rng)?;

        let received_round1_packages = comms
            .get_round1_packages(input, logger, round1_package)
            .await?;

        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(round1_secret_package, &received_round1_packages)?;
        let round2_secret_package = Zeroizing::new(round2_secret_package);

        let received_round2_packages = comms
            .get_round2_packages(input, logger, round2_packages)
            .await?;

        let (key_package, public_key_package) =
            MaybeIntoEvenY::into_even_y(frost::keys::dkg::part3(
                &round2_secret_package,
                &received_round1_packages,
                &received_round2_packages,
            )?);

        let pubkey_map = comms.get_pubkey_identifier_map()?;
        Ok((key_package, public_key_package, pubkey_map))
    };

    let r = doit.await;
    if r.is_err() {
        let _ = comms.cleanup_on_error().await;
    }
    r
}
