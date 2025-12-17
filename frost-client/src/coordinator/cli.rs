use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use frost::{round1::SigningCommitments, Identifier, SigningPackage};
use frost_core::{self as frost, Ciphersuite, Signature};
use frost_rerandomized::RandomizedCiphersuite;

use super::args::Args;
use super::args::ProcessedArgs;
use super::comms::cli::CLIComms;
use super::comms::Comms;
use super::round_1::get_commitments;
use super::round_2::send_signing_package_and_get_signature_shares;

pub async fn cli<C: RandomizedCiphersuite + 'static>(
    args: &Args,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<Signature<C>, Box<dyn std::error::Error>> {
    let pargs = ProcessedArgs::<C>::new(args, reader, logger)?;
    let mut comms = CLIComms::new(reader, logger);
    coordinator(&mut comms, pargs).await
}

pub async fn coordinator<C: RandomizedCiphersuite + 'static>(
    comms: &mut dyn Comms<C>,
    pargs: ProcessedArgs<C>,
) -> Result<Signature<C>, Box<dyn std::error::Error>> {
    if !pargs.randomizers.is_empty() && pargs.randomizers.len() != pargs.messages.len() {
        return Err("Number of randomizers must match number of messages".into());
    }

    let r = get_commitments(&pargs, &mut *comms).await;
    let Ok(participants_config) = r else {
        let _ = comms.cleanup_on_error().await;
        return Err(r.unwrap_err());
    };

    let signing_package = build_signing_package(&pargs, participants_config.commitments.clone());

    let r = send_signing_package_and_get_signature_shares(
        &pargs,
        &mut *comms,
        participants_config,
        &signing_package,
    )
    .await;

    match r {
        Ok(signature) => Ok(signature),
        Err(e) => {
            let _ = comms.cleanup_on_error().await;
            Err(e)
        }
    }
}

pub fn build_signing_package<C: Ciphersuite>(
    args: &ProcessedArgs<C>,
    commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
) -> SigningPackage<C> {
    SigningPackage::new(commitments, &args.messages[0])
}
