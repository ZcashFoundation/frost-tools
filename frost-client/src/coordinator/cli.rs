use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use frost::{round1::SigningCommitments, Identifier, SigningPackage};
use frost_core::{self as frost, Ciphersuite, Signature};
use frost_rerandomized::RandomizedCiphersuite;
use itertools::izip;

use super::args::Args;
use super::args::ProcessedArgs;
use super::comms::cli::CLIComms;
use super::comms::Comms;

pub async fn cli<C: RandomizedCiphersuite + 'static>(
    args: &Args,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<Vec<Signature<C>>, Box<dyn std::error::Error>> {
    let pargs = ProcessedArgs::<C>::new(args, reader, logger)?;
    let mut comms = CLIComms::new(reader, logger);
    coordinator(&mut comms, pargs).await
}

pub async fn coordinator<C: RandomizedCiphersuite + 'static>(
    comms: &mut dyn Comms<C>,
    pargs: ProcessedArgs<C>,
) -> Result<Vec<Signature<C>>, Box<dyn std::error::Error>> {
    if !pargs.randomizers.is_empty() && pargs.randomizers.len() != pargs.messages.len() {
        return Err("Number of randomizers must match number of messages".into());
    }

    // We put the main logic on a block to be able to cleanup if an error is
    // returned anywhere in it.
    let doit = async {
        let commitments = comms
            .get_signing_commitments(
                &pargs.public_key_package,
                pargs.num_signers,
                pargs.messages.len(),
            )
            .await?;

        let signing_packages: Vec<_> = commitments
            .into_iter()
            .enumerate()
            .map(|(i, commitment)| SigningPackage::new(commitment, &pargs.messages[i]))
            .collect();

        let randomizers = if pargs.randomizers.is_empty() {
            None
        } else {
            Some(pargs.randomizers)
        };

        let signature_shares = comms
            .send_signing_package_and_get_signature_shares(
                &signing_packages,
                randomizers.as_deref(),
                pargs.aux_msg.clone(),
            )
            .await?;

        let signatures = if let Some(randomizers) = randomizers {
            let randomizer_params = randomizers
                .into_iter()
                .map(|randomizer| {
                    frost_rerandomized::RandomizedParams::<C>::from_randomizer(
                        pargs.public_key_package.verifying_key(),
                        randomizer,
                    )
                })
                .collect::<Vec<_>>();

            izip!(
                randomizer_params.iter(),
                signing_packages.iter(),
                signature_shares.iter()
            )
            .map(|(randomizer_param, signing_package, signature_share)| {
                frost_rerandomized::aggregate(
                    signing_package,
                    signature_share,
                    &pargs.public_key_package,
                    randomizer_param,
                )
                .unwrap()
            })
            .collect::<Vec<Signature<C>>>()
        } else {
            signing_packages
                .iter()
                .zip(signature_shares.iter())
                .map(|(signing_package, signature_share)| {
                    frost::aggregate::<C>(
                        signing_package,
                        signature_share,
                        &pargs.public_key_package,
                    )
                    .unwrap()
                })
                .collect::<Vec<Signature<C>>>()
        };

        comms.process_signature(&signatures).await?;

        Ok(signatures)
    };

    let r = doit.await;
    if r.is_err() {
        let _ = comms.cleanup_on_error().await;
    }
    r
}

pub fn build_signing_package<C: Ciphersuite>(
    args: &ProcessedArgs<C>,
    commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
) -> SigningPackage<C> {
    SigningPackage::new(commitments, &args.messages[0])
}
