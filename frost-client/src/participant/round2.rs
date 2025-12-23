use crate::api::SendSigningPackageArgs;
use frost_core::{self as frost, Ciphersuite};

use super::comms::Comms;
use frost::{
    keys::KeyPackage,
    round1::{SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Error, Identifier, SigningPackage,
};
use std::io::{BufRead, Write};

#[derive(Clone)]
pub struct Round2Config<C: Ciphersuite> {
    pub signing_package: SigningPackage<C>,
    pub randomizer: Option<frost_rerandomized::Randomizer<C>>,
}

// TODO: refactor to generate config
// TODO: handle errors
pub async fn round_2_request_inputs<C: Ciphersuite>(
    comms: &mut dyn Comms<C>,
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    commitments: SigningCommitments<C>,
    identifier: Identifier<C>,
    rerandomized: bool,
) -> Result<SendSigningPackageArgs<C>, Box<dyn std::error::Error>> {
    comms
        .get_signing_package(input, logger, &[commitments], identifier, rerandomized)
        .await
}

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
