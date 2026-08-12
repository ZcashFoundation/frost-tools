//! Command line interface implementation of the Comms trait.

use frost_core as frost;

use frost_core::Ciphersuite;

use async_trait::async_trait;

use crate::api::{self, SendSigningPackageArgs};
use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};

use std::{
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
};

use super::Comms;

pub fn print_values<C: Ciphersuite>(
    commitments: SigningCommitments<C>,
    logger: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(logger, "=== Round 1 ===")?;
    writeln!(logger, "SigningNonces were generated and stored in memory")?;
    writeln!(
        logger,
        "SigningCommitments:\n{}",
        serde_json::to_string(&commitments).unwrap(),
    )?;
    writeln!(logger, "=== Round 1 Completed ===")?;
    writeln!(
        logger,
        "Please send your SigningCommitments to the coordinator"
    )?;

    Ok(())
}

#[derive(Default)]
pub struct CLIComms<C: Ciphersuite> {
    _phantom: PhantomData<C>,
}

impl<C> CLIComms<C>
where
    C: Ciphersuite,
{
    pub fn new() -> Self {
        Self {
            _phantom: Default::default(),
        }
    }
}

#[async_trait(?Send)]
impl<C> Comms<C> for CLIComms<C>
where
    C: Ciphersuite + 'static,
{
    async fn get_message_count(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
    ) -> Result<u8, Box<dyn Error>> {
        Ok(1)
    }

    async fn get_signing_package(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        commitments: &[SigningCommitments<C>],
        _identifier: Identifier<C>,
        rerandomized: bool,
    ) -> Result<SendSigningPackageArgs<C>, Box<dyn Error>> {
        if commitments.len() != 1 {
            panic!("CLIComms only supports single message");
        }
        let commitments = commitments.first().expect("was just checked");

        print_values(*commitments, output)?;

        writeln!(output, "Enter the JSON-encoded SigningPackage:")?;

        let mut signing_package_json = String::new();

        input.read_line(&mut signing_package_json)?;

        // TODO: change to return a generic Error and use a better error
        let signing_package: SigningPackage<C> = serde_json::from_str(signing_package_json.trim())?;

        if rerandomized {
            writeln!(output, "Enter the randomizer (hex string):")?;

            let mut json = String::new();
            input.read_line(&mut json).unwrap();

            let randomizer =
                frost_rerandomized::Randomizer::<C>::deserialize(&hex::decode(json.trim())?)?;
            let r = api::SendSigningPackageArgs::<C> {
                signing_package: vec![signing_package],
                randomizer: vec![randomizer],
                aux_msg: vec![],
            };
            Ok(r)
        } else {
            let r = api::SendSigningPackageArgs::<C> {
                signing_package: vec![signing_package],
                randomizer: vec![],
                aux_msg: vec![],
            };
            Ok(r)
        }
    }

    async fn send_signature_share(
        &mut self,
        _identifier: Identifier<C>,
        _signature_shares: &[SignatureShare<C>],
    ) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

pub fn read_identifier<C: Ciphersuite + 'static>(
    input: &mut dyn BufRead,
) -> Result<Identifier<C>, Box<dyn Error>> {
    let mut identifier_input = String::new();
    input.read_line(&mut identifier_input)?;
    let bytes = hex::decode(identifier_input.trim())?;
    let identifier = Identifier::<C>::deserialize(&bytes)?;
    Ok(identifier)
}

pub fn validate<C: Ciphersuite>(
    id: Identifier<C>,
    key_package: &PublicKeyPackage<C>,
    id_list: &[Identifier<C>],
) -> Result<(), frost::Error<C>> {
    if !key_package.verifying_shares().contains_key(&id) {
        return Err(frost::Error::MalformedIdentifier);
    }; // TODO: Error is actually that the identifier does not exist
    if id_list.contains(&id) {
        return Err(frost::Error::DuplicatedIdentifier);
    };
    Ok(())
}
