//! Command line interface implementation of the Comms trait.

use frost_core as frost;

use frost_core::Ciphersuite;

use async_trait::async_trait;

use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};

use std::{
    collections::BTreeMap,
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
};

use super::Comms;

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
    async fn get_signing_commitments(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        pub_key_package: &PublicKeyPackage<C>,
        num_of_participants: u16,
    ) -> Result<BTreeMap<Identifier<C>, SigningCommitments<C>>, Box<dyn Error>> {
        let mut participants_list = Vec::new();
        let mut commitments_list: BTreeMap<Identifier<C>, SigningCommitments<C>> = BTreeMap::new();

        for i in 1..=num_of_participants {
            writeln!(output, "Identifier for participant {i:?} (hex encoded): ")?;
            let id_value = read_identifier(input)?;
            validate(id_value, pub_key_package, &participants_list)?;
            participants_list.push(id_value);

            writeln!(
                output,
                "Please enter JSON encoded commitments for participant {}:",
                hex::encode(id_value.serialize())
            )?;
            let mut commitments_input = String::new();
            input.read_line(&mut commitments_input)?;
            let commitments = serde_json::from_str(&commitments_input)?;
            commitments_list.insert(id_value, commitments);
        }

        Ok(commitments_list)
    }

    async fn send_signing_package_and_get_signature_shares(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        signing_package: &SigningPackage<C>,
        randomizer: Option<frost_rerandomized::Randomizer<C>>,
    ) -> Result<BTreeMap<Identifier<C>, SignatureShare<C>>, Box<dyn Error>> {
        if randomizer.is_some() {
            panic!("rerandomized not supported");
        }
        let mut signatures_list: BTreeMap<Identifier<C>, SignatureShare<C>> = BTreeMap::new();
        for p in signing_package.signing_commitments().keys() {
            writeln!(
                output,
                "Please enter JSON encoded signature shares for participant {}:",
                hex::encode(p.serialize())
            )?;

            let mut signature_input = String::new();
            input.read_line(&mut signature_input)?;
            let signatures = serde_json::from_str(&signature_input)?;
            signatures_list.insert(*p, signatures);
        }
        Ok(signatures_list)
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
