//! Command line interface implementation of the Comms trait.

use frost_core::{self as frost, Signature};

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

pub fn print_participants<C: Ciphersuite>(
    logger: &mut dyn Write,
    participants: &BTreeMap<Identifier<C>, SigningCommitments<C>>,
) {
    writeln!(logger, "Selected participants: ",).unwrap();

    for p in participants.keys() {
        writeln!(logger, "{}", serde_json::to_string(p).unwrap()).unwrap();
    }
}

fn print_signing_package<C: Ciphersuite>(
    logger: &mut dyn Write,
    signing_package: &SigningPackage<C>,
) {
    writeln!(
        logger,
        "Signing Package:\n{}",
        serde_json::to_string(&signing_package).unwrap()
    )
    .unwrap();
}

fn print_signature<C: Ciphersuite + 'static>(
    logger: &mut dyn Write,
    group_signature: Signature<C>,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(
        logger,
        "Signature:\n{}",
        hex::encode(&group_signature.serialize()?)
    )?;
    Ok(())
}

pub struct CLIComms<'a, C: Ciphersuite> {
    reader: &'a mut dyn BufRead,
    writer: &'a mut dyn Write,
    _phantom: PhantomData<C>,
}

impl<'a, C> CLIComms<'a, C>
where
    C: Ciphersuite,
{
    pub fn new(reader: &'a mut dyn BufRead, writer: &'a mut dyn Write) -> Self {
        Self {
            reader,
            writer,
            _phantom: Default::default(),
        }
    }
}

#[async_trait(?Send)]
impl<'a, C> Comms<C> for CLIComms<'a, C>
where
    C: Ciphersuite + 'static,
{
    async fn get_signing_commitments(
        &mut self,
        public_key_package: &PublicKeyPackage<C>,
        num_participants: u16,
        num_messages: usize,
    ) -> Result<Vec<BTreeMap<Identifier<C>, SigningCommitments<C>>>, Box<dyn Error>> {
        let mut commitments = Vec::new();
        for _ in 0..num_messages {
            let mut participants_list = Vec::new();
            let mut commitments_list: BTreeMap<Identifier<C>, SigningCommitments<C>> =
                BTreeMap::new();

            for i in 1..=num_participants {
                writeln!(
                    self.writer,
                    "Identifier for participant {i:?} (hex encoded): "
                )?;
                let id_value = read_identifier(self.reader)?;
                validate(id_value, public_key_package, &participants_list)?;
                participants_list.push(id_value);

                writeln!(
                    self.writer,
                    "Please enter JSON encoded commitments for participant {}:",
                    hex::encode(id_value.serialize())
                )?;
                let mut commitments_input = String::new();
                self.reader.read_line(&mut commitments_input)?;
                let commitments = serde_json::from_str(&commitments_input)?;
                commitments_list.insert(id_value, commitments);
            }

            print_participants(self.writer, &commitments_list);
            commitments.push(commitments_list);
        }

        Ok(commitments)
    }

    async fn send_signing_package_and_get_signature_shares(
        &mut self,
        signing_packages: &[SigningPackage<C>],
        randomizers: Option<&[frost_rerandomized::Randomizer<C>]>,
        aux_msg: Option<&[u8]>,
    ) -> Result<Vec<BTreeMap<Identifier<C>, SignatureShare<C>>>, Box<dyn Error>> {
        // TODO: support?
        if randomizers.is_some() {
            panic!("rerandomized not supported");
        }
        if aux_msg.is_some() {
            panic!("auxiliary message not supported");
        }
        let mut signatures_shares = Vec::new();
        for signing_package in signing_packages {
            print_signing_package(self.writer, signing_package);
            let mut signatures_list: BTreeMap<Identifier<C>, SignatureShare<C>> = BTreeMap::new();
            for p in signing_package.signing_commitments().keys() {
                writeln!(
                    self.writer,
                    "Please enter JSON encoded signature shares for participant {}:",
                    hex::encode(p.serialize())
                )?;

                let mut signature_input = String::new();
                self.reader.read_line(&mut signature_input)?;
                let signatures = serde_json::from_str(&signature_input)?;
                signatures_list.insert(*p, signatures);
            }
            signatures_shares.push(signatures_list);
        }
        Ok(signatures_shares)
    }

    async fn process_signature(
        &mut self,
        signatures: &[Signature<C>],
    ) -> Result<(), Box<dyn Error>> {
        for signature in signatures {
            print_signature(self.writer, *signature)?;
        }
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
