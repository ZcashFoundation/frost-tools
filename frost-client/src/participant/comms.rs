pub mod cli;
pub mod http;
pub mod socket;

use async_trait::async_trait;
use eyre::eyre;

use crate::api::SendSigningPackageArgs;
use frost_core::{self as frost, Ciphersuite};

use std::{
    error::Error,
    io::{BufRead, Write},
};

use frost::{
    round1::SigningCommitments,
    round2::SignatureShare,
    serde::{self, Deserialize, Serialize},
    Identifier,
};

#[derive(Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(bound = "C: Ciphersuite")]
#[allow(clippy::large_enum_variant)]
pub enum Message<C: Ciphersuite> {
    IdentifiedCommitments {
        identifier: Identifier<C>,
        commitments: SigningCommitments<C>,
    },
    SigningPackageAndRandomizer {
        signing_package: frost::SigningPackage<C>,
        randomizer: Option<frost_rerandomized::Randomizer<C>>,
    },
    SignatureShare(SignatureShare<C>),
}

#[async_trait(?Send)]
pub trait Comms<C: Ciphersuite> {
    async fn get_message_count(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
    ) -> Result<u8, Box<dyn Error>>;

    async fn get_signing_package(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        commitments: &[SigningCommitments<C>],
        identifier: Identifier<C>,
        rerandomized: bool,
    ) -> Result<SendSigningPackageArgs<C>, Box<dyn Error>>;

    /// Ask the user if they want to sign the message.
    ///
    /// Implementations should show the message to the user (or auxiliary data
    /// that maps to the message) and ask for confirmation.
    ///
    /// The default implementation prints the message to output and reads
    /// confirmation from input.
    async fn confirm_message(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        signing_package: &SendSigningPackageArgs<C>,
    ) -> Result<(), Box<dyn Error>> {
        for signing_package in &signing_package.signing_package {
            writeln!(
                output,
                "Message to be signed (hex-encoded):\n{}\nDo you want to sign it? (y/n)",
                hex::encode(signing_package.message())
            )?;
            let mut sign_it = String::new();
            input.read_line(&mut sign_it)?;
            if sign_it.trim() != "y" {
                return Err(eyre!("signing cancelled").into());
            }
        }
        Ok(())
    }

    async fn send_signature_share(
        &mut self,
        identifier: Identifier<C>,
        signature_share: &[SignatureShare<C>],
    ) -> Result<(), Box<dyn Error>>;
}
