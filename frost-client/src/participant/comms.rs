pub mod cli;
pub mod http;
pub mod socket;

use async_trait::async_trait;

use crate::api::SendSigningPackageArgs;
use frost_core::{self as frost, Ciphersuite};

use std::error::Error;

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
    async fn get_message_count(&mut self) -> Result<u8, Box<dyn Error>>;

    async fn get_signing_package(
        &mut self,
        commitments: &[SigningCommitments<C>],
        identifier: Identifier<C>,
        rerandomized: bool,
    ) -> Result<SendSigningPackageArgs<C>, Box<dyn Error>>;

    /// Ask the user if they want to sign the message.
    ///
    /// Implementations should show the message to the user (or auxiliary data
    /// that maps to the message) and ask for confirmation.
    async fn confirm_message(
        &mut self,
        _signing_package: &SendSigningPackageArgs<C>,
    ) -> Result<(), Box<dyn Error>>;

    async fn send_signature_share(
        &mut self,
        identifier: Identifier<C>,
        signature_share: &[SignatureShare<C>],
    ) -> Result<(), Box<dyn Error>>;
}
