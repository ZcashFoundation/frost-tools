pub mod cli;
pub mod http;
pub mod socket;

use frost_core::{self as frost, Ciphersuite, Signature};

use std::{collections::BTreeMap, error::Error};

use async_trait::async_trait;

use frost::{
    keys::PublicKeyPackage,
    round1::SigningCommitments,
    round2::SignatureShare,
    serde::{self, Deserialize, Serialize},
    Identifier, SigningPackage,
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
        signing_package: SigningPackage<C>,
        randomizer: Option<frost_rerandomized::Randomizer<C>>,
    },
    SignatureShare(SignatureShare<C>),
}

#[async_trait(?Send)]
pub trait Comms<C: Ciphersuite> {
    async fn get_signing_commitments(
        &mut self,
        pub_key_package: &PublicKeyPackage<C>,
        num_of_participants: u16,
    ) -> Result<BTreeMap<Identifier<C>, SigningCommitments<C>>, Box<dyn Error>>;

    async fn send_signing_package_and_get_signature_shares(
        &mut self,
        signing_package: &SigningPackage<C>,
        randomizer: Option<frost_rerandomized::Randomizer<C>>,
    ) -> Result<BTreeMap<Identifier<C>, SignatureShare<C>>, Box<dyn Error>>;

    async fn process_signature(&mut self, signature: &Signature<C>) -> Result<(), Box<dyn Error>>;

    /// Do any cleanups in case an error occurs during the protocol run.
    async fn cleanup_on_error(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
