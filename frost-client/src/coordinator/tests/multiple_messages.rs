#![cfg(test)]

//! End-to-end tests of [`coordinator`] signing several messages in a single
//! session, using an in-memory [`Comms`] that plays the participants.

use std::{collections::BTreeMap, error::Error};

use async_trait::async_trait;
use frost_core::{
    keys::{IdentifierList, KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Field, Group, Identifier, Signature, SigningPackage,
};
use frost_ed25519::Ed25519Sha512;
use frost_rerandomized::{RandomizedCiphersuite, RandomizedParams, Randomizer};
use rand::thread_rng;
use rand::{CryptoRng, RngCore};
use reddsa::frost::redpallas::PallasBlake2b512;

use crate::api::SendSigningPackageArgs;
use crate::coordinator::{args::ProcessedArgs, cli::coordinator, comms::Comms};
use crate::participant::cli::generate_signature;

const MESSAGES: [&[u8]; 3] = [b"first message", b"second message", b"third message"];

/// Simulates `min_signers` participants, each holding a [`KeyPackage`].
struct LocalComms<C: RandomizedCiphersuite> {
    key_packages: BTreeMap<Identifier<C>, KeyPackage<C>>,
    nonces: BTreeMap<Identifier<C>, Vec<SigningNonces<C>>>,
    received_aux_msg: Option<Vec<u8>>,
}

#[async_trait(?Send)]
impl<C: RandomizedCiphersuite + 'static> Comms<C> for LocalComms<C> {
    async fn get_signing_commitments(
        &mut self,
        _public_key_package: &PublicKeyPackage<C>,
        _num_participants: u16,
        num_messages: usize,
    ) -> Result<Vec<BTreeMap<Identifier<C>, SigningCommitments<C>>>, Box<dyn Error>> {
        let mut rng = thread_rng();
        let mut commitments = vec![BTreeMap::new(); num_messages];
        for (id, key_package) in &self.key_packages {
            let mut nonces = Vec::new();
            for commitments in commitments.iter_mut() {
                let (n, c) = frost_core::round1::commit(key_package.signing_share(), &mut rng);
                nonces.push(n);
                commitments.insert(*id, c);
            }
            self.nonces.insert(*id, nonces);
        }
        Ok(commitments)
    }

    async fn send_signing_package_and_get_signature_shares(
        &mut self,
        signing_packages: &[SigningPackage<C>],
        randomizers: Option<&[Randomizer<C>]>,
        aux_msg: Option<Vec<u8>>,
    ) -> Result<Vec<BTreeMap<Identifier<C>, SignatureShare<C>>>, Box<dyn Error>> {
        self.received_aux_msg = aux_msg.clone();
        let mut shares = vec![BTreeMap::new(); signing_packages.len()];
        for (id, key_package) in &self.key_packages {
            let config = SendSigningPackageArgs {
                signing_package: signing_packages.to_vec(),
                randomizer: randomizers.map(|r| r.to_vec()).unwrap_or_default(),
                aux_msg: aux_msg.clone().unwrap_or_default(),
            };
            let signature_shares = generate_signature(config, key_package, &self.nonces[id])?;
            for (shares, share) in shares.iter_mut().zip(signature_shares) {
                shares.insert(*id, share);
            }
        }
        Ok(shares)
    }

    async fn process_signature(
        &mut self,
        _signatures: &[Signature<C>],
    ) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

fn setup<C: RandomizedCiphersuite>() -> (LocalComms<C>, PublicKeyPackage<C>) {
    let mut rng = thread_rng();
    let (shares, public_key_package) =
        frost_core::keys::generate_with_dealer::<C, _>(3, 2, IdentifierList::Default, &mut rng)
            .unwrap();
    let key_packages = shares
        .into_iter()
        .take(2)
        .map(|(id, share)| (id, KeyPackage::try_from(share).unwrap()))
        .collect();
    let comms = LocalComms {
        key_packages,
        nonces: BTreeMap::new(),
        received_aux_msg: None,
    };
    (comms, public_key_package)
}

fn random_randomizer<C: RandomizedCiphersuite>(
    rng: &mut (impl RngCore + CryptoRng),
) -> Randomizer<C> {
    Randomizer::from_scalar(<<C::Group as Group>::Field as Field>::random(rng))
}

fn pargs<C: RandomizedCiphersuite>(
    public_key_package: &PublicKeyPackage<C>,
    randomizers: Vec<Randomizer<C>>,
    aux_msg: Option<Vec<u8>>,
) -> ProcessedArgs<C> {
    ProcessedArgs {
        num_signers: 2,
        public_key_package: public_key_package.clone(),
        messages: MESSAGES.iter().map(|m| m.to_vec()).collect(),
        randomizers,
        aux_msg,
    }
}

#[tokio::test]
async fn signs_multiple_messages() {
    let (mut comms, public_key_package) = setup::<Ed25519Sha512>();
    let aux_msg = Some(b"aux".to_vec());

    let signatures = coordinator(
        &mut comms,
        pargs(&public_key_package, Vec::new(), aux_msg.clone()),
    )
    .await
    .unwrap();

    assert_eq!(signatures.len(), MESSAGES.len());
    for (message, signature) in MESSAGES.iter().zip(&signatures) {
        public_key_package
            .verifying_key()
            .verify(message, signature)
            .unwrap();
    }
    assert_eq!(comms.received_aux_msg, aux_msg);
}

#[tokio::test]
async fn signs_multiple_messages_rerandomized() {
    let (mut comms, public_key_package) = setup::<PallasBlake2b512>();
    let mut rng = thread_rng();
    let randomizers: Vec<Randomizer<PallasBlake2b512>> = MESSAGES
        .iter()
        .map(|_| random_randomizer(&mut rng))
        .collect();

    let signatures = coordinator(
        &mut comms,
        pargs(&public_key_package, randomizers.clone(), None),
    )
    .await
    .unwrap();

    assert_eq!(signatures.len(), MESSAGES.len());
    for ((message, signature), randomizer) in MESSAGES.iter().zip(&signatures).zip(randomizers) {
        RandomizedParams::from_randomizer(public_key_package.verifying_key(), randomizer)
            .randomized_verifying_key()
            .verify(message, signature)
            .unwrap();
    }
}

#[tokio::test]
async fn rejects_randomizer_count_mismatch() {
    let (mut comms, public_key_package) = setup::<PallasBlake2b512>();
    let mut rng = thread_rng();
    let randomizers = vec![random_randomizer(&mut rng)];

    assert!(
        coordinator(&mut comms, pargs(&public_key_package, randomizers, None))
            .await
            .is_err()
    );
}
