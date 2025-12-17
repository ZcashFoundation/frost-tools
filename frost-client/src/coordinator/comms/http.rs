//! HTTP implementation of the Comms trait.

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    marker::PhantomData,
    time::Duration,
    vec,
};

use async_trait::async_trait;
use eyre::{eyre, OptionExt};
use frost_core::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Ciphersuite,
    Identifier, Signature, SigningPackage,
};
use rand::thread_rng;

use crate::cipher::{Cipher, PrivateKey};
use crate::client::Client;
use crate::{
    api::{self, PublicKey, SendSigningPackageArgs, Uuid},
    session::CoordinatorSessionState,
};

use super::super::args::ProcessedArgs;
use super::Comms;

#[derive(Clone)]
pub struct Args<C: Ciphersuite> {
    /// Signers to use in HTTP mode, as a map of public keys to identifiers.
    pub signers: HashMap<PublicKey, Identifier<C>>,

    /// IP to bind to, if using socket comms.
    /// IP to connect to, if using HTTP mode.
    pub ip: String,

    /// Port to bind to, if using socket comms.
    /// Port to connect to, if using HTTP mode.
    pub port: u16,

    /// The coordinator's communication private key for HTTP mode.
    pub comm_privkey: Option<PrivateKey>,

    /// The coordinator's communication public key for HTTP mode.
    pub comm_pubkey: Option<PublicKey>,
}

pub struct HTTPComms<C: Ciphersuite> {
    client: Client,
    session_id: Option<Uuid>,
    args: Args<C>,
    state: CoordinatorSessionState<C>,
    pubkeys: HashMap<PublicKey, Identifier<C>>,
    cipher: Option<Cipher>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> HTTPComms<C> {
    pub fn new(pargs: &ProcessedArgs<C>, args: &Args<C>) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            client: Client::new(format!("https://{}:{}", args.ip, args.port)),
            session_id: None,
            args: args.clone(),
            state: CoordinatorSessionState::new(
                pargs.messages.len(),
                pargs.num_signers as usize,
                args.signers.clone(),
            ),
            pubkeys: Default::default(),
            cipher: None,
            _phantom: Default::default(),
        })
    }
}

#[async_trait(?Send)]
impl<C: Ciphersuite + 'static> Comms<C> for HTTPComms<C> {
    async fn get_signing_commitments(
        &mut self,
        _pub_key_package: &PublicKeyPackage<C>,
        _num_signers: u16,
    ) -> Result<BTreeMap<Identifier<C>, SigningCommitments<C>>, Box<dyn Error>> {
        let mut rng = thread_rng();

        eprintln!("Logging in...");
        let challenge = self.client.challenge().await?.challenge;

        let signature: [u8; 64] = self
            .args
            .comm_privkey
            .clone()
            .ok_or_eyre("comm_privkey must be specified")?
            .sign(challenge.as_bytes(), &mut rng)?;

        self.client
            .login(&api::LoginArgs {
                challenge,
                pubkey: self
                    .args
                    .comm_pubkey
                    .clone()
                    .ok_or_eyre("comm_pubkey must be specified")?,
                signature: signature.to_vec(),
            })
            .await?;

        eprintln!("Creating signing session...");
        let r = self
            .client
            .create_new_session(&api::CreateNewSessionArgs {
                pubkeys: self.args.signers.keys().cloned().collect(),
                message_count: 1,
            })
            .await?;

        if self.args.signers.is_empty() {
            eprintln!(
                "Send the following session ID to participants: {}",
                r.session_id
            );
        }
        self.session_id = Some(r.session_id);

        let Some(comm_privkey) = &self.args.comm_privkey else {
            return Err(eyre!("comm_privkey must be specified").into());
        };

        // If encryption is enabled, create the Noise objects

        let mut cipher = Cipher::new(
            comm_privkey.clone(),
            self.args.signers.keys().cloned().collect(),
        )?;

        eprint!("Waiting for participants to send their commitments...");

        loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id: r.session_id,
                    as_coordinator: true,
                })
                .await?;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
                self.state.recv(msg)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_commitments() {
                break;
            }
        }
        eprintln!();

        self.cipher = Some(cipher);

        let (commitments, pubkeys) = self.state.commitments()?;
        self.pubkeys = pubkeys;

        // TODO: support more than 1
        Ok(commitments[0].clone())
    }

    async fn send_signing_package_and_get_signature_shares(
        &mut self,
        signing_package: &SigningPackage<C>,
        randomizer: Option<frost_rerandomized::Randomizer<C>>,
    ) -> Result<BTreeMap<Identifier<C>, SignatureShare<C>>, Box<dyn Error>> {
        eprintln!("Sending SigningPackage to participants...");
        let cipher = self
            .cipher
            .as_mut()
            .expect("cipher must have been set before");
        let send_signing_package_args = SendSigningPackageArgs {
            signing_package: vec![signing_package.clone()],
            aux_msg: Default::default(),
            randomizer: randomizer.map(|r| vec![r]).unwrap_or_default(),
        };
        // We need to send a message separately for each recipient even if the
        // message is the same, because they are (possibly) encrypted
        // individually for each recipient.
        let pubkeys: Vec<_> = self.pubkeys.keys().cloned().collect();
        for recipient in pubkeys {
            let msg = cipher.encrypt(
                Some(&recipient),
                serde_json::to_vec(&send_signing_package_args)?,
            )?;
            let _r = self
                .client
                .send(&api::SendArgs {
                    session_id: self.session_id.unwrap(),
                    recipients: vec![recipient.clone()],
                    msg,
                })
                .await?;
        }

        eprintln!("Waiting for participants to send their SignatureShares...");

        loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: true,
                })
                .await?;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
                self.state.recv(msg)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_signature_shares() {
                break;
            }
        }
        eprintln!();

        let _r = self
            .client
            .close_session(&api::CloseSessionArgs {
                session_id: self.session_id.unwrap(),
            })
            .await?;

        let _r = self.client.logout().await?;

        let signature_shares = self.state.signature_shares()?;

        // TODO: support more than 1
        Ok(signature_shares[0].clone())
    }

    async fn process_signature(&mut self, _signature: &Signature<C>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    async fn cleanup_on_error(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(session_id) = self.session_id {
            let _r = self
                .client
                .close_session(&api::CloseSessionArgs { session_id })
                .await?;
        }
        Ok(())
    }
}
