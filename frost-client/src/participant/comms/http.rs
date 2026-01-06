//! HTTP implementation of the Comms trait.

use std::rc::Rc;
use std::{error::Error, marker::PhantomData, time::Duration};

use async_trait::async_trait;
use eyre::{eyre, OptionExt};
use frost_core::{round1::SigningCommitments, round2::SignatureShare, Ciphersuite, Identifier};
use rand::thread_rng;
use snow::{HandshakeState, TransportState};

use crate::api::{self, PublicKey, SendSigningPackageArgs, Uuid};
use crate::cipher::{Cipher, PrivateKey};
use crate::client::Client;

use super::Comms;

/// A Noise state.
///
/// This abstracts away some awkwardness in the `snow` crate API, which
/// requires explicitly marking the handshake as finished and switching
/// to a new state object after the first message is sent.
pub struct Noise {
    // These should ideally be a enum, but that makes the implementation much
    // more awkward so I went with easier option which is using two Options.
    // Only one of them must has a value at any given time.
    /// The handshake state; None after handshake is complete.
    handshake_state: Option<HandshakeState>,
    /// The transport state; None before handshake is complete.
    transport_state: Option<TransportState>,
}

impl Noise {
    /// Create a new Noise state from a HandshakeState created with the `snow`
    /// crate.
    pub fn new(handshake_state: HandshakeState) -> Self {
        Self {
            handshake_state: Some(handshake_state),
            transport_state: None,
        }
    }

    /// Write (i.e. encrypts) a message following the same API as `snow`'s
    /// [`HandshakeState::write_message()`] and
    /// [`TransportState::write_message()`].
    pub fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, snow::Error> {
        if let Some(handshake_state) = &mut self.handshake_state {
            // This does the handshake and also writes a first message.
            let r = handshake_state.write_message(payload, message);
            // This `if`` should always be true, we do the check regardless for safety.
            if handshake_state.is_handshake_finished() {
                // Get the transport state from the handshake state and update
                // the struct accordingly.
                let handshake_state = self
                    .handshake_state
                    .take()
                    .expect("there must be a handshake state set");
                self.transport_state = Some(handshake_state.into_transport_mode()?);
            }
            r
        } else if let Some(transport_state) = &mut self.transport_state {
            transport_state.write_message(payload, message)
        } else {
            panic!("invalid state");
        }
    }

    /// Reads (i.e. decrypts) a message following the same API as `snow`'s
    /// [`HandshakeState::read_message()`] and
    /// [`TransportState::read_message()`].
    pub fn read_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, snow::Error> {
        // See comments in [`Self::write_message()`].
        if let Some(handshake_state) = &mut self.handshake_state {
            let r = handshake_state.read_message(payload, message);
            if handshake_state.is_handshake_finished() {
                let handshake_state = self
                    .handshake_state
                    .take()
                    .expect("there must be a handshake state set");
                self.transport_state = Some(handshake_state.into_transport_mode()?);
            }
            r
        } else if let Some(transport_state) = &mut self.transport_state {
            transport_state.read_message(payload, message)
        } else {
            panic!("invalid state");
        }
    }
}

#[derive(Clone)]
pub struct Args<C: Ciphersuite> {
    /// IP to bind to, if using socket comms.
    /// IP to connect to, if using HTTP mode.
    pub ip: String,

    /// Port to bind to, if using socket comms.
    /// Port to connect to, if using HTTP mode.
    pub port: u16,

    /// Optional Session ID
    pub session_id: String,

    /// The participant's communication private key for HTTP mode.
    pub comm_privkey: Option<PrivateKey>,

    /// The participant's communication public key for HTTP mode.
    pub comm_pubkey: Option<PublicKey>,

    /// A function that confirms that a public key from the server is trusted by
    /// the user; returns the same public key.
    // It is a `Rc<dyn Fn>` to make it easier to use;
    // using `fn()` would preclude using closures and using generics would
    // require a lot of code change for something simple.
    #[allow(clippy::type_complexity)]
    pub comm_coordinator_pubkey_getter: Option<Rc<dyn Fn(&PublicKey) -> Option<PublicKey>>>,

    /// A callback to confirm the message to be signed, that must show the
    /// message to the user and return true if they confirm signing.
    #[allow(clippy::type_complexity)]
    pub confirm_message_callback: Rc<dyn Fn(&SendSigningPackageArgs<C>) -> bool>,
}

pub struct HTTPComms<C: Ciphersuite> {
    client: Client,
    session_id: Option<Uuid>,
    access_token: Option<String>,
    args: Args<C>,
    cipher: Option<Cipher>,
    _phantom: PhantomData<C>,
}

// TODO: Improve error handling for invalid session id
impl<C> HTTPComms<C>
where
    C: Ciphersuite,
{
    pub fn new(args: &Args<C>) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            client: Client::new(format!("https://{}:{}", args.ip, args.port)),
            session_id: Uuid::parse_str(&args.session_id).ok(),
            access_token: None,
            args: args.clone(),
            cipher: None,
            _phantom: Default::default(),
        })
    }
}

#[async_trait(?Send)]
impl<C> Comms<C> for HTTPComms<C>
where
    C: Ciphersuite + 'static,
{
    async fn get_message_count(&mut self) -> Result<u8, Box<dyn Error>> {
        let mut rng = thread_rng();

        eprintln!("Logging in...");
        let challenge = self.client.challenge().await?.challenge;

        let signature: [u8; 64] = self
            .args
            .comm_privkey
            .clone()
            .ok_or_eyre("comm_privkey must be specified")?
            .sign(challenge.as_bytes(), &mut rng)?;

        self.access_token = Some(
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
                .await?
                .access_token
                .to_string(),
        );

        eprintln!("Joining signing session...");
        let session_id = match self.session_id {
            Some(s) => s,
            None => {
                // Get session ID from server
                let r = self.client.list_sessions().await?;
                if r.session_ids.len() > 1 {
                    return Err(eyre!("user has more than one FROST session active; use `frost-client sessions` to list them and specify the session ID with `-S`").into());
                } else if r.session_ids.is_empty() {
                    return Err(eyre!("User has no current sessions active. The Coordinator should either specify your username, or manually share the session ID which you can specify with --session_id").into());
                }
                r.session_ids[0]
            }
        };
        self.session_id = Some(session_id);

        let (Some(comm_privkey), Some(comm_coordinator_pubkey_getter)) = (
            &self.args.comm_privkey,
            &self.args.comm_coordinator_pubkey_getter,
        ) else {
            return Err(
                eyre!("comm_privkey and comm_coordinator_pubkey_getter must be specified").into(),
            );
        };

        // We need to know what is the pubkey of the coordinator in order
        // to encrypt message to them.
        let session_info = self
            .client
            .get_session_info(&api::GetSessionInfoArgs { session_id })
            .await?;

        let comm_coordinator_pubkey = comm_coordinator_pubkey_getter(&session_info.coordinator_pubkey).ok_or_eyre("The coordinator for the specified FROST session is not registered in the user's address book")?;

        let cipher = Cipher::new(comm_privkey.clone(), vec![comm_coordinator_pubkey.clone()])?;
        self.cipher = Some(cipher);
        Ok(session_info.message_count)
    }

    async fn get_signing_package(
        &mut self,
        commitments: &[SigningCommitments<C>],
        _identifier: Identifier<C>,
        _rerandomized: bool,
    ) -> Result<SendSigningPackageArgs<C>, Box<dyn Error>> {
        let cipher = self.cipher.as_mut().expect("was previously set");
        let session_id = self.session_id.expect("was previously set");

        // Send Commitments to Server
        eprintln!("Sending commitments to coordinator...");
        let send_commitments_args = commitments;
        let msg = cipher.encrypt(None, serde_json::to_vec(&send_commitments_args)?)?;
        self.client
            .send(&api::SendArgs {
                session_id,
                // Empty recipients: Coordinator
                recipients: vec![],
                msg,
            })
            .await?;

        eprint!("Waiting for coordinator to send signing package...");

        // Receive SigningPackage from Coordinator

        let r: SendSigningPackageArgs<C> = loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id,
                    as_coordinator: false,
                })
                .await?;
            if r.msgs.is_empty() {
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
            } else {
                eprintln!("\nSigning package received");
                let msg = cipher.decrypt(r.msgs[0].clone())?;
                break serde_json::from_slice(&msg.msg)?;
            }
        };

        Ok(r)
    }

    async fn send_signature_share(
        &mut self,
        _identifier: Identifier<C>,
        signature_shares: &[SignatureShare<C>],
    ) -> Result<(), Box<dyn Error>> {
        let cipher = self.cipher.as_mut().expect("was just set");

        // Send signature share to Coordinator

        eprintln!("Sending signature share to coordinator...");

        let send_signature_shares_args = signature_shares.to_vec();

        let msg = cipher.encrypt(None, serde_json::to_vec(&send_signature_shares_args)?)?;

        let _r = self
            .client
            .send(&api::SendArgs {
                session_id: self.session_id.unwrap(),
                // Empty recipients: Coordinator
                recipients: vec![],
                msg,
            })
            .await?;

        let _r = self.client.logout().await?;

        Ok(())
    }

    async fn confirm_message(
        &mut self,
        signing_package: &SendSigningPackageArgs<C>,
    ) -> Result<(), Box<dyn Error>> {
        let confirmed = (self.args.confirm_message_callback)(signing_package);
        if !confirmed {
            return Err(eyre!("User did not confirm signing the message").into());
        }
        Ok(())
    }
}
