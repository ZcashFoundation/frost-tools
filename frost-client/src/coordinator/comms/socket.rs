//! Socket implementation of the Comms trait, using message-io.

use async_trait::async_trait;

use frost_core::{self as frost, Signature};

use frost_core::Ciphersuite;

use eyre::eyre;
use message_io::{
    network::{Endpoint, NetEvent, Transport},
    node::{self, NodeHandler, NodeListener},
};
use tokio::sync::mpsc::{self, Receiver, Sender};

use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};

use std::{collections::BTreeMap, error::Error, marker::PhantomData};

use super::{Comms, Message};

pub struct SocketComms<C: Ciphersuite> {
    input_rx: Receiver<(Endpoint, Vec<u8>)>,
    endpoints: BTreeMap<Identifier<C>, Endpoint>,
    handler: NodeHandler<()>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> SocketComms<C> {
    pub fn new(ip: String, port: String) -> Self {
        let (handler, listener) = node::split::<()>();
        let addr = format!("{}:{}", ip, port);
        let (tx, rx) = mpsc::channel(2000);

        let _ = handler
            .network()
            .listen(Transport::FramedTcp, addr)
            .unwrap();

        let socket_comm = Self {
            input_rx: rx,
            endpoints: BTreeMap::new(),
            handler,
            _phantom: Default::default(),
        };

        // TODO: save handle
        let _handle = tokio::spawn(async move { Self::run(listener, tx) });

        socket_comm
    }

    fn run(listener: NodeListener<()>, input_tx: Sender<(Endpoint, Vec<u8>)>) {
        // Read incoming network events.
        listener.for_each(|event| match event.network() {
            NetEvent::Connected(_, _) => unreachable!(), // Used for explicit connections.
            NetEvent::Accepted(_endpoint, _listener) => println!("Client connected"), // Tcp or Ws
            NetEvent::Message(endpoint, data) => {
                println!("Received: {}", String::from_utf8_lossy(data));
                input_tx.try_send((endpoint, data.to_vec())).unwrap();
            }
            NetEvent::Disconnected(_endpoint) => println!("Client disconnected"), //Tcp or Ws
        });
    }
}

#[async_trait(?Send)]
impl<C: Ciphersuite> Comms<C> for SocketComms<C> {
    async fn get_signing_commitments(
        &mut self,
        _pub_key_package: &PublicKeyPackage<C>,
        num_of_participants: u16,
    ) -> Result<BTreeMap<Identifier<C>, SigningCommitments<C>>, Box<dyn Error>> {
        self.endpoints = BTreeMap::new();
        let mut signing_commitments = BTreeMap::new();
        eprintln!("Waiting for participants to send their commitments...");
        for _ in 0..num_of_participants {
            let (endpoint, data) = self
                .input_rx
                .recv()
                .await
                .ok_or(eyre!("Did not receive all commitments"))?;
            let message: Message<C> = serde_json::from_slice(&data)?;
            if let Message::IdentifiedCommitments {
                identifier,
                commitments,
            } = message
            {
                self.endpoints.insert(identifier, endpoint);
                signing_commitments.insert(identifier, commitments);
            } else {
                Err(eyre!("Expected IdentifiedCommitments message"))?;
            }
        }
        Ok(signing_commitments)
    }

    async fn send_signing_package_and_get_signature_shares(
        &mut self,
        signing_package: &SigningPackage<C>,
        randomizer: Option<frost_rerandomized::Randomizer<C>>,
    ) -> Result<BTreeMap<Identifier<C>, SignatureShare<C>>, Box<dyn Error>> {
        // Send SigningPackage to all participants
        eprintln!("Sending SigningPackage to participants...");

        let data = serde_json::to_vec(&Message::SigningPackageAndRandomizer {
            signing_package: signing_package.clone(),
            randomizer,
        })?;

        for identifier in signing_package.signing_commitments().keys() {
            let endpoint = self
                .endpoints
                .get(identifier)
                .ok_or(eyre!("unknown identifier"))?;
            self.handler.network().send(*endpoint, &data);
        }

        eprintln!("Waiting for participants to send their SignatureShares...");
        // Read SignatureShare from all participants
        let mut signature_shares = BTreeMap::new();
        for _ in 0..signing_package.signing_commitments().len() {
            let (endpoint, data) = self
                .input_rx
                .recv()
                .await
                .ok_or(eyre!("Did not receive all commitments"))?;
            let message: Message<C> = serde_json::from_slice(&data)?;
            if let Message::SignatureShare(signature_share) = message {
                let identifier = self
                    .endpoints
                    .iter()
                    .find_map(|(i, e)| if *e == endpoint { Some(i) } else { None })
                    .ok_or(eyre!("Unknown participant"))?;
                signature_shares.insert(*identifier, signature_share);
            } else {
                Err(eyre!("Expected IdentifiedCommitments message"))?;
            }
        }
        Ok(signature_shares)
    }

    async fn process_signature(&mut self, _signature: &Signature<C>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
