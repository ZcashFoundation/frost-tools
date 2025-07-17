//! Socket implementation of the Comms trait, using message-io.

use async_trait::async_trait;

use frost_core::{self as frost, Ciphersuite};

use crate::api::SendSigningPackageArgs;
use eyre::eyre;
use message_io::{
    network::{Endpoint, NetEvent, Transport},
    node::{self, NodeHandler, NodeListener},
};
use tokio::sync::mpsc::{self, Receiver, Sender};

use frost::{round1::SigningCommitments, round2::SignatureShare, Identifier};

use std::{
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
};

use super::super::args::ProcessedArgs;
use super::{Comms, Message};

pub struct SocketComms<C: Ciphersuite> {
    input_rx: Receiver<(Endpoint, Vec<u8>)>,
    endpoint: Endpoint,
    handler: NodeHandler<()>,
    _phantom: PhantomData<C>,
}

impl<C> SocketComms<C>
where
    C: Ciphersuite,
{
    pub fn new(args: &ProcessedArgs<C>) -> Self {
        let (handler, listener) = node::split::<()>();
        let addr = format!("{}:{}", args.ip, args.port);
        let (tx, rx) = mpsc::channel(2000); // Don't need to receive the endpoint. Change this

        let (endpoint, _addr) = handler
            .network()
            .connect(Transport::FramedTcp, addr)
            .unwrap();

        let socket_comm = Self {
            input_rx: rx,
            endpoint,
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
            NetEvent::Connected(endpoint, false) => {
                println!("Error connecting to server at {endpoint}")
            } // Used for explicit connections.
            NetEvent::Connected(endpoint, true) => println!("Connected to server at {endpoint}"), // Used for explicit connections.
            NetEvent::Accepted(endpoint, _listener) => {
                println!("Server accepted connection at {endpoint}")
            } // Tcp or Ws
            NetEvent::Message(endpoint, data) => {
                println!("Received: {}", String::from_utf8_lossy(data));
                input_tx.try_send((endpoint, data.to_vec())).unwrap();
            }
            NetEvent::Disconnected(endpoint) => {
                println!("Disconnected from server at {endpoint}")
            } //Tcp or Ws
        });
    }
}

#[async_trait(?Send)]
impl<C> Comms<C> for SocketComms<C>
where
    C: Ciphersuite + 'static,
{
    async fn get_signing_package(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        commitments: SigningCommitments<C>,
        identifier: Identifier<C>,
        _rerandomized: bool,
    ) -> Result<SendSigningPackageArgs<C>, Box<dyn Error>> {
        // Send Commitments to Coordinator
        let data = serde_json::to_vec(&Message::<C>::IdentifiedCommitments {
            identifier,
            commitments,
        })?;
        self.handler.network().send(self.endpoint, &data);

        // Receive SigningPackage from Coordinator
        let (_endpoint, data) = self
            .input_rx
            .recv()
            .await
            .ok_or(eyre!("Did not receive signing package!"))?;

        let message: Message<C> = serde_json::from_slice(&data)?;
        if let Message::SigningPackageAndRandomizer {
            signing_package,
            randomizer,
        } = message
        {
            Ok(SendSigningPackageArgs::<C> {
                signing_package: vec![signing_package],
                randomizer: randomizer.map(|r| vec![r]).unwrap_or_default(),
                aux_msg: vec![],
            })
        } else {
            Err(eyre!("Expected SigningPackage message"))?
        }
    }

    async fn send_signature_share(
        &mut self,
        _identifier: Identifier<C>,
        signature_share: SignatureShare<C>,
    ) -> Result<(), Box<dyn Error>> {
        // Send signature shares to Coordinator
        let data = serde_json::to_vec(&Message::SignatureShare(signature_share))?;
        self.handler.network().send(self.endpoint, &data);

        Ok(())
    }
}
