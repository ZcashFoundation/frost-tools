//! Socket implementation of the Comms trait, using message-io.

use async_trait::async_trait;

use frost_core::{self as frost, Signature};

use frost_core::Ciphersuite;

use eyre::eyre;
use message_io::{
    network::{Endpoint, NetEvent, Transport},
    node::{self, NodeHandler, NodeListener},
};
use tokio::sync::mpsc::{self, error::TrySendError, Receiver, Sender};

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
        let run_handler = socket_comm.handler.clone();
        let _handle = tokio::spawn(async move { Self::run(run_handler, listener, tx) });

        socket_comm
    }

    fn run(
        handler: NodeHandler<()>,
        listener: NodeListener<()>,
        input_tx: Sender<(Endpoint, Vec<u8>)>,
    ) {
        // Read incoming network events.
        listener.for_each(|event| match event.network() {
            NetEvent::Connected(_, _) => unreachable!(), // Used for explicit connections.
            NetEvent::Accepted(_endpoint, _listener) => println!("Client connected"), // Tcp or Ws
            NetEvent::Message(endpoint, data) => {
                println!("Received: {}", String::from_utf8_lossy(data));
                match input_tx.try_send((endpoint, data.to_vec())) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        eprintln!("Input queue full, disconnecting client at {endpoint}");
                        handler.network().remove(endpoint.resource_id());
                    }
                    // The receiving side was dropped, so nothing will read further messages.
                    Err(TrySendError::Closed(_)) => handler.stop(),
                }
            }
            NetEvent::Disconnected(_endpoint) => println!("Client disconnected"), //Tcp or Ws
        });
    }
}

#[async_trait(?Send)]
impl<C: Ciphersuite> Comms<C> for SocketComms<C> {
    async fn get_signing_commitments(
        &mut self,
        _public_key_package: &PublicKeyPackage<C>,
        num_participants: u16,
        num_messages: usize,
    ) -> Result<Vec<BTreeMap<Identifier<C>, SigningCommitments<C>>>, Box<dyn Error>> {
        // TODO: support?
        if num_messages != 1 {
            return Err(eyre!("SocketComms only supports one message at a time").into());
        }
        self.endpoints = BTreeMap::new();
        let mut signing_commitments = BTreeMap::new();
        eprintln!("Waiting for participants to send their commitments...");
        for _ in 0..num_participants {
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
        Ok(vec![signing_commitments])
    }

    async fn send_signing_package_and_get_signature_shares(
        &mut self,
        signing_packages: &[SigningPackage<C>],
        randomizers: Option<&[frost_rerandomized::Randomizer<C>]>,
        aux_msg: Option<Vec<u8>>,
    ) -> Result<Vec<BTreeMap<Identifier<C>, SignatureShare<C>>>, Box<dyn Error>> {
        let [signing_package] = signing_packages else {
            return Err(eyre!("SocketComms only supports one message at a time").into());
        };
        let randomizer = match randomizers {
            None => None,
            Some([randomizer]) => Some(*randomizer),
            Some(_) => {
                return Err(eyre!("number of randomizers must match number of messages").into())
            }
        };
        if aux_msg.is_some() {
            return Err(eyre!("SocketComms does not support auxiliary messages").into());
        }

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
        Ok(vec![signature_shares])
    }

    async fn process_signature(
        &mut self,
        _signatures: &[Signature<C>],
    ) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::mpsc as std_mpsc,
        time::{Duration, Instant},
    };

    use frost_ed25519::Ed25519Sha512;
    use message_io::{
        network::{Endpoint, NetEvent, Transport},
        node::{self, NodeHandler},
    };

    use super::SocketComms;

    const TIMEOUT: Duration = Duration::from_secs(10);

    /// Stops a node when dropped, so a failing assertion can't leave a listener
    /// running and block the runtime from shutting down.
    struct StopOnDrop(NodeHandler<()>);

    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.stop();
        }
    }

    fn free_port() -> String {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
            .to_string()
    }

    /// Connects a FramedTcp client to the coordinator, returning the client handler,
    /// the coordinator endpoint, and a channel signalled when the coordinator closes
    /// the connection.
    fn connect_client(port: &str) -> (NodeHandler<()>, Endpoint, std_mpsc::Receiver<()>) {
        let (handler, listener) = node::split::<()>();
        let (endpoint, _) = handler
            .network()
            .connect_sync(Transport::FramedTcp, format!("127.0.0.1:{port}"))
            .unwrap();
        let (disconnected_tx, disconnected_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            listener.for_each(move |event| {
                if let NetEvent::Disconnected(_) = event.network() {
                    let _ = disconnected_tx.send(());
                }
            })
        });
        (handler, endpoint, disconnected_rx)
    }

    async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + TIMEOUT;
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_input_queue_disconnects_peer_and_keeps_listening() {
        let port = free_port();
        let mut comms = SocketComms::<Ed25519Sha512>::new("127.0.0.1".to_string(), port.clone());
        let _stop_comms = StopOnDrop(comms.handler.clone());

        // Flood the coordinator while nothing reads its input queue.
        let (flooder, coordinator, flooder_disconnected) = connect_client(&port);
        let _stop_flooder = StopOnDrop(flooder.clone());
        for _ in 0..3000 {
            flooder.network().send(coordinator, &[0]);
        }

        // The peer that overflows the queue is disconnected.
        flooder_disconnected
            .recv_timeout(TIMEOUT)
            .expect("flooding peer should be disconnected");

        // Nothing reads the queue, so it stays exactly full.
        assert_eq!(comms.input_rx.len(), 2000);

        // The listener is still running and forwards messages from other peers.
        // Frames the flooder sent before it was dropped may still arrive first.
        while comms.input_rx.try_recv().is_ok() {}
        let (client, coordinator, _) = connect_client(&port);
        let _stop_client = StopOnDrop(client.clone());
        client.network().send(coordinator, b"hello");
        let received_hello = async {
            while let Some((_, data)) = comms.input_rx.recv().await {
                if data == b"hello" {
                    return true;
                }
            }
            false
        };
        assert!(
            tokio::time::timeout(TIMEOUT, received_hello)
                .await
                .expect("listener should still forward messages"),
            "input channel should be open"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_comms_stops_listener() {
        let port = free_port();
        let comms = SocketComms::<Ed25519Sha512>::new("127.0.0.1".to_string(), port.clone());
        let handler = comms.handler.clone();
        let _stop_comms = StopOnDrop(handler.clone());
        drop(comms);

        let (client, coordinator, _) = connect_client(&port);
        let _stop_client = StopOnDrop(client.clone());
        client.network().send(coordinator, b"hello");

        wait_until("the listener to stop", || !handler.is_running()).await;
    }
}
