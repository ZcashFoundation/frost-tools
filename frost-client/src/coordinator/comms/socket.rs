//! Socket implementation of the Comms trait, using message-io.

use async_trait::async_trait;

use frost_core::{self as frost, Signature};

use frost_core::Ciphersuite;

use eyre::eyre;
use message_io::{
    network::{Endpoint, NetEvent, SendStatus, Transport},
    node::{self, NodeHandler, NodeListener},
};
use tokio::sync::mpsc;

use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};

use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    error::Error,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use super::{Comms, Message};

type Pending = Arc<Mutex<VecDeque<(Endpoint, Vec<u8>)>>>;

pub struct SocketComms<C: Ciphersuite> {
    pending: Pending,
    ready: mpsc::Receiver<()>,
    endpoints: BTreeMap<Identifier<C>, Endpoint>,
    handler: NodeHandler<()>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> SocketComms<C> {
    pub fn new(ip: String, port: String) -> Self {
        let (handler, listener) = node::split::<()>();
        let addr = format!("{}:{}", ip, port);
        let (tx, rx) = mpsc::channel(1);
        let pending = Pending::default();

        let _ = handler
            .network()
            .listen(Transport::FramedTcp, addr)
            .unwrap();

        let socket_comm = Self {
            pending: pending.clone(),
            ready: rx,
            endpoints: BTreeMap::new(),
            handler,
            _phantom: Default::default(),
        };

        let run_handler = socket_comm.handler.clone();
        tokio::task::spawn_blocking(move || Self::run(run_handler, listener, pending, tx));

        socket_comm
    }

    async fn recv(&mut self) -> Option<(Endpoint, Vec<u8>)> {
        loop {
            if let Some(frame) = self.pending.lock().unwrap().pop_front() {
                return Some(frame);
            }
            self.ready.recv().await?;
        }
    }

    fn run(
        handler: NodeHandler<()>,
        listener: NodeListener<()>,
        pending: Pending,
        ready: mpsc::Sender<()>,
    ) {
        let mut connected = HashSet::new();
        listener.for_each(|event| match event.network() {
            NetEvent::Connected(_, _) => unreachable!(),
            NetEvent::Accepted(endpoint, _) => {
                connected.insert(endpoint);
            }
            NetEvent::Message(endpoint, data) if connected.contains(&endpoint) => {
                let mut queue = pending.lock().unwrap();
                // Each signing round consumes the peer's previous message before
                // requesting another. Reserve at most one pending frame per peer.
                if let Some(index) = queue.iter().position(|(peer, _)| *peer == endpoint) {
                    queue.remove(index);
                } else if queue.len() < 2000 {
                    queue.push_back((endpoint, data.to_vec()));
                    // A pending wakeup already covers every frame in the queue.
                    let _ = ready.try_send(());
                    return;
                }
                drop(queue);
                connected.remove(&endpoint);
                handler.network().remove(endpoint.resource_id());
            }
            NetEvent::Message(_, _) => {}
            NetEvent::Disconnected(endpoint) => {
                connected.remove(&endpoint);
                // A final signature share may still be waiting for the consumer.
            }
        });
    }
}

impl<C: Ciphersuite> Drop for SocketComms<C> {
    fn drop(&mut self) {
        self.handler.stop();
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
            let status = self.handler.network().send(*endpoint, &data);
            if status != SendStatus::Sent {
                return Err(
                    eyre!("Could not send signing package to {endpoint}: {status:?}").into(),
                );
            }
        }

        eprintln!("Waiting for participants to send their SignatureShares...");
        // Read SignatureShare from all participants
        let mut signature_shares = BTreeMap::new();
        for _ in 0..signing_package.signing_commitments().len() {
            let (endpoint, data) = self
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

        // Keep an honest peer's message pending throughout the eviction.
        let (client, coordinator, _) = connect_client(&port);
        let _stop_client = StopOnDrop(client.clone());
        client.network().send(coordinator, b"hello");
        wait_until("the client message", || {
            comms.pending.lock().unwrap().len() == 1
        })
        .await;

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

        let (_, data) = tokio::time::timeout(TIMEOUT, comms.recv())
            .await
            .expect("listener should still forward messages")
            .expect("listener should remain open");
        assert_eq!(data, b"hello");
        assert!(comms.pending.lock().unwrap().is_empty());

        client.network().send(coordinator, b"next");
        let (_, data) = tokio::time::timeout(TIMEOUT, comms.recv())
            .await
            .expect("honest client should stay connected")
            .unwrap();
        assert_eq!(data, b"next");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_comms_stops_listener() {
        let port = free_port();
        let comms = SocketComms::<Ed25519Sha512>::new("127.0.0.1".to_string(), port);
        let pending = comms.pending.clone();
        let handler = comms.handler.clone();
        let _stop_comms = StopOnDrop(handler.clone());
        drop(comms);

        wait_until("the listener to stop", || {
            std::sync::Arc::strong_count(&pending) == 1
        })
        .await;
    }
}
