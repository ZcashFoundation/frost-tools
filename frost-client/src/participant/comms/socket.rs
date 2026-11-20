//! Socket implementation of the Comms trait, using message-io.

use async_trait::async_trait;

use frost_core::{self as frost, Ciphersuite};

use crate::api::SendSigningPackageArgs;
use eyre::eyre;
use message_io::{
    network::{Endpoint, NetEvent, Transport},
    node::{self, NodeHandler, NodeListener},
};
use tokio::sync::mpsc::{self, error::TrySendError, Receiver, Sender};

use frost::{round1::SigningCommitments, round2::SignatureShare, Identifier};

use std::{error::Error, io::stdin, marker::PhantomData};

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
    pub fn new(ip: String, port: String) -> Self {
        let (handler, listener) = node::split::<()>();
        let addr = format!("{}:{}", ip, port);
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
            NetEvent::Connected(endpoint, false) => {
                println!("Error connecting to server at {endpoint}")
            } // Used for explicit connections.
            NetEvent::Connected(endpoint, true) => println!("Connected to server at {endpoint}"), // Used for explicit connections.
            NetEvent::Accepted(endpoint, _listener) => {
                println!("Server accepted connection at {endpoint}")
            } // Tcp or Ws
            NetEvent::Message(endpoint, data) => {
                println!("Received: {}", String::from_utf8_lossy(data));
                match input_tx.try_send((endpoint, data.to_vec())) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        eprintln!("Input queue full, disconnecting from server at {endpoint}");
                        handler.network().remove(endpoint.resource_id());
                    }
                    // The receiving side was dropped, so nothing will read further messages.
                    Err(TrySendError::Closed(_)) => handler.stop(),
                }
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
    async fn get_message_count(&mut self) -> Result<u8, Box<dyn Error>> {
        // TODO: support more
        Ok(1)
    }

    async fn get_signing_package(
        &mut self,
        commitments: &[SigningCommitments<C>],
        identifier: Identifier<C>,
        _rerandomized: bool,
    ) -> Result<SendSigningPackageArgs<C>, Box<dyn Error>> {
        let [commitments] = *commitments else {
            return Err(eyre!("SocketComms only supports one message at a time").into());
        };
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
        signature_shares: &[SignatureShare<C>],
    ) -> Result<(), Box<dyn Error>> {
        let [signature_share] = *signature_shares else {
            return Err(eyre!("SocketComms only supports one message at a time").into());
        };
        // Send signature shares to Coordinator
        let data = serde_json::to_vec(&Message::SignatureShare(signature_share))?;
        self.handler.network().send(self.endpoint, &data);

        Ok(())
    }

    async fn confirm_message(
        &mut self,
        signing_package: &SendSigningPackageArgs<C>,
    ) -> Result<(), Box<dyn Error>> {
        // TODO: replace with callback
        for signing_package in &signing_package.signing_package {
            eprintln!(
                "Message to be signed (hex-encoded):\n{}\nDo you want to sign it? (y/n)",
                hex::encode(signing_package.message())
            );
            let mut sign_it = String::new();
            stdin().read_line(&mut sign_it)?;
            if sign_it.trim() != "y" {
                return Err(eyre::eyre!("signing cancelled").into());
            }
        }
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

    /// Starts a FramedTcp server standing in for the coordinator. Returns its handler,
    /// its port, a channel that yields the endpoint of each accepted connection, and a
    /// channel signalled when a connection is closed.
    fn start_server() -> (
        NodeHandler<()>,
        String,
        std_mpsc::Receiver<Endpoint>,
        std_mpsc::Receiver<()>,
    ) {
        let (handler, listener) = node::split::<()>();
        let (_, addr) = handler
            .network()
            .listen(Transport::FramedTcp, "127.0.0.1:0")
            .unwrap();
        let (accepted_tx, accepted_rx) = std_mpsc::channel();
        let (disconnected_tx, disconnected_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            listener.for_each(move |event| match event.network() {
                NetEvent::Accepted(endpoint, _) => {
                    let _ = accepted_tx.send(endpoint);
                }
                NetEvent::Disconnected(_) => {
                    let _ = disconnected_tx.send(());
                }
                _ => {}
            })
        });
        (
            handler,
            addr.port().to_string(),
            accepted_rx,
            disconnected_rx,
        )
    }

    async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + TIMEOUT;
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_input_queue_disconnects_coordinator() {
        let (server, port, accepted, disconnected) = start_server();
        let _stop_server = StopOnDrop(server.clone());
        let comms = SocketComms::<Ed25519Sha512>::new("127.0.0.1".to_string(), port);
        let _stop_comms = StopOnDrop(comms.handler.clone());
        let participant = accepted.recv_timeout(TIMEOUT).unwrap();

        // Flood the participant while nothing reads its input queue.
        for _ in 0..3000 {
            server.network().send(participant, &[0]);
        }

        disconnected
            .recv_timeout(TIMEOUT)
            .expect("participant should close the flooding connection");
        assert!(comms.handler.is_running());

        // Nothing reads the queue, so it stays exactly full.
        assert_eq!(comms.input_rx.len(), 2000);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_comms_stops_listener() {
        let (server, port, accepted, _) = start_server();
        let _stop_server = StopOnDrop(server.clone());
        let comms = SocketComms::<Ed25519Sha512>::new("127.0.0.1".to_string(), port);
        let participant = accepted.recv_timeout(TIMEOUT).unwrap();
        let handler = comms.handler.clone();
        let _stop_comms = StopOnDrop(handler.clone());
        drop(comms);

        server.network().send(participant, b"hello");

        wait_until("the listener to stop", || !handler.is_running()).await;
    }
}
