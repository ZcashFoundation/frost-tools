use core::str;
use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    time::Duration,
};

use axum_test::TestServer;
use rand::thread_rng;
use reqwest::Certificate;
use uuid::Uuid;
use xeddsa::{xed25519, Sign, Verify};

use frost_client::{cipher::Cipher, session::CoordinatorSessionState};
use frost_core as frost;
use frostd::{args::Args, router, AppState, SendSigningPackageArgs};

#[tokio::test]
async fn test_main_router_ed25519() -> Result<(), Box<dyn std::error::Error>> {
    test_main_router::<frost_ed25519::Ed25519Sha512>(false).await
}

#[tokio::test]
async fn test_main_router_redpallas() -> Result<(), Box<dyn std::error::Error>> {
    test_main_router::<reddsa::frost::redpallas::PallasBlake2b512>(true).await
}

/// Test the entire FROST signing flow using axum_test.
/// This is a good example of the overall flow but it's not a good example
/// of the client code, see the next test for that.
///
/// Also note that this simulates multiple clients using loops. In practice,
/// each client will run independently.
async fn test_main_router<
    C: frost_core::Ciphersuite + frost_rerandomized::RandomizedCiphersuite + 'static,
>(
    rerandomized: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create key shares
    let mut rng = thread_rng();
    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        3,
        2,
        frost::keys::IdentifierList::<C>::Default,
        &mut rng,
    )
    .unwrap();
    let key_packages: BTreeMap<_, _> = shares
        .iter()
        .map(|(identifier, secret_share)| {
            (
                *identifier,
                frost::keys::KeyPackage::try_from(secret_share.clone()).unwrap(),
            )
        })
        .collect();

    // Instantiate test server using axum_test
    let shared_state = AppState::new().await?;
    let router = router(shared_state);
    let server = TestServer::new(router)?;

    // Log in as two different users, Alice and Bob

    let (alice_privkey, alice_pubkey) = Cipher::generate_keypair()?;
    let (bob_privkey, bob_pubkey) = Cipher::generate_keypair()?;

    let res = server.post("/challenge").await;
    res.assert_status_ok();
    let r: frostd::ChallengeOutput = res.json();
    let alice_challenge = r.challenge;

    let res = server.post("/challenge").await;
    res.assert_status_ok();
    let r: frostd::ChallengeOutput = res.json();
    let bob_challenge = r.challenge;

    let alice_signature: [u8; 64] = alice_privkey.sign(alice_challenge.as_bytes(), &mut rng)?;
    let res = server
        .post("/login")
        .json(&frostd::LoginArgs {
            challenge: alice_challenge,
            pubkey: alice_pubkey.clone(),
            signature: alice_signature.to_vec(),
        })
        .await;
    res.assert_status_ok();
    let r: frostd::LoginOutput = res.json();
    let alice_token = r.access_token;

    let bob_signature: [u8; 64] = bob_privkey.sign(bob_challenge.as_bytes(), &mut rng)?;
    let res = server
        .post("/login")
        .json(&frostd::LoginArgs {
            challenge: bob_challenge,
            pubkey: bob_pubkey.clone(),
            signature: bob_signature.to_vec(),
        })
        .await;
    res.assert_status_ok();
    let r: frostd::LoginOutput = res.json();
    let bob_token = r.access_token;
    let tokens = [alice_token, bob_token];

    // As the coordinator, create a new signing session with all participants,
    // for 2 messages
    let res = server
        .post("/create_new_session")
        .authorization_bearer(alice_token)
        .json(&frostd::CreateNewSessionArgs {
            pubkeys: vec![alice_pubkey.clone(), bob_pubkey.clone()],
            message_count: 2,
        })
        .await;
    res.assert_status_ok();
    let r: frostd::CreateNewSessionOutput = res.json();
    let session_id = r.session_id;

    // Generate commitments (one SigningCommitments for each message)
    // and send them to the server; for each participant

    // Map to store the SigningNonces (for each message, for each participant)
    let mut nonces_map = BTreeMap::<_, _>::new();
    for ((identifier, key_package), token) in key_packages.iter().take(2).zip(tokens.iter()) {
        // As participant `identifier`

        // Get the number of messages (the participants wouldn't know without
        // asking the server).
        let res = server
            .post("/get_session_info")
            .authorization_bearer(token)
            .json(&frostd::GetSessionInfoArgs { session_id })
            .await;
        res.assert_status_ok();
        let r: frostd::GetSessionInfoOutput = res.json();

        // Generate SigningCommitments and SigningNonces for each message
        let mut nonces_vec = Vec::new();
        let mut commitments_vec = Vec::new();
        for _ in 0..r.message_count {
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);
            nonces_vec.push(nonces);
            commitments_vec.push(commitments);
        }

        // Store nonces for later use
        nonces_map.insert(*identifier, nonces_vec);

        // Send commitments to server
        let res = server
            .post("/send")
            .authorization_bearer(token)
            .json(&frostd::SendArgs {
                session_id,
                // Empty recipients: Coordinator
                recipients: vec![],
                msg: serde_json::to_vec(&commitments_vec)?,
            })
            .await;
        if res.status_code() != 200 {
            panic!("status code: {}; error: {}", res.status_code(), res.text());
        }
    }

    // As the coordinator, get the commitments
    let comm_pubkeys = [&alice_pubkey, &bob_pubkey];
    let pubkey_identifier_map = comm_pubkeys
        .into_iter()
        .cloned()
        .zip(key_packages.keys().take(2).copied())
        .collect::<HashMap<_, _>>();
    let mut coordinator_state = CoordinatorSessionState::<C>::new(2, 2, pubkey_identifier_map);
    loop {
        let res = server
            .post("/receive")
            .authorization_bearer(alice_token)
            .json(&frostd::ReceiveArgs {
                session_id,
                as_coordinator: true,
            })
            .await;
        res.assert_status_ok();
        let r: frostd::ReceiveOutput = res.json();
        for msg in r.msgs {
            coordinator_state.recv(msg)?;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        if coordinator_state.has_commitments() {
            break;
        }
    }
    let (commitments, usernames) = coordinator_state.commitments()?;

    // As the coordinator, choose messages and create one SigningPackage
    // and one RandomizedParams for each.
    let message1 = "Hello, world!".as_bytes();
    let message2 = "Ola mundo!".as_bytes();
    let aux_msg = "Aux msg".as_bytes();
    let messages = [message1, message2];
    let signing_packages = messages
        .iter()
        .enumerate()
        .map(|(i, msg)| frost::SigningPackage::new(commitments[i].clone(), msg))
        .collect::<Vec<_>>();

    // Will not be used if rerandomized == false but we generate anyway for simplicity
    let randomized_params = signing_packages
        .iter()
        .map(|p| frost_rerandomized::RandomizedParams::new(pubkeys.verifying_key(), p, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;

    // As the coordinator, send the SigningPackages to the server
    let send_signing_package_args = SendSigningPackageArgs {
        signing_package: signing_packages.clone(),
        aux_msg: aux_msg.to_vec(),
        randomizer: if rerandomized {
            randomized_params.iter().map(|p| *p.randomizer()).collect()
        } else {
            Vec::new()
        },
    };
    let res = server
        .post("/send")
        .authorization_bearer(alice_token)
        .json(&frostd::SendArgs {
            session_id,
            recipients: usernames.keys().cloned().collect(),
            msg: serde_json::to_vec(&send_signing_package_args)?,
        })
        .await;
    res.assert_status_ok();

    // As each participant, get SigningPackages and generate the SignatureShares
    // for each.
    for ((identifier, key_package), token) in key_packages.iter().take(2).zip(tokens.iter()) {
        // As participant `identifier`

        // Get SigningPackages
        let r: SendSigningPackageArgs<C> = loop {
            let r = server
                .post("/receive")
                .authorization_bearer(token)
                .json(&frostd::ReceiveArgs {
                    session_id,
                    as_coordinator: false,
                })
                .await
                .json::<frostd::ReceiveOutput>();
            if r.msgs.is_empty() {
                tokio::time::sleep(Duration::from_secs(2)).await;
            } else {
                break serde_json::from_slice(&r.msgs[0].msg)?;
            }
        };

        // Generate SignatureShares for each SigningPackage
        let signature_shares = if rerandomized {
            r.signing_package
                .iter()
                .zip(r.randomizer.iter())
                .enumerate()
                .map(|(i, (signing_package, randomizer))| {
                    frost_rerandomized::sign(
                        signing_package,
                        &nonces_map[identifier][i],
                        key_package,
                        *randomizer,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            r.signing_package
                .iter()
                .enumerate()
                .map(|(i, signing_package)| {
                    frost::round2::sign(signing_package, &nonces_map[identifier][i], key_package)
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        // Send SignatureShares to the server
        let res = server
            .post("/send")
            .authorization_bearer(token)
            .json(&frostd::SendArgs {
                session_id,
                // Empty recipients: Coordinator
                recipients: vec![],
                msg: serde_json::to_vec(&signature_shares)?,
            })
            .await;
        res.assert_status_ok();
    }

    // As the coordinator, get SignatureShares
    loop {
        let r = server
            .post("/receive")
            .authorization_bearer(alice_token)
            .json(&frostd::ReceiveArgs {
                session_id,
                as_coordinator: true,
            })
            .await
            .json::<frostd::ReceiveOutput>();
        for msg in r.msgs {
            coordinator_state.recv(msg)?;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        if coordinator_state.has_signature_shares() {
            break;
        }
    }

    let signature_shares = coordinator_state.signature_shares()?;

    // Generate the final Signature for each message
    let signatures = if rerandomized {
        signing_packages
            .iter()
            .enumerate()
            .map(|(i, p)| {
                frost_rerandomized::aggregate(
                    p,
                    &signature_shares[i],
                    &pubkeys,
                    &randomized_params[i],
                )
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        signing_packages
            .iter()
            .enumerate()
            .map(|(i, p)| frost::aggregate(p, &signature_shares[i], &pubkeys))
            .collect::<Result<Vec<_>, _>>()?
    };

    // Close the session
    let res = server
        .post("/close_session")
        .authorization_bearer(alice_token)
        .json(&frostd::CloseSessionArgs { session_id })
        .await;
    res.assert_status_ok();

    // Verify signatures to test if they were generated correctly
    if rerandomized {
        for (i, p) in randomized_params.iter().enumerate() {
            p.randomized_verifying_key()
                .verify(messages[i], &signatures[i])?;
        }
    } else {
        for (i, m) in messages.iter().enumerate() {
            pubkeys.verifying_key().verify(m, &signatures[i])?;
        }
    }

    // Failure tests

    // Create a signing session for tests, without Bob
    let res = server
        .post("/create_new_session")
        .authorization_bearer(alice_token)
        .json(&frostd::CreateNewSessionArgs {
            pubkeys: vec![alice_pubkey.clone()],
            message_count: 2,
        })
        .await;
    res.assert_status_ok();
    let r: frostd::CreateNewSessionOutput = res.json();
    let session_id = r.session_id;

    // Check if sending to a user not in the session fails
    let res = server
        .post("/send")
        .authorization_bearer(alice_token)
        .json(&frostd::SendArgs {
            session_id,
            recipients: vec![bob_pubkey.clone()],
            msg: vec![],
        })
        .await;
    res.assert_status_internal_server_error();
    let r: frostd::LowError = res.json();
    assert_eq!(r.code, frostd::NOT_IN_SESSION);

    // Check if sending as a user not in the session fails
    let res = server
        .post("/send")
        .authorization_bearer(bob_token)
        .json(&frostd::SendArgs {
            session_id,
            recipients: vec![alice_pubkey.clone()],
            msg: vec![],
        })
        .await;
    res.assert_status_internal_server_error();
    let r: frostd::LowError = res.json();
    assert_eq!(r.code, frostd::NOT_IN_SESSION);

    // Check if sending a too big message fails
    let res = server
        .post("/send")
        .authorization_bearer(alice_token)
        .json(&frostd::SendArgs {
            session_id,
            recipients: vec![alice_pubkey.clone()],
            msg: [0; frostd::MAX_MSG_SIZE + 1].to_vec(),
        })
        .await;
    res.assert_status_internal_server_error();
    let r: frostd::LowError = res.json();
    assert_eq!(r.code, frostd::INVALID_ARGUMENT);

    Ok(())
}

/// Actually spawn the HTTP server and connect to it using reqwest.
/// A better example on how to write client code.
#[tokio::test]
async fn test_http() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let mut rng = thread_rng();

    // For this test, we generate a self-signed certificate.
    // If you're deploying a real server, generate a proper certificate;
    // refer to the documentation.
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    let subject_alt_names = vec!["127.0.0.1".to_string(), "localhost".to_string()];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();
    let temp_dir = tempfile::tempdir()?;
    std::fs::write(temp_dir.path().join("cert.pem"), cert.pem())?;
    std::fs::write(
        temp_dir.path().join("cert.key.pem"),
        key_pair.serialize_pem(),
    )?;

    // Spawn server for testing
    tokio::spawn(async move {
        frostd::run(&Args {
            ip: "127.0.0.1".to_string(),
            port: 2744,
            tls_cert: Some(
                temp_dir
                    .path()
                    .join("cert.pem")
                    .to_str()
                    .unwrap()
                    .to_string(),
            ),
            tls_key: Some(
                temp_dir
                    .path()
                    .join("cert.key.pem")
                    .to_str()
                    .unwrap()
                    .to_string(),
            ),
            no_tls_very_insecure: false,
        })
        .await
        .unwrap();
    });

    // Wait for server to start listening
    // TODO: this could possibly be not enough, use some retry logic instead
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Create a client to make requests. To make HTTPS work in the test, we add
    // the self-signed certificate as the root certificate. For regular use, you
    // should just use `reqwest::Client::new()`, if the server has a proper web
    // certificate.
    let client = reqwest::Client::builder()
        // workaround for bug that prevents additional root certificates from working
        // https://github.com/seanmonstar/reqwest/issues/1260
        // https://github.com/seanmonstar/reqwest/discussions/2428
        .use_rustls_tls()
        .add_root_certificate(Certificate::from_pem(cert.pem().as_bytes())?)
        .build()?;

    let (alice_privkey, alice_pubkey) = Cipher::generate_keypair()?;
    let (bob_privkey, bob_pubkey) = Cipher::generate_keypair()?;

    // Get challenges for login
    let r = client
        .post("https://127.0.0.1:2744/challenge")
        .send()
        .await?;
    if r.status() != reqwest::StatusCode::OK {
        panic!("{:?}", r.json::<frostd::LowError>().await?)
    }
    let r = r.json::<frostd::ChallengeOutput>().await?;
    let alice_challenge = r.challenge;

    // Call key_login to authenticate
    let alice_signature: [u8; 64] = alice_privkey.sign(alice_challenge.as_bytes(), &mut rng)?;
    let r = client
        .post("https://127.0.0.1:2744/login")
        .json(&frostd::LoginArgs {
            challenge: alice_challenge,
            pubkey: alice_pubkey.clone(),
            signature: alice_signature.to_vec(),
        })
        .send()
        .await?;
    if r.status() != reqwest::StatusCode::OK {
        panic!("{:?}", r.json::<frostd::LowError>().await?)
    }
    let r = r.json::<frostd::LoginOutput>().await?;
    let access_token = r.access_token;

    // Call create_new_session
    let r = client
        .post("https://127.0.0.1:2744/create_new_session")
        .bearer_auth(access_token)
        .json(&frostd::CreateNewSessionArgs {
            pubkeys: vec![alice_pubkey.clone(), bob_pubkey.clone()],
            message_count: 1,
        })
        .send()
        .await?;
    if r.status() != reqwest::StatusCode::OK {
        panic!("{:?}", r.json::<frostd::LowError>().await?)
    }
    let r = r.json::<frostd::CreateNewSessionOutput>().await?;
    let session_id = r.session_id;
    println!("Session ID: {session_id}");

    // Error tests

    // Test if passing the wrong session ID returns an error
    let wrong_session_id = Uuid::new_v4();
    let r = client
        .post("https://127.0.0.1:2744/get_session_info")
        .bearer_auth(access_token)
        .json(&frostd::GetSessionInfoArgs {
            session_id: wrong_session_id,
        })
        .send()
        .await?;
    assert_eq!(r.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    let r = r.json::<frostd::LowError>().await?;
    assert_eq!(r.code, frostd::SESSION_NOT_FOUND);

    // Test if trying to close the session as a participant fails
    // Attempt to close the session as a participant (Bob)
    // Log in as Bob
    let r = client
        .post("https://127.0.0.1:2744/challenge")
        .send()
        .await?;
    let r = r.json::<frostd::ChallengeOutput>().await?;
    let bob_challenge = r.challenge;
    let bob_signature: [u8; 64] = bob_privkey.sign(bob_challenge.as_bytes(), &mut rng)?;
    let r = client
        .post("https://127.0.0.1:2744/login")
        .json(&frostd::LoginArgs {
            challenge: bob_challenge,
            pubkey: bob_pubkey.clone(),
            signature: bob_signature.to_vec(),
        })
        .send()
        .await?;
    let r = r.json::<frostd::LoginOutput>().await?;
    let bob_access_token = r.access_token;
    // Try to close the session
    let r = client
        .post("https://127.0.0.1:2744/close_session")
        .bearer_auth(bob_access_token)
        .json(&frostd::CloseSessionArgs { session_id })
        .send()
        .await?;
    assert_eq!(r.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    let r = r.json::<frostd::LowError>().await?;
    assert_eq!(r.code, frostd::NOT_COORDINATOR);

    Ok(())
}

#[test]
fn test_snow() -> Result<(), Box<dyn Error>> {
    let builder = snow::Builder::new("Noise_K_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let keypair_alice = builder.generate_keypair().unwrap();
    let keypair_bob = builder.generate_keypair().unwrap();
    let mut anoise = builder
        .local_private_key(&keypair_alice.private)
        .remote_public_key(&keypair_bob.public)
        .build_initiator()
        .unwrap();

    println!("{}", anoise.is_handshake_finished());

    let mut encrypted = [0u8; 65535];
    let len = anoise
        .write_message("hello world".as_bytes(), &mut encrypted)
        .unwrap();
    let encrypted = &encrypted[0..len];

    let builder = snow::Builder::new("Noise_K_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let mut bnoise = builder
        .local_private_key(&keypair_bob.private)
        .remote_public_key(&keypair_alice.public)
        .build_responder()
        .unwrap();

    let mut decrypted = [0u8; 65535];
    let len = bnoise.read_message(encrypted, &mut decrypted).unwrap();
    let decrypted = &decrypted[0..len];

    let mut anoise = anoise.into_transport_mode()?;
    let mut bnoise = bnoise.into_transport_mode()?;

    println!("{}", str::from_utf8(decrypted).unwrap());

    let mut encrypted = [0u8; 65535];
    let len = anoise
        .write_message("hello world".as_bytes(), &mut encrypted)
        .unwrap();
    let encrypted = &encrypted[0..len];

    let mut decrypted = [0u8; 65535];
    let len = bnoise.read_message(encrypted, &mut decrypted).unwrap();
    let decrypted = &decrypted[0..len];

    println!("{}", str::from_utf8(decrypted).unwrap());

    Ok(())
}

/// Test if signing with a snow keypair works.
#[test]
fn test_snow_keypair() -> Result<(), Box<dyn Error>> {
    let builder = snow::Builder::new("Noise_K_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let keypair = builder.generate_keypair().unwrap();

    let private =
        xed25519::PrivateKey::from(&TryInto::<[u8; 32]>::try_into(keypair.private).unwrap());
    let public = xed25519::PublicKey(TryInto::<[u8; 32]>::try_into(keypair.public).unwrap());
    let msg: &[u8] = b"hello";

    let rng = thread_rng();
    let signature: [u8; 64] = private.sign(msg, rng);
    public.verify(msg, &signature).unwrap();

    Ok(())
}
