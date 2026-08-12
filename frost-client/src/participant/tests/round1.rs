#![cfg(test)]

use std::io::BufWriter;

use frost_ed25519 as frost;

use frost::Identifier;
use frost::{
    keys::{KeyPackage, SigningShare, VerifyingShare},
    round1, Error, VerifyingKey,
};
use participant::{
    args::Args,
    round1::{print_values, request_inputs},
};

use rand::thread_rng;

const PUBLIC_KEY: &str = "adf6ab1f882d04988eadfaa52fb175bf37b6247785d7380fde3fb9d68032470d";
const GROUP_PUBLIC_KEY: &str = "087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e";
const SIGNING_SHARE: &str = "ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104";
const SECRET_SHARE_JSON: &str = r#"{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"identifier":"0100000000000000000000000000000000000000000000000000000000000000","signing_share":"ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104","commitment":["087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e","926d5910e146dccb9148ca39dc7607f4f7123ff1c0ffaf109add1d165c568bf2", "291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc"]}"#;

async fn build_key_package() -> KeyPackage {
    KeyPackage::new(
        Identifier::try_from(1).unwrap(),
        SigningShare::deserialize(&hex::decode(SIGNING_SHARE).unwrap()).unwrap(),
        VerifyingShare::deserialize(&hex::decode(PUBLIC_KEY).unwrap()).unwrap(),
        VerifyingKey::deserialize(&hex::decode(GROUP_PUBLIC_KEY).unwrap()).unwrap(),
        3,
    )
}

#[tokio::test]
async fn check_valid_round_1_inputs() {
    let expected_key_package = build_key_package().await;

    let mut buf = BufWriter::new(Vec::new());
    let args = Args {
        ciphersuite: "ed25519".to_string(),
        cli: true,
        key_package: "-".to_string(),
        ip: "0.0.0.0".to_string(),
        port: 80,
        session_id: "session-id".to_string(),
    };
    let input = SECRET_SHARE_JSON;
    let mut valid_input = input.as_bytes();

    let result_key_package = request_inputs(&args, &mut valid_input, &mut buf)
        .await
        .unwrap();

    assert_eq!(result_key_package, expected_key_package);
}

#[tokio::test]
async fn check_0_input_for_identifier() {
    let mut buf = BufWriter::new(Vec::new());
    let args = Args::default();

    let input = r#"{"identifier":"0000000000000000000000000000000000000000000000000000000000000000","value":"ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104","commitment":["087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e","291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc"],"ciphersuite":"FROST(Ed25519, SHA-512)"}"#;
    let mut invalid_input = input.as_bytes();

    let expected =
        request_inputs::<frost_ed25519::Ed25519Sha512>(&args, &mut invalid_input, &mut buf)
            .await
            .unwrap_err();

    assert_eq!(
        *expected.downcast::<Error>().unwrap(),
        Error::InvalidSecretShare { culprit: None }
    );
}

#[tokio::test]
async fn check_invalid_length_signing_share() {
    let mut buf = BufWriter::new(Vec::new());
    let args = Args::default();

    let input = r#"{"identifier":"0100000000000000000000000000000000000000000000000000000000000000","value":"ed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104","commitment":["087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e","291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc"],"ciphersuite":"FROST(Ed25519, SHA-512)"}"#;

    let mut invalid_input = input.as_bytes();

    let expected =
        request_inputs::<frost_ed25519::Ed25519Sha512>(&args, &mut invalid_input, &mut buf)
            .await
            .unwrap_err();

    assert_eq!(
        *expected.downcast::<Error>().unwrap(),
        Error::InvalidSecretShare { culprit: None }
    );
}

#[tokio::test]
async fn check_invalid_round_1_inputs() {
    let input = r#"{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"signing_share":"ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104","commitment":["087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e","926d5910e146dccb9148ca39dc7607f4f7123ff1c0ffaf109add1d165c568bf2", "291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc"]}"#;

    let mut buf = BufWriter::new(Vec::new());
    let args = Args::default();

    let mut valid_input = input.as_bytes();

    let expected =
        request_inputs::<frost_ed25519::Ed25519Sha512>(&args, &mut valid_input, &mut buf)
            .await
            .unwrap_err();
    assert_eq!(
        *expected.downcast::<Error>().unwrap(),
        Error::InvalidSecretShare { culprit: None }
    );
}

// TODO: Handle this error differently
#[tokio::test]
async fn check_invalid_length_vss_commitment() {
    let mut buf = BufWriter::new(Vec::new());
    let args = Args::default();

    let input = r#"{"identifier":"0100000000000000000000000000000000000000000000000000000000000000","value":"ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104","commitment":["7e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e","291bb78d7e4ef124f5aa6a36cbcf8c276e70fbb4e208212e916d762fc42c1bbc"],"ciphersuite":"FROST(Ed25519, SHA-512)"}"#;

    let mut invalid_input = input.as_bytes();

    let expected =
        request_inputs::<frost_ed25519::Ed25519Sha512>(&args, &mut invalid_input, &mut buf);
    assert!(expected.await.is_err())
}

#[tokio::test]
async fn check_print_values() {
    let mut buf = BufWriter::new(Vec::new());

    let signing_share = SigningShare::deserialize(&hex::decode(SIGNING_SHARE).unwrap()).unwrap();
    let mut rng = thread_rng();
    let (_nonces, commitments) = round1::commit(&signing_share, &mut rng);

    print_values(commitments, &mut buf).unwrap(); // TODO: Run test without random

    let out = String::from_utf8(buf.into_inner().unwrap()).unwrap();

    let log = format!("=== Round 1 ===\nSigningNonces were generated and stored in memory\nSigningCommitments:\n{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"hiding\":\"{}\",\"binding\":\"{}\"}}\n=== Round 1 Completed ===\nPlease send your SigningCommitments to the coordinator\n", &hex::encode(commitments.hiding().serialize().unwrap()), &hex::encode(commitments.binding().serialize().unwrap()));

    assert_eq!(out, log)
}
