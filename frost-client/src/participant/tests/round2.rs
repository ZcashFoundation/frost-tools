#![cfg(test)]

use std::{collections::BTreeMap, io::BufWriter};

use frost_ed25519 as frost;

use frost::Identifier;
use frost::{
    keys::{KeyPackage, SigningShare, VerifyingShare},
    round1::{self, NonceCommitment, SigningCommitments},
    round2::SignatureShare,
    SigningPackage, VerifyingKey,
};
use frostd::SendSigningPackageArgs;
use hex::FromHex;
use participant::cli::generate_signature;
use participant::cli::print_values_round_2;
use participant::comms::cli::CLIComms;
use rand::thread_rng;

const PUBLIC_KEY: &str = "adf6ab1f882d04988eadfaa52fb175bf37b6247785d7380fde3fb9d68032470d";
const GROUP_PUBLIC_KEY: &str = "087e22f970daf6ac5b07b55bd7fc0af6dea199ab847dc34fc92a6f8641a1bb8e";
const SIGNING_SHARE: &str = "ceed7dd148a1a1ec2e65b50ecab6a7c453ccbd38c397c3506a540b7cf0dd9104";
const MESSAGE: &str = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
const MY_HIDING_COMMITMENT: &str =
    "beb81feb53ed75a2695b07f377b464a88c4c2824e7d7b63911b745df01dc2d87";
const MY_BINDING_COMMITMENT: &str =
    "d2102c5f8b8abb7ad2f1706f47a4aab3be6ede28e408f3e74baeff1f6fbcd5c0";
const HIDING_COMMITMENT_2: &str =
    "cc9e9503921cdd3f4d64f2c9e7b22c9ab6d7c940111ce36f84e4a114331c6edd";
const BINDING_COMMITMENT_2: &str =
    "b0e13794eaf00be2e430b16ec7f72ab0b6579e52ca604d17406a4fd1597afd66";

pub fn nonce_commitment(input: &str) -> NonceCommitment {
    NonceCommitment::deserialize(&hex::decode(input).unwrap()).unwrap()
}

#[tokio::test]
async fn check_valid_round_2_inputs() {
    // TODO: refactor

    // Generate commitments

    let mut comms = CLIComms::new();
    let my_signer_commitments = SigningCommitments::new(
        nonce_commitment(MY_HIDING_COMMITMENT),
        nonce_commitment(MY_BINDING_COMMITMENT),
    );

    let signer_commitments_2 = SigningCommitments::new(
        nonce_commitment(HIDING_COMMITMENT_2),
        nonce_commitment(BINDING_COMMITMENT_2),
    );

    let mut signer_commitments = BTreeMap::new();
    signer_commitments.insert(Identifier::try_from(1).unwrap(), my_signer_commitments);
    signer_commitments.insert(Identifier::try_from(2).unwrap(), signer_commitments_2);

    let message = <[u8; 32]>::from_hex(MESSAGE).unwrap();

    let signing_package = r#"{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"signing_commitments":{"0100000000000000000000000000000000000000000000000000000000000000":{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"hiding":"beb81feb53ed75a2695b07f377b464a88c4c2824e7d7b63911b745df01dc2d87","binding":"d2102c5f8b8abb7ad2f1706f47a4aab3be6ede28e408f3e74baeff1f6fbcd5c0"},"0200000000000000000000000000000000000000000000000000000000000000":{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"hiding":"cc9e9503921cdd3f4d64f2c9e7b22c9ab6d7c940111ce36f84e4a114331c6edd","binding":"b0e13794eaf00be2e430b16ec7f72ab0b6579e52ca604d17406a4fd1597afd66"}},"message":"15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673"}"#;

    let expected = Round2Config {
        signing_package: SigningPackage::new(signer_commitments, &message),
        randomizer: None,
    };

    let mut buf = BufWriter::new(Vec::new());

    let input = format!("{}\n", signing_package);
    let mut valid_input = input.as_bytes();

    let round_2_config = round_2_request_inputs(
        &mut comms,
        &mut valid_input,
        &mut buf,
        my_signer_commitments,
        Identifier::try_from(1).unwrap(),
        false,
    )
    .await;

    assert!(round_2_config.is_ok());
    assert_eq!(
        expected.signing_package,
        round_2_config.unwrap().signing_package[0]
    )
}

// TODO: test for invalid inputs

#[tokio::test]
async fn check_sign() {
    let key_package = KeyPackage::new(
        Identifier::try_from(1).unwrap(),
        SigningShare::deserialize(&hex::decode(SIGNING_SHARE).unwrap()).unwrap(),
        VerifyingShare::deserialize(&hex::decode(PUBLIC_KEY).unwrap()).unwrap(),
        VerifyingKey::deserialize(&hex::decode(GROUP_PUBLIC_KEY).unwrap()).unwrap(),
        2,
    );

    let mut rng = thread_rng();

    // TODO: Nonce doesn't seem to be exported. Look into this to improve these tests
    let (nonces, my_commitments) = round1::commit(
        &SigningShare::deserialize(&hex::decode(SIGNING_SHARE).unwrap()).unwrap(),
        &mut rng,
    );

    let signer_commitments_2 = SigningCommitments::new(
        NonceCommitment::deserialize(&hex::decode(HIDING_COMMITMENT_2).unwrap()).unwrap(),
        NonceCommitment::deserialize(&hex::decode(BINDING_COMMITMENT_2).unwrap()).unwrap(),
    );

    let mut signer_commitments = BTreeMap::new();
    signer_commitments.insert(Identifier::try_from(1).unwrap(), my_commitments);
    signer_commitments.insert(Identifier::try_from(2).unwrap(), signer_commitments_2);

    let message =
        &hex::decode("15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673").unwrap();

    let signing_package = SigningPackage::new(signer_commitments, message);

    let config = SendSigningPackageArgs {
        signing_package: vec![signing_package],
        randomizer: vec![],
        aux_msg: vec![],
    };

    let signature = generate_signature(config, &key_package, &nonces);

    assert!(signature.is_ok()) // TODO: Should be able to test this more specifically when I remove randomness from the test
}

#[tokio::test]
async fn check_print_values_round_2() {
    let mut buf = BufWriter::new(Vec::new());

    const SIGNATURE_SHARE: &str =
        "44055c54d0604cbd006f0d1713a22474d7735c5e8816b1878f62ca94bf105900";
    let signature_response =
        SignatureShare::deserialize(&hex::decode(SIGNATURE_SHARE).unwrap()).unwrap();

    print_values_round_2(signature_response, &mut buf).unwrap();

    let log = "Please send the following to the Coordinator\nSignatureShare:\n{\"header\":{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"},\"share\":\"44055c54d0604cbd006f0d1713a22474d7735c5e8816b1878f62ca94bf105900\"}\n";

    let out = String::from_utf8(buf.into_inner().unwrap()).unwrap();

    assert_eq!(out, log);
}
