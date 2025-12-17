#![cfg(test)]

use crate::coordinator::{
    args::{Args, ProcessedArgs},
    comms::cli::CLIComms,
    round_1::{get_commitments, ParticipantsConfig},
    round_2::send_signing_package_and_get_signature_shares,
};
use frost::{
    keys::{PublicKeyPackage, VerifyingShare},
    round1::{NonceCommitment, SigningCommitments},
    Identifier, SigningPackage, VerifyingKey,
};
use frost_ed25519 as frost;
use std::{
    collections::BTreeMap,
    io::{BufWriter, Cursor, Write},
};

use super::common::get_helpers;
use super::common::Helpers;

fn build_pub_key_package() -> (BTreeMap<Identifier, VerifyingShare>, VerifyingKey) {
    let Helpers {
        public_key_1,
        public_key_2,
        public_key_3,
        verifying_key,
        ..
    } = get_helpers();

    let id_1 = Identifier::try_from(1).unwrap();
    let id_2 = Identifier::try_from(2).unwrap();
    let id_3 = Identifier::try_from(3).unwrap();

    let mut signer_pubkeys = BTreeMap::new();
    signer_pubkeys.insert(
        id_1,
        VerifyingShare::deserialize(&hex::decode(public_key_1).unwrap()).unwrap(),
    );
    signer_pubkeys.insert(
        id_2,
        VerifyingShare::deserialize(&hex::decode(public_key_2).unwrap()).unwrap(),
    );
    signer_pubkeys.insert(
        id_3,
        VerifyingShare::deserialize(&hex::decode(public_key_3).unwrap()).unwrap(),
    );

    let group_public = VerifyingKey::deserialize(&hex::decode(verifying_key).unwrap()).unwrap();

    (signer_pubkeys, group_public)
}

fn build_signing_commitments() -> BTreeMap<Identifier, SigningCommitments> {
    let Helpers {
        hiding_commitment_1,
        binding_commitment_1,
        hiding_commitment_3,
        binding_commitment_3,
        ..
    } = get_helpers();

    let id_1 = Identifier::try_from(1).unwrap();
    let id_3 = Identifier::try_from(3).unwrap();

    let signer_commitments_1 = SigningCommitments::new(
        NonceCommitment::deserialize(&hex::decode(hiding_commitment_1).unwrap()).unwrap(),
        NonceCommitment::deserialize(&hex::decode(binding_commitment_1).unwrap()).unwrap(),
    );
    let signer_commitments_3 = SigningCommitments::new(
        NonceCommitment::deserialize(&hex::decode(hiding_commitment_3).unwrap()).unwrap(),
        NonceCommitment::deserialize(&hex::decode(binding_commitment_3).unwrap()).unwrap(),
    );

    let mut signing_commitments = BTreeMap::new();
    signing_commitments.insert(id_1, signer_commitments_1);
    signing_commitments.insert(id_3, signer_commitments_3);

    signing_commitments

    // SigningPackage::new(signing_commitments, b"test")
}

// Input required:
// 1. public key package
// 2. number of signers
// 3. identifiers for all signers
#[tokio::test]
async fn check_step_1() {
    let Helpers {
        participant_id_1,
        participant_id_3,
        pub_key_package,
        commitments_input_1,
        commitments_input_3,
        ..
    } = get_helpers();

    let args = Args::default();
    let mut buf = BufWriter::new(Vec::new());

    // -- INPUTS --

    let num_of_participants = 2u16;

    let signing_commitments = build_signing_commitments();

    let input = format!("{num_of_participants}\n{pub_key_package}\n");

    let pargs = ProcessedArgs::new(&args, &mut input.as_bytes(), &mut buf).unwrap();

    let mut input = Cursor::new(format!(
        "{participant_id_1}\n{commitments_input_1}\n{participant_id_3}\n{commitments_input_3}\n"
    ));
    let mut buf = BufWriter::new(Vec::new());
    let mut comms = CLIComms::new(&mut input, &mut buf);

    let (signer_pub_keys, group_public) = build_pub_key_package();

    let expected_participants_config = ParticipantsConfig {
        commitments: signing_commitments.clone(),
        pub_key_package: PublicKeyPackage::new(signer_pub_keys, group_public),
    };

    let participants_config = get_commitments(&pargs, &mut comms).await;

    assert!(participants_config.unwrap() == expected_participants_config);
}

// // Input required:
// // 1. number of signers (TODO: maybe pass this in?)
// // 2. signatures for all signers
#[tokio::test]
async fn check_step_3() {
    let Helpers {
        participant_id_1,
        participant_id_3,
        signature_1,
        signature_3,
        group_signature,
        message,
        pub_key_package,
        ..
    } = get_helpers();

    let mut buf = BufWriter::new(Vec::new());
    let args = Args::default();

    let input = format!("2\n{pub_key_package}\n{message}\n");
    let pargs = ProcessedArgs::new(&args, &mut input.as_bytes(), &mut buf).unwrap();

    // keygen output

    let (signer_pubkeys, group_public) = build_pub_key_package();

    // step 2 input

    let input = format!("{signature_1}\n{signature_3}\n");

    let mut valid_input = input.as_bytes();

    let commitments = build_signing_commitments();

    let participants_config = ParticipantsConfig {
        commitments: commitments.clone(),
        pub_key_package: PublicKeyPackage::new(signer_pubkeys, group_public),
    };

    let message = hex::decode(message).unwrap();

    let signing_package = SigningPackage::new(commitments, &message);

    // step 3 generate signature
    let mut buf = BufWriter::new(Vec::new());
    let mut comms = CLIComms::new(&mut valid_input, &mut buf);

    send_signing_package_and_get_signature_shares(
        &pargs,
        &mut comms,
        participants_config,
        &signing_package,
    )
    .await
    .unwrap();

    let expected = format!("Signing Package:\n{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"signing_commitments\":{{\"0100000000000000000000000000000000000000000000000000000000000000\":{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"hiding\":\"4a413c35349ebb5cc2b931270c5886df98b6e1e621bd364648b99e3cf7f02bbf\",\"binding\":\"fa99e65abd54bf22a005109591a1a8cf060cdb80155a408b005c5187697d8a4b\"}},\"0300000000000000000000000000000000000000000000000000000000000000\":{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"hiding\":\"50de72191c1d6473954113df25bd05fa4915c01813a70cf1e93db5f75e49e949\",\"binding\":\"ddec2b43bc985d653229ce7bfa829a157c33baad284e2c35eafd8c3886d18a8b\"}}}},\"message\":\"74657374\"}}\nPlease enter JSON encoded signature shares for participant {participant_id_1}:\nPlease enter JSON encoded signature shares for participant {participant_id_3}:\nSignature:\n{group_signature}\n");

    buf.flush().unwrap();
    let actual = String::from_utf8(buf.into_inner().unwrap()).unwrap();

    assert_eq!(expected, actual)
}
