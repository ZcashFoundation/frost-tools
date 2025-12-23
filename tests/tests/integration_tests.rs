use frost_client::coordinator::args::Args as CoordinatorArgs;
use frost_client::coordinator::args::ProcessedArgs;
use frost_client::coordinator::comms::cli::CLIComms as CoordinatorCLIComms;

use frost_client::participant::args::Args as ParticipantArgs;
use frost_client::participant::comms::cli::CLIComms as ParticipantCLIComms;

use frost_ed25519 as frost;

use frost::keys::IdentifierList;
use frost::Identifier;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::BufWriter;
use std::io::Cursor;
use std::vec;

use rand::thread_rng;

use frost_client::trusted_dealer::inputs::request_inputs as trusted_dealer_input;
use frost_client::trusted_dealer::trusted_dealer_keygen::trusted_dealer_keygen;

use frost_client::participant::round2::round_2_request_inputs as participant_input_round_2;
use frost_client::participant::{
    round1::request_inputs as participant_input_round_1, round2::generate_signature,
};

#[tokio::test]
async fn trusted_dealer_journey() {
    let mut buf = BufWriter::new(Vec::new());
    let mut rng = thread_rng();

    let coordinator_args = CoordinatorArgs {
        cli: true,
        public_key_package: "".to_string(),
        signature: "".to_string(),
        message: vec![],
        ..Default::default()
    };

    // For a CLI test we can use the same CLIComms instance
    let mut participant_comms = ParticipantCLIComms::new();
    let participant_args = ParticipantArgs::default();

    // Trusted dealer

    let dealer_input = "3\n5\n\n";

    let dealer_config = trusted_dealer_input::<frost_ed25519::Ed25519Sha512>(
        &frost_client::trusted_dealer::args::Args {
            cli: true,
            ..Default::default()
        },
        &mut dealer_input.as_bytes(),
        &mut buf,
    )
    .unwrap();

    let (shares, pubkeys) =
        trusted_dealer_keygen(&dealer_config, IdentifierList::Default, &mut rng).unwrap();

    // Coordinator step 1

    let num_of_participants = 3;

    let id_input_1 = "0100000000000000000000000000000000000000000000000000000000000000";
    let id_input_2 = "0200000000000000000000000000000000000000000000000000000000000000";
    let id_input_3 = "0300000000000000000000000000000000000000000000000000000000000000";

    let participant_id_1 = Identifier::try_from(1).unwrap();
    let participant_id_2 = Identifier::try_from(2).unwrap();
    let participant_id_3 = Identifier::try_from(3).unwrap();

    let mut key_packages: HashMap<_, _> = HashMap::new();

    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share).unwrap();
        key_packages.insert(identifier, key_package);
    }

    // Round 1

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    for participant_index in 1..=3u16 {
        let participant_identifier = Identifier::try_from(participant_index).unwrap();

        let share = key_packages[&participant_identifier].signing_share();

        let round_1_input = format!(
            "{}\n",
            &serde_json::to_string(&key_packages[&participant_identifier]).unwrap()
        );
        let round_1_config =
            participant_input_round_1(&participant_args, &mut round_1_input.as_bytes(), &mut buf)
                .await
                .unwrap();

        assert_eq!(
            round_1_config.key_package,
            key_packages[&participant_identifier]
        );

        let (nonces, commitments) = frost::round1::commit(share, &mut rng);

        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    let message = "74657374";
    let input = format!(
        "{}\n{}\n{}\n",
        num_of_participants,
        serde_json::to_string(&pubkeys).unwrap(),
        message
    );
    let pcoordinator_args =
        ProcessedArgs::new(&coordinator_args, &mut input.as_bytes(), &mut buf).unwrap();

    let mut input = Cursor::new(format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        id_input_1,
        serde_json::to_string(&commitments_map[&participant_id_1]).unwrap(),
        id_input_2,
        serde_json::to_string(&commitments_map[&participant_id_2]).unwrap(),
        id_input_3,
        serde_json::to_string(&commitments_map[&participant_id_3]).unwrap(),
    ));

    let mut coordinator_comms = CoordinatorCLIComms::new(&mut input, &mut buf);

    let participants_config = frost_client::coordinator::round_1::get_commitments(
        &pcoordinator_args,
        &mut coordinator_comms,
    )
    .await
    .unwrap();

    // Coordinator step 2

    let mut signature_shares = HashMap::new();

    let signing_package = frost_client::coordinator::cli::build_signing_package(
        &pcoordinator_args,
        commitments_map.clone(),
    );

    // Round 2
    let mut buf = BufWriter::new(Vec::new());

    for participant_index in 1..=3 {
        let participant_identifier = Identifier::try_from(participant_index).unwrap();
        let signing_commitments = commitments_map[&participant_identifier];
        let round_2_input = format!("{}\n", serde_json::to_string(&signing_package).unwrap());
        let round_2_config = participant_input_round_2(
            &mut participant_comms,
            &mut round_2_input.as_bytes(),
            &mut buf,
            signing_commitments,
            participant_identifier,
            false,
        )
        .await
        .unwrap();
        let signature = generate_signature(
            round_2_config,
            &key_packages[&participant_identifier],
            &[nonces_map[&participant_identifier].clone()],
        )
        .unwrap();
        signature_shares.insert(participant_identifier, signature);
    }

    // coordinator step 3

    let mut step_3_input = Cursor::new(format!(
        "{}\n{}\n{}\n",
        serde_json::to_string(&signature_shares[&participant_id_1][0]).unwrap(),
        serde_json::to_string(&signature_shares[&participant_id_2][0]).unwrap(),
        serde_json::to_string(&signature_shares[&participant_id_3][0]).unwrap()
    ));
    // We recreate coordinator_comms to be able to provide new input
    let mut coordinator_comms = CoordinatorCLIComms::new(&mut step_3_input, &mut buf);

    let group_signature =
        frost_client::coordinator::round_2::send_signing_package_and_get_signature_shares(
            &pcoordinator_args,
            &mut coordinator_comms,
            participants_config,
            &signing_package,
        )
        .await
        .unwrap();

    // verify

    let is_signature_valid = pubkeys
        .verifying_key()
        .verify("test".as_bytes(), &group_signature)
        .is_ok();
    assert!(is_signature_valid);
}
