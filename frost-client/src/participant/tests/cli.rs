use std::collections::BTreeMap;
use std::io::BufWriter;

use frost_core::{
    keys::{IdentifierList, KeyPackage, PublicKeyPackage},
    round1::SigningNonces,
    Identifier, SigningPackage,
};
use frost_rerandomized::{RandomizedParams, Randomizer};
use rand::thread_rng;
use reddsa::frost::redpallas::PallasBlake2b512 as C;

use super::super::args::Args;
use super::super::cli::{cli, generate_signature};
use crate::api::SendSigningPackageArgs;

// TODO: to restore this test, we need to intercept that generated commitments
// to put them inside the SigningPackage
// #[test]
#[allow(unused)]
async fn check_cli() {
    let args = Args::default();
    let key_package = r#"{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"identifier":"0100000000000000000000000000000000000000000000000000000000000000","signing_share":"ee4a66fec3ced53cac04b0abc309bb57f03f8d7dede033e4ae7b6ef57630120f","commitment":["21446705fa7da298998a567a3c2fdd7274903a886dcde9a77f615d915feb6764","56ce223ffbde8ce5971be587cbb0b8b31aa2bc220a6803b9ce73c63f9f432514","6dcc10da9443ef2c9bbd5fc6a9c3bcd4c5ede8048cc0b1342b091fd1ff6dc53c"]}"#;

    let signing_package = r#"{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"signing_commitments":{"0100000000000000000000000000000000000000000000000000000000000000":{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"hiding":"710a280fcedbcbe626fff055f682e4a525c31f157dd6071ef2c04ea0ecbe8de9","binding":"6dc707cdf26a589b3e2de4f6bae09b94d5d3bb939937b52bc6b16bdecd0b041f"},"0200000000000000000000000000000000000000000000000000000000000000":{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"hiding":"777f011bf695e27ce62474747a9c110cc3b827268047913a21030c3eba0e1eed","binding":"67f051035284cd619f0e7fc583eb3cb0c88d993aad621c856edc0f995f4588b2"},"0300000000000000000000000000000000000000000000000000000000000000":{"header":{"version":0,"ciphersuite":"FROST-ED25519-SHA512-v1"},"hiding":"c052599bb7a52911b6b58e7c20747f12d45d23aab4aec98aaecdc7909dc6aff3","binding":"b3fbefc67070b1b56203ef875a2c7caf24802dbc943bdc62decac33287b63b23"}},"message":"74657374"}"#;
    let group_signature = "\"daae8e867c1c3000687a819262099c44e4799853729d87738b4811637a659f3075829c4ee6c5f6767e11b937e18dce20886b0d3f015caaf4ccdb76d4d185910c\"";

    let mut buf = BufWriter::new(Vec::new());

    let input = format!(
        "{}\n{}\n{}\n",
        key_package, signing_package, group_signature
    );

    let signature =
        cli::<frost_ed25519::Ed25519Sha512>(&args, &mut input.as_bytes(), &mut buf).await;
    assert!(
        signature.is_ok(),
        "invalid signature: {}",
        signature.unwrap_err()
    );
}

const MESSAGES: [&[u8]; 2] = [b"Hello, world!", b"Ola mundo!"];

/// Runs round 1 for `min_signers` participants, one commitment per message,
/// and builds a `SigningPackage` for each message.
#[allow(clippy::type_complexity)]
fn round1() -> (
    BTreeMap<Identifier<C>, KeyPackage<C>>,
    BTreeMap<Identifier<C>, Vec<SigningNonces<C>>>,
    Vec<SigningPackage<C>>,
    PublicKeyPackage<C>,
) {
    let mut rng = thread_rng();
    let (shares, public_key_package) =
        frost_core::keys::generate_with_dealer::<C, _>(3, 2, IdentifierList::Default, &mut rng)
            .unwrap();

    let key_packages: BTreeMap<_, _> = shares
        .into_iter()
        .take(2)
        .map(|(id, share)| (id, KeyPackage::try_from(share).unwrap()))
        .collect();

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = vec![BTreeMap::new(); MESSAGES.len()];
    for (id, key_package) in &key_packages {
        let mut nonces = Vec::new();
        for commitments in commitments_map.iter_mut() {
            let (nonce, commitment) =
                frost_core::round1::commit(key_package.signing_share(), &mut rng);
            nonces.push(nonce);
            commitments.insert(*id, commitment);
        }
        nonces_map.insert(*id, nonces);
    }

    let signing_packages = commitments_map
        .into_iter()
        .zip(MESSAGES.iter())
        .map(|(commitments, message)| SigningPackage::new(commitments, message))
        .collect();

    (
        key_packages,
        nonces_map,
        signing_packages,
        public_key_package,
    )
}

/// Each message must be signed with its own randomizer, otherwise the
/// coordinator cannot aggregate the shares for messages after the first.
#[test]
fn signs_each_message_with_its_own_randomizer() {
    let mut rng = thread_rng();
    let (key_packages, nonces_map, signing_packages, public_key_package) = round1();

    let randomized_params = signing_packages
        .iter()
        .map(|signing_package| {
            RandomizedParams::<C>::new(
                public_key_package.verifying_key(),
                signing_package,
                &mut rng,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let randomizer: Vec<Randomizer<C>> = randomized_params
        .iter()
        .map(|params| *params.randomizer())
        .collect();

    // As each participant, generate one SignatureShare per message.
    let mut shares_map = vec![BTreeMap::new(); MESSAGES.len()];
    for (id, key_package) in &key_packages {
        let config = SendSigningPackageArgs {
            signing_package: signing_packages.clone(),
            aux_msg: Vec::new(),
            randomizer: randomizer.clone(),
        };
        let signature_shares = generate_signature(config, key_package, &nonces_map[id]).unwrap();
        assert_eq!(signature_shares.len(), MESSAGES.len());
        for (shares, share) in shares_map.iter_mut().zip(signature_shares) {
            shares.insert(*id, share);
        }
    }

    // As the coordinator, aggregate each message and check that the
    // resulting signature verifies under that message's randomized key.
    for (i, message) in MESSAGES.iter().enumerate() {
        let signature = frost_rerandomized::aggregate(
            &signing_packages[i],
            &shares_map[i],
            &public_key_package,
            &randomized_params[i],
        )
        .unwrap();
        randomized_params[i]
            .randomized_verifying_key()
            .verify(message, &signature)
            .unwrap();
    }
}

#[test]
fn rejects_randomizer_count_mismatch() {
    let mut rng = thread_rng();
    let (key_packages, nonces_map, signing_packages, public_key_package) = round1();

    // Only one randomizer for two messages.
    let randomizer = vec![*RandomizedParams::<C>::new(
        public_key_package.verifying_key(),
        &signing_packages[0],
        &mut rng,
    )
    .unwrap()
    .randomizer()];

    let (id, key_package) = key_packages.iter().next().unwrap();
    let config = SendSigningPackageArgs {
        signing_package: signing_packages,
        aux_msg: Vec::new(),
        randomizer,
    };

    assert!(generate_signature(config, key_package, &nonces_map[id]).is_err());
}

#[test]
fn rejects_nonce_count_mismatch() {
    let (key_packages, nonces_map, signing_packages, _) = round1();

    let (id, key_package) = key_packages.iter().next().unwrap();
    let config = SendSigningPackageArgs {
        signing_package: signing_packages,
        aux_msg: Vec::new(),
        randomizer: Vec::new(),
    };

    assert!(generate_signature(config, key_package, &nonces_map[id][..1]).is_err());
}
