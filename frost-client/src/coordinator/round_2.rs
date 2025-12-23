use frost_core::{self as frost, Ciphersuite};

use frost::{Signature, SigningPackage};
use frost_rerandomized::{RandomizedCiphersuite, Randomizer};
use rand::thread_rng;
use reddsa::frost::redpallas::PallasBlake2b512;

use super::{args::ProcessedArgs, comms::Comms, round_1::ParticipantsConfig};

pub async fn send_signing_package_and_get_signature_shares<C: RandomizedCiphersuite + 'static>(
    args: &ProcessedArgs<C>,
    comms: &mut dyn Comms<C>,
    participants: ParticipantsConfig<C>,
    signing_package: &SigningPackage<C>,
) -> Result<Signature<C>, Box<dyn std::error::Error>> {
    let group_signature =
        request_inputs_signature_shares(args, comms, participants, signing_package).await?;
    Ok(group_signature)
}

// Input required:
// 1. number of signers (TODO: maybe pass this in?)
// 2. signatures for all signers
async fn request_inputs_signature_shares<C: RandomizedCiphersuite + 'static>(
    args: &ProcessedArgs<C>,
    comms: &mut dyn Comms<C>,
    participants: ParticipantsConfig<C>,
    signing_package: &SigningPackage<C>,
) -> Result<Signature<C>, Box<dyn std::error::Error>> {
    // TODO: support multiple
    let randomizer = if args.randomizers.is_empty() && C::ID == PallasBlake2b512::ID {
        let rng = thread_rng();
        Some(Randomizer::new(rng, signing_package)?)
    } else if args.randomizers.is_empty() {
        None
    } else {
        Some(args.randomizers[0])
    };

    let randomizer_vec = randomizer.map(|r| vec![r]);
    let signatures_list = comms
        .send_signing_package_and_get_signature_shares(
            std::slice::from_ref(signing_package),
            randomizer_vec.as_deref(),
            None,
        )
        .await?;

    let group_signature = if let Some(randomizer) = randomizer {
        let randomizer_params = frost_rerandomized::RandomizedParams::<C>::from_randomizer(
            participants.pub_key_package.verifying_key(),
            randomizer,
        );

        frost_rerandomized::aggregate(
            signing_package,
            &signatures_list[0],
            &participants.pub_key_package,
            &randomizer_params,
        )
        .unwrap()
    } else {
        frost::aggregate::<C>(
            signing_package,
            &signatures_list[0],
            &participants.pub_key_package,
        )
        .unwrap()
    };

    comms.process_signature(&[group_signature]).await?;

    Ok(group_signature)
}
