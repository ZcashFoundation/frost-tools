use frost_core::{self as frost, Ciphersuite};

use frost::{keys::PublicKeyPackage, round1::SigningCommitments, Identifier};

use std::collections::BTreeMap;

use super::{args::ProcessedArgs, comms::Comms};

#[derive(PartialEq, Debug)]
pub struct ParticipantsConfig<C: Ciphersuite> {
    pub commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
    pub pub_key_package: PublicKeyPackage<C>,
}

pub async fn get_commitments<C: Ciphersuite>(
    args: &ProcessedArgs<C>,
    comms: &mut dyn Comms<C>,
) -> Result<ParticipantsConfig<C>, Box<dyn std::error::Error>> {
    let participants = read_commitments(args, comms).await?;
    Ok(participants)
}

// TODO: validate min num of participants

// Input required:
// 1. public key package
// 2. number of participants
// 3. identifiers for all participants
async fn read_commitments<C: Ciphersuite>(
    args: &ProcessedArgs<C>,
    comms: &mut dyn Comms<C>,
) -> Result<ParticipantsConfig<C>, Box<dyn std::error::Error>> {
    let commitments_list = comms
        .get_signing_commitments(&args.public_key_package, args.num_signers)
        .await?;

    Ok(ParticipantsConfig {
        commitments: commitments_list,
        pub_key_package: args.public_key_package.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use frost_ed25519::{
        keys::{PublicKeyPackage, VerifyingShare},
        Error, Identifier, VerifyingKey,
    };

    use super::super::comms::cli::validate;

    const PUBLIC_KEY_1: &str = "fc2c9b8e335c132d9ebe0403c9317aac480bbbf8cbdb1bc3730bb68eb60dadf9";
    const PUBLIC_KEY_2: &str = "2cff4148a2f965801fb1f25f1d2a4e5df2f75b3a57cd06f30471c2c774419a41";
    const GROUP_PUBLIC_KEY: &str =
        "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";

    fn build_pub_key_package() -> PublicKeyPackage {
        let id_1 = Identifier::try_from(1).unwrap();
        let id_2 = Identifier::try_from(2).unwrap();

        let mut signer_pubkeys = BTreeMap::new();
        signer_pubkeys.insert(
            id_1,
            VerifyingShare::deserialize(&hex::decode(PUBLIC_KEY_1).unwrap()).unwrap(),
        );
        signer_pubkeys.insert(
            id_2,
            VerifyingShare::deserialize(&hex::decode(PUBLIC_KEY_2).unwrap()).unwrap(),
        );

        let group_public =
            VerifyingKey::deserialize(&hex::decode(GROUP_PUBLIC_KEY).unwrap()).unwrap();

        PublicKeyPackage::new(signer_pubkeys, group_public)
    }

    #[test]
    fn check_validate() {
        let id_1 = Identifier::try_from(1).unwrap();
        let id_2 = Identifier::try_from(2).unwrap();

        let id_list = [id_1];
        let key_package = build_pub_key_package();

        let validated = validate(id_2, &key_package, &id_list);

        assert!(validated.is_ok())
    }

    #[test]
    fn check_validation_errors_for_missing_identifiers() {
        let id_1 = Identifier::try_from(1).unwrap();
        let id_2 = Identifier::try_from(2).unwrap();
        let id_3 = Identifier::try_from(3).unwrap();

        let id_list = [id_1, id_2];
        let key_package = build_pub_key_package();

        let validated = validate(id_3, &key_package, &id_list);
        assert!(validated.is_err());
        assert!(validated == Err(Error::MalformedIdentifier))
    }

    #[test]
    fn check_validation_errors_for_duplicate_identifiers() {
        let id_1 = Identifier::try_from(1).unwrap();
        let id_2 = Identifier::try_from(2).unwrap();

        let id_list = [id_1, id_2];
        let key_package = build_pub_key_package();

        let validated = validate(id_1, &key_package, &id_list);
        assert!(validated.is_err());
        assert!(validated == Err(Error::DuplicatedIdentifier))
    }
}
