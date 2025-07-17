#![cfg(test)]

pub struct Helpers {
    pub participant_id_1: String,
    pub participant_id_3: String,
    pub public_key_1: String,
    pub public_key_2: String,
    pub public_key_3: String,
    pub verifying_key: String,
    pub pub_key_package: String,
    pub commitments_input_1: String,
    pub commitments_input_3: String,
    pub commitments_from_part_1: String,
    pub commitments_from_part_3: String,
    pub signing_package_helper: String,
    pub message: String,
    pub signature_1: String,
    pub signature_3: String,
    pub group_signature: String,
    pub hiding_commitment_1: String,
    pub binding_commitment_1: String,
    pub hiding_commitment_3: String,
    pub binding_commitment_3: String,
}

pub fn get_helpers() -> Helpers {
    // values

    let participant_id_1 =
        "0100000000000000000000000000000000000000000000000000000000000000".to_string();
    let participant_id_2 =
        "0200000000000000000000000000000000000000000000000000000000000000".to_string();
    let participant_id_3 =
        "0300000000000000000000000000000000000000000000000000000000000000".to_string();
    let public_key_1 =
        "d4a06421802d96e04b0ac84f73d30ac97c9e57e95a46ca689f2045e76e2354a0".to_string();
    let public_key_2 =
        "dedbd6791a9656967ce48c8e952a7bf341a21d9181853a34b7f67a707edc0675".to_string();
    let public_key_3 =
        "adc4d81882fc4e6c0d82accd6ae9b701aae88edafbe1376673a616ba456b37ce".to_string();
    let verifying_key =
        "892508e904eb45ac8e1b4348d6eeb94ac0d3e6b3fe6f9f06a7e1b10979d378ee".to_string();

    let hiding_commitment_1 =
        "4a413c35349ebb5cc2b931270c5886df98b6e1e621bd364648b99e3cf7f02bbf".to_string();
    let hiding_commitment_3 =
        "50de72191c1d6473954113df25bd05fa4915c01813a70cf1e93db5f75e49e949".to_string();
    let binding_commitment_1 =
        "fa99e65abd54bf22a005109591a1a8cf060cdb80155a408b005c5187697d8a4b".to_string();
    let binding_commitment_3 =
        "ddec2b43bc985d653229ce7bfa829a157c33baad284e2c35eafd8c3886d18a8b".to_string();

    let signature_share_1 =
        "a06a646f08efe0347720b18a69f25e2ec3b4176dd86e310e1f559016a18bd903".to_string();
    let signature_share_3 =
        "6fc5bfee50b5784c0b62a1b24bc244bcd46a23fafc61c6f011b7f55044408f08".to_string();

    let message = "74657374".to_string();

    let group_signature = "b606aef4e7530e01a1261e2d2f8c2773ab449f32206d47fc0c7c8cf968f97e610f30245e59a459818282523db5b4a3ea971f3b67d5d0f7fe300c8667e5cb680c".to_string();

    // messages

    let signing_share = "89e9c106192578f94d74c546f0cbb3515e8d87cc6d14558ada1930d50fae3209";
    let commitments = [
        "892508e904eb45ac8e1b4348d6eeb94ac0d3e6b3fe6f9f06a7e1b10979d378ee",
        "33f846d72143920fc7b106924ea021cca8ee33af99847b03de57367ad12182ad",
    ];

    // JSON

    let commitments_from_part_1 = format!("{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"identifier\":\"{}\",\"signing_share\":\"{}\",\"commitment\":[\"{}\",\"{}\"]}}", participant_id_1, signing_share, commitments[0], commitments[1]);

    let commitments_from_part_3 = format!("{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"identifier\":\"{}\",\"signing_share\":\"{}\",\"commitment\":[\"{}\",\"{}\"]}}", participant_id_3, signing_share, commitments[0], commitments[1]);

    let signing_package_helper = format!("{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"signing_commitments\":{{\"{participant_id_1}\":{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"hiding\":\"{hiding_commitment_1}\",\"binding\":\"{binding_commitment_1}\"}},\"{participant_id_3}\":{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"hiding\":\"{hiding_commitment_3}\",\"binding\":\"{binding_commitment_3}\"}}}},\"message\":\"{message}\"}}");

    let signature_1 = format!("{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"share\":\"{signature_share_1}\"}}");
    let signature_3 = format!("{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"share\":\"{signature_share_3}\"}}");

    let pub_key_package = format!("{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"verifying_shares\":{{\"{participant_id_1}\":\"{public_key_1}\",\"{participant_id_2}\":\"{public_key_2}\",\"{participant_id_3}\":\"{public_key_3}\"}},\"verifying_key\":\"{verifying_key}\"}}").to_string();

    let commitments_input_1 = format!("{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"hiding\":\"{hiding_commitment_1}\", \"binding\":\"{binding_commitment_1}\"}}");

    let commitments_input_3 = format!("{{\"header\":{{\"version\":0,\"ciphersuite\":\"FROST-ED25519-SHA512-v1\"}},\"hiding\":\"{hiding_commitment_3}\", \"binding\":\"{binding_commitment_3}\"}}");

    Helpers {
        participant_id_1,
        participant_id_3,
        public_key_1,
        public_key_2,
        public_key_3,
        verifying_key,
        pub_key_package,
        commitments_input_1,
        commitments_input_3,
        commitments_from_part_1,
        commitments_from_part_3,
        signing_package_helper,
        message,
        signature_1,
        signature_3,
        group_signature,
        hiding_commitment_1,
        binding_commitment_1,
        hiding_commitment_3,
        binding_commitment_3,
    }
}
