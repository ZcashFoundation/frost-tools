use std::error::Error;

use eyre::eyre;
use lazy_static::lazy_static;
use rand_core::{CryptoRng, RngCore};

use halo2_proofs::pasta::group::ff::PrimeField;
use orchard::{
    builder::MaybeSigned,
    bundle::Flags,
    circuit::ProvingKey,
    keys::{Scope, SpendValidatingKey},
    note::Rho,
    primitives::redpallas::{self, SpendAuth},
    value::NoteValue,
    Address, Anchor,
};
use sapling_crypto::PaymentAddress;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{components::sapling::zip212_enforcement, TxVersion};
use zcash_primitives::transaction::{
    components::transparent::builder::TransparentBuilder,
    sighash::{signature_hash, SignableInput},
    txid::TxIdDigester,
    Transaction, TransactionData,
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, MainNetwork},
    value::{ZatBalance as Amount, Zatoshis},
};

use crate::transaction_plan::{
    Destination, Hasher, OrchardHasher, Source, TransactionPlan, Witness,
};

lazy_static! {
    pub static ref ORCHARD_ROOTS: Vec<[u8; 32]> = {
        let h = OrchardHasher::new();
        h.empty_roots(32)
    };
}

/// Sign a transaction plan with externally-generated signatures.
/// TODO: make this non-interactive by possibly using a callback
pub fn sign(
    mut rng: &mut (impl RngCore + CryptoRng),
    tx_plan: &TransactionPlan,
    ufvk: &UnifiedFullViewingKey,
) -> Result<Transaction, Box<dyn Error>> {
    // TODO: make params selectable
    let network = MainNetwork;

    let orchard_fvk = ufvk
        .orchard()
        .ok_or(eyre!("UFVK must have an Orchard component"))?;
    let orchard_fvk_hex = hex::encode(orchard_fvk.to_bytes());
    let orchard_ovk = orchard_fvk.clone().to_ovk(Scope::External);

    if tx_plan.orchard_fvk != orchard_fvk_hex {
        return Err(
            eyre!("Key does not match the key used to create the given transaction plan").into(),
        );
    }

    let mut transparent_builder = TransparentBuilder::empty();
    let mut sapling_builder = sapling_crypto::builder::Builder::new(
        zip212_enforcement(&network, BlockHeight::from_u32(tx_plan.anchor_height)),
        sapling_crypto::builder::BundleType::DEFAULT,
        sapling_crypto::Anchor::empty_tree(),
    );

    let orchard_anchor: Anchor =
        orchard::tree::MerkleHashOrchard::from_bytes(&tx_plan.orchard_anchor)
            .unwrap()
            .into();
    let mut orchard_builder = orchard::builder::Builder::new(
        orchard::builder::BundleType::Transactional {
            flags: Flags::ENABLED,
            bundle_required: false,
        },
        orchard_anchor,
    );

    for spend in tx_plan.spends.iter() {
        match &spend.source {
            Source::Transparent { .. } => {
                return Err(eyre!("Only Orchard inputs are supported").into())
            }
            Source::Sapling { .. } => return Err(eyre!("Only Orchard inputs are supported").into()),
            Source::Orchard {
                id_note,
                diversifier,
                rho,
                rseed,
                witness,
            } => {
                let diversifier = orchard::keys::Diversifier::from_bytes(*diversifier);
                let sender_address = orchard_fvk.address(diversifier, Scope::External);
                let value = NoteValue::from_raw(spend.amount);
                let rho = Rho::from_bytes(rho).unwrap();
                let rseed = orchard::note::RandomSeed::from_bytes(*rseed, &rho).unwrap();
                let note = orchard::Note::from_parts(sender_address, value, rho, rseed).unwrap();
                let witness = Witness::from_bytes(*id_note, witness)?;
                let auth_path: Vec<_> = witness
                    .auth_path(32, &ORCHARD_ROOTS, &OrchardHasher::new())
                    .iter()
                    .map(|n| orchard::tree::MerkleHashOrchard::from_bytes(n).unwrap())
                    .collect();
                let merkle_path = orchard::tree::MerklePath::from_parts(
                    witness.position as u32,
                    auth_path.try_into().unwrap(),
                );
                orchard_builder
                    .add_spend(orchard_fvk.clone(), note, merkle_path)
                    .map_err(|e| eyre!(e.to_string()))?;
            }
        }
    }

    for output in tx_plan.outputs.iter() {
        let value = Zatoshis::from_u64(output.amount).unwrap();
        match &output.destination {
            Destination::Transparent(_addr) => {
                let transparent_address = output.destination.transparent();
                transparent_builder
                    .add_output(&transparent_address, value)
                    .map_err(|e| eyre!(e.to_string()))?;
            }
            Destination::Sapling(addr) => {
                let sapling_address = PaymentAddress::from_bytes(addr).unwrap();
                // TODO: use ovk if Sapling support is added?
                sapling_builder
                    .add_output(
                        None,
                        sapling_address,
                        sapling_crypto::value::NoteValue::from_raw(value.into()),
                        *output.memo.as_array(),
                    )
                    .map_err(|e| eyre!(e.to_string()))?;
            }
            Destination::Orchard(addr) => {
                let orchard_address = Address::from_raw_address_bytes(addr).unwrap();
                orchard_builder
                    .add_output(
                        Some(orchard_ovk.clone()),
                        orchard_address,
                        NoteValue::from_raw(output.amount),
                        *output.memo.as_array(),
                    )
                    .map_err(|e| eyre!(e.to_string()))?;
            }
        }
    }

    let transparent_bundle = transparent_builder.build();
    let sapling_bundle = sapling_builder
        .build::<LocalTxProver, LocalTxProver, _, Amount>(&[], &mut rng)
        .unwrap();
    let orchard_bundle = orchard_builder.build(&mut rng).unwrap();

    let prover = LocalTxProver::bundled();

    // TODO: allow specifying a progress notifier
    // TODO: allow returning sapling metadata
    let sapling_bundle = sapling_bundle
        .map(|(bundle, _sapling_meta)| bundle.create_proofs(&prover, &prover, &mut rng, ()));

    let orchard_bundle = orchard_bundle.map(|(b, _m)| b);

    let consensus_branch_id =
        BranchId::for_height(&network, BlockHeight::from_u32(tx_plan.anchor_height));
    let version = TxVersion::suggested_for_branch(consensus_branch_id);

    let unauthed_tx: TransactionData<zcash_primitives::transaction::Unauthorized> =
        TransactionData::from_parts(
            version,
            consensus_branch_id,
            0,
            BlockHeight::from_u32(tx_plan.expiry_height),
            transparent_bundle,
            None,
            sapling_bundle,
            orchard_bundle,
        );

    let txid_parts = unauthed_tx.digest(TxIdDigester);
    let sig_hash = signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);
    let sig_hash: [u8; 32] = *sig_hash.as_ref();

    println!("SIGHASH: {}", hex::encode(sig_hash));

    // There are no transaprent inputs to sign, but we need to move the Bundle
    // to the Authorized state, which we do by calling `apply_signatures()`
    // (which does not take arguments since the transparent-inputs feature is
    // not enabled)
    let transparent_bundle = unauthed_tx.transparent_bundle().map(|tb| {
        tb.clone()
            .apply_signatures(|_| [0; 32], &Default::default())
            .unwrap()
    });

    // There are no Sapling spends to sign, but we need to move the Bundle to
    // the Authorized state, which we do by applying an empty vector of
    // signatures.
    let sapling_bundle = unauthed_tx.sapling_bundle().map(|sb| {
        sb.clone()
            .apply_signatures(&mut rng, sig_hash, &[])
            .unwrap()
    });

    let proving_key = ProvingKey::build();

    let orchard_bundle = unauthed_tx.orchard_bundle().map(|ob| {
        let proven = ob.clone().create_proof(&proving_key, &mut rng).unwrap();
        let proven = proven.prepare(&mut rng, sig_hash);

        let expected_ak: SpendValidatingKey = orchard_fvk.clone().into();

        let mut alphas = Vec::new();
        let proven = proven.map_authorization(
            &mut rng,
            |_rng, _partial, maybe| {
                if let MaybeSigned::SigningMetadata(parts) = &maybe {
                    if *parts.ak() == expected_ak {
                        alphas.push(parts.alpha());
                    }
                }
                maybe
            },
            |_rng, auth| auth,
        );

        let mut signatures = Vec::new();

        for (i, alpha) in alphas.iter().enumerate() {
            println!(
                "Randomizer #{}: {}",
                i,
                hex::encode::<&[u8]>(alpha.to_repr().as_ref())
            );
            let mut buffer = String::new();
            let stdin = std::io::stdin();
            println!("Input hex-encoded signature #{i}: ");
            stdin.read_line(&mut buffer).unwrap();
            let signature = hex::decode(buffer.trim()).unwrap();
            let signature: [u8; 64] = signature.try_into().unwrap();
            let signature = redpallas::Signature::<SpendAuth>::from(signature);
            signatures.push(signature);
        }

        proven
            .append_signatures(&signatures)
            .unwrap()
            .finalize()
            .unwrap()
    });

    let tx_data: TransactionData<zcash_primitives::transaction::Authorized> =
        TransactionData::from_parts(
            version,
            consensus_branch_id,
            0,
            BlockHeight::from_u32(tx_plan.expiry_height),
            transparent_bundle,
            None,
            sapling_bundle,
            orchard_bundle,
        );
    let tx = tx_data.freeze().unwrap();
    Ok(tx)
}
