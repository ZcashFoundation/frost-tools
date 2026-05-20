use std::error::Error;

use eyre::eyre;
use pczt::{roles::low_level_signer::Signer, Pczt};
use rand_core::{CryptoRng, RngCore};

use halo2_proofs::pasta::group::ff::PrimeField;
use orchard::{
    primitives::redpallas::{self, SpendAuth},
    value::NoteValue,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{sighash::SignableInput, txid::TxIdDigester};
use zcash_primitives::transaction::{sighash_v5::v5_signature_hash, TxVersion};

use crate::transaction_plan::TransactionPlan;

pub enum Input {
    YwalletTxPlan(TransactionPlan),
    Pczt(Pczt),
}

/// Sign a transaction plan with externally-generated signatures.
/// TODO: make this non-interactive by possibly using a callback
pub fn sign(
    rng: impl RngCore + CryptoRng,
    network: zcash_protocol::consensus::Network,
    tx_plan: &Input,
    _ufvk: Option<&UnifiedFullViewingKey>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match tx_plan {
        Input::YwalletTxPlan(_plan) => {
            #[cfg(false)]
            sign_ywallet(rng, network, plan, ufvk);
            Err(eyre!("Ywallet signing is disabled"))?
        }
        Input::Pczt(pczt) => sign_pczt(rng, network, pczt),
    }
}

fn sign_pczt(
    _rng: impl RngCore + CryptoRng,
    _network: zcash_protocol::consensus::Network,
    pczt: &Pczt,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let sighash = match pczt.clone().into_effects() {
        None => Err(eyre!(
            "Not enough information to build the transaction's effects"
        ))?,
        Some(tx_data) => {
            let txid_parts = tx_data.digest(TxIdDigester);
            if matches!(tx_data.version(), TxVersion::V5)
                && (tx_data.sapling_bundle().is_some() || tx_data.orchard_bundle().is_some())
            {
                v5_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts)
            } else {
                Err(eyre!(
                    "Only version 5 transactions with shielded components are supported"
                ))?
            }
        }
    };

    println!("SIGHASH: {}", hex::encode(sighash));

    let signer = Signer::new(pczt.clone());

    let mut alphas = vec![];
    signer
        .sign_orchard_with(|_pczt, bundle, _| {
            alphas = bundle
                .actions()
                .iter()
                .enumerate()
                // TODO: remove unwrap
                .filter_map(|(idx, a)| {
                    // TODO: improve dummy detection (check rk instead)
                    if a.spend().value().unwrap() != NoteValue::default() {
                        Some((idx, a.spend().alpha().unwrap()))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            Ok::<_, orchard::pczt::ParseError>(())
        })
        .unwrap();

    let mut signatures = vec![];
    for (idx, alpha) in alphas.iter() {
        println!(
            "Randomizer #{}: {}",
            idx,
            hex::encode::<&[u8]>(alpha.to_repr().as_ref())
        );
        let mut buffer = String::new();
        let stdin = std::io::stdin();
        println!("Input hex-encoded signature #{idx}: ");
        stdin.read_line(&mut buffer).unwrap();
        let signature = hex::decode(buffer.trim()).unwrap();
        let signature: [u8; 64] = signature.try_into().unwrap();
        let signature = redpallas::Signature::<SpendAuth>::from(signature);
        signatures.push((*idx, signature));
    }

    let signer = Signer::new(pczt.clone());
    let signer = signer
        .sign_orchard_with(|_pczt, bundle, _| {
            for (idx, signature) in signatures.into_iter() {
                let action = &mut bundle.actions_mut()[idx];
                action
                    .apply_signature(sighash.as_bytes().try_into().unwrap(), signature)
                    .unwrap();
            }
            Ok::<_, orchard::pczt::ParseError>(())
        })
        .map_err(|e| eyre!("Error signing: {:?}", e))?;
    let pczt = signer.finish();

    Ok(pczt.serialize())
}
