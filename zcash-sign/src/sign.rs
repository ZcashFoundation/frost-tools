use std::error::Error;

use eyre::eyre;
use pczt::roles::low_level_signer::Signer;
use rand_core::{CryptoRng, RngCore};

use halo2_proofs::pasta::group::ff::PrimeField;
use orchard::{
    primitives::redpallas::{self, SpendAuth},
    value::NoteValue,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{sighash::SignableInput, txid::TxIdDigester};
use zcash_primitives::transaction::{sighash_v5::v5_signature_hash, TxVersion};

use crate::{confirm::ParsedPczt, transaction_plan::TransactionPlan};

pub enum Input {
    YwalletTxPlan(TransactionPlan),
    Pczt(ParsedPczt),
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

pub struct SigningInputs {
    pub sighash: Vec<u8>,
    pub alphas: Vec<(usize, Vec<u8>)>,
}

/// Return the sighash and alphas (randomizers) from the PCZT.
pub fn read_pczt_signining_inputs(pczt: &ParsedPczt) -> Result<SigningInputs, Box<dyn Error>> {
    let pczt = &pczt.pczt;
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
    }
    .as_bytes()
    .to_vec();

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
                        Some((idx, a.spend().alpha().unwrap().to_repr().to_vec()))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            Ok::<_, orchard::pczt::ParseError>(())
        })
        .unwrap();

    Ok(SigningInputs { sighash, alphas })
}

pub fn write_pczt_signing_outputs(
    pczt: &ParsedPczt,
    sighash: &[u8],
    signatures: &[Vec<u8>],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signatures = signatures
        .iter()
        .map(|sig_bytes| {
            let sig_array: [u8; 64] = sig_bytes
                .clone()
                .try_into()
                .map_err(|_| eyre!("Signature must be exactly 64 bytes long"))?;
            Ok(redpallas::Signature::<SpendAuth>::from(sig_array))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

    let signer = Signer::new(pczt.pczt.clone());
    let signer = signer
        .sign_orchard_with(|_pczt, bundle, _| {
            bundle
                .actions_mut()
                .iter_mut()
                // TODO: remove unwrap
                .filter(|a| {
                    // TODO: improve dummy detection (check rk instead)
                    a.spend().value().unwrap() != NoteValue::default()
                })
                .zip(signatures.iter())
                .for_each(|(action, signature)| {
                    action
                        .apply_signature(sighash.try_into().unwrap(), signature.clone())
                        .unwrap();
                });
            Ok::<_, orchard::pczt::ParseError>(())
        })
        .map_err(|e| eyre!("Error signing: {:?}", e))?;
    let pczt = signer.finish();

    Ok(pczt.serialize())
}

fn sign_pczt(
    _rng: impl RngCore + CryptoRng,
    _network: zcash_protocol::consensus::Network,
    pczt: &ParsedPczt,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let SigningInputs { sighash, alphas } = read_pczt_signining_inputs(pczt)?;

    println!("SIGHASH: {}", hex::encode(&sighash));

    let mut signatures = vec![];
    for (idx, alpha) in alphas.iter() {
        println!("Randomizer #{}: {}", idx, hex::encode(alpha));
    }
    for (idx, _alpha) in alphas.iter() {
        let mut buffer = String::new();
        let stdin = std::io::stdin();
        println!("Input hex-encoded signature #{idx}: ");
        stdin.read_line(&mut buffer).unwrap();
        let signature = hex::decode(buffer.trim()).unwrap();
        signatures.push(signature);
    }

    write_pczt_signing_outputs(pczt, &sighash, &signatures)
}
