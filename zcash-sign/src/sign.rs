use std::error::Error;

use eyre::eyre;
use pczt::{
    roles::low_level_signer::{OrchardParseError, Signer},
    Pczt,
};
use rand_core::{CryptoRng, RngCore};

use halo2_proofs::pasta::group::ff::PrimeField;
use orchard::primitives::redpallas::{self, SpendAuth};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{
    sighash::SignableInput, sighash_v5::v5_signature_hash, sighash_v6::v6_signature_hash,
    txid::TxIdDigester, TxVersion,
};

use crate::transaction_plan::TransactionPlan;

// The ECC-stack bump grows `Pczt` enough to trip `large_enum_variant`, which was not
// triggered by the previous versions. Boxing a variant would change this crate's public
// API, which is out of scope for a dependency bump; allowed here instead.
#[allow(clippy::large_enum_variant)]
pub enum Input {
    YwalletTxPlan(TransactionPlan),
    Pczt(Pczt),
}

/// Closure error for the low-level signer. `sign_orchard_with` / `sign_ironwood_with`
/// require `E: From<OrchardParseError>`; the apply pass also needs to carry an
/// `apply_signature` failure. Both variants are surfaced through their `Debug`
/// formatting in the `eyre!` messages at the call sites.
#[derive(Debug)]
enum SignErr {
    Parse(#[allow(dead_code)] OrchardParseError),
    Apply(#[allow(dead_code)] orchard::pczt::SignerError),
}

impl From<OrchardParseError> for SignErr {
    fn from(e: OrchardParseError) -> Self {
        SignErr::Parse(e)
    }
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
    let tx_data = pczt
        .clone()
        .into_effects()
        .map_err(|e| eyre!("Not enough information to build the transaction's effects: {e:?}"))?;
    let txid_parts = tx_data.digest(TxIdDigester);

    // Dispatch the sighash by transaction version: Ironwood spends live in v6
    // transactions, whose sighash includes the Ironwood bundle. Using the v5 hash
    // for a v6 transaction yields a hash the transaction extractor rejects
    // (SighashMismatch), and that only surfaces at broadcast.
    let version = tx_data.version();
    let sighash = match version {
        TxVersion::V6 => v6_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts),
        TxVersion::V5 if tx_data.orchard_bundle().is_some() => {
            v5_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts)
        }
        _ => Err(eyre!(
            "Only v6 (Ironwood) and v5 shielded-Orchard transactions are supported"
        ))?,
    };
    let sighash: [u8; 32] = sighash
        .as_ref()
        .try_into()
        .map_err(|_| eyre!("unexpected sighash length"))?;

    println!("SIGHASH: {}", hex::encode(sighash));

    // Pass 1: read the randomizer (alpha) of each real spend awaiting a signature.
    // The bundle is Orchard-shaped in both cases; only the signer entry point and
    // the sighash differ between the Orchard (v5) and Ironwood (v6) pools.
    let mut randomizers: Vec<(usize, [u8; 32])> = vec![];
    let extractor = Signer::new(pczt.clone());
    match version {
        TxVersion::V6 => extractor
            .sign_ironwood_with(|_pczt, bundle, _| -> Result<(), OrchardParseError> {
                collect_randomizers(bundle, &mut randomizers);
                Ok(())
            })
            .map_err(|e| eyre!("sign_ironwood_with (extract): {e:?}"))?,
        _ => extractor
            .sign_orchard_with(|_pczt, bundle, _| -> Result<(), OrchardParseError> {
                collect_randomizers(bundle, &mut randomizers);
                Ok(())
            })
            .map_err(|e| eyre!("sign_orchard_with (extract): {e:?}"))?,
    };

    let signatures = prompt_for_signatures(&randomizers)?;

    // Pass 2: inject each externally-produced RedPallas signature. `apply_signature`
    // verifies it against the spend's rk before accepting.
    let extractor = Signer::new(pczt.clone());
    let signed = match version {
        TxVersion::V6 => extractor
            .sign_ironwood_with(|_pczt, bundle, _| apply_signatures(bundle, sighash, &signatures))
            .map_err(|e| eyre!("sign_ironwood_with (apply): {e:?}"))?,
        _ => extractor
            .sign_orchard_with(|_pczt, bundle, _| apply_signatures(bundle, sighash, &signatures))
            .map_err(|e| eyre!("sign_orchard_with (apply): {e:?}"))?,
    };

    signed
        .finish()
        .serialize()
        .map_err(|e| eyre!("failed to serialize signed PCZT: {e:?}").into())
}

/// Collect `(action index, alpha)` for every real spend still awaiting a signature.
/// A real spend has `spend_auth_sig == None` (dummies were signed by the IO finalizer
/// during `pczt create`) and carries its randomizer `alpha`.
fn collect_randomizers(bundle: &mut orchard::pczt::Bundle, out: &mut Vec<(usize, [u8; 32])>) {
    for (idx, action) in bundle.actions_mut().iter().enumerate() {
        if action.spend().spend_auth_sig().is_none() {
            if let Some(alpha) = action.spend().alpha() {
                let repr = alpha.to_repr();
                let bytes: [u8; 32] = AsRef::<[u8]>::as_ref(&repr)
                    .try_into()
                    .expect("a Pallas scalar repr is 32 bytes");
                out.push((idx, bytes));
            }
        }
    }
}

/// Apply each 64-byte RedPallas signature to the action at the given index.
fn apply_signatures(
    bundle: &mut orchard::pczt::Bundle,
    sighash: [u8; 32],
    signatures: &[(usize, [u8; 64])],
) -> Result<(), SignErr> {
    let actions = bundle.actions_mut();
    for (idx, sig) in signatures {
        let signature = redpallas::Signature::<SpendAuth>::from(*sig);
        actions[*idx]
            .apply_signature(sighash, signature)
            .map_err(SignErr::Apply)?;
    }
    Ok(())
}

/// The index of an action within its bundle, paired with the 64-byte signature for it.
type IndexedSignature = (usize, [u8; 64]);

/// Print each randomizer and read the corresponding hex-encoded signature from stdin.
fn prompt_for_signatures(
    randomizers: &[(usize, [u8; 32])],
) -> Result<Vec<IndexedSignature>, Box<dyn Error>> {
    let mut signatures = vec![];
    for (idx, alpha) in randomizers {
        println!("Randomizer #{idx}: {}", hex::encode(alpha));
        println!("Input hex-encoded signature #{idx}: ");
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;
        let signature = hex::decode(buffer.trim())?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| eyre!("signature #{idx} must be 64 bytes"))?;
        signatures.push((*idx, signature));
    }
    Ok(signatures)
}
