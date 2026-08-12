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

/// Compute the version-appropriate signature hash for `pczt`, returned alongside the
/// transaction version that the rest of the signing flow dispatches on.
///
/// Ironwood spends live in v6 transactions, whose sighash commits to the Ironwood
/// bundle. Using the v5 hash for a v6 transaction yields a hash the transaction
/// extractor rejects (`SighashMismatch`), and that only surfaces at broadcast — so the
/// dispatch is pinned by the tests at the bottom of this file against a real v6
/// Ironwood transaction.
fn sighash_for_pczt(pczt: &Pczt) -> Result<(TxVersion, [u8; 32]), Box<dyn Error>> {
    let tx_data = pczt
        .clone()
        .into_effects()
        .map_err(|e| eyre!("Not enough information to build the transaction's effects: {e:?}"))?;
    let txid_parts = tx_data.digest(TxIdDigester);

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

    Ok((version, sighash))
}

fn sign_pczt(
    _rng: impl RngCore + CryptoRng,
    _network: zcash_protocol::consensus::Network,
    pczt: &Pczt,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let (version, sighash) = sighash_for_pczt(pczt)?;

    println!("SIGHASH: {}", hex::encode(sighash));

    // Pass 1: read the randomizer (alpha) of each real spend awaiting a signature.
    // The bundle is Orchard-shaped in every pool; only the signer entry point and the
    // sighash differ.
    let mut randomizers: Vec<PoolRandomizer> = vec![];
    for &pool in pools_for(version) {
        let extractor = Signer::new(pczt.clone());
        let mut found: Vec<(usize, [u8; 32])> = vec![];
        let signed = match pool {
            Pool::Ironwood => {
                extractor.sign_ironwood_with(|_pczt, bundle, _| -> Result<(), OrchardParseError> {
                    collect_randomizers(bundle, &mut found);
                    Ok(())
                })
            }
            Pool::Orchard => {
                extractor.sign_orchard_with(|_pczt, bundle, _| -> Result<(), OrchardParseError> {
                    collect_randomizers(bundle, &mut found);
                    Ok(())
                })
            }
        };
        signed.map_err(|e| eyre!("{} (extract): {e:?}", pool.signer_name()))?;
        randomizers.extend(found.into_iter().map(|(idx, alpha)| (pool, idx, alpha)));
    }

    let signatures = prompt_for_signatures(&randomizers)?;

    // Pass 2: inject each externally-produced RedPallas signature. `apply_signature`
    // verifies it against the spend's rk before accepting. Each pool's bundle is
    // signed in its own pass, with only the signatures belonging to that pool.
    let mut signed = Signer::new(pczt.clone());
    for &pool in pools_for(version) {
        let for_pool: Vec<IndexedSignature> = signatures
            .iter()
            .filter(|(p, _, _)| *p == pool)
            .map(|(_, idx, sig)| (*idx, *sig))
            .collect();
        if for_pool.is_empty() {
            continue;
        }
        signed = match pool {
            Pool::Ironwood => signed.sign_ironwood_with(|_pczt, bundle, _| {
                apply_signatures(bundle, sighash, &for_pool)
            }),
            Pool::Orchard => signed
                .sign_orchard_with(|_pczt, bundle, _| apply_signatures(bundle, sighash, &for_pool)),
        }
        .map_err(|e| eyre!("{} (apply): {e:?}", pool.signer_name()))?;
    }

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

/// Which Orchard-protocol bundle of the transaction a spend lives in.
///
/// A v6 transaction has two such bundles and either may carry spends: a ZIP 318
/// Orchard-to-Ironwood migration spends from the *Orchard* pool while its only output is
/// in the *Ironwood* pool. The two are reached through different signer entry points, and
/// asking for the wrong one yields no spends rather than an error, so the pool a spend
/// belongs to has to be tracked alongside its action index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pool {
    Orchard,
    Ironwood,
}

impl Pool {
    /// The `pczt` signer entry point for this pool, for use in error messages.
    fn signer_name(self) -> &'static str {
        match self {
            Pool::Orchard => "sign_orchard_with",
            Pool::Ironwood => "sign_ironwood_with",
        }
    }

    /// The lowercase pool name, used to disambiguate prompts.
    fn label(self) -> &'static str {
        match self {
            Pool::Orchard => "orchard",
            Pool::Ironwood => "ironwood",
        }
    }
}

/// The bundles that may carry spends in a transaction of the given version.
///
/// Before NU6.3 there is no Ironwood bundle. From v6 onward both may be populated, so both
/// are inspected; a bundle with no spends awaiting signature simply contributes none.
fn pools_for(version: TxVersion) -> &'static [Pool] {
    match version {
        TxVersion::V6 => &[Pool::Orchard, Pool::Ironwood],
        _ => &[Pool::Orchard],
    }
}

/// A spend awaiting signature: its pool, its action index within that pool's bundle, and
/// its randomizer.
type PoolRandomizer = (Pool, usize, [u8; 32]);

/// The index of an action within its bundle, paired with the 64-byte signature for it.
type IndexedSignature = (usize, [u8; 64]);

/// A signature paired with the pool and action index it applies to.
type PoolSignature = (Pool, usize, [u8; 64]);

/// Print each randomizer and read the corresponding hex-encoded signature from stdin.
fn prompt_for_signatures(
    randomizers: &[PoolRandomizer],
) -> Result<Vec<PoolSignature>, Box<dyn Error>> {
    let mut signatures = vec![];
    for (pool, idx, alpha) in randomizers {
        let pool_label = pool.label();
        println!("Randomizer #{idx} ({pool_label}): {}", hex::encode(alpha));
        println!("Input hex-encoded signature #{idx} ({pool_label}): ");
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;
        let signature = hex::decode(buffer.trim())?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| eyre!("signature #{idx} must be 64 bytes"))?;
        signatures.push((*pool, *idx, signature));
    }
    Ok(signatures)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real, proven, not-yet-signed v6 Ironwood PCZT: the one that became testnet
    /// transaction `a5533fe75575b09d8986a05005d2c0528cf45a1a7e4cc71b304ae76a9e14487d`,
    /// whose Orchard spend was authorized by a 2-of-3 rerandomized FROST signature.
    const IRONWOOD_V6_PCZT: &[u8] = include_bytes!("../tests/fixtures/ironwood_v6.pczt");

    /// The v6 sighash that transaction was actually signed against. For a fully
    /// shielded transaction with no transparent inputs, ZIP 244 makes the txid the
    /// byte-reversal of this value, which is how it can be checked against the chain.
    const IRONWOOD_V6_SIGHASH: &str =
        "7d48149e6ae74a301bc74c7e1a5af48c52c0d20550a086899db07555e73f53a5";

    fn fixture() -> Pczt {
        Pczt::parse(IRONWOOD_V6_PCZT).expect("fixture is a valid PCZT")
    }

    #[test]
    fn ironwood_fixture_is_a_v6_transaction() {
        let (version, _) = sighash_for_pczt(&fixture()).expect("fixture yields a sighash");
        assert_eq!(
            version,
            TxVersion::V6,
            "Ironwood spends must be carried in v6 transactions"
        );
    }

    /// The dispatch must select the v6 sighash for a v6 transaction. This is the
    /// regression guard: `apply_signature` verifies a signature against whatever
    /// sighash it is handed, so signing a v6 transaction with the v5 hash succeeds
    /// locally and is only rejected at broadcast, as `SighashMismatch`.
    #[test]
    fn v6_transaction_gets_the_v6_sighash() {
        let (_, sighash) = sighash_for_pczt(&fixture()).expect("fixture yields a sighash");
        assert_eq!(hex::encode(sighash), IRONWOOD_V6_SIGHASH);
    }

    /// The failure this dispatch exists to prevent: the v5 hash over the same
    /// transaction is a different value, so using it would produce a signature the
    /// extractor rejects.
    #[test]
    fn v5_sighash_over_a_v6_transaction_is_wrong() {
        let tx_data = fixture()
            .into_effects()
            .expect("fixture yields transaction effects");
        let txid_parts = tx_data.digest(TxIdDigester);
        let v5 = v5_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts);
        assert_ne!(
            hex::encode(v5.as_ref()),
            IRONWOOD_V6_SIGHASH,
            "if these ever match, this test no longer guards anything"
        );
    }
}
