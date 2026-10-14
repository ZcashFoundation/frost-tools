use rand::{Rng, RngCore};

use orchard::keys::{FullViewingKey, SpendValidatingKey, SpendingKey};

/// Generate an Orchard `FullViewingKey` from the given `SpendValidatingKey`,
/// which should correspond to a FROST group public key (`VerifyingKey`).
///
/// The operation is randomized;s different calls will generate different
/// `FullViewingKey`s for different `SpendValidatingKey`s.
pub fn generate(rng: &mut impl RngCore, ak: &SpendValidatingKey) -> FullViewingKey {
    let sk = loop {
        let random_bytes = rng.gen::<[u8; 32]>();
        let sk = SpendingKey::from_bytes(random_bytes);
        if sk.is_some().into() {
            break sk.unwrap();
        }
    };

    // Conrado (ZF) directed us to keep this non-quantum-recoverable constructor
    // for now (frost-tools#591); it is the same key derivation, only renamed
    // upstream with strong caveats. Quantum recoverability is deferred.
    FullViewingKey::from_sk_ak_incompatible_with_quantum_recoverability_and_will_be_removed(
        &sk,
        ak.clone(),
    )
}
