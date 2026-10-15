//! ZIP 2005 key derivation vectors for FROST-controlled accounts with `use_qsk = true`
//! (ZIP 2005 § 4.2.3, "Usage with FROST").
//!
//! `ak` comes from the FROST group key; the participants agree on a secret `sk` and
//! derive the rest of the full viewing key from it:
//!
//! ```text
//! nk       = ToBase(PRF^expand_sk([0x07]))
//! qsk      = truncate_32(PRF^expand_sk([0x0C]))
//! qk       = BLAKE3.derive_key("Zcash ZIP 2005 qk-derivation v1", qsk)
//! rivk_ext = ToScalar(PRF^expand_qk([0x0D] || ak || nk))
//! fvk      = ak || nk || rivk_ext
//! ```
//!
//! This test recomputes every field of each vector from `(sk, ak)` using only the hash
//! functions and field arithmetic, then checks that `FullViewingKey::from_bytes` accepts
//! the result and gives the expected default address and UFVK.

use blake2b_simd::Params;
use ff::{FromUniformBytes, PrimeField};
use orchard::keys::{FullViewingKey, Scope};
use pasta_curves::pallas;
use serde_json::Value;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::Network;

const VECTORS: &str = include_str!("fixtures/zip2005_use_qsk.json");
const QK_CONTEXT: &str = "Zcash ZIP 2005 qk-derivation v1";

fn prf_expand(key: &[u8], t: &[&[u8]]) -> [u8; 64] {
    let mut state = Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .to_state();
    state.update(key);
    for part in t {
        state.update(part);
    }
    *state.finalize().as_array()
}

fn field(vector: &Value, name: &str) -> Vec<u8> {
    hex::decode(vector[name].as_str().unwrap()).unwrap()
}

#[test]
fn zip2005_use_qsk_vectors() {
    let data: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(data["qk_context"], QK_CONTEXT);
    let vectors = data["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());

    for (i, v) in vectors.iter().enumerate() {
        let sk = field(v, "sk");
        let ak = field(v, "ak");
        // A FROST group key used as `ak` must have ỹ = 0.
        assert_eq!(ak[31] & 0x80, 0, "vector {i}: ak has ỹ = 1");

        let nk = pallas::Base::from_uniform_bytes(&prf_expand(&sk, &[&[0x07]])).to_repr();
        let qsk: [u8; 32] = prf_expand(&sk, &[&[0x0C]])[..32].try_into().unwrap();
        let qk = blake3::derive_key(QK_CONTEXT, &qsk);
        let rivk_ext =
            pallas::Scalar::from_uniform_bytes(&prf_expand(&qk, &[&[0x0D], &ak, &nk])).to_repr();

        assert_eq!(nk.to_vec(), field(v, "nk"), "vector {i}: nk");
        assert_eq!(qsk.to_vec(), field(v, "qsk"), "vector {i}: qsk");
        assert_eq!(qk.to_vec(), field(v, "qk"), "vector {i}: qk");
        assert_eq!(
            rivk_ext.to_vec(),
            field(v, "rivk_ext"),
            "vector {i}: rivk_ext"
        );

        let fvk_bytes: [u8; 96] = [ak.as_slice(), &nk, &rivk_ext].concat().try_into().unwrap();
        assert_eq!(fvk_bytes.to_vec(), field(v, "fvk"), "vector {i}: fvk");

        let fvk = FullViewingKey::from_bytes(&fvk_bytes).expect("valid full viewing key");
        let address = fvk.address_at(0u64, Scope::External);
        assert_eq!(
            address.to_raw_address_bytes().to_vec(),
            field(v, "default_address_raw"),
            "vector {i}: default address"
        );

        let ufvk = UnifiedFullViewingKey::new(None, Some(fvk)).unwrap();
        assert_eq!(
            ufvk.encode(&Network::TestNetwork),
            v["ufvk_testnet"].as_str().unwrap(),
            "vector {i}: UFVK"
        );
    }
}
