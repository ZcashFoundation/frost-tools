//! Code required to parse and handle a YWallet transaction plan.
//! Mostly copied from YWallet codebase.
#![allow(clippy::all)]
#![allow(warnings)]

use std::io::Read;

use halo2_gadgets::sinsemilla::primitives::SINSEMILLA_S;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::CurveExt as _;
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::pasta::group::prime::PrimeCurveAffine;
use halo2_proofs::pasta::group::Curve;
use halo2_proofs::pasta::pallas;
use halo2_proofs::pasta::pallas::Affine;
use halo2_proofs::pasta::pallas::Point;
use halo2_proofs::pasta::EpAffine;
use serde::{Deserialize, Serialize};
use serde_hex::SerHex;
use serde_hex::Strict;
use serde_with::serde_as;
use zcash_encoding::Optional;
use zcash_encoding::Vector;
use zcash_protocol::memo::MemoBytes;
use zcash_transparent::address::TransparentAddress;

pub type Hash = [u8; 32];

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UTXO {
    pub id: u32,
    pub source: Source,
    pub amount: u64,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum Source {
    Transparent {
        #[serde(with = "SerHex::<Strict>")]
        txid: [u8; 32],
        index: u32,
    },
    Sapling {
        id_note: u32,
        #[serde(with = "SerHex::<Strict>")]
        diversifier: [u8; 11],
        #[serde(with = "SerHex::<Strict>")]
        rseed: [u8; 32],
        #[serde_as(as = "serde_with::hex::Hex")]
        witness: Vec<u8>,
    },
    Orchard {
        id_note: u32,
        #[serde(with = "SerHex::<Strict>")]
        diversifier: [u8; 11],
        #[serde(with = "SerHex::<Strict>")]
        rseed: [u8; 32],
        #[serde(with = "SerHex::<Strict>")]
        rho: [u8; 32],
        #[serde_as(as = "serde_with::hex::Hex")]
        witness: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fill {
    pub id_order: Option<u32>,
    pub destination: Destination,
    pub amount: u64,
    #[serde(with = "MemoBytesProxy")]
    pub memo: MemoBytes,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "MemoBytes")]
pub struct MemoBytesProxy(#[serde(getter = "get_memo_bytes")] pub String);

fn get_memo_bytes(memo: &MemoBytes) -> String {
    hex::encode(memo.as_slice())
}

impl From<MemoBytesProxy> for MemoBytes {
    fn from(p: MemoBytesProxy) -> MemoBytes {
        MemoBytes::from_bytes(&hex::decode(&p.0).unwrap()).unwrap()
    }
}

/// Errors that may result from attempting to construct an invalid memo.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidUtf8(std::str::Utf8Error),
    TooLong(usize),
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
#[serde_as]
pub enum Destination {
    Transparent(#[serde(with = "SerHex::<Strict>")] [u8; 21]), // t1/t3 + Hash
    Sapling(#[serde(with = "SerHex::<Strict>")] [u8; 43]),     // Diversifier + Jubjub Point
    Orchard(#[serde(with = "SerHex::<Strict>")] [u8; 43]),     // Diviersifer + Pallas Point
}

impl Destination {
    pub fn from_transparent(ta: &TransparentAddress) -> Self {
        let mut d = [0u8; 21];
        match ta {
            TransparentAddress::PublicKeyHash(data) => {
                d[0] = 0;
                d[1..21].copy_from_slice(&*data);
            }
            TransparentAddress::ScriptHash(data) => {
                d[0] = 1;
                d[1..21].copy_from_slice(&*data);
            }
        }
        Destination::Transparent(d)
    }

    pub fn transparent(&self) -> TransparentAddress {
        match self {
            Destination::Transparent(data) => {
                let hash: [u8; 20] = data[1..21].try_into().unwrap();
                let ta = if data[0] == 0 {
                    TransparentAddress::PublicKeyHash(hash)
                } else {
                    TransparentAddress::ScriptHash(hash)
                };
                ta
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde_as]
pub struct TransactionPlan {
    pub taddr: String,
    pub fvk: String,
    pub orchard_fvk: String,
    pub anchor_height: u32,
    pub expiry_height: u32,
    #[serde(with = "SerHex::<Strict>")]
    pub orchard_anchor: Hash,
    pub spends: Vec<UTXO>,
    pub outputs: Vec<Fill>,
    pub fee: u64,
    pub net_chg: [i64; 2],
}

#[derive(Clone)]
pub struct Witness {
    pub position: usize,
    pub tree: CTree, // commitment tree at the moment the witness is created: immutable
    pub filled: Vec<Node>, // as more nodes are added, levels get filled up: won't change anymore
    pub cursor: CTree, // partial tree which still updates when nodes are added

    // not used for decryption but identifies the witness
    pub id_note: u32,
    pub cmx: [u8; 32],
}

#[derive(Clone)]
pub struct CTree {
    pub left: Option<Node>,
    pub right: Option<Node>,
    pub parents: Vec<Option<Node>>,
}

fn node_read<R: Read>(mut r: R) -> std::io::Result<Node> {
    let mut hash = [0u8; 32];
    r.read_exact(&mut hash)?;
    Ok(hash)
}

impl CTree {
    pub fn new() -> Self {
        CTree {
            left: None,
            right: None,
            parents: vec![],
        }
    }

    pub fn get_position(&self) -> usize {
        let mut p = 0usize;
        for parent in self.parents.iter().rev() {
            if parent.is_some() {
                p += 1;
            }
            p *= 2;
        }
        if self.left.is_some() {
            p += 1;
        }
        if self.right.is_some() {
            p += 1;
        }
        p
    }

    pub fn root<H: Hasher>(&self, height: usize, empty_roots: &[Node], hasher: &H) -> Node {
        if self.left.is_none() {
            return empty_roots[height];
        }
        // merge the leaves
        let left = self.left.unwrap_or(H::uncommited_node());
        let right = self.right.unwrap_or(H::uncommited_node());
        let mut cur = hasher.node_combine(0, &left, &right);
        // merge the parents
        let mut depth = 1u8;
        for p in self.parents.iter() {
            if let Some(ref left) = p {
                cur = hasher.node_combine(depth, left, &cur);
            } else {
                cur = hasher.node_combine(depth, &cur, &empty_roots[depth as usize]);
            }
            depth += 1;
        }
        // fill in the missing levels
        for d in depth as usize..height {
            cur = hasher.node_combine(d as u8, &cur, &empty_roots[d]);
        }
        cur
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let left = Optional::read(&mut reader, node_read)?;
        let right = Optional::read(&mut reader, node_read)?;
        let parents = Vector::read(&mut reader, |r| Optional::read(r, node_read))?;

        Ok(CTree {
            left,
            right,
            parents,
        })
    }
}

pub type Node = [u8; 32];

impl Witness {
    pub fn new(position: usize, id_note: u32, cmx: &[u8; 32]) -> Witness {
        Witness {
            position,
            id_note,
            tree: CTree::new(),
            filled: vec![],
            cursor: CTree::new(),
            cmx: cmx.clone(),
        }
    }

    pub fn auth_path<H: Hasher>(
        &self,
        height: usize,
        empty_roots: &[Node],
        hasher: &H,
    ) -> Vec<Node> {
        let mut filled_iter = self.filled.iter();
        let mut cursor_used = false;
        let mut next_filler = move |depth: usize| {
            if let Some(f) = filled_iter.next() {
                *f
            } else if !cursor_used {
                cursor_used = true;
                self.cursor.root(depth, empty_roots, hasher)
            } else {
                empty_roots[depth]
            }
        };

        let mut auth_path = vec![];
        if let Some(left) = self.tree.left {
            if self.tree.right.is_some() {
                auth_path.push(left);
            } else {
                auth_path.push(next_filler(0));
            }
        }
        for i in 1..height {
            let p = if i - 1 < self.tree.parents.len() {
                self.tree.parents[i - 1]
            } else {
                None
            };

            if let Some(node) = p {
                auth_path.push(node);
            } else {
                auth_path.push(next_filler(i));
            }
        }
        auth_path
    }

    pub fn read<R: Read>(id_note: u32, mut reader: R) -> std::io::Result<Self> {
        let tree = CTree::read(&mut reader)?;
        let filled = Vector::read(&mut reader, |r| node_read(r))?;
        let cursor = Optional::read(&mut reader, |r| CTree::read(r))?;
        let mut cmx = [0u8; 32];
        reader.read_exact(&mut cmx)?;

        let mut witness = Witness {
            position: 0,
            id_note,
            tree,
            filled,
            cursor: cursor.unwrap_or_else(CTree::new),
            cmx,
        };
        witness.position = witness.tree.get_position() - 1;

        Ok(witness)
    }

    pub fn from_bytes(id_note: u32, bytes: &[u8]) -> std::io::Result<Self> {
        Self::read(id_note, bytes)
    }
}

#[derive(Clone)]
pub struct OrchardHasher {
    Q: Point,
}

pub const Q_PERSONALIZATION: &str = "z.cash:SinsemillaQ";
pub const MERKLE_CRH_PERSONALIZATION: &str = "z.cash:Orchard-MerkleCRH";

impl OrchardHasher {
    pub fn new() -> Self {
        let Q: Point =
            Point::hash_to_curve(Q_PERSONALIZATION)(MERKLE_CRH_PERSONALIZATION.as_bytes());
        OrchardHasher { Q }
    }

    fn node_combine_inner(&self, depth: u8, left: &Node, right: &Node) -> Point {
        let mut acc = self.Q;
        let (S_x, S_y) = SINSEMILLA_S[depth as usize];
        let S_chunk = Affine::from_xy(S_x, S_y).unwrap();
        acc = (acc + S_chunk) + acc; // TODO Bail if + gives point at infinity? Shouldn't happen if data was validated

        // Shift right by 1 bit and overwrite the 256th bit of left
        let mut left = *left;
        let mut right = *right;
        left[31] |= (right[0] & 1) << 7; // move the first bit of right into 256th of left
        for i in 0..32 {
            // move by 1 bit to fill the missing 256th bit of left
            let carry = if i < 31 { (right[i + 1] & 1) << 7 } else { 0 };
            right[i] = right[i] >> 1 | carry;
        }

        // we have 255*2/10 = 51 chunks
        let mut bit_offset = 0;
        let mut byte_offset = 0;
        for _ in 0..51 {
            let mut v = if byte_offset < 31 {
                left[byte_offset] as u16 | (left[byte_offset + 1] as u16) << 8
            } else if byte_offset == 31 {
                left[31] as u16 | (right[0] as u16) << 8
            } else {
                right[byte_offset - 32] as u16 | (right[byte_offset - 31] as u16) << 8
            };
            v = v >> bit_offset & 0x03FF; // keep 10 bits
            let (S_x, S_y) = SINSEMILLA_S[v as usize];
            let S_chunk = Affine::from_xy(S_x, S_y).unwrap();
            acc = (acc + S_chunk) + acc;
            bit_offset += 10;
            if bit_offset >= 8 {
                byte_offset += bit_offset / 8;
                bit_offset %= 8;
            }
        }
        acc
    }
}

pub trait Hasher: Clone + Sync {
    type Extended: Curve + Clone + Send;

    fn uncommited_node() -> Node;
    fn node_combine(&self, depth: u8, left: &Node, right: &Node) -> Node;

    fn node_combine_extended(&self, depth: u8, left: &Node, right: &Node) -> Self::Extended;
    fn normalize(&self, extended: &[Self::Extended]) -> Vec<Node>;

    fn empty_roots(&self, height: usize) -> Vec<Hash> {
        let mut roots = vec![];
        let mut cur = Self::uncommited_node();
        roots.push(cur);
        for depth in 0..height {
            cur = self.node_combine(depth as u8, &cur, &cur);
            roots.push(cur);
        }
        roots
    }
}

impl Hasher for OrchardHasher {
    type Extended = Point;

    fn uncommited_node() -> Node {
        pallas::Base::from(2).to_repr()
    }

    fn node_combine(&self, depth: u8, left: &Node, right: &Node) -> Node {
        let acc = self.node_combine_inner(depth, left, right);
        let p = acc
            .to_affine()
            .coordinates()
            .map(|c| *c.x())
            .unwrap_or_else(pallas::Base::zero);
        p.to_repr()
    }

    fn node_combine_extended(&self, depth: u8, left: &Node, right: &Node) -> Self::Extended {
        self.node_combine_inner(depth, left, right)
    }

    fn normalize(&self, extended: &[Self::Extended]) -> Vec<Node> {
        let mut hash_affine = vec![EpAffine::identity(); extended.len()];
        Point::batch_normalize(extended, &mut hash_affine);
        hash_affine
            .iter()
            .map(|p| {
                p.coordinates()
                    .map(|c| *c.x())
                    .unwrap_or_else(pallas::Base::zero)
                    .to_repr()
            })
            .collect()
    }
}
