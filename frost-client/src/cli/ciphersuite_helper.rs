use std::{error::Error, marker::PhantomData};

use eyre::eyre;
use frost_core::{
    keys::{KeyPackage, PublicKeyPackage},
    Ciphersuite,
};
use frost_ed25519::Ed25519Sha512;
use frost_secp256k1_tr::Secp256K1Sha256TR;
use reddsa::frost::redpallas::PallasBlake2b512;

/// Additional information about a group, derived from the key packages.
#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub hex_verifying_key: String,
    pub threshold: usize,
    pub num_participants: usize,
}

/// A trait that helps obtaining ciphersuite-dependent information.
pub trait CiphersuiteHelper {
    fn group_info(
        &self,
        encoded_key_package: &[u8],
        encoded_public_key_package: &[u8],
    ) -> Result<GroupInfo, Box<dyn Error>>;
}

/// An implementation of CiphersuiteHelper that works for any Ciphersuite.
struct CiphersuiteHelperImpl<C: Ciphersuite> {
    _phantom: PhantomData<C>,
}

impl<C> Default for CiphersuiteHelperImpl<C>
where
    C: Ciphersuite,
{
    fn default() -> Self {
        Self {
            _phantom: Default::default(),
        }
    }
}

/// Get a CiphersuiteHelper for the given ciphersuite.
pub(crate) fn ciphersuite_helper(
    ciphersuite_id: &str,
) -> Result<Box<dyn CiphersuiteHelper>, Box<dyn Error>> {
    if ciphersuite_id == Ed25519Sha512::ID {
        return Ok(Box::new(CiphersuiteHelperImpl::<Ed25519Sha512>::default()));
    } else if ciphersuite_id == PallasBlake2b512::ID {
        return Ok(Box::new(
            CiphersuiteHelperImpl::<PallasBlake2b512>::default(),
        ));
    } else if ciphersuite_id == Secp256K1Sha256TR::ID {
        return Ok(Box::new(
            CiphersuiteHelperImpl::<Secp256K1Sha256TR>::default(),
        ));
    }
    Err(eyre!("invalid ciphersuite ID").into())
}

impl<C> CiphersuiteHelper for CiphersuiteHelperImpl<C>
where
    C: Ciphersuite + 'static,
{
    fn group_info(
        &self,
        encoded_key_package: &[u8],
        encoded_public_key_package: &[u8],
    ) -> Result<GroupInfo, Box<dyn Error>> {
        let key_package: KeyPackage<C> = postcard::from_bytes(encoded_key_package)?;
        let public_key_package: PublicKeyPackage<C> =
            postcard::from_bytes(encoded_public_key_package)?;
        let hex_verifying_key = hex::encode(public_key_package.verifying_key().serialize()?);
        Ok(GroupInfo {
            hex_verifying_key,
            threshold: *key_package.min_signers() as usize,
            num_participants: public_key_package.verifying_shares().len(),
        })
    }
}
