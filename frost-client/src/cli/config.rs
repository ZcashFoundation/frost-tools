// Remove after https://github.com/rust-lang/rust/issues/147648 is fixed
#![allow(unused_assignments)]

use core::str;
use std::{
    collections::BTreeMap,
    error::Error,
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::cipher::{PrivateKey, PublicKey};
use eyre::{eyre, OptionExt};
use frost_core::{Ciphersuite, Identifier};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{ciphersuite_helper::ciphersuite_helper, contact::Contact, write_atomic};

/// The config file, which is serialized with serde.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Config {
    /// The path the config was loaded from.
    #[serde(skip)]
    path: Option<PathBuf>,
    pub version: u8,
    /// The communication key pair for the user.
    pub communication_key: Option<CommunicationKey>,
    /// The address book of the user, keyed by each contact's name.
    #[serde(default)]
    pub contact: BTreeMap<String, Contact>,
    /// The FROST groups the user belongs to, keyed by hex-encoded verifying key
    #[serde(default)]
    pub group: BTreeMap<String, Group>,
}

impl Zeroize for Config {
    fn zeroize(&mut self) {
        self.group.iter_mut().for_each(|(_, g)| g.zeroize());
    }
}

impl ZeroizeOnDrop for Config {}

impl Config {
    pub fn contact_by_pubkey(&self, pubkey: &PublicKey) -> Result<Contact, Box<dyn Error>> {
        if Some(pubkey) == self.communication_key.as_ref().map(|c| &c.pubkey) {
            return Ok(Contact {
                version: Some(0),
                name: "".to_string(),
                pubkey: pubkey.clone(),
            });
        }
        Ok(self
            .contact
            .values()
            .find(|c| c.pubkey == *pubkey)
            .cloned()
            .ok_or_eyre("contact not found")?)
    }
}

/// The communication key pair for the user.
#[derive(Clone, Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct CommunicationKey {
    /// The private key.
    pub privkey: PrivateKey,
    /// The public key.
    pub pubkey: PublicKey,
}

/// A FROST group the user belongs to.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize)]
pub struct Group {
    /// A human-readable description of the group to make it easier to select
    /// groups
    pub description: String,
    /// The ciphersuite being used for the group
    pub ciphersuite: String,
    /// The encoded public key package for the group.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub public_key_package: Vec<u8>,
    /// The user's encoded key package for the group.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub key_package: Vec<u8>,
    /// The default server the participants are using, if any.
    pub server_url: Option<String>,
    /// The group participants, keyed by hex-encoded identifier
    #[zeroize(skip)]
    pub participant: BTreeMap<String, Participant>,
}

impl ZeroizeOnDrop for Group {}

impl Group {
    /// Returns a human-readable summary of the contact; used when it is
    /// printed to the terminal.
    pub fn as_human_readable_summary(&self, config: &Config) -> Result<String, Box<dyn Error>> {
        let helper = ciphersuite_helper(&self.ciphersuite)?;
        let info = helper.group_info(&self.key_package, &self.public_key_package)?;
        let mut s = format!(
            "Group \"{}\"\nPublic key {}\nServer URL: {}\nThreshold: {}\nParticipants: {}\n",
            self.description,
            info.hex_verifying_key,
            self.server_url.clone().unwrap_or_default(),
            info.threshold,
            info.num_participants
        );
        for participant in self.participant.values() {
            let contact = config.contact_by_pubkey(&participant.pubkey)?;
            s += &format!("\t{}\t({})\n", contact.name, hex::encode(contact.pubkey.0));
        }
        Ok(s)
    }

    /// Get a group participant by their pubkey.
    pub fn participant_by_pubkey(&self, pubkey: &PublicKey) -> Result<Participant, Box<dyn Error>> {
        Ok(self
            .participant
            .values()
            .find(|p| p.pubkey == *pubkey)
            .cloned()
            .ok_or_eyre("Participant not found")?)
    }
}

/// A FROST group participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    /// The identifier of the participant in the group.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub identifier: Vec<u8>,
    /// The communication public key for the participant.
    pub pubkey: PublicKey,
}

impl Participant {
    /// Return the parsed identifier for the participant.
    pub fn identifier<C: Ciphersuite>(&self) -> Result<Identifier<C>, Box<dyn std::error::Error>> {
        Ok(Identifier::<C>::deserialize(&self.identifier)?)
    }
}

impl Config {
    /// Returns the default path of the config
    /// ($HOME/.config/frost/credentials.toml in Linux) if `path` is None,
    /// otherwise parse the given path and return it.
    pub fn parse_path(path: Option<String>) -> Result<PathBuf, Box<dyn Error>> {
        if let Some(path) = path {
            Ok(PathBuf::from_str(&path)?)
        } else {
            Ok(dirs::config_local_dir()
                .unwrap()
                .join("frost")
                .join("credentials.toml"))
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Read the config from given path, or the default path if None.
    /// If the path does not exist, it will load a default (empty) config.
    /// Calling `write()` later will write to the specified path.
    pub fn read(path: Option<String>) -> Result<Self, Box<dyn Error>> {
        let path = Self::parse_path(path)?;
        if !path.exists() {
            return Ok(Config {
                path: Some(path),
                ..Default::default()
            });
        }
        let bytes = Zeroizing::new(std::fs::read(&path)?);
        let s = str::from_utf8(&bytes)?;
        let mut config: Config = toml::from_str(s)?;
        config.path = Some(path);
        Ok(config)
    }

    /// Write the config to path it was loaded from.
    pub fn write(&self) -> Result<(), Box<dyn Error>> {
        let s = Zeroizing::new(toml::to_string_pretty(self)?);
        let bytes = s.as_bytes();
        Ok(write_atomic::write_file(
            self.path
                .clone()
                .ok_or_else(|| eyre!("path not specified"))?,
            bytes,
        )?)
    }
}
