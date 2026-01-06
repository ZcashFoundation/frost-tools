use std::error::Error;
use std::io::stdin;
use std::rc::Rc;

use eyre::eyre;
use eyre::Context;
use eyre::OptionExt;
use reddsa::frost::redpallas::PallasBlake2b512;
use reqwest::Url;

use frost_core::keys::KeyPackage;
use frost_core::Ciphersuite;
use frost_ed25519::Ed25519Sha512;
use frost_rerandomized::RandomizedCiphersuite;
use serde::Deserialize;
use serde::Serialize;

use super::{args::Command, config::Config};

use crate::api::SendSigningPackageArgs;
use crate::participant::args;
use crate::participant::cli::participant;
use crate::participant::comms::http::HTTPComms;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ParsedAuxMsg<'a> {
    pub content_type: &'a str,
    pub data: Option<&'a [u8]>,
}

fn parse_aux_msg(aux_msg: &[u8]) -> Result<ParsedAuxMsg<'_>, Box<dyn Error>> {
    let parsed: ParsedAuxMsg = postcard::from_bytes(aux_msg)?;
    Ok(parsed)
}

fn confirm_message<C: Ciphersuite>(args: &SendSigningPackageArgs<C>) -> bool {
    let aux_msg = match parse_aux_msg(&args.aux_msg) {
        Err(_) => {
            eprintln!("Warning: Unable to parse auxiliary message.");
            return false;
        }
        Ok(aux_msg) => aux_msg,
    };
    if aux_msg.content_type == zcash_sign::PCZT_CONTENT_TYPE {
        // For PCZT, all messages are sighashes, and they should all be the same
        let signed_sighash = args.signing_package[0].message();
        if args
            .signing_package
            .iter()
            .all(|sp| sp.message() != signed_sighash)
        {
            eprintln!("Warning: Inconsistent sighashes in signing packages.");
            return false;
        }
        match zcash_sign::confirm::confirm(signed_sighash, aux_msg.data.unwrap_or_default()) {
            Err(_) => {
                eprintln!("Warning: The computed sighash does not match the provided sighash.");
                return false;
            }
            Ok(parsed_pczt) => {
                parsed_pczt.print_effects(None).unwrap();
            }
        }
        eprintln!("Do you want to sign the above transaction? (y/n)");
        let mut sign_it = String::new();
        stdin().read_line(&mut sign_it).unwrap();
        if sign_it.trim() != "y" {
            return false;
        }
        return true;
    }
    for signing_package in &args.signing_package {
        eprintln!(
            "Message to be signed (hex-encoded):\n{}\nDo you want to sign it? (y/n)",
            hex::encode(signing_package.message())
        );
        let mut sign_it = String::new();
        stdin().read_line(&mut sign_it).unwrap();
        if sign_it.trim() != "y" {
            return false;
        }
    }
    true
}

pub async fn run(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Participant { config, group, .. } = (*args).clone() else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let group = config.group.get(&group).ok_or_eyre("Group not found")?;

    if group.ciphersuite == Ed25519Sha512::ID {
        run_for_ciphersuite::<Ed25519Sha512>(args).await
    } else if group.ciphersuite == PallasBlake2b512::ID {
        run_for_ciphersuite::<PallasBlake2b512>(args).await
    } else {
        Err(eyre!("unsupported ciphersuite").into())
    }
}

pub(crate) async fn run_for_ciphersuite<C: RandomizedCiphersuite + 'static>(
    args: &Command,
) -> Result<(), Box<dyn Error>> {
    let Command::Participant {
        config,
        server_url,
        group,
        session,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let group = config.group.get(&group).ok_or_eyre("Group not found")?;

    let key_package: KeyPackage<C> = postcard::from_bytes(&group.key_package)?;

    let server_url = if let Some(server_url) = server_url {
        server_url
    } else {
        group.server_url.clone().ok_or_eyre("server-url required")?
    };
    let server_url_parsed =
        Url::parse(&format!("https://{server_url}")).wrap_err("error parsing server-url")?;

    let group_participants = group.participant.clone();

    let pargs = args::ProcessedArgs { key_package };

    let args = crate::participant::comms::http::Args {
        ip: server_url_parsed
            .host_str()
            .ok_or_eyre("host missing in URL")?
            .to_owned(),
        port: server_url_parsed
            .port_or_known_default()
            .expect("always works for https"),
        session_id: session.unwrap_or_default(),
        comm_privkey: Some(
            config
                .communication_key
                .clone()
                .ok_or_eyre("user not initialized")?
                .privkey
                .clone(),
        ),
        comm_pubkey: Some(
            config
                .communication_key
                .ok_or_eyre("user not initialized")?
                .pubkey
                .clone(),
        ),
        comm_coordinator_pubkey_getter: Some(Rc::new(move |coordinator_pubkey| {
            group_participants
                .values()
                .find(|p| p.pubkey == *coordinator_pubkey)
                .map(|p| p.pubkey.clone())
        })),
        confirm_message_callback: Rc::new(confirm_message::<C>),
    };

    let mut comms = HTTPComms::new(&args)?;

    participant(&mut comms, pargs).await?;

    Ok(())
}
