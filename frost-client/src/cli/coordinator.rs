use std::collections::HashMap;
use std::error::Error;

use eyre::eyre;
use eyre::Context;
use eyre::OptionExt;

use crate::cipher::PublicKey;
use frost_core::keys::PublicKeyPackage;
use frost_core::Ciphersuite;
use frost_ed25519::Ed25519Sha512;
use frost_rerandomized::RandomizedCiphersuite;
use reddsa::frost::redpallas::PallasBlake2b512;
use reqwest::Url;

use crate::coordinator::args;
use crate::coordinator::cli;

use super::args::Command;
use super::config::Config;

pub async fn run(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Coordinator { config, group, .. } = (*args).clone() else {
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
    let Command::Coordinator {
        config,
        server_url,
        group,
        signers,
        message,
        randomizer,
        signature,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let group = config.group.get(&group).ok_or_eyre("Group not found")?;

    let public_key_package: PublicKeyPackage<C> = postcard::from_bytes(&group.public_key_package)?;

    let mut input = Box::new(std::io::stdin().lock());
    let mut output = std::io::stdout();

    let server_url = if let Some(server_url) = server_url {
        server_url
    } else {
        group.server_url.clone().ok_or_eyre("server-url required")?
    };
    let server_url_parsed =
        Url::parse(&format!("https://{server_url}")).wrap_err("error parsing server-url")?;

    let signers = signers
        .iter()
        .map(|s| {
            let pubkey = PublicKey(hex::decode(s)?.to_vec());
            let contact = group.participant_by_pubkey(&pubkey)?;
            Ok((pubkey, contact.identifier()?))
        })
        .collect::<Result<HashMap<_, _>, Box<dyn Error>>>()?;
    let num_signers = signers.len() as u16;

    let pargs = args::ProcessedArgs {
        cli: false,
        http: true,
        signers,
        num_signers,
        public_key_package,
        messages: args::read_messages(&message, &mut output, &mut input)?,
        randomizers: args::read_randomizers(&randomizer, &mut output, &mut input)?,
        signature,
        ip: server_url_parsed
            .host_str()
            .ok_or_eyre("host missing in URL")?
            .to_owned(),
        port: server_url_parsed
            .port_or_known_default()
            .expect("always works for https"),
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
    };

    cli::cli_for_processed_args(pargs, &mut input, &mut output).await?;

    Ok(())
}
