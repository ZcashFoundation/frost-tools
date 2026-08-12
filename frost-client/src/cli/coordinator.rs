use std::collections::HashMap;
use std::error::Error;
use std::fs;

use eyre::eyre;
use eyre::Context;
use eyre::OptionExt;
use frost_core::Signature;

use crate::cipher::PublicKey;
use crate::coordinator::comms::http::HTTPComms;
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

#[derive(clap::Args, Clone, Debug)]
pub struct CoordinatorCommand {
    /// The path to the config file to manage. If not specified, it uses
    /// $HOME/.local/frost/credentials.toml
    #[arg(short, long)]
    pub config: Option<String>,
    /// The server URL to use. If not specified, it will use the server URL
    /// for the specified group, if any.
    #[arg(short, long)]
    pub server_url: Option<String>,
    /// The group to use, identified by the group public key (use `groups`
    /// to list)
    #[arg(short, long)]
    pub group: String,
    /// The comma-separated hex-encoded public keys of the signers to use.
    #[arg(short = 'S', long, value_delimiter = ',')]
    pub signers: Vec<String>,
    /// The messages to sign. Each instance can be a file with the raw message,
    /// "" or "-". If "" or "-" is specified, then it will be read from standard
    /// input as a hex string. If none are passed, a single one will be read
    /// from standard input as a hex string.
    #[arg(short = 'm', long)]
    pub message: Vec<String>,
    /// The randomizers to use. Each instance can be a file with the raw
    /// randomizer, "" or "-". If "" or "-" is specified, then it will be
    /// read from standard input as a hex string. If none are passed, random
    /// ones will be generated if the ciphersuite is redpallas. If one or
    /// more are passed, the number should match the `message` parameter.
    #[arg(short = 'r', long)]
    pub randomizer: Vec<String>,
    /// Where to write the generated raw bytes signature. If "-", the
    /// human-readable hex-string is printed to stdout.
    #[arg(short = 'o', long, default_value = "")]
    pub signature: String,
}

pub async fn run(args: &Command) -> Result<Vec<u8>, Box<dyn Error>> {
    let Command::Coordinator(CoordinatorCommand { config, group, .. }) = (*args).clone() else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let group = config.group.get(&group).ok_or_eyre("Group not found")?;

    let signature = if group.ciphersuite == Ed25519Sha512::ID {
        run_for_ciphersuite::<Ed25519Sha512>(args)
            .await?
            .serialize()?
    } else if group.ciphersuite == PallasBlake2b512::ID {
        run_for_ciphersuite::<PallasBlake2b512>(args)
            .await?
            .serialize()?
    } else {
        return Err(eyre!("unsupported ciphersuite").into());
    };

    Ok(signature)
}

pub(crate) async fn run_for_ciphersuite<C: RandomizedCiphersuite + 'static>(
    args: &Command,
) -> Result<Signature<C>, Box<dyn Error>> {
    let Command::Coordinator(CoordinatorCommand {
        config,
        server_url,
        group,
        signers,
        message,
        randomizer,
        signature: signature_fn,
    }) = (*args).clone()
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
        num_signers,
        public_key_package,
        messages: args::read_messages(&message, &mut output, &mut input)?,
        randomizers: args::read_randomizers(&randomizer, &mut output, &mut input)?,
    };

    let args = crate::coordinator::comms::http::Args {
        signers,
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

    let mut comms = HTTPComms::new(&pargs, &args)?;

    let signature = cli::coordinator(&mut comms, pargs).await?;

    let serialized_signature = signature.serialize()?;
    if signature_fn.is_empty() || signature_fn == "-" {
        println!("{}", hex::encode(&serialized_signature));
    } else {
        fs::write(&signature_fn, &serialized_signature)?;
        eprintln!("Raw signature written to {}", signature_fn);
    }
    Ok(signature)
}
