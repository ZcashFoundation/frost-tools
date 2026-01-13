use std::collections::HashMap;
use std::error::Error;

use eyre::eyre;
use eyre::Context;
use eyre::OptionExt;
use frost_core::Signature;
use frost_rerandomized::Randomizer;
use serde::Deserialize;
use serde::Serialize;
use zcash_sign::confirm::ParsedPczt;

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

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ParsedAuxMsg<'a> {
    pub content_type: &'a str,
    pub data: Option<&'a [u8]>,
}

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
    /// An optional auxiliary message to include in the signing package.
    #[arg(short = 'a', long)]
    pub aux_message: Option<String>,
    /// The content type of the messages. Defaults to
    /// "application/octet-stream". If "application/vnd.zcash.pczt" is
    /// specified, the messages and randomizers must be empty, and the
    /// `aux_message` argument must contain a PCZT file. The signed PCZT will be
    /// written to the file specified by the `signature` argument.
    #[arg(short = 't', long, default_value = "application/octet-stream")]
    pub content_type: String,
    /// Where to write the generated raw bytes signatures. Each instance can be
    /// a file path where the raw signature will be written, or "-". If "-" is
    /// specified, the human-readable hex-string is printed to stdout.
    #[arg(short = 'o', long, default_value = "")]
    pub signature: Vec<String>,
}

pub async fn run(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Coordinator(CoordinatorCommand { config, group, .. }) = (*args).clone() else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let group = config.group.get(&group).ok_or_eyre("Group not found")?;

    if group.ciphersuite == Ed25519Sha512::ID {
        run_for_ciphersuite::<Ed25519Sha512>(args).await?
    } else if group.ciphersuite == PallasBlake2b512::ID {
        run_for_ciphersuite::<PallasBlake2b512>(args).await?
    } else {
        return Err(eyre!("unsupported ciphersuite").into());
    };

    Ok(())
}

pub(crate) async fn run_for_ciphersuite<C: RandomizedCiphersuite + 'static>(
    args: &Command,
) -> Result<(), Box<dyn Error>> {
    let Command::Coordinator(cmd) = args else {
        panic!("invalid Command");
    };
    let CoordinatorCommand {
        config,
        server_url,
        group,
        signers,
        message: _,
        randomizer: _,
        signature: _,
        aux_message: _,
        content_type,
    } = cmd.clone();

    let config = Config::read(config)?;

    let group = config.group.get(&group).ok_or_eyre("Group not found")?;

    let public_key_package: PublicKeyPackage<C> = postcard::from_bytes(&group.public_key_package)?;

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

    let signing_inputs = read_signing_inputs::<C>(cmd)?;

    let pargs = args::ProcessedArgs {
        num_signers,
        public_key_package,
        messages: signing_inputs.messages.clone(),
        randomizers: signing_inputs.randomizers.clone(),
        aux_msg: signing_inputs.aux_msg.clone(),
        content_type,
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

    let signatures = cli::coordinator(&mut comms, pargs).await?;

    write_signing_outputs(cmd, &signing_inputs, signatures)?;

    Ok(())
}

struct SigningInputs<C: frost_core::Ciphersuite> {
    messages: Vec<Vec<u8>>,
    randomizers: Vec<Randomizer<C>>,
    aux_msg: Option<Vec<u8>>,
}

fn read_signing_inputs<C: frost_core::Ciphersuite>(
    cmd: &CoordinatorCommand,
) -> Result<SigningInputs<C>, Box<dyn Error>> {
    let mut input = Box::new(std::io::stdin().lock());
    let mut output = std::io::stdout();

    if cmd.content_type == "application/octet-stream" {
        if cmd.message.len() != cmd.signature.len() {
            return Err("Number of messages must match number of signature output files".into());
        }

        Ok(SigningInputs {
            messages: args::read_messages(&cmd.message, &mut output, &mut input)?,
            randomizers: args::read_randomizers(&cmd.randomizer, &mut output, &mut input)?,
            aux_msg: cmd
                .aux_message
                .as_ref()
                .map(|filename| args::read_aux_message(filename, &mut output, &mut input))
                .transpose()?,
        })
    } else if cmd.content_type == zcash_sign::PCZT_CONTENT_TYPE {
        if !cmd.message.is_empty() || !cmd.randomizer.is_empty() {
            return Err("For PCZT, only the aux_message must be specified with the PCZT; no messages and randomizers must be specified".into());
        }
        let filename = cmd
            .aux_message
            .as_ref()
            .ok_or_eyre("aux_message must be specified")?;
        let pczt_bytes = args::read_aux_message(filename, &mut output, &mut input)?;
        let pczt = zcash_sign::confirm::ParsedPczt::parse(&pczt_bytes)?;
        let zcash_sign::SigningInputs { sighash, alphas } =
            zcash_sign::read_pczt_signining_inputs(&pczt)?;
        Ok(SigningInputs {
            // Create a vector with sighash repeated for each alpha
            messages: vec![sighash; alphas.len()],
            randomizers: alphas
                .into_iter()
                .map(|(_idx, alpha_bytes)| {
                    let alpha_array: [u8; 32] = alpha_bytes.try_into().unwrap();
                    Randomizer::<C>::deserialize(&alpha_array).unwrap()
                })
                .collect(),
            aux_msg: Some(pczt_bytes),
        })
    } else {
        Err("content type not supported".into())
    }
}

fn write_signing_outputs<C: frost_core::Ciphersuite>(
    cmd: &CoordinatorCommand,
    inputs: &SigningInputs<C>,
    signatures: Vec<Signature<C>>,
) -> Result<(), Box<dyn Error>> {
    let signatures = signatures
        .into_iter()
        .map(|sig| sig.serialize())
        .collect::<Result<Vec<_>, frost_core::Error<C>>>()?;
    match cmd.content_type.as_str() {
        "application/octet-stream" => {
            args::write_signatures(&cmd.signature, &signatures)?;
        }
        zcash_sign::PCZT_CONTENT_TYPE => {
            let pczt = ParsedPczt::parse(
                &inputs
                    .aux_msg
                    .clone()
                    .ok_or_eyre("aux_msg must be specified")?,
            )?;
            let signed_pczt_bytes =
                zcash_sign::write_pczt_signing_outputs(&pczt, &inputs.messages[0], &signatures)?;
            args::write_signatures(&cmd.signature, &[signed_pczt_bytes])?;
        }
        _ => {
            return Err("content type not supported".into());
        }
    }
    Ok(())
}
