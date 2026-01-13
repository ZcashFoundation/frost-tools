use std::{
    env,
    error::Error,
    fs,
    io::{BufRead, Write},
};

use clap::Parser;
use eyre::eyre;

use frost_core::{keys::PublicKeyPackage, Ciphersuite};
use frost_rerandomized::Randomizer;

use super::input::read_from_file_or_stdin;

#[derive(Clone, Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short = 'C', long, default_value = "ed25519")]
    pub ciphersuite: String,

    /// CLI mode. If enabled, it will prompt for inputs from stdin
    /// and print values to stdout, ignoring other flags.
    /// If false, socket communication is enabled.
    #[arg(long, default_value_t = false)]
    pub cli: bool,

    /// The comma-separated usernames of the signers to use in HTTP mode.
    /// If HTTP mode is enabled and this is empty, then the session ID
    /// will be printed and will have to be shared manually.
    #[arg(short = 'S', long, value_delimiter = ',')]
    pub signers: Vec<String>,

    /// The number of participants. If `signers` is specified, it will use the
    /// length of `signers`. Otherwise, if 0, it will prompt for a value.
    #[arg(short = 'n', long, default_value_t = 0)]
    pub num_signers: u16,

    /// Public key package to use. Can be a file with a JSON-encoded
    /// package, or "-". If the file does not exist or if "-" is specified,
    /// then it will be read from standard input.
    #[arg(short = 'P', long, default_value = "public-key-package.json")]
    pub public_key_package: String,

    /// The messages to sign. Each instance can be a file with the raw message,
    /// "" or "-". If "" or "-" is specified, then it will be read from standard
    /// input as a hex string. If none are passed, a single one will be read
    /// from standard input as a hex string.
    #[arg(short = 'm', long)]
    pub message: Vec<String>,

    /// The content type of the messages. Defaults to "application/octet-stream".
    #[arg(short = 't', long, default_value = "application/octet-stream")]
    pub content_type: String,

    /// The randomizers to use. Each instance can be a file with the raw
    /// randomizer, "" or "-". If "" or "-" is specified, then it will be read
    /// from standard input as a hex string. If none are passed, random ones
    /// will be generated. If one or more are passed, the number should match
    /// the `message` parameter.
    #[arg(short = 'r', long)]
    pub randomizer: Vec<String>,

    /// Where to write the generated raw bytes signature. If "-", the
    /// human-readable hex-string is printed to stdout.
    #[arg(short = 's', long, default_value = "")]
    pub signature: String,

    /// IP to bind to, if using socket comms.
    /// IP to connect to, if using HTTP mode.
    #[arg(short, long, default_value = "0.0.0.0")]
    pub ip: String,

    /// Port to bind to, if using socket comms.
    /// Port to connect to, if using HTTP mode.
    #[arg(short, long, default_value_t = 443)]
    pub port: u16,
}

#[derive(Clone)]
pub struct ProcessedArgs<C: Ciphersuite> {
    /// The number of participants.
    pub num_signers: u16,

    /// Public key package to use.
    pub public_key_package: PublicKeyPackage<C>,

    /// The messages to sign.
    pub messages: Vec<Vec<u8>>,

    /// The randomizers to use.
    pub randomizers: Vec<Randomizer<C>>,

    /// An optional auxiliary message to include in the signing package.
    pub aux_msg: Option<Vec<u8>>,

    /// The content type of the messages.
    pub content_type: String,
}

impl<C: Ciphersuite + 'static> ProcessedArgs<C> {
    /// Create a ProcessedArgs from a Args.
    ///
    /// Validates inputs and reads/parses arguments.
    pub fn new(
        args: &Args,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
    ) -> Result<Self, Box<dyn Error>> {
        let num_signers = if !args.signers.is_empty() {
            args.signers.len() as u16
        } else if args.num_signers == 0 {
            writeln!(output, "The number of participants: ")?;

            let mut participants = String::new();
            input.read_line(&mut participants)?;
            participants.trim().parse::<u16>()?
        } else {
            args.num_signers
        };

        let out = read_from_file_or_stdin(
            input,
            output,
            "public key package",
            &args.public_key_package,
        )?;

        let public_key_package: PublicKeyPackage<C> = serde_json::from_str(&out)?;

        let messages = read_messages(&args.message, output, input)?;

        println!("Processing randomizer {:?}", args.randomizer);
        let randomizers = read_randomizers(&args.randomizer, output, input)?;

        Ok(ProcessedArgs {
            num_signers,
            public_key_package,
            messages,
            randomizers,
            // TODO: add support
            aux_msg: None,
            content_type: args.content_type.clone(),
        })
    }
}

pub fn read_password(password_env_name: &str) -> Result<String, Box<dyn Error>> {
    if password_env_name.is_empty() {
        Ok(
            rpassword::prompt_password("Password: ")
                .map_err(|_| eyre!("Error reading password"))?,
        )
    } else {
        Ok(env::var(password_env_name).map_err(|_| eyre!("The password argument must specify the name of a environment variable containing the password"))?)
    }
}

pub fn read_messages(
    message_paths: &[String],
    output: &mut dyn Write,
    input: &mut dyn BufRead,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let messages = if message_paths.is_empty() {
        writeln!(output, "The message to be signed (hex encoded)")?;
        let mut msg = String::new();
        input.read_line(&mut msg)?;
        vec![hex::decode(msg.trim())?]
    } else {
        message_paths
            .iter()
            .map(|filename| {
                let msg = if *filename == "-" || filename.is_empty() {
                    writeln!(output, "The message to be signed (hex encoded)")?;
                    let mut msg = String::new();
                    input.read_line(&mut msg)?;
                    hex::decode(msg.trim())?
                } else {
                    eprintln!("Reading message from {}...", &filename);
                    fs::read(filename)?
                };
                Ok(msg)
            })
            .collect::<Result<_, Box<dyn Error>>>()?
    };
    Ok(messages)
}

pub fn read_aux_message(
    filename: &String,
    output: &mut dyn Write,
    input: &mut dyn BufRead,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let msg = if *filename == "-" || filename.is_empty() {
        writeln!(output, "The aux message to be sent (hex encoded)")?;
        let mut msg = String::new();
        input.read_line(&mut msg)?;
        hex::decode(msg.trim())?
    } else {
        eprintln!("Reading aux message from {}...", &filename);
        fs::read(filename)?
    };
    Ok(msg)
}

pub fn read_randomizers<C: Ciphersuite + 'static>(
    randomizer_paths: &[String],
    output: &mut dyn Write,
    input: &mut dyn BufRead,
) -> Result<Vec<Randomizer<C>>, Box<dyn Error>> {
    let randomizers = if randomizer_paths.is_empty() {
        Vec::new()
    } else {
        randomizer_paths
            .iter()
            .map(|filename| {
                let randomizer = if filename == "-" || filename.is_empty() {
                    writeln!(output, "Enter the randomizer (hex string):")?;
                    let mut randomizer = String::new();
                    input.read_line(&mut randomizer)?;
                    let bytes = hex::decode(randomizer.trim())?;
                    frost_rerandomized::Randomizer::deserialize(&bytes)?
                } else {
                    eprintln!("Reading randomizer from {}...", &filename);
                    let bytes = fs::read(filename)?;
                    frost_rerandomized::Randomizer::deserialize(&bytes)?
                };
                Ok(randomizer)
            })
            .collect::<Result<_, Box<dyn Error>>>()?
    };
    Ok(randomizers)
}

pub fn write_signatures(
    filenames: &[String],
    signatures: &[Vec<u8>],
) -> Result<(), Box<dyn Error>> {
    for (signature, signature_fn) in signatures.iter().zip(filenames.iter()) {
        if signature_fn == "-" || signature_fn.is_empty() {
            let hex_signature = hex::encode(signature);
            eprintln!("{hex_signature}");
        } else {
            fs::write(signature_fn, signature)?;
            eprintln!("Output written to {}", signature_fn);
        }
    }
    Ok(())
}
