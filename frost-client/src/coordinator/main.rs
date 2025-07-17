use std::io;

use clap::Parser;

use frost_client::coordinator::{args::Args, cli::cli};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();
    let r = if args.ciphersuite == "ed25519" {
        cli::<frost_ed25519::Ed25519Sha512>(&args, &mut reader, &mut logger).await
    } else if args.ciphersuite == "redpallas" {
        cli::<reddsa::frost::redpallas::PallasBlake2b512>(&args, &mut reader, &mut logger).await
    } else {
        panic!("invalid ciphersuite");
    };

    // Force process to exit; since socket comms spawn a thread, it will keep
    // running forever. Ideally we should join() the thread but this works for
    // now.
    match r {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

// Choose participants -> send message to those participants - gen message to send

// Choose message - receive commitments - build commitment list - send to participants

// Receive signature shares - aggregate - send to participants. signautre shares must be validated first

// Verify group signature
