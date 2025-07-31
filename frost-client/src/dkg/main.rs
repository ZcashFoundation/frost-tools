use std::io;

use clap::Parser;

use frost_client::dkg::{args::Args, cli::cli};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut reader = Box::new(io::stdin().lock());
    let mut logger = io::stdout();

    if args.ciphersuite == "ed25519" {
        cli::<frost_ed25519::Ed25519Sha512>(&mut reader, &mut logger).await?;
    } else if args.ciphersuite == "redpallas" {
        cli::<reddsa::frost::redpallas::PallasBlake2b512>(&mut reader, &mut logger).await?;
    } else if args.ciphersuite == "secp256k1-tr" {
        cli::<frost_secp256k1_tr::Secp256K1Sha256TR>(&mut reader, &mut logger).await?;
    }

    Ok(())
}
