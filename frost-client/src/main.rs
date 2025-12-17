use std::error::Error;

use clap::Parser;
use frost_client::cli;
use frost_client::cli::args::{Args, Command};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    stable_eyre::install()?;
    let args = Args::parse();

    match args.command {
        Command::Init { .. } => cli::init::init(&args.command).await,
        Command::Export { .. } => cli::contact::export(&args.command),
        Command::Import { .. } => cli::contact::import(&args.command),
        Command::Contacts { .. } => cli::contact::list(&args.command),
        Command::RemoveContact { .. } => cli::contact::remove(&args.command),
        Command::Groups { .. } => cli::group::list(&args.command),
        Command::RemoveGroup { .. } => cli::group::remove(&args.command),
        Command::Sessions { .. } => cli::session::list(&args.command).await,
        Command::TrustedDealer { .. } => cli::trusted_dealer::trusted_dealer(&args.command),
        Command::Dkg { .. } => cli::dkg::dkg(&args.command).await,
        Command::Coordinator { .. } => cli::coordinator::run(&args.command).await.map(|_| ()),
        Command::Participant { .. } => cli::participant::run(&args.command).await,
    }?;

    Ok(())
}
