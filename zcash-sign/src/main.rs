mod args;

use std::{error::Error, fs};

use base64::{prelude::BASE64_STANDARD, Engine as _};
use clap::Parser as _;
use eyre::eyre;
use rand::{thread_rng, RngCore};

use orchard::keys::{Scope, SpendValidatingKey};
use sapling_crypto::zip32::ExtendedSpendingKey;
use zcash_client_backend::address::UnifiedAddress;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{self};

use zcash_sign::transaction_plan::TransactionPlan;

use args::{Args, Command};

fn generate(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Generate {
        ak,
        danger_dummy_sapling,
        network,
    } = args
    else {
        panic!("invalid Command");
    };
    let params: consensus::Network = match network.as_str() {
        "main" => consensus::Network::MainNetwork,
        "test" => consensus::Network::TestNetwork,
        _ => Err(eyre!("Invalid network: {}", network))?,
    };

    let ak = hex::decode(ak.trim()).unwrap();
    let ak = SpendValidatingKey::from_bytes(&ak).ok_or(eyre!("Invalid ak"))?;

    let mut rng = rand::thread_rng();

    let fvk = zcash_sign::generate(&mut rng, &ak);

    let orchard_address = fvk.address_at(0u64, Scope::External);
    let unified_address = UnifiedAddress::from_receivers(Some(orchard_address), None, None)
        .expect("must work with a shielded address");
    // TODO: make params selectable
    let unified_address_str = unified_address.encode(&params);

    println!("Orchard-only unified address: {unified_address_str:?}");

    let sapling_fvk = if *danger_dummy_sapling {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed[..]);
        let spending_key = ExtendedSpendingKey::master(&seed);
        Some(spending_key.to_diversifiable_full_viewing_key())
    } else {
        None
    };

    let ufvk = UnifiedFullViewingKey::new(sapling_fvk, Some(fvk.clone())).unwrap();
    let ufvk_str = ufvk.encode(&params);

    println!("Unified Full Viewing Key: {ufvk_str:?}");

    Ok(())
}

fn sign(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Sign {
        tx_plan,
        ufvk,
        tx: tx_path,
        network,
    } = args
    else {
        panic!("invalid Command")
    };
    let params: consensus::Network = match network.as_str() {
        "main" => consensus::Network::MainNetwork,
        "test" => consensus::Network::TestNetwork,
        _ => Err(eyre!("Invalid network: {}", network))?,
    };

    let tx_plan = fs::read_to_string(tx_plan)?;
    let tx_plan: TransactionPlan = serde_json::from_str(&tx_plan)?;

    let ufvk = UnifiedFullViewingKey::decode(&params, ufvk.trim()).unwrap();

    let mut rng = thread_rng();

    let tx = zcash_sign::sign(&mut rng, &tx_plan, &ufvk)?;

    let mut tx_bytes = vec![];
    tx.write(&mut tx_bytes).unwrap();

    fs::write(tx_path, BASE64_STANDARD.encode(&tx_bytes))?;
    println!("Tx written to {tx_path}");

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    match args.command {
        Command::Generate { .. } => generate(&args.command),
        Command::Sign { .. } => sign(&args.command),
    }?;

    Ok(())
}
