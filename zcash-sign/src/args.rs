use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Generate a new UnifiedFullViewingKey from a SpendValidatingKey.
    Generate {
        /// The SpendValidatingKey (VerifyingKey in FROST) to use
        #[arg(short, long)]
        ak: String,
        /// The network the address will be generated for: "main" or "test" (default: "main")
        #[arg(short, long)]
        #[arg(default_value = "main")]
        network: String,
        /// Whether to generate a dummy Sapling key along with the Orchard key.
        /// Require for Ywallet use since it does not support Orchard-only keys.
        /// DANGER: make sure to not send to the Sapling address, or your
        /// funds will become unspendable!
        #[arg(long, default_value_t = false)]
        danger_dummy_sapling: bool,
    },
    /// Sign a transaction plan with a externally-generated signature.
    Sign {
        /// The file containing the JSON Ywallet transaction plan
        #[arg(short = 'i', long)]
        tx_plan: String,

        /// The file where to write the signed transaction
        #[arg(short = 'o', long)]
        tx: String,

        /// The UnifiedFullViewingKey generated previously, in hex format
        #[arg(short, long)]
        ufvk: String,

        /// The network the address will be generated for: "main" or "test" (default: "main")
        #[arg(short, long)]
        #[arg(default_value = "main")]
        network: String,
    },
}
