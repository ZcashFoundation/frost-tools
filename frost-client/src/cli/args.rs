use clap::{Parser, Subcommand};

use crate::cli::coordinator::CoordinatorCommand;

#[derive(Parser, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    /// Initializes the user, generating a communication key pair and saving to
    /// the config file.
    ///
    /// WARNING: the config file will contain your private FROST shares in
    /// clear. Keep it safe and never share it with anyone. Future versions of
    /// this tool might encrypt the config file.
    Init {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Exports the user's contact, printing a string with the contact
    /// information encoded.
    Export {
        /// The name to use when exporting.
        #[arg(short, long)]
        name: String,
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Imports a contact into the user's address book, in the config file.
    Import {
        /// The contact exported with `export``
        contact: String,
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Lists the contacts in the user's address book, in the config file.
    Contacts {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Remove a contact from the user's address book.
    RemoveContact {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
        /// The public key of the contact to remove (list with `contacts`).
        #[arg(short, long)]
        pubkey: String,
    },
    /// Generate FROST shares using a trusted dealer. Should only be used for
    /// tests.
    ///
    /// IMPORTANT: this should only be used for tests. After a trusted dealer
    /// key generation, the participants need to validate their received shares
    /// before generating a key package. This tool does not do that and writes
    /// just the key packages into the config files, making it impossible for
    /// participants to verify them since the required information is lost.
    ///
    /// A future version of this tool might support running the trusted dealer
    /// using the FROST server; but there is no benefit in doing that instead of
    /// using distributed key generation (DKG).
    TrustedDealer {
        /// The path to the config file to manage.
        ///
        /// You can specify `num_signers` different paths. In that case, the
        /// group information will be added to each config file. This is
        /// particularly useful for tests, where all participants are run in the
        /// same machine with a config file for each.
        ///
        /// If a single path is specified (or none, which will use
        /// $HOME/.local/frost/credentials.toml), then it will run the trusted
        /// dealer process via the FROST server (TODO: this is not supported yet)
        #[arg(short, long)]
        config: Vec<String>,
        /// A description of the group being created. Will be written to the
        /// participant's config files and will help them identify groups.
        #[arg(short, long)]
        description: String,
        /// The comma-separated name of each participant.
        #[arg(short = 'N', long, value_delimiter = ',')]
        names: Vec<String>,
        /// The server URL, if desired. Note that this does not connect to the
        /// server; it will just associated the server URL with the group in the
        /// config file.
        #[arg(short, long)]
        server_url: Option<String>,
        /// The ciphersuite to use.
        #[arg(short = 'C', long, default_value = "ed25519")]
        ciphersuite: String,
        /// The threshold (minimum number of signers).
        #[arg(short = 't', long, default_value_t = 2)]
        threshold: u16,
        /// The total number of participants (maximum number of signers).
        #[arg(short = 'n', long, default_value_t = 3)]
        num_signers: u16,
    },
    /// Generate FROST shares using Distributed Key Generation.
    Dkg {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
        /// A description of the group being created. Will be written to the
        /// participant's config files and will help them identify groups.
        #[arg(short, long)]
        description: String,
        /// The server URL through which DKG will be run.
        #[arg(short, long)]
        server_url: String,
        #[arg(short = 'C', long, default_value = "ed25519")]
        ciphersuite: String,
        /// The threshold (minimum number of signers).
        #[arg(short = 't', long)]
        threshold: u16,
        /// The comma-separated hex-encoded public keys of the other
        /// participants to use. Must be specified only for the first participant
        /// who creates the DKG session.
        #[arg(short = 'S', long, value_delimiter = ',')]
        participants: Vec<String>,
    },
    /// Lists the groups the user is in.
    Groups {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Remove a group from the config.
    RemoveGroup {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
        /// The group to remove, identified by the group public key (use
        /// `groups` to list)
        #[arg(short, long)]
        group: String,
    },
    /// Lists the active FROST signing sessions the user is in.
    Sessions {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
        /// The server URL to use. If `group` is specified and `server_url`
        /// is not, it will use the server URL associated with `group` if any.
        #[arg(short, long)]
        server_url: Option<String>,
        /// Optional group whose associated server URL will be used, identified
        /// by the group public key (use `groups` to list).
        #[arg(short, long)]
        group: Option<String>,
        /// Whether to also close all existing sessions. Useful for cleaning
        /// up lingering sessions due to errors or if participants give up.
        #[arg(long, default_value_t = false)]
        close_all: bool,
    },
    /// Start a new FROST signing session.
    Coordinator(CoordinatorCommand),
    /// Participate in a FROST signing session.
    Participant {
        /// The path to the config file to manage. If not specified, it uses
        /// $HOME/.local/frost/credentials.toml
        #[arg(short, long)]
        config: Option<String>,
        /// The server URL to use. If not specified, it will use the server URL
        /// for the specified group, if any. It will use the username previously
        /// logged in via the `login` subcommand for the given server.
        #[arg(short, long)]
        server_url: Option<String>,
        /// The group to use, identified by the group public key (use `groups`
        /// to list)
        #[arg(short, long)]
        group: String,
        /// The session ID to use (use `sessions` to list). Can be omitted in
        /// case there is a single active session.
        #[arg(short = 'S', long)]
        session: Option<String>,
    },
}
