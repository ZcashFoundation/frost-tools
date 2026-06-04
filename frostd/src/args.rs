use clap::Parser;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// IP to bind to.
    #[arg(short, long, default_value = "0.0.0.0")]
    pub ip: String,

    /// Port to bind to.
    #[arg(short, long, default_value_t = 2744)]
    pub port: u16,

    /// The path of the certificate to use for HTTPS (PEM format).
    ///
    /// For production deployments, it's recommended to provide HTTPS using
    /// a reverse proxy such as nginx. In that case, set `no_tls_very_insecure`
    /// instead.
    #[arg(short = 'c', long)]
    pub tls_cert: Option<String>,

    /// The path of the private key to use for HTTPS (PEM format).
    #[arg(short = 'k', long)]
    pub tls_key: Option<String>,

    /// Flag to disable TLS/HTTPS. DO NOT set this flag unless you're providing
    /// TLS/HTTPS on your own (e.g. with nginx or another reverse proxy).
    #[arg(short, long, default_value_t = false)]
    pub no_tls_very_insecure: bool,
}

impl Args {
    /// Get the effective IP to use, considering the arguments passed.
    pub fn ip(&self) -> String {
        self.ip.clone()
    }
}
