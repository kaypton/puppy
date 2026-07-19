//! Connection settings for the puppy dashboard API.

use clap::Parser;

/// Command-line arguments / connection configuration.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "puppy-tui",
    version,
    about = "Terminal UI dashboard for puppy-server"
)]
pub struct ConnectionConfig {
    /// Base URL of the puppy dashboard API, e.g. https://127.0.0.1:8443
    #[arg(long, default_value = "https://127.0.0.1:8443")]
    pub server: String,

    /// Bearer token for the dashboard API (omit when the server has no token configured)
    #[arg(long)]
    pub token: Option<String>,

    /// Skip TLS certificate verification (self-signed certs)
    #[arg(short = 'k', long)]
    pub ignore_tls: bool,
}
