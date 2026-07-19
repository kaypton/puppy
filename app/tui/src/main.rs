//! puppy-tui: terminal UI dashboard for puppy-server.
//!
//! Talks to the puppy dashboard HTTP API (docs/HTTP-API.md) and renders
//! system info, stats, connections, frontends, backends, config and the
//! live event stream in the terminal.

use clap::Parser;

/// Terminal UI dashboard for puppy-server.
#[derive(Debug, Parser)]
#[command(name = "puppy-tui", version, about)]
struct Args {
    /// Base URL of the puppy dashboard API, e.g. https://127.0.0.1:8443
    #[arg(long, default_value = "https://127.0.0.1:8443")]
    server: String,

    /// Bearer token for the dashboard API (empty disables auth)
    #[arg(long)]
    token: Option<String>,

    /// Skip TLS certificate verification (self-signed certs)
    #[arg(short = 'k', long)]
    ignore_tls: bool,
}

fn main() {
    let args = Args::parse();
    println!(
        "puppy-tui scaffold: server={} token={} ignore_tls={}",
        args.server,
        args.token.as_deref().unwrap_or("<none>"),
        args.ignore_tls
    );
    println!("UI not implemented yet.");
}
