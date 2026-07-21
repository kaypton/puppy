//! puppy-server binary entry point.
//!
//! Parses `--config`, loads and validates the configuration, builds the
//! selected frontend, and runs it until Ctrl-C / SIGTERM.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tracing::error;

use puppy_core::stats::{ConnectionRegistry, EventBus, StatsRegistry};

use server::{build_frontend, init_tracing, ConfigError};

/// Command-line interface for puppy-server.
///
/// `--config/-c` is required; flag/argument errors print usage, while
/// configuration and runtime errors do not.
#[derive(Parser, Debug)]
#[command(name = "puppy-server", version, about = "Run the puppy proxy server")]
struct Cli {
	/// Path to the TOML configuration file.
	#[arg(short, long, value_name = "PATH")]
	config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
	init_tracing();

	let cli = match Cli::try_parse() {
		Ok(c) => c,
		Err(e) => {
			// clap handles usage printing for flag/argument errors.
			e.exit();
		}
	};

	match run(&cli.config).await {
		Ok(()) => ExitCode::SUCCESS,
		Err(e) => {
			error!("{e:#}");
			ExitCode::from(1)
		}
	}
}

/// Loads the configuration, builds the selected frontend, and runs it until
/// shutdown.
async fn run(config_path: &std::path::Path) -> Result<(), anyhow::Error> {
	let config = config::load(config_path).map_err(|e| anyhow::anyhow!(format_config_error(e)))?;

	let stats_registry = StatsRegistry::new();
	let conn_reg = ConnectionRegistry::new();
	let bus = EventBus::new();

	let stats_deps = puppy_core::stats::Deps {
		name: config.frontend.clone(),
		stats: Some(stats_registry),
		conn_reg: Some(conn_reg),
		bus: Some(bus),
	};

	let frontend = build_frontend(&config, stats_deps)?;

	// Run until Ctrl-C or SIGTERM. tokio's `ctrl_c()` covers SIGINT and, on
	// Unix, SIGTERM is forwarded to the same future via the runtime's signal
	// handler.
	let shutdown = async {
		let _ = tokio::signal::ctrl_c().await;
	};
	frontend
		.run(shutdown)
		.await
		.map_err(|e| anyhow::anyhow!(e.to_string()))?;
	Ok(())
}

/// Formats a `ConfigError` for stderr output. The `ConfigError` `Display` impl
/// already produces the wrapping (`load configuration "...": ...` and
/// `validate configuration "...": ...`), so we just forward it.
fn format_config_error(e: ConfigError) -> String {
	e.to_string()
}
