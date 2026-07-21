//! puppy-server binary entry point.
//!
//! Parses `--config`, loads and validates the configuration, builds the
//! selected frontend, and runs it until Ctrl-C / SIGTERM.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Status};

use puppy_core::stats::{ConnectionRegistry, EventBus, StatsRegistry};

use puppy_observability::{run_checkpoint, Database, LogHub, ObservabilityService};
use puppy_rpc::v1::observability_server::ObservabilityServer;
use server::{build_frontend, init_tracing_with_log, ConfigError};

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
			eprintln!("{e:#}");
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
	let cancel = CancellationToken::new();
	let instance_id = puppy_core::stats::generate_connection_id();
	let started_at_ms = now_ms();

	let mut grpc_runtime = None;
	if config.grpc.as_ref().is_some_and(|grpc| grpc.enabled) {
		let grpc = config.grpc.as_ref().expect("checked above");
		let observability = config.observability.as_ref().expect("validated");
		let db_path = resolve_path(config_path, &observability.database_path);
		let log_directory = resolve_path(config_path, &observability.log_directory);
		let database = Database::open(&db_path)?;
		let log_hub = LogHub::new(&log_directory, instance_id.clone())?;
		log_hub.apply_retention(
			observability.log_retention_days,
			observability.log_max_total_bytes,
		)?;
		database.apply_retention(
			observability.connection_retention_days,
			observability.connection_max_rows,
		)?;
		init_tracing_with_log(Some(log_hub.clone()));

		let service = ObservabilityService::new(
			database.clone(),
			stats_registry.clone(),
			conn_reg.clone(),
			log_hub.clone(),
			instance_id.clone(),
			started_at_ms,
		);
		let log_retention_cancel = cancel.clone();
		let log_retention_days = observability.log_retention_days;
		let log_max_bytes = observability.log_max_total_bytes;
		tokio::spawn(async move {
			let mut ticker = tokio::time::interval(Duration::from_secs(86_400));
			ticker.tick().await;
			loop {
				tokio::select! {
					_ = log_retention_cancel.cancelled() => break,
					_ = ticker.tick() => {
						if let Err(error) = log_hub.apply_retention(log_retention_days, log_max_bytes) {
							tracing::error!(%error, "apply log retention failed");
						}
					}
				}
			}
		});
		let addr = format!("{}:{}", grpc.listen_address, grpc.listen_port).parse()?;
		let cert = tokio::fs::read(resolve_path(config_path, &grpc.tls_cert_file)).await?;
		let key = tokio::fs::read(resolve_path(config_path, &grpc.tls_key_file)).await?;
		let interceptor = BearerAuth {
			expected: Arc::new(format!("Bearer {}", grpc.token).into_bytes()),
		};
		let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
		health_reporter
			.set_serving::<ObservabilityServer<ObservabilityService>>()
			.await;
		let checkpoint_cancel = cancel.clone();
		let checkpoint_db = database.clone();
		let checkpoint_reg = conn_reg.clone();
		let checkpoint_instance = instance_id.clone();
		let checkpoint_interval = Duration::from_millis(observability.checkpoint_interval_ms);
		let retention_days = observability.connection_retention_days;
		let max_rows = observability.connection_max_rows;
		tokio::spawn(async move {
			run_checkpoint(
				checkpoint_db,
				checkpoint_reg,
				checkpoint_instance,
				checkpoint_interval,
				retention_days,
				max_rows,
				checkpoint_cancel,
			)
			.await;
		});
		grpc_runtime = Some((
			addr,
			Identity::from_pem(cert, key),
			ObservabilityServer::with_interceptor(service, interceptor),
			health_service,
		));
	} else {
		init_tracing_with_log(None);
	}

	let stats_deps = puppy_core::stats::Deps {
		name: config.frontend.clone(),
		backend: String::new(),
		stats: Some(stats_registry.clone()),
		conn_reg: Some(conn_reg.clone()),
		bus: Some(bus),
	};

	let frontend = build_frontend(&config, stats_deps)?;

	let frontend_cancel = cancel.clone();
	let mut frontend_task = tokio::spawn(async move {
		frontend
			.run(frontend_cancel.cancelled_owned())
			.await
			.map_err(|e| e.to_string())
	});
	let mut grpc_task = grpc_runtime.map(|(addr, identity, service, health_service)| {
		let grpc_cancel = cancel.clone();
		tokio::spawn(async move {
			Server::builder()
				.tls_config(ServerTlsConfig::new().identity(identity))?
				.add_service(health_service)
				.add_service(service)
				.serve_with_shutdown(addr, grpc_cancel.cancelled_owned())
				.await
				.map_err(anyhow::Error::from)
		})
	});

	let outcome: Result<(), anyhow::Error> = if let Some(task) = grpc_task.as_mut() {
		tokio::select! {
			result = &mut frontend_task => result.map_err(anyhow::Error::from)?.map_err(anyhow::Error::msg),
			result = task => result.map_err(anyhow::Error::from)?,
			_ = tokio::signal::ctrl_c() => Ok(()),
		}
	} else {
		tokio::select! {
			result = &mut frontend_task => result.map_err(anyhow::Error::from)?.map_err(anyhow::Error::msg),
			_ = tokio::signal::ctrl_c() => Ok(()),
		}
	};
	cancel.cancel();
	if !frontend_task.is_finished() {
		let _ = frontend_task.await;
	}
	if let Some(task) = grpc_task {
		if !task.is_finished() {
			let _ = task.await;
		}
	}
	outcome?;
	Ok(())
}

fn resolve_path(config_path: &std::path::Path, value: &str) -> PathBuf {
	let path = std::path::Path::new(value);
	if path.is_absolute() {
		path.to_path_buf()
	} else {
		config_path
			.parent()
			.unwrap_or_else(|| std::path::Path::new("."))
			.join(path)
	}
}

fn now_ms() -> i64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis() as i64
}

#[derive(Clone)]
struct BearerAuth {
	expected: Arc<Vec<u8>>,
}

impl Interceptor for BearerAuth {
	fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
		let supplied = request
			.metadata()
			.get("authorization")
			.map(MetadataValue::as_encoded_bytes)
			.unwrap_or_default();
		if supplied.ct_eq(self.expected.as_slice()).into() {
			Ok(request)
		} else {
			Err(Status::unauthenticated("unauthorized"))
		}
	}
}

/// Formats a `ConfigError` for stderr output. The `ConfigError` `Display` impl
/// already produces the wrapping (`load configuration "...": ...` and
/// `validate configuration "...": ...`), so we just forward it.
fn format_config_error(e: ConfigError) -> String {
	e.to_string()
}
