//! gRPC tunnel upstream backend: forwards traffic to a target through a
//! remote gRPC tunnel server using a bidirectional `Connect` frame stream.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use grpc_tunnel::tunnel_client::TunnelClient;
use grpc_tunnel::{client_channel, connect_frame, GrpcStream};
use http::Uri;
use hyper_util::rt::TokioIo;
use puppy_core::backend::{
	Backend, BackendError, BoxedStream, Capability, Dialer, Protocol, Target,
};
use tokio::net::TcpStream;
use tokio::sync::OnceCell;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tower_service::Service;

pub mod config;
pub use config::{ConfigError, Configuration, TYPE};

/// Runtime configuration for the gRPC tunnel proxy backend.
///
/// The TOML-decoded [`Configuration`] is converted into this runtime form via
/// [`Configuration::backend_config`].
#[derive(Clone, Default)]
pub struct BackendConfiguration {
	/// Address of the remote gRPC tunnel server (`host:port`).
	pub server_address: String,
	/// Enables TLS to the tunnel server when `true`.
	pub tls: bool,
	/// PEM file of additional CA certificates.
	pub tls_ca_file: String,
	/// Overrides the TLS SNI and verification name.
	pub tls_server_name: String,
	/// Disables certificate verification. Mutually exclusive with
	/// `tls_ca_file`.
	pub tls_insecure_skip_verify: bool,
	/// Bearer token sent as the `authorization` metadata header.
	pub token: String,
	/// Pre-built TLS client config. When `Some`, used as-is for the TLS
	/// connection to the tunnel server. When `None` and `tls` is `true`, a
	/// config is built from the fields above. Mainly intended for test
	/// injection.
	pub tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl BackendConfiguration {
	/// Validates the runtime configuration fields.
	///
	/// Error strings are prefixed with `"grpcproxy: "` for consistency with
	/// the rest of the backend's diagnostics.
	pub fn validate(&self) -> Result<(), ConfigError> {
		if self.server_address.is_empty() {
			return Err(ConfigError::Validation(
				"grpcproxy: server address is required".to_string(),
			));
		}
		if !self.tls
			&& (!self.tls_ca_file.is_empty()
				|| !self.tls_server_name.is_empty()
				|| self.tls_insecure_skip_verify)
		{
			return Err(ConfigError::Validation(
				"grpcproxy: tls_ca_file, tls_server_name, and tls_insecure_skip_verify require tls = true"
					.to_string(),
			));
		}
		if self.tls_insecure_skip_verify && !self.tls_ca_file.is_empty() {
			return Err(ConfigError::Validation(
				"grpcproxy: tls_insecure_skip_verify and tls_ca_file are mutually exclusive"
					.to_string(),
			));
		}
		Ok(())
	}
}

impl Configuration {
	/// Adds runtime dependencies to the backend's file configuration and
	/// validates the resulting runtime configuration.
	pub fn backend_config(&self) -> Result<BackendConfiguration, ConfigError> {
		let bc = BackendConfiguration {
			server_address: self.server_address.clone(),
			tls: self.tls,
			tls_ca_file: self.tls_ca_file.clone(),
			tls_server_name: self.tls_server_name.clone(),
			tls_insecure_skip_verify: self.tls_insecure_skip_verify,
			token: self.token.clone(),
			tls_config: None,
		};
		bc.validate()?;
		Ok(bc)
	}
}

/// gRPC tunnel proxy backend.
///
/// Each `dial` opens a `Connect` bidi stream on a shared, lazily established
/// [`Channel`], announces the target with the initial connect frame, and
/// returns the byte stream adapting the frame pair.
pub struct GrpcProxyBackend {
	config: BackendConfiguration,
	tls_config: Option<Arc<rustls::ClientConfig>>,
	channel: OnceCell<Channel>,
}

impl GrpcProxyBackend {
	/// Applies defaults and returns a gRPC tunnel backend. Configuration
	/// validation must be performed via `validate()` (typically through
	/// `Configuration::backend_config`) before calling `new`.
	pub fn new(config: BackendConfiguration) -> Result<Self, BackendError> {
		let tls_config = if let Some(tc) = &config.tls_config {
			Some(tc.clone())
		} else if config.tls {
			let built =
				build_client_tls_config(&config.tls_ca_file, config.tls_insecure_skip_verify)
					.map_err(|e| BackendError::Other(e.to_string()))?;
			Some(Arc::new(built))
		} else {
			None
		};
		Ok(Self {
			config,
			tls_config,
			channel: OnceCell::new(),
		})
	}

	/// Returns the shared channel, establishing it on first use. The channel
	/// connects lazily, so connection failures surface on the first RPC.
	async fn channel(&self) -> Result<&Channel, BackendError> {
		self.channel
			.get_or_try_init(|| async { self.build_channel() })
			.await
	}

	/// Builds the endpoint channel: plaintext via the default HTTP connector,
	/// TLS via a rustls connector so an injected or custom-built
	/// [`rustls::ClientConfig`] (including `tls_insecure_skip_verify`) applies.
	///
	/// The endpoint URI always uses the `http` scheme: tonic rejects an
	/// `https` URI unless its own TLS config is set, but here TLS is handled
	/// inside [`RustlsConnector`], underneath tonic's connector wrapper.
	fn build_channel(&self) -> Result<Channel, BackendError> {
		let endpoint = Endpoint::from_shared(format!("http://{}", self.config.server_address))
			.map_err(|e| BackendError::Other(format!("grpcproxy: parse server address: {e}")))?;
		match &self.tls_config {
			Some(tls_config) => {
				let connector = RustlsConnector::new(
					tls_config.clone(),
					tls_server_host(&self.config.server_address, &self.config.tls_server_name),
				);
				Ok(endpoint.connect_with_connector_lazy(connector))
			}
			None => Ok(endpoint.connect_lazy()),
		}
	}
}

#[async_trait]
impl Backend for GrpcProxyBackend {
	/// Capabilities report that the gRPC tunnel can carry any TCP application
	/// protocol, but cannot carry UDP.
	fn capabilities(&self) -> Vec<Capability> {
		vec![Capability {
			network: "tcp".to_string(),
			protocol: Protocol::Any,
		}]
	}

	/// Opens a `Connect` bidi stream on the shared channel, sends the connect
	/// frame announcing `target`, and returns the tunneled connection. The
	/// `dialer` is unused: the tunnel server dials the target on our behalf.
	async fn dial(
		&self,
		target: Target,
		_dialer: &dyn Dialer,
	) -> Result<BoxedStream, BackendError> {
		let channel = self.channel().await?;
		let mut client = TunnelClient::new(channel.clone());

		let (tx, rx) = client_channel();
		let mut request = tonic::Request::new(ReceiverStream::new(rx));
		if !self.config.token.is_empty() {
			let value =
				MetadataValue::try_from(format!("Bearer {}", self.config.token)).map_err(|e| {
					BackendError::Other(format!("grpcproxy: build authorization metadata: {e}"))
				})?;
			request.metadata_mut().insert("authorization", value);
		}

		// Queue the connect frame before opening the stream; the channel is
		// buffered, so the frame is flushed once the RPC starts.
		tx.send(connect_frame(target.net(), &target.host, target.port))
			.await
			.map_err(|_| {
				BackendError::Other("grpcproxy: send connect frame: channel closed".to_string())
			})?;

		let response = client
			.connect(request)
			.await
			.map_err(|e| BackendError::Other(format!("grpcproxy: open tunnel stream: {e}")))?;

		Ok(Box::new(GrpcStream::new(response.into_inner(), tx)))
	}
}

/// Returns the host portion of `server_address` (without IPv6 brackets), or
/// `server_name` when non-empty.
fn tls_server_host(server_address: &str, server_name: &str) -> String {
	if !server_name.is_empty() {
		return server_name.to_string();
	}
	// Strip the port and, for IPv6 literals, the brackets.
	if let Some(rest) = server_address.strip_prefix('[') {
		if let Some(close) = rest.find(']') {
			return rest[..close].to_string();
		}
	}
	server_address
		.rsplit_once(':')
		.map(|(h, _)| h.to_string())
		.unwrap_or_else(|| server_address.to_string())
}

/// Builds a `rustls::ClientConfig` for the tunnel server connection. The
/// config always advertises the `h2` ALPN protocol required by gRPC.
fn build_client_tls_config(
	ca_file: &str,
	insecure: bool,
) -> Result<rustls::ClientConfig, BuildTlsError> {
	// Build root certificate store.
	let mut root_store = rustls::RootCertStore::empty();
	if !ca_file.is_empty() {
		let pem =
			std::fs::read(ca_file).map_err(|e| format!("grpcproxy: read TLS CA file: {e}"))?;
		let mut reader = std::io::Cursor::new(&pem);
		let certs = rustls_pemfile::certs(&mut reader)
			.collect::<Result<Vec<_>, _>>()
			.map_err(|e| format!("grpcproxy: parse CA file: {e}"))?;
		if certs.is_empty() {
			return Err(format!("grpcproxy: no certificates parsed from {ca_file}").into());
		}
		for cert in certs {
			root_store
				.add(cert)
				.map_err(|e| format!("grpcproxy: add CA certificate: {e}"))?;
		}
	} else {
		// Load native system roots. If none are available (rare), fall back
		// to an empty store (handshake will fail on signed certs).
		let result = rustls_native_certs::load_native_certs();
		for cert in result.certs {
			let _ = root_store.add(cert);
		}
		if !result.errors.is_empty() {
			tracing::warn!("errors loading native certs: {:?}", result.errors);
		}
	}

	let mut config = if insecure {
		rustls::ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
			.with_no_client_auth()
	} else {
		rustls::ClientConfig::builder()
			.with_root_certificates(root_store)
			.with_no_client_auth()
	};
	config.alpn_protocols = vec![b"h2".to_vec()];
	Ok(config)
}

/// Error type for `build_client_tls_config` so we can carry string messages
/// without depending on `thiserror` here (the Backend impl wraps it as
/// `BackendError::Other`).
#[derive(Debug)]
struct BuildTlsError(String);

impl std::fmt::Display for BuildTlsError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

impl std::error::Error for BuildTlsError {}

impl From<String> for BuildTlsError {
	fn from(s: String) -> Self {
		Self(s)
	}
}

/// No-op certificate verifier used when `tls_insecure_skip_verify` is `true`.
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
	fn verify_server_cert(
		&self,
		_end_entity: &rustls::pki_types::CertificateDer<'_>,
		_intermediates: &[rustls::pki_types::CertificateDer<'_>],
		_server_name: &rustls::pki_types::ServerName<'_>,
		_ocsp_response: &[u8],
		_now: rustls::pki_types::UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		_message: &[u8],
		_cert: &rustls::pki_types::CertificateDer<'_>,
		_dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}

	fn verify_tls13_signature(
		&self,
		_message: &[u8],
		_cert: &rustls::pki_types::CertificateDer<'_>,
		_dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		vec![
			rustls::SignatureScheme::RSA_PKCS1_SHA256,
			rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
			rustls::SignatureScheme::RSA_PSS_SHA256,
			rustls::SignatureScheme::RSA_PKCS1_SHA384,
			rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
			rustls::SignatureScheme::RSA_PSS_SHA384,
			rustls::SignatureScheme::RSA_PKCS1_SHA512,
			rustls::SignatureScheme::RSA_PSS_SHA512,
			rustls::SignatureScheme::ED25519,
			rustls::SignatureScheme::ED448,
		]
	}
}

/// tonic connector that dials TCP and upgrades to TLS with a caller-provided
/// [`rustls::ClientConfig`]. Used instead of tonic's built-in TLS connector so
/// injected configs and `tls_insecure_skip_verify` work unchanged.
#[derive(Clone)]
struct RustlsConnector {
	tls_config: Arc<rustls::ClientConfig>,
	server_name: String,
}

impl RustlsConnector {
	fn new(tls_config: Arc<rustls::ClientConfig>, server_name: String) -> Self {
		Self {
			tls_config,
			server_name,
		}
	}
}

impl Service<Uri> for RustlsConnector {
	type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
	type Error = std::io::Error;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		Poll::Ready(Ok(()))
	}

	fn call(&mut self, uri: Uri) -> Self::Future {
		let tls_config = self.tls_config.clone();
		let server_name = self.server_name.clone();
		Box::pin(async move {
			let host = uri
				.host()
				.ok_or_else(|| {
					std::io::Error::new(std::io::ErrorKind::InvalidInput, "uri missing host")
				})?
				.to_string();
			let port = uri.port_u16().unwrap_or(443);
			let tcp = TcpStream::connect((host.as_str(), port)).await?;
			let name = ServerName::try_from(server_name)
				.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
			let tls = tokio_rustls::TlsConnector::from(tls_config)
				.connect(name, tcp)
				.await?;
			Ok(TokioIo::new(tls))
		})
	}
}
