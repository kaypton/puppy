//! SOCKS5 upstream backend: forwards traffic to a target through an upstream
//! SOCKS5 proxy (proxy chaining). Implements RFC 1928 (SOCKS5) and RFC 1929
//! (username/password sub-negotiation).
//!
//! Error strings are kept stable so tests can match on substrings.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use puppy_core::backend::{
	Backend, BackendError, BoxedStream, Capability, Dialer, Protocol, Target,
};
use puppy_core::socks5;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

pub mod config;
pub use config::{ConfigError, Configuration, TYPE};

/// Runtime configuration for the SOCKS5 chaining backend.
///
/// The TOML-decoded [`Configuration`] is converted into this runtime form
/// via [`Configuration::backend_config`].
#[derive(Clone, Default)]
pub struct BackendConfiguration {
	/// Upstream SOCKS5 proxy address (`host:port`).
	pub proxy_address: String,
	/// Username for RFC 1929 username/password sub-negotiation. Required to
	/// be paired with `password`.
	pub username: String,
	/// Password for RFC 1929 username/password sub-negotiation. Required to
	/// be paired with `username`.
	pub password: String,
	/// Enables TLS to the upstream proxy when `true`.
	pub tls: bool,
	/// PEM file of additional CA certificates.
	pub tls_ca_file: String,
	/// Overrides the TLS SNI and verification name.
	pub tls_server_name: String,
	/// Disables certificate verification. Mutually exclusive with
	/// `tls_ca_file`.
	pub tls_insecure_skip_verify: bool,
	/// Pre-built TLS client config. When `Some`, used as-is for the TLS
	/// connection to the upstream proxy. When `None` and `tls` is `true`, a
	/// config is built from the fields above. Mainly intended for test
	/// injection.
	pub tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl BackendConfiguration {
	/// Validates the runtime configuration fields.
	///
	/// Error strings are prefixed with `"socksproxy: "` so callers see a
	/// consistent, machine-greppable prefix.
	pub fn validate(&self) -> Result<(), ConfigError> {
		if self.proxy_address.is_empty() {
			return Err(ConfigError::Validation(
				"socksproxy: proxy address is required".to_string(),
			));
		}
		if (self.username.is_empty()) != (self.password.is_empty()) {
			return Err(ConfigError::Validation(
				"socksproxy: username and password must both be set or both be empty".to_string(),
			));
		}
		if !self.tls
			&& (!self.tls_ca_file.is_empty()
				|| !self.tls_server_name.is_empty()
				|| self.tls_insecure_skip_verify)
		{
			return Err(ConfigError::Validation(
				"socksproxy: tls_ca_file, tls_server_name, and tls_insecure_skip_verify require tls = true"
					.to_string(),
			));
		}
		if self.tls_insecure_skip_verify && !self.tls_ca_file.is_empty() {
			return Err(ConfigError::Validation(
				"socksproxy: tls_insecure_skip_verify and tls_ca_file are mutually exclusive"
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
			proxy_address: self.proxy_address.clone(),
			username: self.username.clone(),
			password: self.password.clone(),
			tls: self.tls,
			tls_ca_file: self.tls_ca_file.clone(),
			tls_server_name: self.tls_server_name.clone(),
			tls_insecure_skip_verify: self.tls_insecure_skip_verify,
			tls_config: None,
		};
		bc.validate()?;
		Ok(bc)
	}
}

/// SOCKS5 chaining backend.
pub struct SocksProxyBackend {
	config: BackendConfiguration,
	tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl SocksProxyBackend {
	/// Applies defaults and returns a chaining backend. Configuration
	/// validation must be performed via `validate()` (typically through
	/// `Configuration::backend_config`) before calling `new`.
	pub fn new(config: BackendConfiguration) -> Result<Self, BackendError> {
		let tls_config = if let Some(tc) = &config.tls_config {
			Some(tc.clone())
		} else if config.tls {
			let built = build_client_tls_config(
				&config.proxy_address,
				&config.tls_server_name,
				&config.tls_ca_file,
				config.tls_insecure_skip_verify,
			)
			.map_err(|e| BackendError::Other(e.to_string()))?;
			Some(Arc::new(built))
		} else {
			None
		};
		Ok(Self { config, tls_config })
	}
}

#[async_trait]
impl Backend for SocksProxyBackend {
	/// Capabilities report that SOCKS5 CONNECT can tunnel any TCP application
	/// protocol, but cannot carry UDP.
	fn capabilities(&self) -> Vec<Capability> {
		vec![Capability {
			network: "tcp".to_string(),
			protocol: Protocol::Any,
		}]
	}

	/// Dials the upstream SOCKS5 proxy, negotiates authentication, issues a
	/// CONNECT to `target`, and returns the tunneled connection.
	async fn dial(&self, target: Target, dialer: &dyn Dialer) -> Result<BoxedStream, BackendError> {
		let conn = dialer
			.dial_context("tcp", &self.config.proxy_address)
			.await
			.map_err(|e| BackendError::Other(format!("socksproxy: dial upstream proxy: {e}")))?;

		// Wrap in TLS if configured.
		let conn: BoxedStream = if let Some(tls_config) = &self.tls_config {
			let server_name = rustls::pki_types::ServerName::try_from(tls_server_host(
				&self.config.proxy_address,
				&self.config.tls_server_name,
			))
			.map_err(|e| BackendError::Other(format!("socksproxy: parse TLS server name: {e}")))?;
			let connector = TlsConnector::from(tls_config.clone());
			let tls_conn = connector.connect(server_name, conn).await.map_err(|e| {
				BackendError::Other(format!(
					"socksproxy: TLS handshake with upstream proxy: {e}"
				))
			})?;
			Box::new(tls_conn)
		} else {
			conn
		};

		// Buffer reads so bytes pulled past the SOCKS5 handshake (early
		// tunnel data) are preserved.
		let mut buffered = BufferedStream::new(conn);

		negotiate_method(&mut buffered, &self.config).await?;
		socks5_connect(&mut buffered, &target).await?;

		Ok(Box::new(buffered))
	}
}

/// Performs the SOCKS5 method selection handshake.
///
/// When the backend has credentials it offers username/password auth
/// alongside no-auth; otherwise it offers only no-auth.
async fn negotiate_method(
	stream: &mut BufferedStream,
	config: &BackendConfiguration,
) -> Result<(), BackendError> {
	// Build method list.
	let mut methods: Vec<u8> = vec![socks5::METHOD_NO_AUTH];
	if !config.username.is_empty() {
		methods.push(socks5::METHOD_USERNAME_PASSWORD);
	}

	let mut req = Vec::with_capacity(2 + methods.len());
	req.push(socks5::VERSION);
	req.push(methods.len() as u8);
	req.extend_from_slice(&methods);
	stream
		.write_all(&req)
		.await
		.map_err(|e| BackendError::Other(format!("socksproxy: write method negotiation: {e}")))?;

	let mut header = [0u8; 2];
	stream
		.read_exact(&mut header)
		.await
		.map_err(|e| BackendError::Other(format!("socksproxy: read method negotiation: {e}")))?;
	if header[0] != socks5::VERSION {
		return Err(BackendError::Other(format!(
			"socksproxy: unexpected SOCKS version 0x{:02x} during method negotiation",
			header[0]
		)));
	}
	let method = header[1];
	match method {
		socks5::METHOD_NO_AUTH => Ok(()),
		socks5::METHOD_USERNAME_PASSWORD => username_password_auth(stream, config).await,
		socks5::METHOD_NO_ACCEPTABLE => Err(BackendError::Other(
			"socksproxy: upstream proxy rejected connection (no acceptable method)".to_string(),
		)),
		other => Err(BackendError::Other(format!(
			"socksproxy: upstream proxy selected unsupported method 0x{other:02x}"
		))),
	}
}

/// Performs the RFC 1929 username/password sub-negotiation.
async fn username_password_auth(
	stream: &mut BufferedStream,
	config: &BackendConfiguration,
) -> Result<(), BackendError> {
	if config.username.len() > 255 || config.password.len() > 255 {
		return Err(BackendError::Other(
			"socksproxy: username and password must each be at most 255 bytes".to_string(),
		));
	}
	let mut req = Vec::with_capacity(3 + config.username.len() + config.password.len());
	req.push(socks5::AUTH_VERSION);
	req.push(config.username.len() as u8);
	req.extend_from_slice(config.username.as_bytes());
	req.push(config.password.len() as u8);
	req.extend_from_slice(config.password.as_bytes());
	stream.write_all(&req).await.map_err(|e| {
		BackendError::Other(format!("socksproxy: write username/password auth: {e}"))
	})?;

	let mut resp = [0u8; 2];
	stream.read_exact(&mut resp).await.map_err(|e| {
		BackendError::Other(format!("socksproxy: read username/password auth: {e}"))
	})?;
	if resp[0] != socks5::AUTH_VERSION {
		return Err(BackendError::Other(format!(
			"socksproxy: unexpected auth version 0x{:02x}",
			resp[0]
		)));
	}
	if resp[1] != 0x00 {
		return Err(BackendError::Other(
			"socksproxy: upstream proxy rejected credentials".to_string(),
		));
	}
	Ok(())
}

/// Issues a SOCKS5 CONNECT request for `target` and consumes the reply,
/// leaving the stream ready for tunnel data.
async fn socks5_connect(stream: &mut BufferedStream, target: &Target) -> Result<(), BackendError> {
	let req = encode_socks5_request(target).map_err(BackendError::Other)?;
	stream
		.write_all(&req)
		.await
		.map_err(|e| BackendError::Other(format!("socksproxy: write CONNECT request: {e}")))?;

	let mut header = [0u8; 4];
	stream
		.read_exact(&mut header)
		.await
		.map_err(|e| BackendError::Other(format!("socksproxy: read CONNECT response: {e}")))?;
	if header[0] != socks5::VERSION {
		return Err(BackendError::Other(format!(
			"socksproxy: unexpected SOCKS version 0x{:02x} in CONNECT response",
			header[0]
		)));
	}
	if header[1] != socks5::REP_SUCCESS {
		return Err(BackendError::Other(format!(
			"socksproxy: upstream proxy returned {}",
			socks5::reply_text(header[1])
		)));
	}

	// Skip BND.ADDR + BND.PORT using the shared address reader. Both the
	// host and port are discarded.
	if let Err(e) = socks5::read_socks5_address(stream, header[3]).await {
		return Err(BackendError::Other(format!(
			"socksproxy: read CONNECT bind address: {e}"
		)));
	}
	Ok(())
}

/// Builds the SOCKS5 CONNECT request bytes for `target`.
///
/// Public so tests can exercise it directly.
pub fn encode_socks5_request(target: &Target) -> Result<Vec<u8>, String> {
	let host = &target.host;
	let port = target.port;
	if host.is_empty() {
		return Err("socksproxy: target host is required".to_string());
	}
	if port == 0 {
		return Err("socksproxy: target port is required".to_string());
	}

	let mut req: Vec<u8> = vec![socks5::VERSION, socks5::CMD_CONNECT, 0x00];
	match host.parse::<IpAddr>() {
		Ok(IpAddr::V4(v4)) => {
			req.push(socks5::ATYP_IPV4);
			req.extend_from_slice(&v4.octets());
		}
		Ok(IpAddr::V6(v6)) => {
			req.push(socks5::ATYP_IPV6);
			req.extend_from_slice(&v6.octets());
		}
		Err(_) => {
			if host.len() > 255 {
				return Err(format!(
					"socksproxy: target domain {host:?} exceeds 255 bytes"
				));
			}
			req.push(socks5::ATYP_DOMAIN);
			req.push(host.len() as u8);
			req.extend_from_slice(host.as_bytes());
		}
	}
	req.extend_from_slice(&port.to_be_bytes());
	Ok(req)
}

/// Returns the host portion of `proxy_address`, or `server_name` when non-empty.
fn tls_server_host(proxy_address: &str, server_name: &str) -> String {
	if !server_name.is_empty() {
		return server_name.to_string();
	}
	// Strip port. Handle IPv6 [::1]:443 form.
	if let Some(rest) = proxy_address.strip_prefix('[') {
		if let Some(close) = rest.find(']') {
			return proxy_address[..close + 1].to_string();
		}
	}
	proxy_address
		.rsplit_once(':')
		.map(|(h, _)| h.to_string())
		.unwrap_or_else(|| proxy_address.to_string())
}

/// Builds a `rustls::ClientConfig` for the upstream proxy connection.
fn build_client_tls_config(
	proxy_address: &str,
	server_name: &str,
	ca_file: &str,
	insecure: bool,
) -> Result<rustls::ClientConfig, BuildTlsError> {
	let _host = tls_server_host(proxy_address, server_name);

	// Build root certificate store.
	let mut root_store = rustls::RootCertStore::empty();
	if !ca_file.is_empty() {
		let pem =
			std::fs::read(ca_file).map_err(|e| format!("socksproxy: read TLS CA file: {e}"))?;
		let mut reader = std::io::Cursor::new(&pem);
		let certs = rustls_pemfile::certs(&mut reader)
			.collect::<Result<Vec<_>, _>>()
			.map_err(|e| format!("socksproxy: parse CA file: {e}"))?;
		if certs.is_empty() {
			return Err(format!("socksproxy: no certificates parsed from {ca_file}").into());
		}
		for cert in certs {
			root_store
				.add(cert)
				.map_err(|e| format!("socksproxy: add CA certificate: {e}"))?;
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

	let config = if insecure {
		rustls::ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
			.with_no_client_auth()
	} else {
		rustls::ClientConfig::builder()
			.with_root_certificates(root_store)
			.with_no_client_auth()
	};
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

/// Wraps a stream with a small read buffer so that bytes pulled past the
/// SOCKS5 handshake (the early tunnel data the upstream may have sent) are
/// preserved for subsequent `poll_read` calls.
struct BufferedStream {
	inner: BoxedStream,
	buf: Vec<u8>,
}

impl BufferedStream {
	fn new(inner: BoxedStream) -> Self {
		Self {
			inner,
			buf: Vec::new(),
		}
	}
}

impl tokio::io::AsyncRead for BufferedStream {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		dst: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		let this = self.get_mut();
		// First drain the leftover buffer.
		if !this.buf.is_empty() {
			let n = std::cmp::min(this.buf.len(), dst.remaining());
			dst.put_slice(&this.buf[..n]);
			this.buf.drain(..n);
			return std::task::Poll::Ready(Ok(()));
		}
		// Delegate to the underlying stream.
		std::pin::Pin::new(&mut this.inner).poll_read(cx, dst)
	}
}

impl tokio::io::AsyncWrite for BufferedStream {
	fn poll_write(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		src: &[u8],
	) -> std::task::Poll<std::io::Result<usize>> {
		std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, src)
	}

	fn poll_flush(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
	}
}
