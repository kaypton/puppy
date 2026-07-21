//! HTTP CONNECT upstream backend: forwards traffic to a target through an
//! upstream HTTP proxy using the CONNECT method (proxy chaining).

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use puppy_core::backend::{
	Backend, BackendError, BoxedStream, Capability, Dialer, Protocol, Target,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

pub mod config;
pub use config::{ConfigError, Configuration, TYPE};

/// Runtime configuration for the HTTP CONNECT chaining backend.
///
/// The TOML-decoded [`Configuration`] is converted into this runtime form via
/// [`Configuration::backend_config`].
#[derive(Clone, Default)]
pub struct BackendConfiguration {
	/// Upstream HTTP proxy address (`host:port`).
	pub proxy_address: String,
	/// Username for HTTP Basic Proxy-Authorization. Required to be paired
	/// with `password`.
	pub username: String,
	/// Password for HTTP Basic Proxy-Authorization. Required to be paired
	/// with `username`.
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
	/// Error strings are prefixed with `"httpproxy: "` for consistency with
	/// the rest of the backend's diagnostics.
	pub fn validate(&self) -> Result<(), ConfigError> {
		if self.proxy_address.is_empty() {
			return Err(ConfigError::Validation(
				"httpproxy: proxy address is required".to_string(),
			));
		}
		if (self.username.is_empty()) != (self.password.is_empty()) {
			return Err(ConfigError::Validation(
				"httpproxy: username and password must both be set or both be empty".to_string(),
			));
		}
		if !self.tls
			&& (!self.tls_ca_file.is_empty()
				|| !self.tls_server_name.is_empty()
				|| self.tls_insecure_skip_verify)
		{
			return Err(ConfigError::Validation(
				"httpproxy: tls_ca_file, tls_server_name, and tls_insecure_skip_verify require tls = true"
					.to_string(),
			));
		}
		if self.tls_insecure_skip_verify && !self.tls_ca_file.is_empty() {
			return Err(ConfigError::Validation(
				"httpproxy: tls_insecure_skip_verify and tls_ca_file are mutually exclusive"
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

/// HTTP CONNECT chaining backend.
pub struct HttpProxyBackend {
	config: BackendConfiguration,
	tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl HttpProxyBackend {
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
impl Backend for HttpProxyBackend {
	/// Capabilities report that HTTP CONNECT can tunnel any TCP application
	/// protocol, but cannot carry UDP.
	fn capabilities(&self) -> Vec<Capability> {
		vec![Capability {
			network: "tcp".to_string(),
			protocol: Protocol::Any,
		}]
	}

	/// Dials the upstream proxy, issues a CONNECT to `target`, and returns the
	/// tunneled connection.
	async fn dial(&self, target: Target, dialer: &dyn Dialer) -> Result<BoxedStream, BackendError> {
		let conn = dialer
			.dial_context("tcp", &self.config.proxy_address)
			.await
			.map_err(|e| BackendError::Other(format!("httpproxy: dial upstream proxy: {e}")))?;

		// Wrap in TLS if configured.
		let conn: BoxedStream = if let Some(tls_config) = &self.tls_config {
			let server_name = rustls::pki_types::ServerName::try_from(tls_server_host(
				&self.config.proxy_address,
				&self.config.tls_server_name,
			))
			.map_err(|e| BackendError::Other(format!("httpproxy: parse TLS server name: {e}")))?;
			let connector = TlsConnector::from(tls_config.clone());
			let tls_conn = connector.connect(server_name, conn).await.map_err(|e| {
				BackendError::Other(format!("httpproxy: TLS handshake with upstream proxy: {e}"))
			})?;
			Box::new(tls_conn)
		} else {
			conn
		};

		// Build CONNECT request.
		let target_addr = target.address();
		let mut req = String::new();
		req.push_str(&format!(
			"CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n"
		));
		if !self.config.username.is_empty() {
			let creds = base64::engine::general_purpose::STANDARD
				.encode(format!("{}:{}", self.config.username, self.config.password));
			req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
		}
		req.push_str("\r\n");

		// Wrap with a BufWriter-like abstraction so we can write the CONNECT
		// request, then read the response, then preserve any early tunnel
		// bytes the response reader pulled past the headers.
		let mut buffered = BufferedStream::new(conn);

		buffered
			.write_all(req.as_bytes())
			.await
			.map_err(|e| BackendError::Other(format!("httpproxy: write CONNECT: {e}")))?;

		// Read CONNECT response.
		let status_line = buffered
			.read_http_response_line()
			.await
			.map_err(|e| BackendError::Other(format!("httpproxy: read CONNECT response: {e}")))?;

		// status_line: "HTTP/1.1 200 Connection Established"
		let status_code = status_line.split_whitespace().nth(1).ok_or_else(|| {
			BackendError::Other(format!(
				"httpproxy: read CONNECT response: malformed status line: {status_line}"
			))
		})?;

		let code: u16 = status_code.parse().map_err(|_| {
			BackendError::Other(format!(
				"httpproxy: read CONNECT response: malformed status line: {status_line}"
			))
		})?;

		if code / 100 != 2 {
			// Format the error as "httpproxy: upstream proxy returned <status>"
			// where <status> is the full status (e.g. "403 Forbidden" or
			// "407 Proxy Authentication Required").
			let status_text = &status_line[status_line.find(' ').unwrap_or(0) + 1..];
			return Err(BackendError::Other(format!(
				"httpproxy: upstream proxy returned {status_text}"
			)));
		}

		Ok(Box::new(buffered))
	}
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
			std::fs::read(ca_file).map_err(|e| format!("httpproxy: read TLS CA file: {e}"))?;
		let mut reader = std::io::Cursor::new(&pem);
		let certs = rustls_pemfile::certs(&mut reader)
			.collect::<Result<Vec<_>, _>>()
			.map_err(|e| format!("httpproxy: parse CA file: {e}"))?;
		if certs.is_empty() {
			return Err(format!("httpproxy: no certificates parsed from {ca_file}").into());
		}
		for cert in certs {
			root_store
				.add(cert)
				.map_err(|e| format!("httpproxy: add CA certificate: {e}"))?;
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
/// CONNECT response header (the early tunnel data the upstream may have sent)
/// are preserved for subsequent `poll_read` calls.
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

	/// Reads the HTTP response line and headers, draining them. Returns the
	/// status line. Any bytes pulled past the headers are kept in `buf` for
	/// subsequent reads.
	async fn read_http_response_line(&mut self) -> std::io::Result<String> {
		// Read until end of headers (\r\n\r\n).
		let mut header_buf = Vec::new();
		let mut byte = [0u8; 1];
		loop {
			let n = self.read(&mut byte).await?;
			if n == 0 {
				return Err(std::io::Error::new(
					std::io::ErrorKind::UnexpectedEof,
					"connection closed before end of headers",
				));
			}
			header_buf.push(byte[0]);
			if header_buf.ends_with(b"\r\n\r\n") {
				break;
			}
			if header_buf.len() > 16 * 1024 {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"response headers too large",
				));
			}
		}
		let status_line = header_buf
			.split(|&b| b == b'\r')
			.next()
			.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no status line"))?
			.to_vec();
		String::from_utf8(status_line)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
