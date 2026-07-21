//! End-to-end TLS and authentication coverage for the observability gRPC API.

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

use assert_cmd::cargo::CommandCargoExt;
use puppy_rpc::v1::observability_client::ObservabilityClient;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tonic::Request;

fn free_port() -> u16 {
	let listener = TcpListener::bind("127.0.0.1:0").expect("free port");
	listener.local_addr().unwrap().port()
}

fn certificate() -> (String, String) {
	use rcgen::{CertificateParams, KeyPair, SanType};
	let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
	params
		.subject_alt_names
		.push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
	let key = KeyPair::generate().unwrap();
	let cert = params.self_signed(&key).unwrap();
	(cert.pem(), key.serialize_pem())
}

#[tokio::test]
async fn grpc_requires_bearer_token_over_tls() {
	let directory = tempfile::tempdir().unwrap();
	let proxy_port = free_port();
	let grpc_port = free_port();
	let (cert, key) = certificate();
	std::fs::write(directory.path().join("server.pem"), &cert).unwrap();
	std::fs::write(directory.path().join("server-key.pem"), key).unwrap();
	let config = format!(
		r#"frontend = "fe"

[frontends.fe]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = {proxy_port}
backend = "direct"
shim = "default"

[backends.direct]
type = "direct"

[shims.default]
buffer_size = 32768

[grpc]
enabled = true
listen_address = "127.0.0.1"
listen_port = {grpc_port}
tls_cert_file = "server.pem"
tls_key_file = "server-key.pem"
token = "test-token"

[observability]
database_path = "history.sqlite3"
log_directory = "logs"
"#
	);
	let config_path = directory.path().join("puppy.toml");
	std::fs::write(&config_path, config).unwrap();
	let mut child = Command::cargo_bin("puppy-server")
		.unwrap()
		.args(["--config", config_path.to_str().unwrap()])
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
		.unwrap();

	let endpoint = format!("https://127.0.0.1:{grpc_port}");
	let mut client = None;
	for _ in 0..50 {
		let channel = Endpoint::from_shared(endpoint.clone())
			.unwrap()
			.tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(cert.clone())))
			.unwrap()
			.connect()
			.await;
		if let Ok(channel) = channel {
			client = Some(ObservabilityClient::new(channel));
			break;
		}
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	let mut client = client.expect("gRPC server did not start");
	let unauthenticated = client.get_overview(Request::new(())).await.unwrap_err();
	assert_eq!(unauthenticated.code(), tonic::Code::Unauthenticated);

	let mut request = Request::new(());
	request
		.metadata_mut()
		.insert("authorization", "Bearer test-token".parse().unwrap());
	let overview = client.get_overview(request).await.unwrap().into_inner();
	assert_eq!(overview.api_version, "v1");
	assert!(!overview.server_instance_id.is_empty());

	#[cfg(unix)]
	unsafe {
		libc::kill(child.id() as i32, libc::SIGTERM);
	}
	#[cfg(not(unix))]
	let _ = child.kill();
	let _ = child.wait();
}

#[tokio::test]
async fn grpc_allows_plaintext_without_token() {
	let directory = tempfile::tempdir().unwrap();
	let proxy_port = free_port();
	let grpc_port = free_port();
	let config = format!(
		r#"frontend = "fe"

[frontends.fe]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = {proxy_port}
backend = "direct"
shim = "default"

[backends.direct]
type = "direct"

[shims.default]
buffer_size = 32768

[grpc]
enabled = true
listen_address = "127.0.0.1"
listen_port = {grpc_port}

[observability]
database_path = "history.sqlite3"
log_directory = "logs"
"#
	);
	let config_path = directory.path().join("puppy.toml");
	std::fs::write(&config_path, config).unwrap();
	let mut child = Command::cargo_bin("puppy-server")
		.unwrap()
		.args(["--config", config_path.to_str().unwrap()])
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
		.unwrap();

	let endpoint = format!("http://127.0.0.1:{grpc_port}");
	let mut client = None;
	for _ in 0..50 {
		if let Ok(channel) = Endpoint::from_shared(endpoint.clone())
			.unwrap()
			.connect()
			.await
		{
			client = Some(ObservabilityClient::new(channel));
			break;
		}
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	let overview = client
		.expect("plaintext gRPC server did not start")
		.get_overview(Request::new(()))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(overview.api_version, "v1");

	#[cfg(unix)]
	unsafe {
		libc::kill(child.id() as i32, libc::SIGTERM);
	}
	#[cfg(not(unix))]
	let _ = child.kill();
	let _ = child.wait();
}
