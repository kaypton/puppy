fn main() -> Result<(), Box<dyn std::error::Error>> {
	let protoc = protoc_bin_vendored::protoc_bin_path()?;
	std::env::set_var("PROTOC", protoc);
	tonic_build::configure()
		.build_server(true)
		.build_client(true)
		// The `Connect` RPC collides with the generated transport `connect`
		// constructor, so clients are built with `TunnelClient::new(channel)`.
		.build_transport(false)
		.compile_protos(&["proto/tunnel.proto"], &["proto"])?;
	println!("cargo:rerun-if-changed=proto/tunnel.proto");
	Ok(())
}
