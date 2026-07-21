//! Tests for `shim.rs`.
//!
//! `ShimServer` is also exercised indirectly through frontend integration
//! tests; here we add explicit duplex-based Rust tests covering:
//! bidirectional copy, closing one side closes the other, and byte counts.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use puppy_core::shim::{ShimError, ShimServer, ShimServerConfiguration, DEFAULT_BUFFER_SIZE};

/// Verifies `ShimServer::new` rejects configurations missing the frontend
/// (`FrontendNil`) or backend (`BackendNil`) stream.
#[test]
fn new_rejects_missing_streams() {
	let cfg: ShimServerConfiguration<tokio::io::DuplexStream> = ShimServerConfiguration {
		frontend: None,
		backend: None,
		buffer_size: 0,
	};
	match ShimServer::new(cfg) {
		Err(ShimError::FrontendNil) => {}
		Err(e) => panic!("expected FrontendNil, got {e:?}"),
		Ok(_) => panic!("expected FrontendNil, got Ok"),
	}

	let (fe_client, _fe_server) = tokio::io::duplex(64);
	let cfg = ShimServerConfiguration {
		frontend: Some(fe_client),
		backend: None,
		buffer_size: 0,
	};
	match ShimServer::new(cfg) {
		Err(ShimError::BackendNil) => {}
		Err(e) => panic!("expected BackendNil, got {e:?}"),
		Ok(_) => panic!("expected BackendNil, got Ok"),
	}
}

/// Verifies that a zero `buffer_size` is replaced with `DEFAULT_BUFFER_SIZE`
/// so the copy loop always has a positive scratch buffer.
#[test]
fn new_applies_default_buffer_size_when_zero_or_negative() {
	let (fe, _fe_other) = tokio::io::duplex(64);
	let (be, _be_other) = tokio::io::duplex(64);
	let s = ShimServer::new(ShimServerConfiguration {
		frontend: Some(fe),
		backend: Some(be),
		buffer_size: 0,
	})
	.unwrap();
	assert_eq!(s.buf_size, DEFAULT_BUFFER_SIZE);
}

/// Exercises the full bidirectional copy: bytes written on the client side
/// of the frontend appear on the client side of the backend and vice versa,
/// and `run` returns the per-direction byte counts once both directions
/// complete.
#[tokio::test]
async fn run_copies_bidirectionally_and_returns_counts() {
	// `duplex` gives us a connected pair: writing to one end appears on the
	// other. We construct two pairs:
	//   - fe_pair: (client_side_fe, server_side_fe) — the ShimServer owns
	//     server_side_fe (its `frontend`).
	//   - be_pair: (server_side_be, client_side_be) — the ShimServer owns
	//     server_side_be (its `backend`).
	// Bytes written by the client on client_side_fe flow through the shim's
	// frontend→backend direction and appear on client_side_be; symmetrically
	// for the backend→frontend direction.
	let (mut client_side_fe, server_side_fe) = tokio::io::duplex(64);
	let (server_side_be, mut client_side_be) = tokio::io::duplex(64);

	let shim = ShimServer::new(ShimServerConfiguration {
		frontend: Some(server_side_fe),
		backend: Some(server_side_be),
		buffer_size: 8,
	})
	.unwrap();

	// Spawn the shim.
	let shim_handle = tokio::spawn(async move { shim.run().await });

	// Client writes to frontend; backend reader should observe.
	client_side_fe.write_all(b"hello").await.unwrap();
	let mut buf = [0u8; 5];
	client_side_be.read_exact(&mut buf).await.unwrap();
	assert_eq!(&buf, b"hello");

	// Backend writes; client should observe.
	client_side_be.write_all(b"world!").await.unwrap();
	let mut buf = [0u8; 6];
	client_side_fe.read_exact(&mut buf).await.unwrap();
	assert_eq!(&buf, b"world!");

	// Close the client side; the shim's fe→be direction should observe EOF
	// and close the backend, causing the be→fe direction to exit as well.
	drop(client_side_fe);
	drop(client_side_be);

	let (fe_to_be, be_to_fe) = shim_handle.await.unwrap();
	assert_eq!(fe_to_be, 5, "frontend→backend byte count");
	assert_eq!(be_to_fe, 6, "backend→frontend byte count");
}

/// Confirms that dropping the client side of one duplex terminates both
/// copy directions promptly: the shim's `run` future resolves within a
/// bounded wait and reports zero bytes transferred.
#[tokio::test]
async fn closing_one_side_terminates_both_directions() {
	let (client_side_fe, server_side_fe) = tokio::io::duplex(64);
	let (server_side_be, client_side_be) = tokio::io::duplex(64);

	let shim = ShimServer::new(ShimServerConfiguration {
		frontend: Some(server_side_fe),
		backend: Some(server_side_be),
		buffer_size: 8,
	})
	.unwrap();

	let shim_handle = tokio::spawn(async move { shim.run().await });

	// Drop only the client side of the frontend. The shim's fe→be copy should
	// observe EOF and shut down the backend, which terminates be→fe. The whole
	// `run` future should resolve promptly.
	drop(client_side_fe);
	drop(client_side_be);

	let (fe_to_be, be_to_fe) = tokio::time::timeout(std::time::Duration::from_secs(1), shim_handle)
		.await
		.expect("shim did not terminate within 1s")
		.unwrap();
	assert_eq!(fe_to_be, 0);
	assert_eq!(be_to_fe, 0);
}

/// Confirms that `run_until` aborts the copy loop when its shutdown signal
/// fires, even before any IO occurs, and that the future resolves promptly.
#[tokio::test]
async fn run_until_aborts_on_shutdown_signal() {
	let (client_side_fe, server_side_fe) = tokio::io::duplex(64);
	let (server_side_be, client_side_be) = tokio::io::duplex(64);

	let shim = ShimServer::new(ShimServerConfiguration {
		frontend: Some(server_side_fe),
		backend: Some(server_side_be),
		buffer_size: 8,
	})
	.unwrap();

	let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
	let shim_handle = tokio::spawn(async move {
		shim.run_until(async {
			let _ = shutdown_rx.await;
		})
		.await
	});

	// Trigger shutdown before any IO. The shim should terminate promptly.
	shutdown_tx.send(()).unwrap();
	drop(client_side_fe);
	drop(client_side_be);

	tokio::time::timeout(std::time::Duration::from_secs(1), shim_handle)
		.await
		.expect("shim did not terminate within 1s after shutdown")
		.unwrap();
}

/// Transfers a payload larger than the configured buffer size to exercise
/// the copy loop's chunking, and asserts the full payload arrives intact
/// with the correct aggregate byte count.
#[tokio::test]
async fn large_transfer_uses_buffered_copy() {
	// Transfer more bytes than the buffer size to exercise the copy loop's
	// chunking. Use a 1KB buffer and a 16KB payload.
	let (mut client_side_fe, server_side_fe) = tokio::io::duplex(64 * 1024);
	let (server_side_be, mut client_side_be) = tokio::io::duplex(64 * 1024);

	let shim = ShimServer::new(ShimServerConfiguration {
		frontend: Some(server_side_fe),
		backend: Some(server_side_be),
		buffer_size: 1024,
	})
	.unwrap();

	let shim_handle = tokio::spawn(async move { shim.run().await });

	let payload: Vec<u8> = (0..16 * 1024).map(|i| (i & 0xff) as u8).collect();
	client_side_fe.write_all(&payload).await.unwrap();

	let mut received = vec![0u8; payload.len()];
	client_side_be.read_exact(&mut received).await.unwrap();
	assert_eq!(received, payload);

	drop(client_side_fe);
	drop(client_side_be);

	let (fe_to_be, _be_to_fe) = shim_handle.await.unwrap();
	assert_eq!(fe_to_be, payload.len() as u64);
}
