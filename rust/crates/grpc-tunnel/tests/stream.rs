use std::io;

use futures_util::StreamExt;
use grpc_tunnel::{
	client_channel, connect_frame, frame, parse_connect, payload_frame, ConnectRequest, Frame,
	GrpcStream,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::wrappers::ReceiverStream;

/// Builds a connected client/server stream pair backed by in-memory channels.
///
/// The connect frame is sent by the client and consumed by the server before
/// the server-side `GrpcStream` is built, mirroring the real wiring.
async fn stream_pair() -> (GrpcStream, GrpcStream, (String, String, u16)) {
	let (client_tx, client_rx) = client_channel();
	let (server_tx, server_rx) = client_channel();

	client_tx
		.send(connect_frame("tcp", "example.com", 443))
		.await
		.unwrap();

	let mut requests = ReceiverStream::new(client_rx).map(Ok);
	let first = requests.next().await.unwrap().unwrap();
	let target = parse_connect(first).unwrap();

	let client = GrpcStream::new(ReceiverStream::new(server_rx).map(Ok), client_tx);
	let server = GrpcStream::new(requests, server_tx);
	(client, server, target)
}

#[tokio::test]
async fn payload_bytes_round_trip() {
	let (mut client, mut server, target) = stream_pair().await;
	assert_eq!(target, ("tcp".to_owned(), "example.com".to_owned(), 443));

	let echo = tokio::spawn(async move {
		let mut buf = vec![0u8; 5];
		server.read_exact(&mut buf).await.unwrap();
		assert_eq!(&buf, b"hello");
		server.write_all(b"world").await.unwrap();
	});

	client.write_all(b"hello").await.unwrap();
	let mut buf = vec![0u8; 5];
	client.read_exact(&mut buf).await.unwrap();
	assert_eq!(&buf, b"world");
	echo.await.unwrap();
}

#[tokio::test]
async fn read_ends_at_eof_when_peer_closes() {
	let (client_tx, _client_rx) = client_channel();
	let (server_tx, server_rx) = client_channel();
	let mut client = GrpcStream::new(ReceiverStream::new(server_rx).map(Ok), client_tx);
	drop(server_tx);

	let mut buf = Vec::new();
	client.read_to_end(&mut buf).await.unwrap();
	assert!(buf.is_empty());
}

#[tokio::test]
async fn parse_connect_decodes_target() {
	let frame = connect_frame("udp", "10.0.0.1", 53);
	let (network, host, port) = parse_connect(frame).unwrap();
	assert_eq!(
		(network.as_str(), host.as_str(), port),
		("udp", "10.0.0.1", 53)
	);
}

#[tokio::test]
async fn parse_connect_rejects_payload_frame() {
	let err = parse_connect(payload_frame(&b"x"[..])).unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn parse_connect_rejects_out_of_range_port() {
	let frame = Frame {
		kind: Some(frame::Kind::Connect(ConnectRequest {
			network: "tcp".to_owned(),
			host: "example.com".to_owned(),
			port: 70000,
		})),
	};
	let err = parse_connect(frame).unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn read_rejects_repeated_connect_frame() {
	let (client_tx, client_rx) = client_channel();
	client_tx
		.send(connect_frame("tcp", "example.com", 443))
		.await
		.unwrap();
	let (server_tx, _server_rx) = client_channel();
	let mut server = GrpcStream::new(ReceiverStream::new(client_rx).map(Ok), server_tx);

	let mut buf = [0u8; 1];
	let err = server.read(&mut buf).await.unwrap_err();
	assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn write_after_peer_close_is_broken_pipe() {
	let (client_tx, client_rx) = client_channel();
	let (_server_tx, server_rx) = client_channel();
	let mut client = GrpcStream::new(ReceiverStream::new(server_rx).map(Ok), client_tx);
	drop(client_rx);

	let err = client.write_all(b"x").await.unwrap_err();
	assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
}
