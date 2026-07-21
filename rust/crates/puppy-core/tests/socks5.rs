//! Tests for `socks5.rs`.

use std::io;

use puppy_core::socks5::{
	read_socks5_address, reply_text, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6,
	REP_ADDR_TYPE_NOT_SUPPORTED, REP_CMD_NOT_SUPPORTED, REP_CONNECTION_NOT_ALLOWED,
	REP_CONNECTION_REFUSED, REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE, REP_NETWORK_UNREACHABLE,
	REP_SUCCESS, REP_TTL_EXPIRED,
};

/// Verifies `reply_text` returns the human-readable strings defined by
/// RFC 1928 for each known reply code, and falls back to "unknown error"
/// for unrecognized codes.
#[test]
fn reply_text_matches_rfc_strings() {
	let cases = [
		(REP_SUCCESS, "succeeded"),
		(REP_GENERAL_FAILURE, "general SOCKS server failure"),
		(
			REP_CONNECTION_NOT_ALLOWED,
			"connection not allowed by ruleset",
		),
		(REP_NETWORK_UNREACHABLE, "network unreachable"),
		(REP_HOST_UNREACHABLE, "host unreachable"),
		(REP_CONNECTION_REFUSED, "connection refused"),
		(REP_TTL_EXPIRED, "TTL expired"),
		(REP_CMD_NOT_SUPPORTED, "command not supported"),
		(REP_ADDR_TYPE_NOT_SUPPORTED, "address type not supported"),
		(0xFF, "unknown error"),
	];
	for (rep, want) in cases {
		let got = reply_text(rep);
		assert!(
			got.contains(want),
			"reply_text(0x{rep:02x}) = {got:?}, want substring {want:?}"
		);
	}
}

/// Decodes each SOCKS5 address type (IPv4, IPv6, domain) from a byte
/// stream and asserts the parsed host/port, and confirms that truncated or
/// unknown-address-type inputs produce errors with the expected messages.
#[tokio::test]
async fn read_socks5_address_decodes_all_types_and_errors() {
	#[allow(clippy::type_complexity)]
	let cases: &[(&str, u8, &[u8], &str, u16, Option<&str>)] = &[
		(
			"ipv4",
			ATYP_IPV4,
			&[127, 0, 0, 1, 0x1F, 0x90],
			"127.0.0.1",
			8080,
			None,
		),
		(
			"ipv6",
			ATYP_IPV6,
			&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xBB],
			"::1",
			443,
			None,
		),
		(
			"domain",
			ATYP_DOMAIN,
			&[
				11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x00, 0x50,
			],
			"example.com",
			80,
			None,
		),
		(
			"unknown atyp",
			0x09,
			&[1, 2],
			"",
			0,
			Some("unknown address type 0x09"),
		),
		(
			"ipv4 short",
			ATYP_IPV4,
			&[127, 0, 0],
			"",
			0,
			Some("read IPv4 address"),
		),
		(
			"domain length short",
			ATYP_DOMAIN,
			&[],
			"",
			0,
			Some("read domain length"),
		),
		(
			"domain body short",
			ATYP_DOMAIN,
			&[5, b'a', b'b'],
			"",
			0,
			Some("read domain"),
		),
		(
			"port short",
			ATYP_IPV4,
			&[127, 0, 0, 1, 0x1F],
			"",
			0,
			Some("read port"),
		),
	];

	for (name, atyp, input, want_host, want_port, want_err) in cases {
		let mut reader = io::Cursor::new(*input);
		let result = read_socks5_address(&mut reader, *atyp).await;
		match (*want_err, result) {
			(Some(want_err), Err(err)) => {
				assert!(
					err.to_string().contains(want_err),
					"[{name}] error = {err:?}, want substring {want_err:?}"
				);
			}
			(None, Ok((host, port))) => {
				assert_eq!(host, *want_host, "[{name}] host mismatch");
				assert_eq!(port, *want_port, "[{name}] port mismatch");
			}
			(Some(_), Ok(_)) => panic!("[{name}] expected error, got Ok"),
			(None, Err(err)) => panic!("[{name}] unexpected error: {err}"),
		}
	}
}

/// Confirms that an immediate EOF from the reader surfaces as
/// `ErrorKind::UnexpectedEof` (preserved through error wrapping) so callers
/// can distinguish clean disconnects from malformed frames.
#[tokio::test]
async fn read_socks5_address_propagates_eof_kind() {
	// A reader that immediately yields EOF. `read_exact` returns
	// `ErrorKind::UnexpectedEof` (the Rust analogue of `io.EOF` after
	// `io.ReadFull`). The wrapping in `read_socks5_address` preserves the
	// kind, mirroring `errors.Is(err, io.EOF)` via `%w` wrapping.
	let mut reader = io::Cursor::new(Vec::<u8>::new());
	let err = read_socks5_address(&mut reader, ATYP_IPV4)
		.await
		.expect_err("expected EOF");
	assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}
