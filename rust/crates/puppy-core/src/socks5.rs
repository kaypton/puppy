//! SOCKS5 protocol constants and address reader.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt};

/// SOCKS5 protocol version.
pub const VERSION: u8 = 0x05;

/// Method: No authentication required.
pub const METHOD_NO_AUTH: u8 = 0x00;
/// Method: Username/password (RFC 1929).
pub const METHOD_USERNAME_PASSWORD: u8 = 0x02;
/// Method: No acceptable methods.
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// RFC 1929 auth version.
pub const AUTH_VERSION: u8 = 0x01;

/// Command: CONNECT.
pub const CMD_CONNECT: u8 = 0x01;

/// Address type: IPv4.
pub const ATYP_IPV4: u8 = 0x01;
/// Address type: Domain name.
pub const ATYP_DOMAIN: u8 = 0x03;
/// Address type: IPv6.
pub const ATYP_IPV6: u8 = 0x04;

/// Reply code: succeeded.
pub const REP_SUCCESS: u8 = 0x00;
/// Reply code: general SOCKS server failure.
pub const REP_GENERAL_FAILURE: u8 = 0x01;
/// Reply code: connection not allowed by ruleset.
pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
/// Reply code: network unreachable.
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
/// Reply code: host unreachable.
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
/// Reply code: connection refused.
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
/// Reply code: TTL expired.
pub const REP_TTL_EXPIRED: u8 = 0x06;
/// Reply code: command not supported.
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
/// Reply code: address type not supported.
pub const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Returns the RFC 1928 text for a reply code.
///
/// Unknown codes produce `unknown error (0x<hex>)` matching `strconv.FormatUint(.., 16)`.
pub fn reply_text(rep: u8) -> String {
	match rep {
		REP_SUCCESS => "succeeded".to_string(),
		REP_GENERAL_FAILURE => "general SOCKS server failure".to_string(),
		REP_CONNECTION_NOT_ALLOWED => "connection not allowed by ruleset".to_string(),
		REP_NETWORK_UNREACHABLE => "network unreachable".to_string(),
		REP_HOST_UNREACHABLE => "host unreachable".to_string(),
		REP_CONNECTION_REFUSED => "connection refused".to_string(),
		REP_TTL_EXPIRED => "TTL expired".to_string(),
		REP_CMD_NOT_SUPPORTED => "command not supported".to_string(),
		REP_ADDR_TYPE_NOT_SUPPORTED => "address type not supported".to_string(),
		other => format!("unknown error (0x{other:x})"),
	}
}

/// Reads DST.ADDR + DST.PORT from a SOCKS5 request/reply given `atyp`.
///
/// The underlying `io::Error` kind is preserved (so `ErrorKind::UnexpectedEof`
/// propagates like `errors.Is(err, io.EOF)`).
pub async fn read_socks5_address<R: AsyncRead + Unpin>(
	reader: &mut R,
	atyp: u8,
) -> io::Result<(String, u16)> {
	let host = match atyp {
		ATYP_IPV4 => {
			let mut buf = [0u8; 4];
			read_full(reader, &mut buf, "read IPv4 address").await?;
			Ipv4Addr::from(buf).to_string()
		}
		ATYP_IPV6 => {
			let mut buf = [0u8; 16];
			read_full(reader, &mut buf, "read IPv6 address").await?;
			Ipv6Addr::from(buf).to_string()
		}
		ATYP_DOMAIN => {
			let mut len_buf = [0u8; 1];
			read_full(reader, &mut len_buf, "read domain length").await?;
			let len = len_buf[0] as usize;
			let mut buf = vec![0u8; len];
			read_full(reader, &mut buf, "read domain").await?;
			String::from_utf8(buf).map_err(|e| {
				io::Error::new(io::ErrorKind::InvalidData, format!("read domain: {e}"))
			})?
		}
		other => {
			return Err(io::Error::other(format!(
				"unknown address type 0x{other:02x}"
			)))
		}
	};

	let mut port_buf = [0u8; 2];
	read_full(reader, &mut port_buf, "read port").await?;
	let port = u16::from_be_bytes(port_buf);

	Ok((host, port))
}

/// Wraps `read_exact` so the underlying error kind is preserved and the message
/// is prefixed with `what`, matching `fmt.Errorf("%s: %w", what, err)`.
async fn read_full<R: AsyncRead + Unpin>(
	reader: &mut R,
	buf: &mut [u8],
	what: &str,
) -> io::Result<()> {
	reader
		.read_exact(buf)
		.await
		.map_err(|e| io::Error::new(e.kind(), format!("{what}: {e}")))?;
	Ok(())
}
