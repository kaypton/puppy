//! SOCKS5 frontend: accepts CONNECT requests, optionally authenticates the
//! client via RFC 1929 username/password, and tunnels traffic to a
//! backend-selected upstream via a `ShimServer`.
//!
//! Only the CONNECT command (0x01) is supported; UDP ASSOCIATE
//! and BIND return `command not supported` (0x07) per RFC 1928.

pub mod config;
pub mod handshake;
pub mod server;

pub use config::{ConfigError, ServerConfiguration, TYPE};
pub use server::Server;

pub use config::SocksFrontendConfiguration;
