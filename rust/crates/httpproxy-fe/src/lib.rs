//! HTTP CONNECT frontend: accepts CONNECT requests, optionally authenticates
//! the client, and tunnels traffic to a backend-selected upstream via a
//! `ShimServer`.
//!
//! Error strings and HTTP response bodies are kept stable so tests can match
//! on substrings.

pub mod config;
pub mod handshake;
pub mod server;

pub use config::{CamouflageMethod, ConfigError, ServerConfiguration, TYPE};
pub use server::Server;

pub use config::HttpFrontendConfiguration;
