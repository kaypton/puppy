//! gRPC tunnel frontend: accepts gRPC bidirectional-streaming tunnel requests,
//! optionally authenticates the client with a bearer token, and tunnels
//! traffic to a backend-selected upstream via a `ShimServer`.
//!
//! The wire protocol (connect frame followed by payload frames) is defined by
//! the shared `grpc-tunnel` crate.

pub mod config;
pub mod server;
pub mod service;

pub use config::{ConfigError, ServerConfiguration, TYPE};
pub use server::Server;
pub use service::TunnelService;

pub use config::GrpcFrontendConfiguration;
