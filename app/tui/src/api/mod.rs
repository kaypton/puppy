//! Dashboard HTTP API access layer.

pub mod client;
pub mod sse;
pub mod types;

pub use client::{ApiClient, ApiError};
