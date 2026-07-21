//! Puppy shared core: backend traits, SOCKS5 primitives, counting, stats, shim, TLS, egress.
//!
//! This crate intentionally depends only on foundational crates (tokio, parking_lot,
//! rustls, socket2, etc.) and never on any business crate.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod backend;
pub mod counting;
pub mod shim;
pub mod socks5;
pub mod stats;
