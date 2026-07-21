//! TUN frontend (Phase 9 / M2).
//!
//! Currently houses the platform-agnostic pure-logic modules. Platform-specific
//! device, egress, and route code is added incrementally in subsequent
//! sub-phases.

pub mod addr;
pub mod config;
pub mod device;
#[cfg(target_os = "macos")]
pub mod device_darwin;
#[cfg(target_os = "linux")]
pub mod device_linux;
pub mod egress;
pub mod protocol;
pub mod route;
#[cfg(target_os = "macos")]
pub mod route_darwin;
#[cfg(target_os = "linux")]
pub mod route_linux;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub mod route_other;
pub mod routes;

#[cfg(target_os = "linux")]
pub mod dns_intercept_linux;

#[cfg(target_os = "linux")]
pub mod nft;

pub mod stack;

pub mod dispatch;

pub mod pumps;

pub mod server;

#[cfg(test)]
mod loopback_test;
