//! Platform-agnostic TUN device abstraction.
//!
//! Mirrors Go `pkg/tunproxy/device.go`. `Read` and `Write` operate on raw IP
//! packets (no Layer-2 framing, no packet information header).

use std::io;

/// Error returned by `Read`/`Write` after `Close` has been called.
///
/// Mirrors Go `ErrDeviceClosed` (pkg/tunproxy/device.go:25).
pub const ERR_DEVICE_CLOSED: &str = "tunproxy: device closed";

/// Default MTU when the configuration does not specify one.
///
/// Mirrors Go `defaultMTU = 1500` (pkg/tunproxy/device.go:28).
pub const DEFAULT_MTU: u32 = 1500;

/// Returns an `io::Error` representing a closed device.
pub fn err_device_closed() -> io::Error {
	io::Error::other(ERR_DEVICE_CLOSED)
}

/// Platform-agnostic TUN device abstraction.
///
/// Mirrors Go `Device` interface (pkg/tunproxy/device.go:11). Read and Write
/// operate on raw IP packets (no Layer-2 framing, no packet information
/// header).
pub trait Device: Send {
	/// Returns the OS-assigned interface name (e.g. "utun4", "tun0").
	fn name(&self) -> &str;

	/// Returns the device maximum transmission unit in bytes.
	fn mtu(&self) -> u32;

	/// Pulls the next inbound IP packet from the device into `p`. Returns the
	/// number of bytes read, or an error. After `close` has been called,
	/// returns [`err_device_closed`].
	fn read(&mut self, p: &mut [u8]) -> io::Result<usize>;

	/// Pushes an outbound IP packet to the device. Returns the number of
	/// bytes written (typically `p.len()`), or an error. After `close` has
	/// been called, returns [`err_device_closed`].
	fn write(&mut self, p: &[u8]) -> io::Result<usize>;

	/// Releases the device. Subsequent `read`/`write` return
	/// [`err_device_closed`].
	fn close(&mut self) -> io::Result<()>;

	/// Returns the raw file descriptor of the underlying socket/file. Used by
	/// `AsyncFd` to integrate with tokio's reactor.
	#[cfg(unix)]
	fn as_raw_fd(&self) -> std::os::unix::io::RawFd;
}

/// Opens a TUN device.
///
/// Mirrors Go `openDevice` (pkg/tunproxy/device.go, declared in
/// `device_darwin.go`/`device_linux.go`/`device_other.go`). The platform
/// implementation is selected at compile time.
pub fn open_device(name: &str, mtu: u32) -> io::Result<Box<dyn Device>> {
	#[cfg(target_os = "macos")]
	{
		crate::device_darwin::open_device(name, mtu)
	}
	#[cfg(target_os = "linux")]
	{
		crate::device_linux::open_device(name, mtu)
	}
	#[cfg(not(any(target_os = "macos", target_os = "linux")))]
	{
		let _ = (name, mtu);
		Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"tunproxy: TUN device not supported on this platform",
		))
	}
}
