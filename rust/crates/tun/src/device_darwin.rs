//! macOS (utun) TUN device implementation.
//!
//! Mirrors Go `pkg/tunproxy/device_darwin.go`. Uses the kernel control socket
//! API (`AF_SYSTEM` + `SYSPROTO_CONTROL` + `com.apple.net.utun_control`) to
//! open a utunN interface, then `getsockopt(UTUN_OPT_IFNAME)` to retrieve the
//! assigned interface name.

#![cfg(target_os = "macos")]

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::device::{Device, DEFAULT_MTU, ERR_DEVICE_CLOSED};

// macOS kernel control constants not exposed by libc.
const AF_SYSTEM: libc::c_int = 32;
const SYSPROTO_CONTROL: libc::c_int = 2;
const AF_SYS_CONTROL: u16 = 2;
const CTL_IOCG_INFO: libc::c_ulong = 0xc0644e03;
const UTUN_OPT_IFNAME: libc::c_int = 2;
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const MAX_KCTL_NAME: usize = 96;

// SIOCSIFMTU on macOS is not exposed by the `libc` crate; the value comes from
// <net/if.h> (computed as `_IOW('i', 0x52, struct ifreq)`).
const SIOCSIFMTU: libc::c_ulong = 0x80206934;

/// `struct ctl_info` from `<sys/kern_control.h>`.
#[repr(C)]
struct CtlInfo {
	id: u32,
	name: [u8; MAX_KCTL_NAME],
}

/// `struct sockaddr_ctl` from `<sys/kern_control.h>`.
#[repr(C)]
struct SockaddrCtl {
	sc_len: u8,
	sc_family: u8,
	sc_sysaddr: u16,
	sc_id: u32,
	sc_unit: u32,
	sc_reserved: [u32; 5],
}

/// macOS utun device wrapper.
pub struct DarwinDevice {
	fd: OwnedFd,
	name: String,
	mtu: u32,
}

/// Opens a utunN device on macOS. If `name` is empty or "utun" the kernel
/// assigns the next free unit; "utunN" requests a specific unit.
///
/// Mirrors Go `openDevice` (pkg/tunproxy/device_darwin.go:72). Error strings
/// are byte-for-byte identical to Go.
pub fn open_device(name: &str, mtu: u32) -> io::Result<Box<dyn Device>> {
	let mtu = if mtu == 0 { DEFAULT_MTU } else { mtu };

	let unit = parse_utun_unit(name)?;

	// Create the kernel control socket.
	let fd = unsafe { libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
	if fd < 0 {
		return Err(io::Error::from_raw_os_error(errno())
			.with_note("tunproxy: socket(AF_SYSTEM_CONTROL)".to_string()));
	}
	let fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(fd) };

	// CTLIOCGINFO to look up the kernel control ID by name.
	let mut info = CtlInfo {
		id: 0,
		name: [0u8; MAX_KCTL_NAME],
	};
	let name_bytes = UTUN_CONTROL_NAME.as_bytes();
	let copy_len = name_bytes.len().min(MAX_KCTL_NAME - 1);
	info.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

	let ret = unsafe {
		libc::ioctl(
			fd.as_raw_fd(),
			CTL_IOCG_INFO as _,
			&mut info as *mut CtlInfo,
		)
	};
	if ret < 0 {
		return Err(
			io::Error::from_raw_os_error(errno()).with_note("tunproxy: CTLIOCGINFO".to_string())
		);
	}

	// connect(2) to the utun control socket.
	let addr = SockaddrCtl {
		sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
		sc_family: AF_SYSTEM as u8,
		sc_sysaddr: AF_SYS_CONTROL,
		sc_id: info.id,
		sc_unit: unit as u32,
		sc_reserved: [0u32; 5],
	};
	let ret = unsafe {
		libc::connect(
			fd.as_raw_fd(),
			&addr as *const SockaddrCtl as *const libc::sockaddr,
			std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
		)
	};
	if ret < 0 {
		return Err(io::Error::from_raw_os_error(errno())
			.with_note(format!("tunproxy: connect utun unit {unit}")));
	}

	// Get the assigned interface name via getsockopt(UTUN_OPT_IFNAME).
	let assigned = utun_name(&fd)?;

	// Set the MTU via SIOCSIFMTU on a routing socket.
	if let Err(e) = set_link_mtu(&assigned, mtu as i32) {
		return Err(e.with_note("tunproxy: set MTU".to_string()));
	}

	// Set non-blocking.
	let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
	if ret < 0 {
		return Err(
			io::Error::from_raw_os_error(errno()).with_note("tunproxy: set nonblock".to_string())
		);
	}

	Ok(Box::new(DarwinDevice {
		fd,
		name: assigned,
		mtu,
	}))
}

impl Device for DarwinDevice {
	fn name(&self) -> &str {
		&self.name
	}

	fn mtu(&self) -> u32 {
		self.mtu
	}

	fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
		// utun reads prepend a 4-byte protocol family header on macOS.
		if p.len() < 4 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"tunproxy: read buffer too small",
			));
		}
		let n = unsafe { libc::read(self.fd.as_raw_fd(), p.as_mut_ptr() as *mut _, p.len()) };
		if n < 0 {
			let e = io::Error::from_raw_os_error(errno());
			if is_closed(&e) {
				return Err(io::Error::other(ERR_DEVICE_CLOSED));
			}
			return Err(e);
		}
		let n = n as usize;
		if n < 4 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!("tunproxy: short utun read ({n} bytes)"),
			));
		}
		// Strip the 4-byte protocol family header in place.
		p.copy_within(4..n, 0);
		Ok(n - 4)
	}

	fn write(&mut self, p: &[u8]) -> io::Result<usize> {
		let buf = encode_utun_packet(p)?;
		let n = unsafe { libc::write(self.fd.as_raw_fd(), buf.as_ptr() as *const _, buf.len()) };
		if n < 0 {
			let e = io::Error::from_raw_os_error(errno());
			if is_closed(&e) {
				return Err(io::Error::other(ERR_DEVICE_CLOSED));
			}
			return Err(e);
		}
		if n as usize != buf.len() {
			return Err(io::Error::new(
				io::ErrorKind::WriteZero,
				format!("tunproxy: short utun write ({} of {} bytes)", n, buf.len()),
			));
		}
		Ok(p.len())
	}

	fn close(&mut self) -> io::Result<()> {
		// OwnedFd closes on drop; nothing to do here.
		Ok(())
	}

	fn as_raw_fd(&self) -> RawFd {
		self.fd.as_raw_fd()
	}
}

/// Prepends the protocol-family header required by macOS utun.
///
/// XNU expects this field in network byte order (`htonl(AF_INET)` /
/// `htonl(AF_INET6)`). Using native byte order makes Apple Silicon and Intel
/// write `02 00 00 00` for IPv4 instead of `00 00 00 02`; the write can
/// succeed while the kernel discards the packet, which leaves TCP sockets
/// stuck in SYN-RECEIVED.
fn encode_utun_packet(packet: &[u8]) -> io::Result<Vec<u8>> {
	let family: u32 = match packet.first().map(|byte| byte >> 4) {
		Some(4) => libc::AF_INET as u32,
		Some(6) => libc::AF_INET6 as u32,
		_ => {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"tunproxy: cannot write non-IP packet to utun",
			))
		}
	};
	let mut framed = Vec::with_capacity(4 + packet.len());
	framed.extend_from_slice(&family.to_be_bytes());
	framed.extend_from_slice(packet);
	Ok(framed)
}

/// Returns true if the error indicates the device fd has been closed.
fn is_closed(e: &io::Error) -> bool {
	matches!(e.raw_os_error(), Some(libc::EBADF))
}

/// Reads the assigned utun interface name via `getsockopt(UTUN_OPT_IFNAME)`.
///
/// Mirrors Go `utunName` (pkg/tunproxy/device_darwin.go:183).
fn utun_name(fd: &OwnedFd) -> io::Result<String> {
	let mut buf = [0u8; 17];
	let mut olen: libc::socklen_t = buf.len() as libc::socklen_t;
	let ret = unsafe {
		libc::getsockopt(
			fd.as_raw_fd(),
			SYSPROTO_CONTROL,
			UTUN_OPT_IFNAME,
			buf.as_mut_ptr() as *mut _,
			&mut olen as *mut _,
		)
	};
	if ret < 0 {
		return Err(io::Error::from_raw_os_error(errno())
			.with_note("tunproxy: getsockopt UTUN_OPT_IFNAME".to_string()));
	}
	let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
	Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}

/// Parses "", "utun", or "utunN" and returns the unit number (0 means
/// kernel-assigned).
///
/// Mirrors Go `parseUtunUnit` (pkg/tunproxy/device_darwin.go:208).
pub(crate) fn parse_utun_unit(name: &str) -> io::Result<u32> {
	if name.is_empty() || name == "utun" {
		return Ok(0);
	}
	let rest = name.strip_prefix("utun").ok_or_else(|| {
		io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("tunproxy: device name must be empty or utunN, got {name:?}"),
		)
	})?;
	let mut unit: u32 = 0;
	for c in rest.chars() {
		if !c.is_ascii_digit() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("tunproxy: device name must be empty or utunN, got {name:?}"),
			));
		}
		unit = unit
			.checked_mul(10)
			.and_then(|v| v.checked_add((c as u8 - b'0') as u32))
			.ok_or_else(|| {
				io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("tunproxy: device name must be empty or utunN, got {name:?}"),
				)
			})?;
	}
	Ok(unit)
}

/// `struct ifreq` layout used by SIOCSIFMTU on macOS.
#[repr(C)]
struct IfreqMtu {
	ifr_name: [libc::c_char; 16],
	ifr_mtu: libc::c_int,
	_pad: [u8; 20],
}

/// Sets the MTU of the named interface via `SIOCSIFMTU` on a routing socket.
///
/// Mirrors Go `setLinkMTU` (pkg/tunproxy/device_darwin.go:234).
fn set_link_mtu(name: &str, mtu: i32) -> io::Result<()> {
	// macOS uses AF_ROUTE / SOCK_RAW for the routing socket.
	let s = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0) };
	if s < 0 {
		return Err(io::Error::from_raw_os_error(errno()));
	}
	let fd = unsafe { OwnedFd::from_raw_fd(s) };

	let mut ifr = IfreqMtu {
		ifr_name: [0; 16],
		ifr_mtu: mtu,
		_pad: [0; 20],
	};
	let name_bytes = name.as_bytes();
	let copy_len = name_bytes.len().min(15);
	for (i, b) in name_bytes[..copy_len].iter().enumerate() {
		ifr.ifr_name[i] = *b as libc::c_char;
	}

	let ret = unsafe { libc::ioctl(fd.as_raw_fd(), SIOCSIFMTU as _, &mut ifr as *mut IfreqMtu) };
	if ret < 0 {
		return Err(io::Error::from_raw_os_error(errno()));
	}
	Ok(())
}

/// Returns the thread-local errno.
fn errno() -> libc::c_int {
	std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Helper trait to attach a note to an `io::Error` (Go-style `%w` wrapping).
trait ErrorNote {
	fn with_note(self, note: String) -> io::Error;
}

impl ErrorNote for io::Error {
	fn with_note(self, note: String) -> io::Error {
		io::Error::new(self.kind(), format!("{note}: {self}"))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn encode_utun_ipv4_uses_network_byte_order() {
		let packet = [0x45, 0, 0, 20];
		let framed = encode_utun_packet(&packet).unwrap();
		assert_eq!(&framed[..4], &[0, 0, 0, libc::AF_INET as u8]);
		assert_eq!(&framed[4..], &packet);
	}

	#[test]
	fn encode_utun_ipv6_uses_network_byte_order() {
		let packet = [0x60, 0, 0, 0];
		let framed = encode_utun_packet(&packet).unwrap();
		assert_eq!(&framed[..4], &(libc::AF_INET6 as u32).to_be_bytes());
		assert_eq!(&framed[4..], &packet);
	}

	#[test]
	fn encode_utun_rejects_non_ip_packet() {
		let err = encode_utun_packet(&[0]).unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}

	#[test]
	fn parse_utun_unit_empty() {
		assert_eq!(parse_utun_unit("").unwrap(), 0);
	}

	#[test]
	fn parse_utun_unit_bare() {
		assert_eq!(parse_utun_unit("utun").unwrap(), 0);
	}

	#[test]
	fn parse_utun_unit_zero() {
		assert_eq!(parse_utun_unit("utun0").unwrap(), 0);
	}

	#[test]
	fn parse_utun_unit_nine() {
		assert_eq!(parse_utun_unit("utun9").unwrap(), 9);
	}

	#[test]
	fn parse_utun_unit_hundred() {
		assert_eq!(parse_utun_unit("utun100").unwrap(), 100);
	}

	#[test]
	fn parse_utun_unit_invalid_tun_prefix() {
		let err = parse_utun_unit("tun0").unwrap_err();
		assert!(err
			.to_string()
			.contains("device name must be empty or utunN"));
	}

	#[test]
	fn parse_utun_unit_invalid_x() {
		let err = parse_utun_unit("utunx").unwrap_err();
		assert!(err
			.to_string()
			.contains("device name must be empty or utunN"));
	}

	#[test]
	fn parse_utun_unit_invalid_dash() {
		let err = parse_utun_unit("utun-1").unwrap_err();
		assert!(err
			.to_string()
			.contains("device name must be empty or utunN"));
	}
}
