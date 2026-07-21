//! Linux TUN device implementation.
//!
//! Mirrors Go `pkg/tunproxy/device_linux.go`. Uses `/dev/net/tun` with
//! `IFF_TUN | IFF_NO_PI` so reads/writes carry raw IP packets (no packet
//! information header).

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::device::{Device, DEFAULT_MTU, ERR_DEVICE_CLOSED};

// TUNSETIFF from <linux/if_tun.h>.
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

/// `struct ifreq` layout used by TUNSETIFF and SIOCSIFMTU on Linux.
#[repr(C)]
struct Ifreq {
	ifr_name: [libc::c_char; libc::IF_NAMESIZE],
	ifr_data: IfreqUnion,
}

#[repr(C)]
union IfreqUnion {
	flags: libc::c_short,
	mtu: libc::c_int,
}

/// Linux TUN device wrapper.
pub struct LinuxDevice {
	fd: OwnedFd,
	name: String,
	mtu: u32,
}

/// Opens a TUN device on Linux. If `name` is empty the kernel assigns the next
/// free tunN. The device is created without a packet information header
/// (`IFF_NO_PI`) so reads/writes carry raw IP packets.
///
/// Mirrors Go `openDevice` (pkg/tunproxy/device_linux.go:23). Error strings
/// are byte-for-byte identical to Go.
pub fn open_device(name: &str, mtu: u32) -> io::Result<Box<dyn Device>> {
	let mtu = if mtu == 0 { DEFAULT_MTU } else { mtu };

	// Open /dev/net/tun with O_RDWR | O_CLOEXEC.
	let file = OpenOptions::new()
		.read(true)
		.write(true)
		.custom_flags(libc::O_CLOEXEC)
		.open("/dev/net/tun")?;
	let fd: OwnedFd = file.into();

	// Build the ifreq for TUNSETIFF.
	let mut ifr = Ifreq {
		ifr_name: [0; libc::IF_NAMESIZE],
		ifr_data: IfreqUnion { flags: 0 },
	};
	let name_bytes = name.as_bytes();
	let copy_len = name_bytes.len().min(libc::IF_NAMESIZE - 1);
	for (i, b) in name_bytes[..copy_len].iter().enumerate() {
		ifr.ifr_name[i] = *b as libc::c_char;
	}
	// SAFETY: writing to the flags variant; the union is plain old data.
	unsafe {
		ifr.ifr_data.flags = IFF_TUN | IFF_NO_PI;
	}

	let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut ifr as *mut Ifreq) };
	if ret < 0 {
		return Err(
			io::Error::from_raw_os_error(errno()).with_note("tunproxy: TUNSETIFF".to_string())
		);
	}

	// Read the assigned interface name back from ifr_name.
	let assigned = {
		let name_end = ifr
			.ifr_name
			.iter()
			.position(|&c| c == 0)
			.unwrap_or(ifr.ifr_name.len());
		String::from_utf8_lossy(
			&ifr.ifr_name[..name_end]
				.iter()
				.map(|&c| c as u8)
				.collect::<Vec<_>>(),
		)
		.into_owned()
	};

	// Set non-blocking.
	let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
	if ret < 0 {
		return Err(
			io::Error::from_raw_os_error(errno()).with_note("tunproxy: set nonblock".to_string())
		);
	}

	// Set the MTU via SIOCSIFMTU on a dummy datagram socket.
	if mtu != 0 {
		if let Err(e) = set_link_mtu(&assigned, mtu as i32) {
			return Err(e.with_note("tunproxy: set MTU".to_string()));
		}
	}

	Ok(Box::new(LinuxDevice {
		fd,
		name: assigned,
		mtu,
	}))
}

impl Device for LinuxDevice {
	fn name(&self) -> &str {
		&self.name
	}

	fn mtu(&self) -> u32 {
		self.mtu
	}

	fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
		let n = unsafe { libc::read(self.fd.as_raw_fd(), p.as_mut_ptr() as *mut _, p.len()) };
		if n < 0 {
			let e = io::Error::from_raw_os_error(errno());
			if e.raw_os_error() == Some(libc::EBADF) {
				return Err(io::Error::new(io::ErrorKind::Other, ERR_DEVICE_CLOSED));
			}
			return Err(e);
		}
		Ok(n as usize)
	}

	fn write(&mut self, p: &[u8]) -> io::Result<usize> {
		let n = unsafe { libc::write(self.fd.as_raw_fd(), p.as_ptr() as *const _, p.len()) };
		if n < 0 {
			let e = io::Error::from_raw_os_error(errno());
			if e.raw_os_error() == Some(libc::EBADF) {
				return Err(io::Error::new(io::ErrorKind::Other, ERR_DEVICE_CLOSED));
			}
			return Err(e);
		}
		Ok(n as usize)
	}

	fn close(&mut self) -> io::Result<()> {
		// OwnedFd closes on drop; nothing to do here.
		Ok(())
	}

	fn as_raw_fd(&self) -> RawFd {
		self.fd.as_raw_fd()
	}
}

/// Sets the MTU of the named interface via `SIOCSIFMTU` on a dummy datagram
/// socket.
///
/// Mirrors Go `setLinkMTU` (pkg/tunproxy/device_linux.go:86).
fn set_link_mtu(name: &str, mtu: i32) -> io::Result<()> {
	let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
	if s < 0 {
		return Err(io::Error::from_raw_os_error(errno()));
	}
	let fd = unsafe { OwnedFd::from_raw_fd(s) };

	let mut ifr = Ifreq {
		ifr_name: [0; libc::IF_NAMESIZE],
		ifr_data: IfreqUnion { mtu: 0 },
	};
	let name_bytes = name.as_bytes();
	let copy_len = name_bytes.len().min(libc::IF_NAMESIZE - 1);
	for (i, b) in name_bytes[..copy_len].iter().enumerate() {
		ifr.ifr_name[i] = *b as libc::c_char;
	}
	unsafe {
		ifr.ifr_data.mtu = mtu;
	}

	let ret = unsafe {
		libc::ioctl(
			fd.as_raw_fd(),
			libc::SIOCSIFMTU as _,
			&mut ifr as *mut Ifreq,
		)
	};
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
