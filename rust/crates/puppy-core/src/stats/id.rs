//! Connection-id generation.

use std::sync::atomic::{AtomicU64, Ordering};

use rand::RngCore;

/// Process-wide monotonic counter used as a suffix for connection IDs.
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Returns a short, unique connection identifier of the form
/// `conn-<randhex>-<counter-base36>`.
///
/// The random prefix gives uniqueness across restarts; the counter gives
/// uniqueness within a process. The format is `conn-<randhex>-<counter>`; we
/// preserve that layout.
pub fn generate_connection_id() -> String {
	let n = ID_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
	let mut buf = [0u8; 4];
	rand::thread_rng().fill_bytes(&mut buf);
	format!("conn-{}-{}", hex_encode(&buf), base36_encode(n))
}

fn hex_encode(bytes: &[u8]) -> String {
	let mut s = String::with_capacity(bytes.len() * 2);
	for b in bytes {
		s.push_str(&format!("{b:02x}"));
	}
	s
}

/// Encodes `n` in base 36 using lowercase letters (matches
/// `strconv.FormatUint(n, 36)`).
fn base36_encode(mut n: u64) -> String {
	if n == 0 {
		return "0".to_string();
	}
	const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
	let mut out = Vec::new();
	while n > 0 {
		out.push(DIGITS[(n % 36) as usize]);
		n /= 36;
	}
	out.reverse();
	String::from_utf8(out).expect("base36 digits are ASCII")
}
