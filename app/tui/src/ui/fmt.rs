//! Value formatting helpers, mirroring app/desktop/puppy utils/format.ts.

/// Human-readable byte count (binary units).
pub fn fmt_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if n < KIB {
        format!("{n} B")
    } else if n < MIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else if n < GIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    }
}

/// Human-readable uptime like `2d 3h 4m`, `1h 2m 3s`, `5m 0s`, `42s`.
pub fn fmt_uptime(seconds: f64) -> String {
    let s = seconds.max(0.0) as u64;
    let d = s / 86400;
    let h = (s % 86400) / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {sec}s")
    } else if m > 0 {
        format!("{m}m {sec}s")
    } else {
        format!("{sec}s")
    }
}

/// RFC 3339 timestamp → compact local-ish display.
///
/// The dashboard emits RFC 3339 (e.g. `2026-07-15T19:30:00+08:00`). Without a
/// timezone database we cannot convert to true local time; rendering the
/// timestamp's own date/time portion keeps the display deterministic and
/// matches what the server logged. Falls back to the raw string on parse
/// failure, mirroring format.ts.
pub fn fmt_time(iso: &str) -> String {
    // 取 "YYYY-MM-DDTHH:MM:SS" 部分显示。
    let bytes = iso.as_bytes();
    if bytes.len() >= 19 && bytes[4] == b'-' && bytes[7] == b'-' && bytes[10] == b'T' {
        format!("{} {}", &iso[..10], &iso[11..19])
    } else {
        iso.to_string()
    }
}

/// Seconds elapsed between an RFC 3339 `started_at` and now, formatted via
/// [`fmt_uptime`]. Returns "-" when the timestamp cannot be parsed.
pub fn fmt_elapsed_since(started_at: &str) -> String {
    let start = match parse_rfc3339_seconds(started_at) {
        Some(s) => s,
        None => return "-".to_string(),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    fmt_uptime(now.saturating_sub(start) as f64)
}

/// Minimal RFC 3339 parser: handles `YYYY-MM-DDTHH:MM:SS(±HH:MM|Z)`.
/// Returns seconds since UNIX epoch. Rejects malformed input.
fn parse_rfc3339_seconds(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // 时区偏移（秒）。
    let rest = &s[19..];
    let offset: i64 = if rest.starts_with('Z') || rest.is_empty() {
        0
    } else if (rest.starts_with('+') || rest.starts_with('-')) && rest.len() >= 6 {
        let sign = if rest.starts_with('-') { -1 } else { 1 };
        let oh: i64 = rest.get(1..3)?.parse().ok()?;
        let om: i64 = rest.get(4..6)?.parse().ok()?;
        sign * (oh * 3600 + om * 60)
    } else {
        return None;
    };

    // days-from-civil 算法（Howard Hinnant），把年月日转为相对 1970-01-01 的天数。
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    let local_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    let utc_secs = local_secs - offset;
    u64::try_from(utc_secs).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_formatting() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1024), "1.00 KiB");
        assert_eq!(fmt_bytes(2048), "2.00 KiB");
        assert_eq!(fmt_bytes(1048576), "1.00 MiB");
        assert_eq!(fmt_bytes(2097152), "2.00 MiB");
        assert_eq!(fmt_bytes(1073741824), "1.00 GiB");
    }

    #[test]
    fn uptime_formatting() {
        assert_eq!(fmt_uptime(0.0), "0s");
        assert_eq!(fmt_uptime(42.9), "42s");
        assert_eq!(fmt_uptime(300.0), "5m 0s");
        assert_eq!(fmt_uptime(3661.0), "1h 1m 1s");
        assert_eq!(fmt_uptime(1800.5), "30m 0s");
        assert_eq!(fmt_uptime(90061.0), "1d 1h 1m");
    }

    #[test]
    fn time_formatting() {
        assert_eq!(fmt_time("2026-07-15T19:30:00+08:00"), "2026-07-15 19:30:00");
        assert_eq!(fmt_time("not-a-date"), "not-a-date");
    }

    #[test]
    fn rfc3339_parsing() {
        // 1970-01-01T00:00:00Z == 0
        assert_eq!(parse_rfc3339_seconds("1970-01-01T00:00:00Z"), Some(0));
        // +08:00 的零点对应 UTC 前一天的 16:00，为负值 -> None（拒绝）
        assert_eq!(parse_rfc3339_seconds("1970-01-01T00:00:00+08:00"), None);
        // 2026-07-15T19:30:00+08:00 == 2026-07-15T11:30:00Z
        let a = parse_rfc3339_seconds("2026-07-15T19:30:00+08:00").unwrap();
        let b = parse_rfc3339_seconds("2026-07-15T11:30:00Z").unwrap();
        assert_eq!(a, b);
        assert!(parse_rfc3339_seconds("garbage").is_none());
        assert!(parse_rfc3339_seconds("2026-13-01T00:00:00Z").is_none());
    }
}
