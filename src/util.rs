//! Small helpers shared by both modes.

use std::time::{SystemTime, UNIX_EPOCH};

/// Moves a process-lifetime object (runtime state, counters) to a `&'static` reference.
///
/// The service state lives exactly as long as the process, so handing out `&'static`
/// references avoids an atomic `Arc` clone on every connection and request.
pub fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// Wall-clock seconds since the Unix epoch (0 if the clock is before 1970).
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Short printable form of a session id for logs and the status page.
pub fn short_id(id: &[u8]) -> String {
    use std::fmt::Write;
    id.iter().take(4).fold(String::with_capacity(8), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
