//! Session table, per-session anti-replay window and handshake replay cache.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::crypto::SessionKeys;
use crate::proto::SessionId;

/// Sessions kept per paired client (normally the current one plus one in its grace period).
const MAX_SESSIONS_PER_CLIENT: usize = 16;
const MAX_SESSIONS: usize = 100_000;
const MAX_HELLO_REPLAY_ENTRIES: usize = 100_000;
/// How far request sequence numbers may arrive out of order: a request whose head reaches the
/// server after 2^20 later requests of the same session (e.g. a long upload behind a buffering
/// intermediary while the client keeps sending) is refused as too old. 128 KiB per session.
const REPLAY_WINDOW: u64 = 1 << 20;
/// An evicted session used more recently than this suggests a pairing key shared by several
/// client processes.
const SHARED_KEY_HINT: Duration = Duration::from_secs(60);

/// Sliding anti-replay window over request sequence numbers (RFC 6479 style bitmap).
struct ReplayWindow {
    /// Highest accepted sequence number + 1.
    top: u64,
    bits: Box<[u64]>,
}

impl ReplayWindow {
    fn new() -> Self {
        Self { top: 0, bits: vec![0; (REPLAY_WINDOW / 64) as usize].into_boxed_slice() }
    }

    fn slot(seq: u64) -> (usize, u64) {
        let i = seq % REPLAY_WINDOW;
        ((i / 64) as usize, 1 << (i % 64))
    }

    /// True if `seq` was not seen yet and is not too old.
    fn is_fresh(&self, seq: u64) -> bool {
        if seq >= self.top {
            return true;
        }
        if self.top - seq > REPLAY_WINDOW {
            return false;
        }
        let (w, b) = Self::slot(seq);
        self.bits[w] & b == 0
    }

    /// Clears the slots of `from..=to` (fewer than REPLAY_WINDOW of them), a word at a time.
    fn clear(&mut self, from: u64, to: u64) {
        let mut s = from;
        while s <= to {
            let i = s % REPLAY_WINDOW;
            let bit = i % 64;
            let span = (64 - bit).min(to - s + 1);
            let mask = if span == 64 { u64::MAX } else { ((1u64 << span) - 1) << bit };
            self.bits[(i / 64) as usize] &= !mask;
            s += span;
        }
    }

    /// Records `seq`; false if it is a replay or too old.
    fn accept(&mut self, seq: u64) -> bool {
        if seq >= self.top {
            if seq - self.top >= REPLAY_WINDOW {
                self.bits.fill(0);
            } else {
                self.clear(self.top, seq);
            }
            self.top = seq + 1;
        } else if self.top - seq > REPLAY_WINDOW {
            return false;
        }
        let (w, b) = Self::slot(seq);
        if self.bits[w] & b != 0 {
            return false;
        }
        self.bits[w] |= b;
        true
    }
}

pub struct Session {
    pub client: usize,
    pub keys: SessionKeys,
    created: Instant,
    expires: Instant,
    /// Milliseconds after `created` of the last accepted request (LRU eviction).
    last_used_ms: AtomicU64,
    window: Mutex<ReplayWindow>,
}

impl Session {
    /// When the key exchange happened, on the server's clock.
    pub fn started(&self) -> Instant {
        self.created
    }

    fn age(&self) -> Duration {
        self.created.elapsed()
    }

    pub fn is_fresh(&self, seq: u64) -> bool {
        self.window.lock().is_fresh(seq)
    }

    /// Consumes `seq`; false for replays.
    pub fn accept_seq(&self, seq: u64) -> bool {
        let accepted = self.window.lock().accept(seq);
        if accepted {
            self.last_used_ms.store(self.age().as_millis() as u64, Relaxed);
        }
        accepted
    }

    fn last_used(&self) -> Instant {
        self.created + Duration::from_millis(self.last_used_ms.load(Relaxed))
    }
}

/// What `SessionStore::insert` had to do to make room.
pub enum Inserted {
    Fresh,
    /// The least recently used session of this client was evicted while it was still in use.
    EvictedActive,
}

/// Live sessions. Each expires `lifetime + grace` after its key exchange: the client rotates
/// at `lifetime`, the grace period lets requests that raced with the rotation complete.
pub struct SessionStore {
    map: RwLock<HashMap<SessionId, Arc<Session>>>,
    lifetime: Duration,
    grace: Duration,
}

impl SessionStore {
    pub fn new(lifetime: Duration, grace: Duration) -> Self {
        Self { map: RwLock::new(HashMap::new()), lifetime, grace }
    }

    pub fn lifetime(&self) -> Duration {
        self.lifetime
    }

    pub fn get(&self, id: &SessionId) -> Option<Arc<Session>> {
        let now = Instant::now();
        self.map.read().get(id).filter(|s| s.expires > now).cloned()
    }

    pub fn insert(&self, id: SessionId, client: usize, keys: SessionKeys) -> Result<Inserted, &'static str> {
        let created = Instant::now();
        let session = Arc::new(Session {
            client,
            keys,
            created,
            expires: created + self.lifetime + self.grace,
            last_used_ms: AtomicU64::new(0),
            window: Mutex::new(ReplayWindow::new()),
        });
        let mut map = self.map.write();
        map.retain(|_, s| s.expires > created);
        let mut outcome = Inserted::Fresh;
        let mine = map.values().filter(|s| s.client == client).count();
        if mine >= MAX_SESSIONS_PER_CLIENT {
            let lru = map
                .iter()
                .filter(|(_, s)| s.client == client)
                .min_by_key(|(_, s)| s.last_used())
                .map(|(id, s)| (*id, s.last_used()));
            if let Some((lru_id, last_used)) = lru {
                map.remove(&lru_id);
                if created.duration_since(last_used) < SHARED_KEY_HINT {
                    outcome = Inserted::EvictedActive;
                }
            }
        }
        if map.len() >= MAX_SESSIONS {
            return Err("session table full");
        }
        map.insert(id, session);
        Ok(outcome)
    }

    pub fn reap(&self) {
        let now = Instant::now();
        self.map.write().retain(|_, s| s.expires > now);
    }

    /// (live sessions, live sessions per client index)
    pub fn counts(&self, clients: usize) -> (usize, Vec<usize>) {
        let now = Instant::now();
        let mut per = vec![0; clients];
        let map = self.map.read();
        for s in map.values().filter(|s| s.expires > now) {
            per[s.client] += 1;
        }
        (per.iter().sum(), per)
    }
}

/// Remembers recently seen handshake randoms until their timestamp leaves the skew window.
#[derive(Default)]
pub struct HelloReplayCache {
    seen: HashMap<[u8; 32], u64>,
}

impl HelloReplayCache {
    pub fn insert(&mut self, random: [u8; 32], expires_unix: u64, now_unix: u64) -> Result<(), &'static str> {
        if self.seen.contains_key(&random) {
            return Err("replayed handshake");
        }
        if self.seen.len() >= MAX_HELLO_REPLAY_ENTRIES {
            self.prune(now_unix);
            if self.seen.len() >= MAX_HELLO_REPLAY_ENTRIES {
                return Err("too many handshakes");
            }
        }
        self.seen.insert(random, expires_unix);
        Ok(())
    }

    pub fn prune(&mut self, now_unix: u64) {
        self.seen.retain(|_, exp| *exp >= now_unix);
        self.seen.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(5));
        assert!(w.accept(3));
        assert!(!w.accept(3));
        assert!(w.is_fresh(4));
        assert!(w.accept(4));
        assert!(w.accept(REPLAY_WINDOW + 10));
        // 5 is now outside the window.
        assert!(!w.is_fresh(5));
        assert!(!w.accept(5));
        assert!(w.accept(REPLAY_WINDOW + 9));
        assert!(!w.accept(REPLAY_WINDOW + 9));
        // A large jump clears the bitmap but duplicates are still caught afterwards.
        assert!(w.accept(10 * REPLAY_WINDOW));
        assert!(!w.accept(10 * REPLAY_WINDOW));
        assert!(w.accept(10 * REPLAY_WINDOW - 1));
        assert!(!w.accept(9 * REPLAY_WINDOW));
    }

    #[test]
    fn replay_window_word_clearing_matches_bitwise() {
        // Compare against a naive set over pseudo-random forward jumps and late arrivals.
        let mut w = ReplayWindow::new();
        let mut seen = std::collections::HashSet::new();
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut top = 0u64;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let seq = if x.is_multiple_of(3) { top.saturating_sub(x % 5000) } else { top + x % 300 };
            let expected = seq + REPLAY_WINDOW >= top.max(seq + 1) && !seen.contains(&seq);
            assert_eq!(w.accept(seq), expected, "seq {seq} top {top}");
            if expected {
                seen.insert(seq);
                top = top.max(seq + 1);
            }
        }
    }

    #[test]
    fn hello_replay_cache() {
        let mut c = HelloReplayCache::default();
        assert!(c.insert([1; 32], 100, 50).is_ok());
        assert!(c.insert([1; 32], 100, 50).is_err());
        c.prune(101);
        assert!(c.seen.is_empty());
    }
}
