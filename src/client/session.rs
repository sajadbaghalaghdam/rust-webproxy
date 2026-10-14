//! Client side of the key exchange: keeps one live session and rotates it before it expires.
//!
//! Key exchanges run in their own task, one at a time; any number of requests can wait for the
//! outcome, and a request that goes away does not abort the exchange for the others.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Limited};
use parking_lot::{Mutex, RwLock};
use ring::rand::SystemRandom;
use serde_json::{json, Value};
use tokio::sync::watch;
use tracing::{info, warn};

use super::Tunnel;
use crate::body::full_body;
use crate::crypto::{self, PairingKey, SessionKeys, HELLO_OK_LEN};
use crate::net::set_tunnel_headers;
use crate::proto::{error_chain, SessionId};
use crate::stats::{human_duration, Stats};
use crate::util::{short_id, unix_now};

/// Failed key exchanges are retried no sooner than this, doubling up to MAX_BACKOFF;
/// requests arriving meanwhile fail fast with the last error.
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Shortest session lifetime the client accepts from a server.
const MIN_LIFETIME_SECS: u32 = 10;
/// Wall-clock time running ahead of the monotonic clock by more than this means the host was
/// suspended: the monotonic session clock (and the age stamps based on it) are then behind.
const SUSPEND_SLACK_SECS: u64 = 30;
/// The rotation task re-checks this often, so a suspend or clock jump is noticed promptly.
const ROTATION_CHECK: Duration = Duration::from_secs(60);
/// A key exchange that fails on the connection (e.g. a pooled connection the CDN had just
/// closed) is retried with a fresh HELLO this many times.
const CONNECTION_RETRIES: usize = 1;
/// Requests failing in transit without any answer make the client suspect a lost session (see
/// `SessionManager::suspect_lost`); such renewals start at most this often.
const SUSPICION_INTERVAL: Duration = Duration::from_secs(10);

pub type HandshakeError = Arc<str>;

pub struct Session {
    pub id: SessionId,
    pub keys: SessionKeys,
    next_seq: AtomicU64,
    established: Instant,
    established_unix: u64,
    /// When the rotation task replaces this session.
    rekey_at: Instant,
    /// When the server stops accepting it.
    use_until: Instant,
    /// Session-clock time (ms) of the latest authenticated answer.
    answered_ms: AtomicU64,
}

impl Session {
    pub fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Relaxed)
    }

    /// Start of the session clock; requests carry their age on it (see `body::Freshness`).
    pub fn started(&self) -> Instant {
        self.established
    }

    /// Milliseconds on the session clock.
    pub fn clock_ms(&self) -> u64 {
        self.established.elapsed().as_millis() as u64
    }

    /// The server answered a request of this session (so it still knows the session).
    pub fn mark_answered(&self) {
        self.answered_ms.fetch_max(self.clock_ms(), Relaxed);
    }

    fn answered_since(&self, clock_ms: u64) -> bool {
        self.answered_ms.load(Relaxed) >= clock_ms
    }

    /// The monotonic clock stops while the host is suspended; the server's does not.
    fn suspended_since_established(&self) -> bool {
        let wall = unix_now().saturating_sub(self.established_unix);
        wall > self.established.elapsed().as_secs() + SUSPEND_SLACK_SECS
    }

    fn usable(&self) -> bool {
        Instant::now() < self.use_until && !self.suspended_since_established()
    }

    fn due_for_rotation(&self) -> bool {
        Instant::now() >= self.rekey_at || self.suspended_since_established()
    }
}

struct Failure {
    at: Instant,
    retry_after: Instant,
    error: HandshakeError,
}

#[derive(Default)]
struct Control {
    in_flight: bool,
    consecutive_failures: u32,
    last_failure: Option<Failure>,
    /// Last renewal started by `suspect_lost`.
    last_suspicion: Option<Instant>,
}

pub struct SessionManager {
    pairing: PairingKey,
    rng: SystemRandom,
    handshake_timeout: Duration,
    stats: &'static Stats,
    current: RwLock<Option<Arc<Session>>>,
    control: Mutex<Control>,
    /// Bumped whenever a key exchange finishes (successfully or not).
    finished: watch::Sender<u64>,
    rotations: AtomicU64,
}

impl SessionManager {
    pub fn new(pairing: PairingKey, handshake_timeout: Duration, stats: &'static Stats) -> Self {
        Self {
            pairing,
            rng: SystemRandom::new(),
            handshake_timeout,
            stats,
            current: RwLock::new(None),
            control: Mutex::new(Control::default()),
            finished: watch::Sender::new(0),
            rotations: AtomicU64::new(0),
        }
    }

    fn current(&self) -> Option<Arc<Session>> {
        self.current.read().clone()
    }

    /// A usable session, running (or joining) a key exchange if there is none.
    pub async fn get(&'static self, tunnel: &'static Tunnel) -> Result<Arc<Session>, HandshakeError> {
        match self.current() {
            Some(s) if s.usable() => Ok(s),
            _ => self.wait_for(tunnel, Session::usable).await,
        }
    }

    /// The server rejected session `id` (restart or expiry): stop using it and start a key
    /// exchange right away; the next `get` waits for (or joins) it.
    pub fn invalidate(&'static self, tunnel: &'static Tunnel, id: SessionId) {
        let mut ctl = self.control.lock();
        let mut current = self.current.write();
        if current.as_ref().is_some_and(|s| s.id == id) {
            *current = None;
            drop(current);
            let _ = self.start_exchange(tunnel, &mut ctl);
        }
    }

    /// Starts a key exchange that replaces session `id` without discarding it first, so
    /// requests keep using it meanwhile (it is still valid on the server).
    pub fn renew(&'static self, tunnel: &'static Tunnel, id: SessionId) {
        let mut ctl = self.control.lock();
        self.renew_locked(tunnel, id, &mut ctl);
    }

    /// A request on `session` failed in transit (broken connection, gateway error) and nothing
    /// on the session was answered since `since_ms`. The server may have lost the session
    /// while the CDN hid its 401, e.g. by resetting a large upload: renew it in the background,
    /// at most once per SUSPICION_INTERVAL.
    pub fn suspect_lost(&'static self, tunnel: &'static Tunnel, session: &Session, since_ms: u64) {
        if session.answered_since(since_ms) {
            return;
        }
        let mut ctl = self.control.lock();
        if ctl.last_suspicion.is_some_and(|t| t.elapsed() < SUSPICION_INTERVAL) {
            return;
        }
        if self.renew_locked(tunnel, session.id, &mut ctl) {
            ctl.last_suspicion = Some(Instant::now());
        }
    }

    /// Starts a key exchange replacing session `id`, unless it was replaced already; true if
    /// one is running now.
    fn renew_locked(&'static self, tunnel: &'static Tunnel, id: SessionId, ctl: &mut Control) -> bool {
        self.current().is_none_or(|s| s.id == id) && self.start_exchange(tunnel, ctl).is_ok()
    }

    /// Starts a key exchange unless one is running; fails fast while the backoff after the
    /// last failure lasts.
    fn start_exchange(&'static self, tunnel: &'static Tunnel, ctl: &mut Control) -> Result<(), HandshakeError> {
        if ctl.in_flight {
            return Ok(());
        }
        if let Some(f) = ctl.last_failure.as_ref().filter(|f| Instant::now() < f.retry_after) {
            return Err(Arc::clone(&f.error));
        }
        ctl.in_flight = true;
        tokio::spawn(self.exchange(tunnel));
        Ok(())
    }

    /// Waits until the current session satisfies `accept`, starting a key exchange unless one
    /// is already running or the last one failed too recently.
    async fn wait_for(
        &'static self,
        tunnel: &'static Tunnel,
        accept: impl Fn(&Session) -> bool,
    ) -> Result<Arc<Session>, HandshakeError> {
        let mut finished = self.finished.subscribe();
        {
            let mut ctl = self.control.lock();
            if let Some(s) = self.current().filter(|s| accept(s)) {
                return Ok(s);
            }
            self.start_exchange(tunnel, &mut ctl)?;
        }
        loop {
            if finished.changed().await.is_err() {
                return Err("key exchange task stopped".into());
            }
            if let Some(s) = self.current().filter(|s| accept(s)) {
                return Ok(s);
            }
            let ctl = self.control.lock();
            if !ctl.in_flight {
                return Err(ctl.last_failure.as_ref().map_or_else(|| "no session available".into(), |f| Arc::clone(&f.error)));
            }
        }
    }

    /// One key exchange, run as its own task; publishes the outcome to all waiters.
    async fn exchange(&'static self, tunnel: &'static Tunnel) {
        let attempts = async {
            let mut attempt = 0;
            loop {
                match self.handshake(tunnel).await {
                    Err(Failed::Connection(e)) if attempt < CONNECTION_RETRIES => {
                        attempt += 1;
                        tracing::debug!("key exchange connection failed, retrying: {e}");
                    }
                    other => return other.map_err(Failed::into_message),
                }
            }
        };
        let outcome = tokio::time::timeout(self.handshake_timeout, attempts)
            .await
            .unwrap_or_else(|_| Err("key exchange timed out".into()));
        {
            let mut ctl = self.control.lock();
            ctl.in_flight = false;
            match outcome {
                Ok(session) => {
                    self.stats.handshake_ok();
                    *self.current.write() = Some(Arc::new(session));
                    ctl.consecutive_failures = 0;
                    ctl.last_failure = None;
                }
                Err(error) => {
                    self.stats.handshake_failed();
                    ctl.consecutive_failures = ctl.consecutive_failures.saturating_add(1);
                    let backoff = backoff(ctl.consecutive_failures);
                    let now = Instant::now();
                    warn!("key exchange failed (next attempt in {}s at the earliest): {error}", backoff.as_secs());
                    ctl.last_failure = Some(Failure { at: now, retry_after: now + backoff, error: error.into() });
                }
            }
        }
        self.finished.send_modify(|n| *n = n.wrapping_add(1));
    }

    async fn handshake(&self, tunnel: &Tunnel) -> Result<Session, Failed> {
        let pending = crypto::client_hello(&self.pairing, &self.rng, unix_now()).map_err(|e| e.to_string())?;
        let mut req = Request::post(tunnel.uri.clone())
            .body(full_body(Bytes::copy_from_slice(pending.message())))
            .map_err(|e| e.to_string())?;
        set_tunnel_headers(req.headers_mut(), Some(pending.message().len() as u64));

        let resp = tunnel
            .http
            .request(req)
            .await
            .map_err(|e| Failed::Connection(format!("cannot reach server: {}", error_chain(&e))))?;
        match resp.status() {
            StatusCode::OK => {}
            StatusCode::FORBIDDEN => {
                return Err("server rejected the key exchange (wrong pairing key or clock skew)".to_string().into())
            }
            StatusCode::UPGRADE_REQUIRED => {
                return Err("client and server run incompatible webproxy versions; upgrade both".to_string().into())
            }
            s => return Err(format!("server answered HTTP {s} to the key exchange").into()),
        }
        let body = Limited::new(resp.into_body(), HELLO_OK_LEN)
            .collect()
            .await
            .map_err(|_| "failed to read the key exchange response".to_string())?
            .to_bytes();
        let est = crypto::client_finish(&self.pairing, pending, &body).map_err(|e| e.to_string())?;
        if est.lifetime_secs < MIN_LIFETIME_SECS {
            return Err("server announced an invalid session lifetime".to_string().into());
        }
        let lifetime = Duration::from_secs(est.lifetime_secs.into());
        // Rotate a little before the server stops honouring the session.
        let rotate_after = lifetime.saturating_sub((lifetime / 10).min(Duration::from_secs(120)));
        let now = Instant::now();
        info!(
            session = %short_id(&est.session_id),
            rotates_in = %human_duration(rotate_after.as_secs()),
            "new session keys established"
        );
        Ok(Session {
            id: est.session_id,
            keys: est.keys,
            next_seq: AtomicU64::new(0),
            established: now,
            established_unix: unix_now(),
            rekey_at: now + rotate_after,
            use_until: now + lifetime,
            answered_ms: AtomicU64::new(0),
        })
    }

    /// Background task: establishes the first session and replaces it before it expires.
    pub async fn rotate_forever(&'static self, tunnel: &'static Tunnel) {
        let mut finished = self.finished.subscribe();
        let mut retry = MIN_BACKOFF;
        loop {
            let current = self.current();
            if let Some(s) = current.as_ref().filter(|s| !s.due_for_rotation()) {
                retry = MIN_BACKOFF;
                // Wake up when it is due (checking periodically, as a suspend delays the
                // monotonic deadline), or re-evaluate when another path installed a session.
                let wake = s.rekey_at.min(Instant::now() + ROTATION_CHECK);
                tokio::select! {
                    () = tokio::time::sleep_until(wake.into()) => {}
                    _ = finished.changed() => {}
                }
                continue;
            }
            let old = current.map(|s| s.id);
            match self.wait_for(tunnel, move |s| Some(s.id) != old && s.usable()).await {
                Ok(_) => {
                    if old.is_some() {
                        self.rotations.fetch_add(1, Relaxed);
                    }
                }
                Err(_) => {
                    // Already logged by the exchange; try again after a pause.
                    tokio::time::sleep(retry).await;
                    retry = (retry * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    pub fn status(&self) -> Value {
        let now = Instant::now();
        let session = self.current().map(|s| {
            let rotates_in = s.rekey_at.saturating_duration_since(now).as_secs();
            json!({
                "id": short_id(&s.id),
                "age_secs": unix_now().saturating_sub(s.established_unix),
                "rotates_in_secs": rotates_in,
                "rotates_in": human_duration(rotates_in),
                "requests": s.next_seq.load(Relaxed),
            })
        });
        let last_error = self
            .control
            .lock()
            .last_failure
            .as_ref()
            .map(|f| json!({ "error": &*f.error, "secs_ago": f.at.elapsed().as_secs() }));
        json!({
            "session": session,
            "key_rotations": self.rotations.load(Relaxed),
            "last_key_exchange_error": last_error,
        })
    }
}

/// Why a key exchange failed.
enum Failed {
    /// The connection broke before an answer arrived; a fresh attempt may succeed.
    Connection(String),
    Other(String),
}

impl Failed {
    fn into_message(self) -> String {
        match self {
            Failed::Connection(m) | Failed::Other(m) => m,
        }
    }
}

impl From<String> for Failed {
    fn from(message: String) -> Self {
        Failed::Other(message)
    }
}

/// Delay before the next attempt after `failures` consecutive failed key exchanges.
fn backoff(failures: u32) -> Duration {
    MIN_BACKOFF.saturating_mul(1 << failures.saturating_sub(1).min(5)).min(MAX_BACKOFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(5), Duration::from_secs(16));
        assert_eq!(backoff(50), MAX_BACKOFF);
    }

    fn session(established_unix: u64) -> Session {
        let now = Instant::now();
        Session {
            id: [1; 16],
            keys: crate::body::test_util::keys().0,
            next_seq: AtomicU64::new(0),
            established: now,
            established_unix,
            rekey_at: now + Duration::from_secs(3600),
            use_until: now + Duration::from_secs(3700),
            answered_ms: AtomicU64::new(0),
        }
    }

    #[test]
    fn suspend_makes_a_session_unusable() {
        let fresh = session(unix_now());
        assert!(fresh.usable() && !fresh.due_for_rotation());
        // Two minutes of wall-clock time passed that the monotonic clock did not see.
        let resumed = session(unix_now() - 120);
        assert!(!resumed.usable() && resumed.due_for_rotation());
    }

    #[test]
    fn answers_are_tracked_on_the_session_clock() {
        let s = session(unix_now());
        assert!(s.answered_since(0));
        std::thread::sleep(Duration::from_millis(5));
        let sent = s.clock_ms();
        assert!(!s.answered_since(sent), "nothing answered since the request was sent");
        s.mark_answered();
        assert!(s.answered_since(sent));
    }
}
