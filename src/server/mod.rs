//! Server mode: terminates the tunnel, forwards decrypted requests to their destination and
//! encrypts the responses back.

mod allow;
mod handshake;
mod sessions;
mod tunnel;

pub use allow::AllowList;

use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use bytes::Bytes;
use http::{header, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use parking_lot::Mutex;
use ring::rand::SystemRandom;
use serde_json::{json, Value};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::info;
use zeroize::Zeroize;

use crate::body::{discard, full_body, FrameReader, OutBody, StreamCtx};
use crate::config::{body_limit, optional_secs, parse_optional_addr, ServerConfig};
use crate::crypto::{parse_pairing_key, PairingKey, HELLO_OK_LEN};
use crate::net::{self, set_tunnel_headers, HttpClient, ServeOptions, ShutdownSignal};
use crate::proto::{MSG_DATA, MSG_HELLO, VERSION};
use crate::stats::{human_duration, Stats};
use crate::util::{leak, unix_now};
use sessions::{HelloReplayCache, SessionStore};

/// Everything a peer must deliver before it is authenticated (message prefix, HELLO or
/// request head) has to arrive within this time.
const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent streams per HTTP/2 connection from the CDN.
const H2_MAX_STREAMS: u32 = 256;
/// Lower bound for TCP_USER_TIMEOUT on the CDN listener (see `ServeOptions`).
const MIN_TCP_USER_TIMEOUT: Duration = Duration::from_secs(120);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);

struct PairedClient {
    name: String,
    pairing: PairingKey,
    last_handshake_unix: AtomicU64,
}

pub struct ServerState {
    cfg: ServerConfig,
    clients: Vec<PairedClient>,
    sessions: SessionStore,
    hello_replay: Mutex<HelloReplayCache>,
    allow: AllowList,
    http: HttpClient,
    rng: SystemRandom,
    /// Admission control: one permit per tunnel request, held until its response is done.
    requests: Semaphore,
    stats: &'static Stats,
}

impl ServerState {
    fn new(mut cfg: ServerConfig, stats: &'static Stats) -> Result<Self, String> {
        // The keys are parsed into PairingKeys; wipe their text so it is not kept around.
        let entries = std::mem::take(&mut cfg.clients);
        let mut clients = Vec::with_capacity(entries.len());
        for mut entry in entries {
            let pairing = PairingKey::new(&*parse_pairing_key(&entry.key)?);
            entry.key.zeroize();
            clients.push(PairedClient { name: entry.name, pairing, last_handshake_unix: AtomicU64::new(0) });
        }
        let http = net::build_client(&net::ClientOptions {
            connect_timeout: Duration::from_secs(cfg.upstream_connect_timeout_secs),
            pool_idle_timeout: Duration::from_secs(cfg.upstream_pool_idle_secs),
            pool_max_idle_per_host: cfg.upstream_pool_max_idle,
            extra_ca: cfg.upstream_ca_file.as_deref(),
        })?;
        let lifetime = Duration::from_secs(cfg.rekey_interval_secs);
        // Old sessions stay usable a little past the client's rotation point.
        let grace = Duration::from_secs((cfg.rekey_interval_secs / 10).clamp(5, 600));
        Ok(Self {
            allow: AllowList::parse(&cfg.allowed_targets)?,
            clients,
            sessions: SessionStore::new(lifetime, grace),
            hello_replay: Mutex::new(HelloReplayCache::default()),
            http,
            rng: SystemRandom::new(),
            requests: Semaphore::new(cfg.max_requests),
            stats,
            cfg,
        })
    }

    fn stream_ctx(&self) -> StreamCtx {
        StreamCtx { stats: self.stats, idle_timeout: optional_secs(self.cfg.stream_idle_timeout_secs) }
    }

    /// Largest request body in bytes (`None` = no limit).
    fn max_request_body(&self) -> Option<u64> {
        body_limit(self.cfg.max_request_body_mb)
    }

    fn early_response(&self) -> Option<Duration> {
        optional_secs(self.cfg.early_response_secs)
    }

    fn status(&self) -> Value {
        let (total, per_client) = self.sessions.counts(self.clients.len());
        let now = unix_now();
        let clients: Vec<Value> = self
            .clients
            .iter()
            .zip(per_client)
            .map(|(c, sessions)| {
                let last = c.last_handshake_unix.load(Relaxed);
                json!({
                    "name": c.name,
                    "sessions": sessions,
                    "last_key_exchange_secs_ago": (last > 0).then(|| now.saturating_sub(last)),
                })
            })
            .collect();
        json!({
            "sessions": {
                "active": total,
                "rekey_interval_secs": self.cfg.rekey_interval_secs,
                "rekey_interval": human_duration(self.cfg.rekey_interval_secs),
            },
            "clients": clients,
        })
    }
}

pub async fn run(cfg: ServerConfig, shutdown: ShutdownSignal) -> Result<(), String> {
    let stats = Stats::new("server");
    let tls = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(cert), Some(key)) => Some(net::load_tls_acceptor(cert, key)?),
        _ => None,
    };
    let st: &'static ServerState = leak(ServerState::new(cfg, stats)?);

    let listener = net::bind_listener(st.cfg.listen).map_err(|e| format!("cannot bind {}: {e}", st.cfg.listen))?;
    if let Some(addr) = parse_optional_addr(&st.cfg.status_listen)? {
        stats.set_extra(Box::new(|| st.status()));
        crate::stats::spawn_status_server(addr, stats).await?;
        info!("status page on http://{addr}/");
    }
    tokio::spawn(maintenance(st));
    let handshakes = "key exchange(s) (wrong key, clock skew, replay or version)";
    tokio::spawn(crate::stats::summarize_rejections(stats, MAINTENANCE_INTERVAL, Some(handshakes)));
    info!(
        listen = %st.cfg.listen,
        tls = tls.is_some(),
        path = %st.cfg.tunnel_path,
        clients = st.clients.len(),
        rekey = %human_duration(st.cfg.rekey_interval_secs),
        "server started"
    );

    let opts = ServeOptions {
        max_connections: st.cfg.max_connections,
        idle_timeout: Duration::from_secs(st.cfg.idle_timeout_secs),
        drain_timeout: Duration::from_secs(st.cfg.shutdown_timeout_secs),
        h2_max_streams: H2_MAX_STREAMS,
        // Never shorter than the stream idle timeout, so legitimate back-pressure survives;
        // with idle timeouts disabled (long SSE pauses) dead peers are left to keepalive.
        tcp_user_timeout: st.stream_ctx().idle_timeout.map(|t| t.max(MIN_TCP_USER_TIMEOUT)),
        tls,
    };
    net::serve(listener, opts, stats, shutdown, move |req| handle(req, st)).await;
    Ok(())
}

/// Drops expired sessions and replay entries.
async fn maintenance(st: &'static ServerState) {
    let mut tick = tokio::time::interval(MAINTENANCE_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        st.sessions.reap();
        st.hello_replay.lock().prune(unix_now());
    }
}

/// What an unauthenticated tunnel message turned out to be.
#[allow(clippy::large_enum_variant, reason = "short-lived value, moved once")]
enum Authenticated {
    Hello([u8; HELLO_OK_LEN]),
    Request(tunnel::Accepted),
}

async fn handle(req: Request<Incoming>, st: &'static ServerState) -> Result<Response<OutBody>, Infallible> {
    if req.method() != Method::POST || req.uri().path() != st.cfg.tunnel_path {
        return Ok(outer_response(StatusCode::NOT_FOUND));
    }
    let reader = FrameReader::new(req.into_body(), st.stream_ctx());
    let authenticated = timeout(PRE_AUTH_TIMEOUT, authenticate(st, reader))
        .await
        .unwrap_or_else(|_| Err(StatusCode::REQUEST_TIMEOUT.into()));
    Ok(match authenticated {
        Ok(Authenticated::Hello(reply)) => {
            octet_response(full_body(Bytes::copy_from_slice(&reply)), Some(HELLO_OK_LEN as u64))
        }
        // Admission is counted for authenticated requests only, so unauthenticated traffic
        // cannot use up the budget. It is bounded by connections, streams and the deadline,
        // plus the drain of an upload refused with 401 (see `discard`).
        Ok(Authenticated::Request(accepted)) => match st.requests.try_acquire() {
            Ok(permit) => tunnel::respond(st, accepted, st.stats.request_started().with_permit(permit)).await,
            Err(_) => {
                st.stats.rejected_busy();
                outer_response(StatusCode::SERVICE_UNAVAILABLE)
            }
        },
        Err(Refused { status, unread }) => {
            if let Some(body) = unread {
                // Let the sender finish its upload so it receives the answer (a reset
                // connection would hide it); bounded like any discarded body.
                discard(body).await;
            }
            outer_response(status)
        }
    })
}

/// Why a tunnel message was refused before it was authenticated.
pub(super) struct Refused {
    status: StatusCode,
    /// Rest of the request body, drained before answering.
    unread: Option<Incoming>,
}

impl From<StatusCode> for Refused {
    fn from(status: StatusCode) -> Self {
        Self { status, unread: None }
    }
}

async fn authenticate(st: &ServerState, mut reader: FrameReader<Incoming>) -> Result<Authenticated, Refused> {
    let prefix = reader.read_exact(2).await.map_err(|_| StatusCode::BAD_REQUEST)?;
    match (prefix[0], prefix[1]) {
        (VERSION, MSG_HELLO) => Ok(Authenticated::Hello(handshake::accept(st, reader).await?)),
        (VERSION, MSG_DATA) => tunnel::accept(st, reader).await.map(Authenticated::Request),
        (VERSION, _) => Err(StatusCode::BAD_REQUEST.into()),
        _ => {
            // A peer speaking another protocol version: tell it so instead of a vague 400.
            st.stats.handshake_failed();
            Err(StatusCode::UPGRADE_REQUIRED.into())
        }
    }
}

/// Unencrypted response visible to the CDN; it reveals nothing beyond the status code.
fn outer_response(status: StatusCode) -> Response<OutBody> {
    let reason = status.canonical_reason().unwrap_or_default();
    let mut r = Response::new(full_body(Bytes::from_static(reason.as_bytes())));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// 200 response carrying tunnel bytes.
fn octet_response(body: OutBody, len: Option<u64>) -> Response<OutBody> {
    let mut r = Response::new(body);
    set_tunnel_headers(r.headers_mut(), len);
    if len.is_none() {
        // Streamed responses (SSE, slow destinations): ask nginx-based intermediaries not to
        // buffer them.
        r.headers_mut().insert(HeaderName::from_static("x-accel-buffering"), HeaderValue::from_static("no"));
    }
    r
}
