//! Lock-free counters and the local status endpoint (`/` HTML, `/status.json`).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, SemaphorePermit};
use tracing::{debug, warn};

/// Counters live on their own cache line so hot updates from different cores don't contend.
#[repr(align(64))]
#[derive(Default)]
struct Counter(AtomicU64);

#[repr(align(64))]
#[derive(Default)]
struct Gauge(AtomicI64);

type ExtraFn = Box<dyn Fn() -> Value + Send + Sync>;

pub struct Stats {
    mode: &'static str,
    started: Instant,
    conns_active: Gauge,
    conns_total: Counter,
    reqs_active: Gauge,
    reqs_total: Counter,
    reqs_failed: Counter,
    bytes_rx: Counter,
    bytes_tx: Counter,
    hs_ok: Counter,
    hs_failed: Counter,
    rejected_unknown: Counter,
    rejected_busy: Counter,
    rejected_replay: Counter,
    rejected_stale: Counter,
    extra: OnceLock<ExtraFn>,
}

/// Totals of refused requests, for periodic log summaries.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Rejections {
    pub handshakes: u64,
    pub unknown_session: u64,
    pub busy: u64,
    pub replayed: u64,
    pub stale: u64,
}

/// Decrements the active-connection gauge when dropped.
pub struct ConnGuard(&'static Stats);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.conns_active.0.fetch_sub(1, Relaxed);
    }
}

/// Decrements the active-request gauge when dropped (held until the response body finishes).
/// It can also carry the request's admission permit, released at the same moment.
pub struct ActiveGuard {
    stats: &'static Stats,
    _permit: Option<SemaphorePermit<'static>>,
}

impl ActiveGuard {
    pub fn with_permit(mut self, permit: SemaphorePermit<'static>) -> Self {
        self._permit = Some(permit);
        self
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.stats.reqs_active.0.fetch_sub(1, Relaxed);
    }
}

impl Stats {
    /// One instance per process; it lives as long as the service (see `util::leak`).
    pub fn new(mode: &'static str) -> &'static Self {
        crate::util::leak(Self {
            mode,
            started: Instant::now(),
            conns_active: Gauge::default(),
            conns_total: Counter::default(),
            reqs_active: Gauge::default(),
            reqs_total: Counter::default(),
            reqs_failed: Counter::default(),
            bytes_rx: Counter::default(),
            bytes_tx: Counter::default(),
            hs_ok: Counter::default(),
            hs_failed: Counter::default(),
            rejected_unknown: Counter::default(),
            rejected_busy: Counter::default(),
            rejected_replay: Counter::default(),
            rejected_stale: Counter::default(),
            extra: OnceLock::new(),
        })
    }

    pub fn conn_opened(&'static self) -> ConnGuard {
        self.conns_total.0.fetch_add(1, Relaxed);
        self.conns_active.0.fetch_add(1, Relaxed);
        ConnGuard(self)
    }

    pub fn request_started(&'static self) -> ActiveGuard {
        self.reqs_total.0.fetch_add(1, Relaxed);
        self.reqs_active.0.fetch_add(1, Relaxed);
        ActiveGuard { stats: self, _permit: None }
    }

    pub fn request_failed(&self) {
        self.reqs_failed.0.fetch_add(1, Relaxed);
    }

    /// Encrypted tunnel bytes received.
    pub fn add_rx(&self, n: usize) {
        self.bytes_rx.0.fetch_add(n as u64, Relaxed);
    }

    /// Encrypted tunnel bytes sent.
    pub fn add_tx(&self, n: usize) {
        self.bytes_tx.0.fetch_add(n as u64, Relaxed);
    }

    pub fn handshake_ok(&self) {
        self.hs_ok.0.fetch_add(1, Relaxed);
    }

    pub fn handshake_failed(&self) {
        self.hs_failed.0.fetch_add(1, Relaxed);
    }

    /// A request named a session the server does not know (restart, expiry, or forged).
    pub fn rejected_unknown_session(&self) {
        self.rejected_unknown.0.fetch_add(1, Relaxed);
    }

    /// A request was refused because `max_requests` were already in flight.
    pub fn rejected_busy(&self) {
        self.rejected_busy.0.fetch_add(1, Relaxed);
    }

    pub fn rejected_replay(&self) {
        self.rejected_replay.0.fetch_add(1, Relaxed);
    }

    pub fn rejected_stale(&self) {
        self.rejected_stale.0.fetch_add(1, Relaxed);
    }

    pub fn rejections(&self) -> Rejections {
        Rejections {
            handshakes: self.hs_failed.0.load(Relaxed),
            unknown_session: self.rejected_unknown.0.load(Relaxed),
            busy: self.rejected_busy.0.load(Relaxed),
            replayed: self.rejected_replay.0.load(Relaxed),
            stale: self.rejected_stale.0.load(Relaxed),
        }
    }

    /// Mode-specific fields (sessions, key rotation…) merged into the snapshot.
    pub fn set_extra(&self, f: ExtraFn) {
        let _ = self.extra.set(f);
    }

    pub fn snapshot(&self) -> Value {
        let rx = self.bytes_rx.0.load(Relaxed);
        let tx = self.bytes_tx.0.load(Relaxed);
        let mut v = json!({
            "mode": self.mode,
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": self.started.elapsed().as_secs(),
            "connections": {
                "active": self.conns_active.0.load(Relaxed),
                "total": self.conns_total.0.load(Relaxed),
            },
            "requests": {
                "active": self.reqs_active.0.load(Relaxed),
                "total": self.reqs_total.0.load(Relaxed),
                "failed": self.reqs_failed.0.load(Relaxed),
            },
            "traffic": {
                "received_bytes": rx,
                "sent_bytes": tx,
                "total_bytes": rx + tx,
                "received": human_bytes(rx),
                "sent": human_bytes(tx),
                "total": human_bytes(rx + tx),
            },
            "handshakes": {
                "ok": self.hs_ok.0.load(Relaxed),
                "failed": self.hs_failed.0.load(Relaxed),
            },
            "rejected": {
                "unknown_session": self.rejected_unknown.0.load(Relaxed),
                "busy": self.rejected_busy.0.load(Relaxed),
                "replayed": self.rejected_replay.0.load(Relaxed),
                "stale": self.rejected_stale.0.load(Relaxed),
            },
        });
        if let (Some(f), Some(obj)) = (self.extra.get(), v.as_object_mut()) {
            if let Value::Object(extra) = f() {
                obj.extend(extra);
            }
        }
        v
    }
}

/// Logs one summary line per interval with the requests refused since the last one, instead of
/// a line per event (which an attacker could trigger at will). Failed key exchanges are included
/// under `handshakes` when they are refusals (server side).
pub async fn summarize_rejections(stats: &'static Stats, every: Duration, handshakes: Option<&'static str>) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut before = stats.rejections();
    loop {
        tick.tick().await;
        let now = stats.rejections();
        let parts: Vec<String> = [
            (now.handshakes - before.handshakes, handshakes),
            (now.unknown_session - before.unknown_session, Some("request(s) for unknown sessions (e.g. after a restart)")),
            (now.busy - before.busy, Some("request(s) over max_requests")),
            (now.replayed - before.replayed, Some("replayed request(s)")),
            (now.stale - before.stale, Some("request(s) delayed beyond max_request_age_secs")),
        ]
        .into_iter()
        .filter_map(|(n, what)| what.filter(|_| n > 0).map(|what| format!("{n} {what}")))
        .collect();
        if !parts.is_empty() {
            warn!("refused in the last {}s: {} (WEBPROXY_LOG=debug shows details)", every.as_secs(), parts.join(", "));
        }
        before = now;
    }
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

pub fn human_duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Concurrent connections served by the status endpoint.
const STATUS_MAX_CONNECTIONS: usize = 32;

/// Binds the status listener (failing fast on errors) and serves it in the background.
pub async fn spawn_status_server(addr: SocketAddr, stats: &'static Stats) -> Result<(), String> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot bind status listener {addr}: {e}"))?;
    let limit = Arc::new(Semaphore::new(STATUS_MAX_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let permit = limit.clone().acquire_owned().await.expect("semaphore is never closed");
            let (tcp, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    warn!("status accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            tokio::spawn(async move {
                let _permit = permit;
                let svc = service_fn(move |req| async move { Ok::<_, Infallible>(status_response(&req, stats)) });
                let conn = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(10))
                    .serve_connection(TokioIo::new(tcp), svc);
                if let Err(e) = conn.await {
                    debug!(%peer, "status connection error: {e}");
                }
            });
        }
    });
    Ok(())
}

fn status_response(req: &Request<Incoming>, stats: &Stats) -> Response<Full<Bytes>> {
    let (status, ctype, body) = match (req.method(), req.uri().path()) {
        (&Method::GET, "/status.json") | (&Method::GET, "/json") => {
            let body = serde_json::to_vec_pretty(&stats.snapshot()).unwrap_or_default();
            (StatusCode::OK, "application/json", Bytes::from(body))
        }
        (&Method::GET, "/") => (StatusCode::OK, "text/html; charset=utf-8", Bytes::from_static(STATUS_HTML.as_bytes())),
        _ => (StatusCode::NOT_FOUND, "text/plain", Bytes::from_static(b"not found")),
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, ctype)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Full::new(body))
        .expect("static response parts are valid")
}

const STATUS_HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>webproxy status</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2433;--mute:#667085;--acc:#2563eb;--bd:#e4e7ec}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8ee;--mute:#98a2b3;--acc:#60a5fa;--bd:#262b36}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:20px 16px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mute);margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px}
.k{color:var(--mute);font-size:13px}.v{font-size:24px;font-weight:600;font-variant-numeric:tabular-nums}
pre{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px;overflow:auto;font-size:13px}
</style></head><body><main>
<h1>webproxy <span id="mode"></span></h1><div class="sub" id="sub">loading…</div>
<div class="grid" id="cards"></div>
<h3>Details</h3><pre id="raw"></pre>
</main><script>
function fmtDur(s){const d=Math.floor(s/86400),h=Math.floor(s/3600)%24,m=Math.floor(s/60)%60;return (d?d+'d ':'')+(h?h+'h ':'')+m+'m '+(s%60)+'s'}
async function tick(){try{const r=await fetch('/status.json',{cache:'no-store'});const s=await r.json();
document.getElementById('mode').textContent='('+s.mode+')';
document.getElementById('sub').textContent='v'+s.version+' · up '+fmtDur(s.uptime_secs);
const c=[['Active connections',s.connections.active],['Total connections',s.connections.total],
['Active requests',s.requests.active],['Total requests',s.requests.total],['Failed requests',s.requests.failed],
['Received',s.traffic.received],['Sent',s.traffic.sent],['Total traffic',s.traffic.total],
['Handshakes ok',s.handshakes.ok],['Handshakes failed',s.handshakes.failed]];
document.getElementById('cards').innerHTML=c.map(([k,v])=>'<div class="card"><div class="k">'+k+'</div><div class="v">'+v+'</div></div>').join('');
document.getElementById('raw').textContent=JSON.stringify(s,null,2);}catch(e){document.getElementById('sub').textContent='error: '+e}}
tick();setInterval(tick,2000);
</script></body></html>"#;
