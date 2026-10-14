//! Client mode: accepts plain HTTP from local applications, encrypts every request into the
//! tunnel and decrypts the responses.

mod forward;
mod session;
mod target;

pub use target::TargetBase;

use std::convert::Infallible;
use std::time::Duration;

use http::{Request, Response, StatusCode, Uri};
use hyper::body::Incoming;
use serde_json::{json, Value};
use tokio::sync::Semaphore;
use tracing::{debug, info};
use zeroize::Zeroize;

use crate::body::{OutBody, StreamCtx};
use crate::config::{body_limit, optional_secs, parse_optional_addr, ClientConfig};
use crate::crypto::{parse_pairing_key, PairingKey};
use crate::net::{self, HttpClient, Reject, ServeOptions, ShutdownSignal};
use crate::stats::Stats;
use crate::util::leak;
use session::SessionManager;

/// Concurrent streams per HTTP/2 connection from local applications.
const LOCAL_H2_MAX_STREAMS: u32 = 100;

/// Outer transport to the server (normally through the CDN).
pub struct Tunnel {
    http: HttpClient,
    uri: Uri,
}

pub struct ClientState {
    tunnel: Tunnel,
    sessions: SessionManager,
    default_target: Option<TargetBase>,
    rewrite_redirects: bool,
    preserve_host: bool,
    allowed_hosts: Vec<String>,
    /// Largest request body in bytes (`None` = no limit).
    max_request_body: Option<u64>,
    response_timeout: Duration,
    stream_idle_timeout: Option<Duration>,
    /// Admission control: one permit per request in flight.
    requests: Semaphore,
    /// Slots for HTTP/1.0 responses that must be buffered.
    http10_buffers: Semaphore,
    stats: &'static Stats,
}

impl ClientState {
    fn stream_ctx(&self) -> StreamCtx {
        StreamCtx { stats: self.stats, idle_timeout: self.stream_idle_timeout }
    }

    fn status(&self) -> Value {
        let mut v = self.sessions.status();
        if let Some(obj) = v.as_object_mut() {
            obj.insert("server_url".into(), json!(self.tunnel.uri.to_string()));
        }
        v
    }
}

pub async fn run(mut cfg: ClientConfig, shutdown: ShutdownSignal) -> Result<(), String> {
    let stats = Stats::new("client");
    let pairing = PairingKey::new(&*parse_pairing_key(&cfg.key)?);
    cfg.key.zeroize();
    let http = net::build_client(&net::ClientOptions {
        connect_timeout: Duration::from_secs(cfg.connect_timeout_secs),
        pool_idle_timeout: Duration::from_secs(cfg.pool_idle_secs),
        pool_max_idle_per_host: cfg.pool_max_idle,
        extra_ca: cfg.ca_file.as_deref(),
    })?;
    let uri: Uri = cfg.server_url.parse().map_err(|_| "invalid server_url".to_string())?;
    let default_target = cfg.default_target.as_deref().map(TargetBase::parse).transpose()?;
    let st: &'static ClientState = leak(ClientState {
        tunnel: Tunnel { http, uri },
        sessions: SessionManager::new(pairing, Duration::from_secs(cfg.connect_timeout_secs + 20), stats),
        rewrite_redirects: cfg.rewrite_redirects,
        default_target,
        preserve_host: cfg.preserve_host,
        allowed_hosts: std::mem::take(&mut cfg.allowed_hosts),
        max_request_body: body_limit(cfg.max_request_body_mb),
        response_timeout: Duration::from_secs(cfg.response_timeout_secs),
        stream_idle_timeout: optional_secs(cfg.stream_idle_timeout_secs),
        requests: Semaphore::new(cfg.max_requests),
        http10_buffers: Semaphore::new(forward::HTTP10_BUFFERS),
        stats,
    });

    let listener = net::bind_listener(cfg.listen).map_err(|e| format!("cannot bind {}: {e}", cfg.listen))?;
    if let Some(addr) = parse_optional_addr(&cfg.status_listen)? {
        stats.set_extra(Box::new(|| st.status()));
        crate::stats::spawn_status_server(addr, stats).await?;
        info!("status page on http://{addr}/");
    }
    info!(listen = %cfg.listen, server = %cfg.server_url, "client started");
    // Establishes the first session right away, then keeps rotating it.
    tokio::spawn(st.sessions.rotate_forever(&st.tunnel));
    // Failed key exchanges are logged with their cause as they happen.
    tokio::spawn(crate::stats::summarize_rejections(stats, Duration::from_secs(30), None));

    let opts = ServeOptions {
        max_connections: cfg.max_connections,
        idle_timeout: Duration::from_secs(cfg.idle_timeout_secs),
        drain_timeout: Duration::from_secs(cfg.shutdown_timeout_secs),
        h2_max_streams: LOCAL_H2_MAX_STREAMS,
        // Local apps may legitimately apply back-pressure for long periods.
        tcp_user_timeout: None,
        tls: None,
    };
    net::serve(listener, opts, stats, shutdown, move |req| handle(req, st)).await;
    Ok(())
}

async fn handle(req: Request<Incoming>, st: &'static ClientState) -> Result<Response<OutBody>, Infallible> {
    let Ok(permit) = st.requests.try_acquire() else {
        st.stats.rejected_busy();
        return Ok(Reject::new(StatusCode::SERVICE_UNAVAILABLE, "too many requests in flight (max_requests)").into_response());
    };
    let guard = st.stats.request_started().with_permit(permit);
    Ok(forward::forward(st, req, guard).await.unwrap_or_else(|reject| {
        st.stats.request_failed();
        debug!(status = %reject.status, "{}", reject.message);
        reject.into_response()
    }))
}
