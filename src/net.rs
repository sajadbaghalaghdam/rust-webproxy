//! Sockets, accept loop, TLS and HTTP client plumbing shared by both modes.

use std::borrow::Cow;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode, Uri, Version};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::body::{full_body, OutBody, SendProgress};
use crate::proto::{BoxError, ERROR_HEADER};
use crate::stats::Stats;

pub type HttpClient = Client<TimeoutConnector<HttpsConnector<HttpConnector>>, OutBody>;

/// Becomes `true` once the process should stop accepting work.
pub type ShutdownSignal = watch::Receiver<bool>;

const LISTEN_BACKLOG: u32 = 4096;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const KEEPALIVE_TIME: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_RETRIES: u32 = 5;

/// Headers of every outer tunnel message (request or response).
pub fn set_tunnel_headers(h: &mut HeaderMap, content_length: Option<u64>) {
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(n) = content_length {
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(n));
    }
}

/// A request webproxy refuses or cannot complete, answered with a plain-text error.
#[derive(Debug)]
pub struct Reject {
    pub status: StatusCode,
    pub message: Cow<'static, str>,
    stale: bool,
    retry_after: Option<HeaderValue>,
}

/// `x-webproxy-error` value marking a request the server refused as delayed in transit.
pub const STALE_ERROR: &str = "stale";

impl Reject {
    pub fn new(status: StatusCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self { status, message: message.into(), stale: false, retry_after: None }
    }

    /// Passes a `Retry-After` hint on to the application.
    pub fn retry_after(mut self, value: Option<HeaderValue>) -> Self {
        self.retry_after = value;
        self
    }

    /// Marks a request refused because it was delayed in transit (see `body::Freshness`).
    pub fn stale(mut self) -> Self {
        self.stale = true;
        self
    }

    pub fn is_stale(&self) -> bool {
        self.stale
    }

    /// Value of the `x-webproxy-error` header for this rejection.
    pub fn error_header(&self) -> HeaderValue {
        HeaderValue::from_static(if self.stale { STALE_ERROR } else { "1" })
    }

    /// `webproxy: <message>\n`, the body of every error webproxy generates itself.
    pub fn body(&self) -> Bytes {
        Bytes::from(format!("webproxy: {}\n", self.message))
    }

    /// Error response generated locally (marked with `x-webproxy-error`).
    pub fn into_response(self) -> Response<OutBody> {
        let mut r = Response::new(full_body(self.body()));
        *r.status_mut() = self.status;
        let h = r.headers_mut();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(ERROR_HEADER, self.error_header());
        if let Some(v) = self.retry_after {
            h.insert(header::RETRY_AFTER, v);
        }
        r
    }
}

/// Outcome of waiting for an answer to a request whose body is being streamed.
pub enum Waited<T> {
    Answer(T),
    /// The request body stopped moving for `stall` before it was sent completely.
    SendStalled,
    /// No answer within `limit` after the request was sent completely.
    TimedOut,
}

/// Waits for `response`. While the request body is still being sent, it only has to keep
/// moving (no progress for `stall` fails, `None` = no bound); once it has been sent
/// completely, the answer must come within `limit`. Long uploads are therefore not cut off,
/// and stalled ones are.
pub async fn await_response<F: Future>(
    response: F,
    progress: &SendProgress,
    stall: Option<Duration>,
    limit: Duration,
) -> Waited<F::Output> {
    let deadline = async {
        while !progress.is_done() {
            match stall {
                Some(stall) => {
                    let idle = progress.idle_for();
                    if idle >= stall {
                        return Waited::SendStalled;
                    }
                    tokio::select! {
                        () = progress.finished() => {}
                        () = tokio::time::sleep(stall - idle) => {}
                    }
                }
                None => progress.finished().await,
            }
        }
        tokio::time::sleep(limit).await;
        Waited::TimedOut
    };
    tokio::select! {
        biased;
        r = response => Waited::Answer(r),
        outcome = deadline => outcome,
    }
}

/// Bounds the whole connection setup — DNS, TCP and TLS — of an inner connector.
#[derive(Clone)]
pub struct TimeoutConnector<C> {
    inner: C,
    timeout: Duration,
}

impl<C> tower_service::Service<Uri> for TimeoutConnector<C>
where
    C: tower_service::Service<Uri>,
    C::Future: Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = C::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<C::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connecting = self.inner.call(uri);
        let limit = self.timeout;
        Box::pin(async move {
            match tokio::time::timeout(limit, connecting).await {
                Ok(result) => result.map_err(Into::into),
                Err(_) => Err("connection setup (DNS, TCP, TLS) timed out".into()),
            }
        })
    }
}

/// Listening socket with a large backlog (and SO_REUSEADDR on Unix for fast restarts).
pub fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    // On Windows SO_REUSEADDR would allow other processes to steal the port.
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(LISTEN_BACKLOG)
}

/// Per-socket options for accepted connections: no Nagle delay, and dead-peer detection.
fn tune_socket(tcp: &TcpStream, user_timeout: Option<Duration>) {
    let _ = tcp.set_nodelay(true);
    let sock = SockRef::from(tcp);
    let keepalive = TcpKeepalive::new()
        .with_time(KEEPALIVE_TIME)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    let _ = sock.set_tcp_keepalive(&keepalive);
    #[cfg(target_os = "linux")]
    if user_timeout.is_some() {
        let _ = sock.set_tcp_user_timeout(user_timeout);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = user_timeout;
}

pub struct ServeOptions {
    pub max_connections: usize,
    /// HTTP/1 connections that don't deliver a request head within this time are closed;
    /// idle HTTP/2 connections are closed gracefully; connections that never send a request
    /// are dropped.
    pub idle_timeout: Duration,
    /// After shutdown is signalled, open connections get this long to finish.
    pub drain_timeout: Duration,
    /// Concurrent streams per HTTP/2 connection.
    pub h2_max_streams: u32,
    /// Linux TCP_USER_TIMEOUT: abort connections whose sent data stays unacknowledged this
    /// long. On Linux 5.11+ it also aborts a peer that keeps a zero window this long, so it
    /// must not be shorter than legitimate back-pressure pauses.
    pub tcp_user_timeout: Option<Duration>,
    pub tls: Option<TlsAcceptor>,
}

fn server_builder(opts: &ServeOptions) -> auto::Builder<TokioExecutor> {
    let mut b = auto::Builder::new(TokioExecutor::new());
    b.http1().timer(TokioTimer::new()).header_read_timeout(opts.idle_timeout).keep_alive(true);
    b.http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(20))
        .max_concurrent_streams(opts.h2_max_streams)
        .adaptive_window(true);
    b
}

/// Accept loop. Returns after `shutdown` fires and open connections drained (or the drain
/// timeout passed). Connections beyond `max_connections` wait in the kernel backlog.
pub async fn serve<H, Fut>(
    listener: TcpListener,
    opts: ServeOptions,
    stats: &'static Stats,
    mut shutdown: ShutdownSignal,
    handler: H,
) where
    H: Fn(Request<Incoming>) -> Fut + Copy + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<OutBody>, Infallible>> + Send + 'static,
{
    let builder = Arc::new(server_builder(&opts));
    let limit = Arc::new(Semaphore::new(opts.max_connections));
    loop {
        let permit = tokio::select! {
            p = limit.clone().acquire_owned() => p.expect("semaphore is never closed"),
            _ = shutdown.wait_for(|stop| *stop) => break,
        };
        let (tcp, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(x) => x,
                Err(e) => {
                    // Typically EMFILE/ENFILE: back off instead of spinning.
                    warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = shutdown.wait_for(|stop| *stop) => break,
        };
        tune_socket(&tcp, opts.tcp_user_timeout);
        let conn_guard = stats.conn_opened();
        let builder = Arc::clone(&builder);
        let tls = opts.tls.clone();
        let shutdown = shutdown.clone();
        let idle = opts.idle_timeout;
        tokio::spawn(async move {
            let _permit = permit;
            let _conn_guard = conn_guard;
            match tls {
                None => serve_connection(tcp, &builder, handler, idle, shutdown).await,
                Some(acceptor) => match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(stream)) => serve_connection(stream, &builder, handler, idle, shutdown).await,
                    Ok(Err(e)) => debug!(%peer, "TLS handshake failed: {e}"),
                    Err(_) => debug!(%peer, "TLS handshake timed out"),
                },
            }
        });
    }
    drop(listener);
    let open = opts.max_connections - limit.available_permits();
    if open > 0 {
        info!("waiting up to {}s for {open} open connection(s) to finish", opts.drain_timeout.as_secs());
    }
    let all = u32::try_from(opts.max_connections).unwrap_or(u32::MAX);
    if tokio::time::timeout(opts.drain_timeout, limit.acquire_many(all)).await.is_err() {
        warn!("drain timeout reached; closing remaining connections");
    }
}

/// Request activity of one connection, as seen by its watchdog.
struct Activity {
    started: Instant,
    requests: AtomicU64,
    /// Milliseconds after `started` at which the latest request arrived.
    last_request_ms: AtomicU64,
    http2: AtomicBool,
}

impl Activity {
    fn request_arrived(&self, version: Version) {
        self.requests.fetch_add(1, Relaxed);
        self.last_request_ms.store(self.started.elapsed().as_millis() as u64, Relaxed);
        if version == Version::HTTP_2 {
            self.http2.store(true, Relaxed);
        }
    }

    fn idle_deadline(&self, idle: Duration) -> Instant {
        self.started + Duration::from_millis(self.last_request_ms.load(Relaxed)) + idle
    }
}

/// Serves one connection (HTTP/1 or HTTP/2) under a watchdog: connections that never send a
/// request are dropped, idle HTTP/2 connections are closed gracefully (streams in flight still
/// complete; idle HTTP/1 is handled by hyper's header read timeout, which only runs between
/// requests), and shutdown triggers a graceful close.
async fn serve_connection<I, H, Fut>(
    io: I,
    builder: &auto::Builder<TokioExecutor>,
    handler: H,
    idle: Duration,
    mut shutdown: ShutdownSignal,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Fn(Request<Incoming>) -> Fut + Copy + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<OutBody>, Infallible>> + Send + 'static,
{
    let activity = Arc::new(Activity {
        started: Instant::now(),
        requests: AtomicU64::new(0),
        last_request_ms: AtomicU64::new(0),
        http2: AtomicBool::new(false),
    });
    let seen = Arc::clone(&activity);
    let svc = service_fn(move |req: Request<Incoming>| {
        seen.request_arrived(req.version());
        handler(req)
    });
    let conn = builder.serve_connection(TokioIo::new(io), svc);
    tokio::pin!(conn);
    let mut closing = false;
    loop {
        // Watched: connections without any request yet, and HTTP/2 connections.
        let watched = activity.requests.load(Relaxed) == 0 || activity.http2.load(Relaxed);
        let deadline = activity.idle_deadline(idle);
        tokio::select! {
            res = conn.as_mut() => {
                if let Err(e) = res {
                    debug!("connection closed with error: {e}");
                }
                return;
            }
            () = tokio::time::sleep_until(deadline), if watched && !closing => {
                if activity.idle_deadline(idle) > Instant::now() {
                    continue; // a request arrived meanwhile
                }
                if activity.requests.load(Relaxed) == 0 {
                    return; // never sent a request (silent peer, unfinished preface)
                }
                conn.as_mut().graceful_shutdown();
                closing = true;
            }
            _ = shutdown.wait_for(|stop| *stop), if !closing => {
                conn.as_mut().graceful_shutdown();
                closing = true;
            }
        }
    }
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("cannot read certificates from {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("no certificate found in {}", path.display()));
    }
    Ok(certs)
}

pub fn load_tls_acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor, String> {
    let certs = read_certs(cert)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("cannot read TLS key {}: {e}", key.display()))?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("invalid TLS certificate/key: {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

pub struct ClientOptions<'a> {
    pub connect_timeout: Duration,
    pub pool_idle_timeout: Duration,
    pub pool_max_idle_per_host: usize,
    /// Extra PEM CA bundle trusted in addition to the Mozilla roots.
    pub extra_ca: Option<&'a Path>,
}

/// HTTP/1.1 client with a connection pool, for http and https URLs.
///
/// HTTP/2 is deliberately not negotiated: hyper's pool keeps a single HTTP/2 connection per
/// host, so all traffic (including key exchanges) would queue behind its stream limit,
/// whereas the HTTP/1.1 pool opens connections in parallel and keeps them warm.
pub fn build_client(o: &ClientOptions<'_>) -> Result<HttpClient, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = o.extra_ca {
        for cert in read_certs(path)? {
            roots.add(cert).map_err(|e| format!("invalid CA certificate in {}: {e}", path.display()))?;
        }
    }
    let tls = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_connect_timeout(Some(o.connect_timeout));
    http.set_keepalive(Some(KEEPALIVE_TIME));
    http.set_keepalive_interval(Some(KEEPALIVE_INTERVAL));
    http.set_keepalive_retries(Some(KEEPALIVE_RETRIES));

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    let connector = TimeoutConnector { inner: https, timeout: o.connect_timeout };

    Ok(Client::builder(TokioExecutor::new())
        .timer(TokioTimer::new())
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(o.pool_idle_timeout)
        .pool_max_idle_per_host(o.pool_max_idle_per_host)
        .build(connector))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::test_util::Stalled;
    use crate::body::ProgressBody;
    use http_body_util::{BodyExt, Full};

    #[tokio::test(start_paused = true)]
    async fn stalled_uploads_and_silent_servers_are_told_apart() {
        let stall = Some(Duration::from_secs(5));
        let limit = Duration::from_secs(60);
        // The body never moves: a stall, after `stall`.
        let (_body, progress) = ProgressBody::new(Stalled);
        let started = tokio::time::Instant::now();
        assert!(matches!(await_response(std::future::pending::<()>(), &progress, stall, limit).await, Waited::SendStalled));
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        // Sent completely: from then on the answer has `limit`.
        let (body, progress) = ProgressBody::new(Full::new(Bytes::from_static(b"x")));
        body.collect().await.unwrap();
        let started = tokio::time::Instant::now();
        assert!(matches!(await_response(std::future::pending::<()>(), &progress, stall, limit).await, Waited::TimedOut));
        assert_eq!(started.elapsed(), limit);
        assert!(matches!(await_response(async { 7 }, &progress, stall, limit).await, Waited::Answer(7)));
    }

    struct NeverConnects;

    impl tower_service::Service<Uri> for NeverConnects {
        type Response = ();
        type Error = io::Error;
        type Future = std::future::Pending<io::Result<()>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Uri) -> Self::Future {
            std::future::pending()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connection_setup_is_bounded() {
        let mut connector = TimeoutConnector { inner: NeverConnects, timeout: Duration::from_secs(3) };
        let started = tokio::time::Instant::now();
        let err = tower_service::Service::call(&mut connector, Uri::from_static("http://h")).await.err().unwrap();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert_eq!(started.elapsed(), Duration::from_secs(3));
    }
}
