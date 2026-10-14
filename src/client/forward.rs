//! One local request: encrypt it into the tunnel, decrypt the answer.

use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use http::request::Parts;
use http::uri::Authority;
use http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Either, Full};
use hyper::body::Incoming;
use tokio::time::timeout;
use tracing::debug;

use super::session::{HandshakeError, Session};
use super::target::{self, RouteOrigin, TargetBase};
use super::ClientState;
use crate::body::{
    discard, known_len, BodyFailure, CappedBody, ChunkList, FrameReader, OutBody, ProgressBody, SealBody,
};
use crate::crypto::{Opener, Sealer};
use crate::net::{await_response, set_tunnel_headers, Reject, Waited, STALE_ERROR};
use crate::proto::{
    error_chain, strip_hop_by_hop, ProtoError, RequestHead, ResponseHead, DATA_PREFIX_LEN, ERROR_HEADER, MSG_DATA,
    MSG_DATA_OK, SESSION_ID_LEN, TARGET_HEADER, URL_HEADER, VERSION,
};
use crate::stats::ActiveGuard;
use crate::util::short_id;

/// Bodies of safe requests (GET, HEAD, OPTIONS, TRACE) up to this size are buffered so the
/// request can be resent transparently when the server lost our session (e.g. it restarted).
const REPLAYABLE_BODY_LIMIT: u64 = 64 * 1024;
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// HTTP/1.0 cannot signal an aborted body of unknown length, so such responses are buffered
/// (up to this size, in at most `HTTP10_BUFFERS` at a time) and delivered once their end has
/// been authenticated.
const HTTP10_BUFFER_LIMIT: u64 = 16 << 20;
pub(super) const HTTP10_BUFFERS: usize = 16;

type LocalBody = Either<Full<Bytes>, CappedBody<Incoming>>;

/// Request body, buffered when small enough to be sent twice.
enum Payload {
    Buffered(Bytes),
    /// Streamed bodies are counted against the size limit as they pass.
    Streaming(Option<CappedBody<Incoming>>),
}

impl Payload {
    async fn read(body: Incoming, len: Option<u64>, st: &ClientState, replayable: bool) -> Result<Self, Reject> {
        let limit = st.max_request_body;
        if let (Some(len), Some(limit)) = (len, limit) {
            if len > limit {
                return refuse(body, body_too_large(limit)).await;
            }
        }
        match len {
            Some(n) if replayable && n <= REPLAYABLE_BODY_LIMIT => match timeout(BODY_READ_TIMEOUT, body.collect()).await {
                Ok(Ok(collected)) => Ok(Self::Buffered(collected.to_bytes())),
                Ok(Err(e)) => Err(Reject::new(StatusCode::BAD_REQUEST, format!("cannot read request body: {e}"))),
                Err(_) => Err(Reject::new(StatusCode::REQUEST_TIMEOUT, "timed out reading request body")),
            },
            // The tunnel side sees no progress while an over-limit body drains (see CappedBody).
            _ => Ok(Self::Streaming(Some(CappedBody::new(body, limit, st.stream_idle_timeout)))),
        }
    }

    /// Body for the next attempt (a buffered body is shared, not copied).
    fn next_body(&mut self) -> Result<LocalBody, Reject> {
        match self {
            Self::Buffered(bytes) => Ok(Either::Left(Full::new(bytes.clone()))),
            Self::Streaming(body) => body
                .take()
                .map(Either::Right)
                .ok_or_else(|| Reject::new(StatusCode::INTERNAL_SERVER_ERROR, "request body already consumed")),
        }
    }
}

/// How the local request was made, for shaping the local response.
struct LocalRequest {
    http10: bool,
    /// `(destination base, local Host)` when redirects to the destination are rewritten.
    redirect: Option<(RedirectFrom, HeaderValue)>,
}

/// Destination base whose redirects are pointed back at the client.
enum RedirectFrom {
    Default(&'static TargetBase),
    Target(TargetBase),
}

impl RedirectFrom {
    fn base(&self) -> &TargetBase {
        match self {
            Self::Default(base) => base,
            Self::Target(base) => base,
        }
    }
}

#[allow(clippy::large_enum_variant, reason = "short-lived value, moved once")]
enum Attempt {
    Answered(Response<Incoming>, Opener),
    /// Outer 401: the server does not know the session — or the CDN pretends so.
    SessionRejected,
    /// The connection to the server failed before an answer arrived.
    ConnectionFailed(Reject),
}

pub(super) async fn forward(st: &'static ClientState, req: Request<Incoming>, guard: ActiveGuard) -> Result<Response<OutBody>, Reject> {
    reject_unsupported(&req)?;
    let (parts, body) = req.into_parts();
    // Refusals before anything is sent drain the upload first, so the application sees the
    // answer rather than a reset connection.
    let (head, local) = match tunnel_request(st, parts, known_len(&body)) {
        Ok(request) => request,
        Err(reject) => return refuse(body, reject).await,
    };
    let mut session = match st.sessions.get(&st.tunnel).await {
        Ok(session) => session,
        Err(e) => return refuse(body, handshake_failed(e)).await,
    };
    // The answer to a rejected session is not authenticated, so the first copy may have been
    // delivered after all: only requests that are safe to repeat are resent automatically.
    let resendable = head.method.is_safe();
    let mut payload = Payload::read(body, head.body_len, st, resendable).await?;
    // A safe request with a buffered body may be sent once more.
    let mut retries = usize::from(resendable && matches!(payload, Payload::Buffered(_)));
    loop {
        let failure = match send(st, &session, &head, payload.next_body()?).await? {
            Attempt::Answered(resp, opener) => return open_response(st, resp, opener, guard, local, &session).await,
            Attempt::ConnectionFailed(reject) => reject,
            Attempt::SessionRejected => {
                // The server no longer knows the session (restart, expiry) — or the CDN pretends
                // so. Either way the next request needs a new one; its key exchange starts now.
                debug!(session = %short_id(&session.id), "server rejected the session; re-keying");
                st.sessions.invalidate(&st.tunnel, session.id);
                Reject::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the tunnel session was rejected; the request was not resent automatically (it may already have been delivered)",
                )
            }
        };
        if retries == 0 {
            return Err(failure);
        }
        retries -= 1;
        debug!("resending a safe request: {}", failure.message);
        session = st.sessions.get(&st.tunnel).await.map_err(handshake_failed)?;
    }
}

/// Answers with `reject` once the unread request body has been drained.
async fn refuse<T>(body: Incoming, reject: Reject) -> Result<T, Reject> {
    discard(body).await;
    Err(reject)
}

/// The head to tunnel (destination resolved, headers cleaned up) and what shaping the local
/// response needs.
fn tunnel_request(st: &'static ClientState, mut parts: Parts, body_len: Option<u64>) -> Result<(RequestHead, LocalRequest), Reject> {
    check_local_host(st, &parts)?;
    let route = target::resolve(&mut parts, st.default_target.as_ref())?;
    let local = LocalRequest {
        http10: parts.version == Version::HTTP_10,
        redirect: redirect_rewrite(st, &parts, route.origin),
    };
    let mut headers = parts.headers;
    strip_hop_by_hop(&mut headers);
    headers.remove(TARGET_HEADER);
    headers.remove(URL_HEADER);
    headers.remove(header::EXPECT);
    if !st.preserve_host {
        let host = route.uri.authority().map_or("", |a| host_of(a.as_str()));
        let host = HeaderValue::from_str(host).map_err(|_| Reject::new(StatusCode::BAD_REQUEST, "invalid target host"))?;
        headers.insert(header::HOST, host);
    } else if !headers.contains_key(header::HOST) {
        // HTTP/2 clients send :authority instead of Host.
        if let Some(authority) = parts.uri.authority() {
            headers.insert(header::HOST, HeaderValue::from_str(authority.as_str()).expect("an authority is a valid header value"));
        }
    }
    Ok((RequestHead { method: parts.method, uri: route.uri, body_len, headers }, local))
}

fn handshake_failed(e: HandshakeError) -> Reject {
    Reject::new(StatusCode::BAD_GATEWAY, format!("key exchange failed: {e}"))
}

fn body_too_large(limit: u64) -> Reject {
    Reject::new(StatusCode::PAYLOAD_TOO_LARGE, format!("request body exceeds the limit of {} MiB", limit >> 20))
}

fn reject_unsupported(req: &Request<Incoming>) -> Result<(), Reject> {
    if req.method() == Method::CONNECT {
        return Err(Reject::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "CONNECT (HTTPS tunnelling) is not supported; send plain HTTP to webproxy and name the \
             https:// destination with the X-Tunnel-Url or X-Tunnel-Target header",
        ));
    }
    let websocket = req
        .headers()
        .get_all(header::UPGRADE)
        .iter()
        .any(|v| v.as_bytes().windows(9).any(|w| w.eq_ignore_ascii_case(b"websocket")));
    if websocket {
        return Err(Reject::new(StatusCode::NOT_IMPLEMENTED, "WebSocket upgrades are not supported"));
    }
    Ok(())
}

/// `host[:port]` without userinfo.
fn host_of(authority: &str) -> &str {
    authority.rsplit('@').next().unwrap_or(authority)
}

/// The Host the local app addressed: the Host header, or the HTTP/2 :authority.
fn local_host(parts: &Parts) -> Option<HeaderValue> {
    match parts.headers.get(header::HOST) {
        Some(v) => Some(v.clone()),
        None => HeaderValue::from_str(parts.uri.authority()?.as_str()).ok(),
    }
}

/// DNS-rebinding protection: a web page that rebinds its own name to 127.0.0.1 can reach the
/// client, but then its Host header carries that name. Only IP literals, localhost and
/// configured names are accepted (proxy-mode requests name their destination explicitly).
fn check_local_host(st: &ClientState, parts: &Parts) -> Result<(), Reject> {
    if parts.version <= Version::HTTP_11 && parts.uri.scheme().is_some() {
        return Ok(());
    }
    // HTTP/1.0 requests may omit Host; browsers never do.
    let Some(value) = local_host(parts) else { return Ok(()) };
    let host: Authority = value
        .to_str()
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Reject::new(StatusCode::BAD_REQUEST, "invalid Host header"))?;
    let name = host.host();
    let allowed = name.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().is_ok()
        || name.eq_ignore_ascii_case("localhost")
        || st.allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(name));
    if allowed {
        Ok(())
    } else {
        Err(Reject::new(StatusCode::MISDIRECTED_REQUEST, format!("host `{name}` is not in allowed_hosts")))
    }
}

/// Redirects from a base-URL destination (`default_target` or `X-Tunnel-Target`) are pointed
/// back at this client, so following them stays inside the tunnel. Exact URLs and proxy-mode
/// requests are left alone.
fn redirect_rewrite(st: &'static ClientState, parts: &Parts, origin: RouteOrigin) -> Option<(RedirectFrom, HeaderValue)> {
    if !st.rewrite_redirects {
        return None;
    }
    let from = match origin {
        RouteOrigin::Default => RedirectFrom::Default(st.default_target.as_ref()?),
        RouteOrigin::Base(base) => RedirectFrom::Target(base),
        RouteOrigin::Proxy | RouteOrigin::ExactUrl => return None,
    };
    Some((from, local_host(parts)?))
}

/// Points `Location` / `Content-Location` values inside `base` (absolute, or origin-relative
/// under its path prefix) at `http://<local_host>` plus their path below the base. The result
/// is always absolute: a remainder such as `//host` or `/\host` stays a path on this client.
fn rewrite_location(headers: &mut HeaderMap, base: &TargetBase, local_host: &HeaderValue) {
    let Ok(local_host) = local_host.to_str() else { return };
    for name in [header::LOCATION, header::CONTENT_LOCATION] {
        let Some(value) = headers.get(&name).and_then(|v| v.to_str().ok()) else { continue };
        let Some(path) = base.local_path(value) else { continue };
        let slash = if path.starts_with('/') { "" } else { "/" };
        if let Ok(value) = HeaderValue::from_str(&format!("http://{local_host}{slash}{path}")) {
            headers.insert(name, value);
        }
    }
}

fn seal_rejection(e: ProtoError) -> Reject {
    let status = if e.is_size_limit() { StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE } else { StatusCode::BAD_REQUEST };
    Reject::new(status, e.0)
}

/// Longest `Retry-After` (seconds) taken over from an outer, unauthenticated response.
const MAX_RETRY_AFTER_SECS: u64 = 3600;

/// The local answer for an unexpected outer status (sent by the server or an intermediary).
fn outer_status_rejection(status: StatusCode, headers: &HeaderMap) -> Reject {
    let local = match status.as_u16() {
        429 => StatusCode::TOO_MANY_REQUESTS,
        503 => StatusCode::SERVICE_UNAVAILABLE,
        413 => StatusCode::PAYLOAD_TOO_LARGE,
        408 | 504 | 522 | 524 => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::BAD_GATEWAY,
    };
    let hint = if status == StatusCode::UPGRADE_REQUIRED { " (client and server run incompatible versions)" } else { "" };
    // Only a plain, bounded delay in seconds is passed on.
    let retry_after = matches!(local, StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE)
        .then(|| headers.get(header::RETRY_AFTER))
        .flatten()
        .filter(|v| v.to_str().ok().and_then(|s| s.parse::<u64>().ok()).is_some_and(|s| s <= MAX_RETRY_AFTER_SECS))
        .cloned();
    Reject::new(local, format!("tunnel server answered HTTP {status}{hint}")).retry_after(retry_after)
}

/// Gateway errors (but not "busy") may stand for a lost session whose 401 never arrived.
fn may_hide_lost_session(status: StatusCode) -> bool {
    status.is_server_error() && status != StatusCode::SERVICE_UNAVAILABLE
}

/// Sends one attempt of the request over the tunnel.
async fn send(st: &'static ClientState, session: &Session, head: &RequestHead, body: LocalBody) -> Result<Attempt, Reject> {
    let sent_at = session.clock_ms();
    let seq = session.next_seq();
    let keys = session.keys.request_keys(seq);
    let mut prefix = [0u8; DATA_PREFIX_LEN];
    prefix[0] = VERSION;
    prefix[1] = MSG_DATA;
    prefix[2..2 + SESSION_ID_LEN].copy_from_slice(&session.id);
    prefix[2 + SESSION_ID_LEN..].copy_from_slice(&seq.to_be_bytes());

    let sealed = SealBody::new(&prefix, head, body, Sealer::new(keys.c2s), st.stream_ctx(), None, Some(session.started()))
        .map_err(|e| seal_rejection(e.error))?;
    let wire_len = sealed.wire_len();
    let (sealed, progress) = ProgressBody::new(sealed);
    let mut outer = Request::new(sealed.boxed_unsync());
    *outer.method_mut() = Method::POST;
    *outer.uri_mut() = st.tunnel.uri.clone();
    set_tunnel_headers(outer.headers_mut(), wire_len);

    let resp = match await_response(st.tunnel.http.request(outer), &progress, st.stream_idle_timeout, st.response_timeout).await {
        Waited::Answer(Ok(r)) => r,
        Waited::Answer(Err(e)) => {
            let failure = BodyFailure::of(&e);
            if failure == BodyFailure::TooLarge {
                return Err(body_too_large(st.max_request_body.unwrap_or_default()));
            }
            // A failed local upload says nothing about the session.
            if failure != BodyFailure::Source {
                st.sessions.suspect_lost(&st.tunnel, session, sent_at);
            }
            let reject = Reject::new(StatusCode::BAD_GATEWAY, format!("tunnel request failed: {}", error_chain(&e)));
            return Ok(Attempt::ConnectionFailed(reject));
        }
        Waited::SendStalled => return Err(Reject::new(StatusCode::GATEWAY_TIMEOUT, "the request stopped moving towards the tunnel server")),
        Waited::TimedOut => return Err(Reject::new(StatusCode::GATEWAY_TIMEOUT, "tunnel server did not answer in time")),
    };
    match resp.status() {
        StatusCode::OK => Ok(Attempt::Answered(resp, Opener::new(keys.s2c))),
        StatusCode::UNAUTHORIZED => Ok(Attempt::SessionRejected),
        s => {
            if may_hide_lost_session(s) {
                st.sessions.suspect_lost(&st.tunnel, session, sent_at);
            }
            Err(outer_status_rejection(s, resp.headers()))
        }
    }
}

/// Decrypts the tunnel response into the response for the local application.
async fn open_response(
    st: &'static ClientState,
    resp: Response<Incoming>,
    mut opener: Opener,
    guard: ActiveGuard,
    local: LocalRequest,
    session: &Session,
) -> Result<Response<OutBody>, Reject> {
    let invalid = |what: &str| Reject::new(StatusCode::BAD_GATEWAY, format!("invalid tunnel response: {what}"));
    let mut reader = FrameReader::new(resp.into_body(), st.stream_ctx());
    // A slow destination makes the server start the response early; the head follows later.
    let head = timeout(st.response_timeout, async {
        match reader.read_exact(2).await {
            Ok(prefix) if prefix[..] == [VERSION, MSG_DATA_OK] => reader.read_head(&mut opener).await,
            Ok(_) => Err("unexpected prefix".into()),
            Err(e) => Err(e),
        }
    })
    .await
    .map_err(|_| Reject::new(StatusCode::GATEWAY_TIMEOUT, "tunnel server did not answer in time"))?
    .map_err(|e| invalid(&e.to_string()))?;
    session.mark_answered();
    let ResponseHead { status, body_len, mut headers } = ResponseHead::decode(head).map_err(|e| invalid(e.0))?;
    strip_hop_by_hop(&mut headers);
    if status == StatusCode::SERVICE_UNAVAILABLE && headers.get(ERROR_HEADER).is_some_and(|v| v == STALE_ERROR) {
        // Authenticated (the server strips this marker from destination responses): a request
        // arrived too late. If our session clock is off (e.g. after a suspend), a new key
        // exchange realigns it; the current session stays usable meanwhile.
        st.sessions.renew(&st.tunnel, session.id);
    }
    if let Some((from, local_host)) = &local.redirect {
        rewrite_location(&mut headers, from.base(), local_host);
    }
    let body = reader.into_body(opener, body_len, Some(guard), None).await.map_err(|e| invalid(&e.to_string()))?;
    let body = if local.http10 && body_len.is_none() {
        // The destination has already answered: wait for a buffer rather than refusing (a
        // refusal would suggest the request was not processed).
        let Ok(Ok(slot)) = timeout(st.response_timeout, st.http10_buffers.acquire()).await else {
            return Err(Reject::new(StatusCode::GATEWAY_TIMEOUT, "too many HTTP/1.0 responses are being buffered"));
        };
        let buffered = timeout(st.response_timeout, ChunkList::read(body, HTTP10_BUFFER_LIMIT, slot))
            .await
            .map_err(|_| invalid("HTTP/1.0 response did not complete in time"))?
            .map_err(|e| invalid(&format!("HTTP/1.0 response not completed: {e}")))?;
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(buffered.len()));
        buffered.boxed_unsync()
    } else {
        body.boxed_unsync()
    };
    let mut r = Response::new(body);
    *r.status_mut() = status;
    *r.headers_mut() = headers;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_rewriting() {
        let local = HeaderValue::from_static("127.0.0.1:8080");
        let rewrite = |base: &str, location: &'static str| {
            let mut h = HeaderMap::new();
            h.insert(header::LOCATION, HeaderValue::from_static(location));
            rewrite_location(&mut h, &TargetBase::parse(base).unwrap(), &local);
            h[header::LOCATION].to_str().unwrap().to_owned()
        };
        let base = "http://api.internal:3000/v2";
        assert_eq!(rewrite(base, "HTTP://API.internal:3000/v2/login?next=/"), "http://127.0.0.1:8080/login?next=/");
        assert_eq!(rewrite(base, "http://api.internal:3000/v2?x=1"), "http://127.0.0.1:8080/?x=1");
        // Origin-relative paths under the prefix lose it (the client adds it back) and become
        // absolute, so nothing below the prefix can name another origin.
        assert_eq!(rewrite(base, "/v2/login"), "http://127.0.0.1:8080/login");
        assert_eq!(rewrite(base, "/v2"), "http://127.0.0.1:8080/");
        assert_eq!(rewrite(base, "/v2//evil.com/"), "http://127.0.0.1:8080//evil.com/");
        assert_eq!(rewrite(base, "/v2/\\evil.com"), "http://127.0.0.1:8080/\\evil.com");
        // Outside the base: a shared prefix only, another path, another host, case-sensitive paths.
        for outside in ["http://api.internal:3000/v2x", "/other", "/V2/login", "http://api.internal:30001/v2", "//evil/v2"] {
            assert_eq!(rewrite(base, outside), outside);
        }
        // Without a prefix, relative redirects already work.
        assert_eq!(rewrite("http://api.internal:3000", "/login"), "/login");
        assert_eq!(rewrite("http://api.internal:3000", "http://api.internal:3000"), "http://127.0.0.1:8080/");
    }

    #[test]
    fn outer_statuses_keep_their_meaning() {
        let none = HeaderMap::new();
        let map = |s: u16| outer_status_rejection(StatusCode::from_u16(s).unwrap(), &none).status.as_u16();
        assert_eq!([map(429), map(503), map(413), map(524), map(400)], [429, 503, 413, 504, 502]);
        assert!(outer_status_rejection(StatusCode::UPGRADE_REQUIRED, &none).message.contains("incompatible"));
        let mut h = HeaderMap::new();
        h.insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
        let response = outer_status_rejection(StatusCode::TOO_MANY_REQUESTS, &h).into_response();
        assert_eq!(response.headers()[header::RETRY_AFTER], "30");
        h.insert(header::RETRY_AFTER, HeaderValue::from_static("999999"));
        let response = outer_status_rejection(StatusCode::TOO_MANY_REQUESTS, &h).into_response();
        assert!(!response.headers().contains_key(header::RETRY_AFTER), "implausible values are dropped");
        let suspicious: Vec<u16> = [502, 503, 504, 520, 429, 413].into_iter().filter(|&s| may_hide_lost_session(StatusCode::from_u16(s).unwrap())).collect();
        assert_eq!(suspicious, [502, 504, 520]);
    }
}
