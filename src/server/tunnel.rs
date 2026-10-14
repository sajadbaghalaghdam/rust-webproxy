//! One tunnelled request: authenticate, forward to the destination, encrypt the response.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::uri::Authority;
use http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use tokio::time::Interval;
use tracing::{debug, warn};

use super::{octet_response, Refused, ServerState};
use crate::body::{
    discard, known_len, BodyFailure, CappedBody, Freshness, FrameReader, OutBody, ProgressBody, SealBody, SealError,
    SendProgress,
};
use crate::crypto::{Opener, Sealer};
use crate::net::{await_response, Reject, Waited};
use crate::proto::{
    error_chain, strip_hop_by_hop, BoxError, RequestHead, ResponseHead, SessionId, DATA_PREFIX_LEN, ERROR_HEADER,
    MSG_DATA_OK, SESSION_ID_LEN, VERSION,
};
use crate::stats::ActiveGuard;
use crate::util::short_id;

const RESPONSE_PREFIX: [u8; 2] = [VERSION, MSG_DATA_OK];
/// Keep-alive frame header sent while a deferred response waits for the destination.
const KEEPALIVE_FRAME: [u8; 4] = [0; 4];

type Outcome = Result<Response<Incoming>, Reject>;
type Exchange = Pin<Box<dyn Future<Output = Outcome> + Send>>;

/// An authenticated request whose head has been decrypted.
pub(super) struct Accepted {
    head: RequestHead,
    reader: FrameReader<Incoming>,
    opener: Opener,
    sealer: Sealer,
    freshness: Freshness,
}

/// Resolves the session, rejects replays and decrypts the request head. Runs under the
/// server's pre-authentication deadline.
pub(super) async fn accept(st: &ServerState, mut reader: FrameReader<Incoming>) -> Result<Accepted, Refused> {
    let prefix = reader.read_exact(DATA_PREFIX_LEN - 2).await.map_err(|_| StatusCode::BAD_REQUEST)?;
    let (sid, seq) = prefix.split_at(SESSION_ID_LEN);
    let sid: SessionId = sid.try_into().expect("prefix holds a session id");
    let seq = u64::from_be_bytes(seq.try_into().expect("prefix holds a sequence number"));

    // 401 makes the client run a new key exchange (e.g. after a server restart). The rest of
    // the upload is drained first, so a large one still gets to see this answer.
    let Some(session) = st.sessions.get(&sid) else {
        st.stats.rejected_unknown_session();
        return Err(Refused { status: StatusCode::UNAUTHORIZED, unread: Some(reader.into_inner()) });
    };
    if !session.is_fresh(seq) {
        st.stats.rejected_replay();
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let keys = session.keys.request_keys(seq);
    let mut opener = Opener::new(keys.c2s);
    let head = reader.read_head(&mut opener).await.map_err(|_| StatusCode::BAD_REQUEST)?;
    // Only authenticated requests consume a sequence number, and every one does.
    if !session.accept_seq(seq) {
        st.stats.rejected_replay();
        debug!(session = %short_id(&sid), seq, "replayed request rejected");
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let head = RequestHead::decode(head).map_err(|_| StatusCode::BAD_REQUEST)?;
    let freshness = Freshness {
        session_started: session.started(),
        max_age: Duration::from_secs(st.cfg.max_request_age_secs),
    };
    Ok(Accepted { head, reader, opener, sealer: Sealer::new(keys.s2c), freshness })
}

/// Forwards an accepted request and answers with the encrypted outcome.
pub(super) async fn respond(st: &'static ServerState, accepted: Accepted, guard: ActiveGuard) -> Response<OutBody> {
    let Accepted { head, reader, opener, sealer, freshness } = accepted;
    let prepared = match prepare(st, head, reader, opener, freshness).await {
        Ok(p) => p,
        Err(reject) => return sealed_response(st, Err(reject), sealer, guard),
    };
    let Some(early) = st.early_response() else {
        return sealed_response(st, exchange(st, prepared).await, sealer, guard);
    };
    let progress = Arc::clone(&prepared.progress);
    let mut exchange: Exchange = Box::pin(exchange(st, prepared));
    let slow = async {
        progress.finished().await;
        tokio::time::sleep(early).await;
    };
    tokio::select! {
        biased;
        outcome = &mut exchange => sealed_response(st, outcome, sealer, guard),
        () = slow => {
            // The destination is slow to answer: start the response now so the CDN sees
            // bytes, keep it alive, and send the sealed outcome on the same stream later.
            let mut keepalive = tokio::time::interval_at(tokio::time::Instant::now() + early, early);
            keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let body = DeferredBody {
                st,
                prefix: Some(Bytes::from_static(&RESPONSE_PREFIX)),
                pending: Some((exchange, sealer, guard)),
                keepalive,
                sealed: None,
            };
            octet_response(body.boxed_unsync(), None)
        }
    }
}

fn sealed_response(st: &ServerState, outcome: Outcome, sealer: Sealer, guard: ActiveGuard) -> Response<OutBody> {
    let (body, len) = seal_outcome(st, outcome, sealer, guard, &RESPONSE_PREFIX);
    octet_response(body, len)
}

/// The upstream request, ready to be sent.
struct Prepared {
    request: Request<OutBody>,
    progress: Arc<SendProgress>,
    /// For diagnostics; an Authority clone is a reference-count increment.
    authority: Option<Authority>,
}

/// Checks the destination and builds the upstream request around the decrypted body.
async fn prepare(
    st: &ServerState,
    head: RequestHead,
    reader: FrameReader<Incoming>,
    opener: Opener,
    freshness: Freshness,
) -> Result<Prepared, Reject> {
    let RequestHead { method, uri, body_len, mut headers } = head;
    if let Err(reject) = check_target(st, &uri, &headers) {
        // The request is authenticated: let the client finish its upload so it sees the answer.
        discard(reader.into_inner()).await;
        return Err(reject);
    }
    strip_hop_by_hop(&mut headers);
    headers.remove(header::EXPECT);
    if body_len.is_none() && matches!(method, Method::GET | Method::HEAD) {
        // hyper would otherwise send these without a body; keep the client's streamed body.
        headers.insert(header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    }
    let max_body = st.max_request_body();
    let body = reader
        .into_body(opener, body_len, None, Some(freshness))
        .await
        .map_err(|e| body_rejection(BodyFailure::of(&*e), &*e, max_body))?;
    if let (Some(len), Some(limit)) = (body_len, max_body) {
        if len > limit {
            // Read the rest of the upload so the client gets to see the answer.
            discard(body).await;
            return Err(body_too_large(limit));
        }
    }
    // Progress is measured inside the cap, so draining an over-limit upload counts as moving.
    let (body, progress) = ProgressBody::new(body);
    let body = CappedBody::new(body, max_body, None);
    let authority = uri.authority().cloned();
    let mut request = Request::new(body.boxed_unsync());
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.headers_mut() = headers;
    Ok(Prepared { request, progress, authority })
}

/// Sends the request to its destination and waits for the answer.
async fn exchange(st: &ServerState, prepared: Prepared) -> Outcome {
    let Prepared { request, progress, authority } = prepared;
    let limit = Duration::from_secs(st.cfg.upstream_response_timeout_secs);
    let stall = st.stream_ctx().idle_timeout;
    match await_response(st.http.request(request), &progress, stall, limit).await {
        Waited::Answer(Ok(resp)) => {
            debug!(target = ?authority, status = resp.status().as_u16(), "forwarded");
            Ok(resp)
        }
        Waited::Answer(Err(e)) => {
            let failure = BodyFailure::of(&e);
            if failure == BodyFailure::Other {
                warn!(target = ?authority, "upstream request failed: {}", error_chain(&e));
            }
            Err(body_rejection(failure, &e, st.max_request_body()))
        }
        Waited::SendStalled => {
            warn!(target = ?authority, "request body stalled while sending to the destination");
            Err(Reject::new(StatusCode::GATEWAY_TIMEOUT, "the request body stopped moving"))
        }
        Waited::TimedOut => {
            warn!(target = ?authority, "upstream timed out");
            Err(Reject::new(StatusCode::GATEWAY_TIMEOUT, "upstream did not respond in time"))
        }
    }
}

/// Maps a failure while reading the request body (or forwarding it) to the answer. Faults of
/// the tunnel stream (the sender's or the CDN's) are gateway errors like the destination's,
/// since the destination may have seen part of the request.
fn body_rejection(failure: BodyFailure, e: &(dyn std::error::Error + 'static), max_body: Option<u64>) -> Reject {
    match failure {
        BodyFailure::TooLarge => body_too_large(max_body.unwrap_or_default()),
        BodyFailure::Stale(delay) => Reject::new(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("request was delayed in transit by {}s and was not completed", delay.as_secs()),
        )
        .stale(),
        BodyFailure::TunnelStalled => {
            debug!("request body from the tunnel stalled: {}", error_chain(e));
            Reject::new(StatusCode::GATEWAY_TIMEOUT, "the request body stopped arriving through the tunnel")
        }
        BodyFailure::TunnelBroken => {
            debug!("request body from the tunnel failed: {}", error_chain(e));
            Reject::new(StatusCode::BAD_GATEWAY, format!("the request did not arrive intact through the tunnel: {}", error_chain(e)))
        }
        BodyFailure::Source | BodyFailure::Other => {
            Reject::new(StatusCode::BAD_GATEWAY, format!("upstream error: {}", error_chain(e)))
        }
    }
}

fn body_too_large(limit: u64) -> Reject {
    Reject::new(StatusCode::PAYLOAD_TOO_LARGE, format!("request body exceeds the server limit of {} MiB", limit >> 20))
}

/// The destination (and the Host header the client chose) must be allowed by the server.
fn check_target(st: &ServerState, uri: &Uri, headers: &HeaderMap) -> Result<(), Reject> {
    let default_port = match uri.scheme_str() {
        Some("http") => 80,
        Some("https") => 443,
        _ => return Err(Reject::new(StatusCode::BAD_REQUEST, "target must be an http:// or https:// URL")),
    };
    let host = uri.host().ok_or_else(|| Reject::new(StatusCode::BAD_REQUEST, "target URL has no host"))?;
    let port = uri.port_u16().unwrap_or(default_port);
    let denied = |h: &str| {
        warn!(host = %h, port, "target rejected by allowed_targets");
        Reject::new(StatusCode::FORBIDDEN, format!("target {h}:{port} is not allowed by the server"))
    };
    if !st.allow.permits(host, port) {
        return Err(denied(host));
    }
    if let Some(value) = headers.get(header::HOST) {
        let host_header = value
            .to_str()
            .ok()
            .and_then(|v| v.parse::<Authority>().ok())
            .ok_or_else(|| Reject::new(StatusCode::BAD_REQUEST, "invalid Host header"))?;
        // The connection goes to the URI's port; only the name in Host matters.
        if !st.allow.permits(host_header.host(), port) {
            return Err(denied(host_header.host()));
        }
    }
    Ok(())
}

/// Encrypts the outcome of an exchange into a tunnel body following `prefix`.
fn seal_outcome(
    st: &ServerState,
    outcome: Outcome,
    sealer: Sealer,
    guard: ActiveGuard,
    prefix: &[u8],
) -> (OutBody, Option<u64>) {
    let resp = match outcome {
        Ok(resp) => resp,
        Err(reject) => {
            st.stats.request_failed();
            if reject.is_stale() {
                st.stats.rejected_stale();
            }
            return seal_error(st, sealer, &reject, Some(guard), prefix);
        }
    };
    let (parts, body) = resp.into_parts();
    let mut headers = parts.headers;
    strip_hop_by_hop(&mut headers);
    // webproxy's own error marker must not be forgeable by a destination.
    headers.remove(ERROR_HEADER);
    let head = ResponseHead { status: parts.status, body_len: known_len(&body), headers };
    match SealBody::new(prefix, &head, body, sealer, st.stream_ctx(), Some(guard), None) {
        Ok(sealed) => {
            let len = sealed.wire_len();
            (sealed.boxed_unsync(), len)
        }
        Err(SealError { error, sealer }) => {
            st.stats.request_failed();
            let reject = Reject::new(StatusCode::BAD_GATEWAY, format!("destination response not forwarded: {error}"));
            seal_error(st, sealer, &reject, None, prefix)
        }
    }
}

/// Encrypted error response: only the client can read the status and message.
fn seal_error(
    st: &ServerState,
    sealer: Sealer,
    reject: &Reject,
    guard: Option<ActiveGuard>,
    prefix: &[u8],
) -> (OutBody, Option<u64>) {
    let body = reject.body();
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    headers.insert(ERROR_HEADER, reject.error_header());
    let head = ResponseHead { status: reject.status, body_len: Some(body.len() as u64), headers };
    let sealed = SealBody::new(prefix, &head, Full::new(body), sealer, st.stream_ctx(), guard, None)
        .unwrap_or_else(|_| unreachable!("a two-header head always fits in a frame"));
    let len = sealed.wire_len();
    (sealed.boxed_unsync(), len)
}

/// Response body for slow destinations: the prefix goes out immediately, keep-alive headers
/// follow every `early_response_secs`, and the sealed outcome comes on the same stream once
/// the exchange completes.
struct DeferredBody {
    st: &'static ServerState,
    prefix: Option<Bytes>,
    pending: Option<(Exchange, Sealer, ActiveGuard)>,
    keepalive: Interval,
    sealed: Option<OutBody>,
}

impl Body for DeferredBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if let Some(prefix) = this.prefix.take() {
            this.st.stats.add_tx(prefix.len());
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        if let Some((exchange, _, _)) = this.pending.as_mut() {
            let Poll::Ready(outcome) = exchange.as_mut().poll(cx) else {
                ready!(this.keepalive.poll_tick(cx));
                this.st.stats.add_tx(KEEPALIVE_FRAME.len());
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(&KEEPALIVE_FRAME)))));
            };
            let (_, sealer, guard) = this.pending.take().expect("pending checked above");
            this.sealed = Some(seal_outcome(this.st, outcome, sealer, guard, &[]).0);
        }
        match this.sealed.as_mut() {
            Some(body) => Pin::new(body).poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.is_none() && self.pending.is_none() && self.sealed.as_ref().is_none_or(Body::is_end_stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ProtoError;

    #[test]
    fn body_failures_map_to_answers() {
        let e = ProtoError("cause");
        let answer = |f| {
            let r = body_rejection(f, &e, Some(8 << 20));
            (r.status.as_u16(), r.is_stale())
        };
        assert_eq!(answer(BodyFailure::TooLarge), (413, false));
        assert_eq!(answer(BodyFailure::Stale(Duration::from_secs(400))), (503, true));
        assert_eq!(answer(BodyFailure::TunnelStalled), (504, false));
        assert_eq!(answer(BodyFailure::TunnelBroken), (502, false));
        assert_eq!(answer(BodyFailure::Other), (502, false));
        assert!(body_rejection(BodyFailure::TooLarge, &e, Some(8 << 20)).message.contains("8 MiB"));
    }
}
