//! Encrypting a message (head + body) into a tunnel stream.

use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};

use super::idle::{poll_with_idle, IdleTimer};
use super::{known_len, StreamCtx, STAMP_LEN};
use crate::crypto::{self, Sealer, FRAME_OVERHEAD};
use crate::proto::{BoxError, EncodeHead, ProtoError, FRAME_SIZE};
use crate::stats::{ActiveGuard, Stats};

/// Typical encoded head size; larger heads grow the buffer once.
const HEAD_CAPACITY_HINT: usize = 1024;

/// The body being sealed failed where it comes from (e.g. the local application aborted or
/// stalled its upload), as opposed to the connection it is sent on.
#[derive(Debug)]
pub(super) struct SourceError(BoxError);

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "body source: {}", self.0)
    }
}

impl std::error::Error for SourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// `SealBody::new` failed; the sealer is returned unused so an error can still be sealed.
pub struct SealError {
    pub error: ProtoError,
    pub sealer: Sealer,
}

/// Encrypting body: emits `prefix | head frame | body frames | final frame`.
///
/// The final frame always carries the last body bytes (so a receiver can't hand a complete
/// body on before the final frame has been verified) and, for requests, the sender's age
/// stamp. When the inner body has an exact length, frames are cut at fixed FRAME_SIZE
/// boundaries so the total wire length is known up front (the outer message then carries a
/// Content-Length, which CDNs handle best). Otherwise each chunk is sealed as soon as it
/// arrives to keep streaming latency low (SSE, long polling…); requests hold back only its
/// last byte.
pub struct SealBody<B> {
    inner: B,
    sealer: Sealer,
    head: Option<Bytes>,
    staging: BytesMut,
    /// Plaintext bytes still expected from `inner` (exact mode only).
    exact_left: Option<u64>,
    /// Wire bytes still to be emitted, when known.
    wire_left: Option<u64>,
    /// Requests: start of the session, for the age stamp ending the final frame.
    stamp_origin: Option<std::time::Instant>,
    /// Requests of unknown length: the last byte received so far, sealed only once more data
    /// (or the end) follows, so the final frame always carries body bytes.
    held: Option<u8>,
    done: bool,
    stats: &'static Stats,
    idle: Option<IdleTimer>,
    guard: Option<ActiveGuard>,
}

impl<B> SealBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    #[allow(clippy::result_large_err, reason = "the error returns the sealer so an encrypted error can still be sent")]
    pub fn new(
        prefix: &[u8],
        head: &impl EncodeHead,
        inner: B,
        mut sealer: Sealer,
        ctx: StreamCtx,
        guard: Option<ActiveGuard>,
        stamp_origin: Option<std::time::Instant>,
    ) -> Result<Self, SealError> {
        let exact = known_len(&inner);
        let mut out = BytesMut::with_capacity(prefix.len() + HEAD_CAPACITY_HINT + 2 * FRAME_OVERHEAD + STAMP_LEN);
        out.extend_from_slice(prefix);
        if let Err(error) = sealer.seal_with(&mut out, false, |buf| head.encode_into(buf)) {
            return Err(SealError { error, sealer });
        }
        let trailer_len = if stamp_origin.is_some() { STAMP_LEN as u64 } else { 0 };
        let wire_left = exact.map(|n| out.len() as u64 + crypto::sealed_body_len(n, trailer_len));
        let mut body = Self {
            inner,
            sealer,
            head: None,
            staging: BytesMut::new(),
            exact_left: exact,
            wire_left,
            stamp_origin,
            held: None,
            done: false,
            stats: ctx.stats,
            idle: IdleTimer::new(ctx.idle_timeout),
            guard,
        };
        if exact == Some(0) {
            let stamp = body.stamp();
            if let Err(error) = body.sealer.seal_into(&mut out, [&[], &[], stamp.as_slice()], true) {
                return Err(SealError { error, sealer: body.sealer });
            }
            body.done = true;
        }
        body.head = Some(out.freeze());
        Ok(body)
    }

    /// Total number of bytes this body will produce, when known.
    pub fn wire_len(&self) -> Option<u64> {
        self.wire_left
    }

    /// The age stamp for the final frame (empty for responses).
    fn stamp(&self) -> StampBytes {
        match self.stamp_origin {
            Some(origin) => StampBytes::Some((origin.elapsed().as_millis() as u64).to_be_bytes()),
            None => StampBytes::None,
        }
    }

    fn emit(&mut self, b: Bytes) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.stats.add_tx(b.len());
        if let Some(w) = self.wire_left.as_mut() {
            *w = w.saturating_sub(b.len() as u64);
        }
        Poll::Ready(Some(Ok(Frame::data(b))))
    }

    fn fail(&mut self, e: BoxError) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.done = true;
        self.guard = None;
        Poll::Ready(Some(Err(SourceError(e).into())))
    }

    fn seal_chunk(&mut self, data: Bytes) -> Result<Option<Bytes>, BoxError> {
        let Some(left) = self.exact_left else {
            return self.seal_streamed(data);
        };
        let n = data.len() as u64;
        if n > left {
            return Err(ProtoError("body is longer than its announced length").into());
        }
        let left = left - n;
        self.exact_left = Some(left);
        let pending = self.staging.len() + data.len();
        let mut out = BytesMut::with_capacity(pending + (pending / FRAME_SIZE + 1) * FRAME_OVERHEAD + STAMP_LEN);
        let mut rest: &[u8] = &data;
        loop {
            let pending = self.staging.len() + rest.len();
            // A full frame goes out only while more bytes follow it: the last bytes of the
            // body always travel in the final frame.
            if pending < FRAME_SIZE || (pending == FRAME_SIZE && left == 0) {
                break;
            }
            let take = FRAME_SIZE - self.staging.len();
            self.sealer.seal_into(&mut out, [&self.staging, &rest[..take], &[]], false)?;
            self.staging.clear();
            rest = &rest[take..];
        }
        if left == 0 {
            let stamp = self.stamp();
            self.sealer.seal_into(&mut out, [&self.staging, rest, stamp.as_slice()], true)?;
            self.staging = BytesMut::new();
            self.done = true;
        } else if !rest.is_empty() {
            if self.staging.capacity() == 0 {
                self.staging.reserve(FRAME_SIZE);
            }
            self.staging.extend_from_slice(rest);
        }
        Ok(if out.is_empty() { None } else { Some(out.freeze()) })
    }

    /// Unknown length: seal right away to keep latency low. Requests hold back the last byte
    /// of each (non-empty) chunk until more data or the end follows, so the final frame carries
    /// body bytes while every chunk still reaches the receiver at once.
    fn seal_streamed(&mut self, data: Bytes) -> Result<Option<Bytes>, BoxError> {
        let (mut rest, keep) = match self.stamp_origin {
            Some(_) => {
                let (now, last) = data.split_at(data.len() - 1);
                (now, Some(last[0]))
            }
            None => (&data[..], None),
        };
        let held = self.held.take();
        let mut first = held.as_slice();
        let pending = first.len() + rest.len();
        let mut out = BytesMut::with_capacity(pending + pending.div_ceil(FRAME_SIZE) * FRAME_OVERHEAD);
        while !first.is_empty() || !rest.is_empty() {
            let take = rest.len().min(FRAME_SIZE - first.len());
            self.sealer.seal_into(&mut out, [first, &rest[..take], &[]], false)?;
            first = &[];
            rest = &rest[take..];
        }
        self.held = keep;
        Ok(if out.is_empty() { None } else { Some(out.freeze()) })
    }

    fn seal_final(&mut self) -> Result<Bytes, BoxError> {
        self.done = true;
        if self.exact_left.is_some_and(|l| l != 0) {
            return Err(ProtoError("body is shorter than its announced length").into());
        }
        let stamp = self.stamp();
        let held = self.held.take();
        let mut out = BytesMut::with_capacity(self.staging.len() + held.as_slice().len() + FRAME_OVERHEAD + STAMP_LEN);
        self.sealer.seal_into(&mut out, [&self.staging, held.as_slice(), stamp.as_slice()], true)?;
        self.staging = BytesMut::new();
        Ok(out.freeze())
    }
}

/// An age stamp, or nothing.
enum StampBytes {
    Some([u8; STAMP_LEN]),
    None,
}

impl StampBytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            StampBytes::Some(b) => b,
            StampBytes::None => &[],
        }
    }
}

impl<B> Body for SealBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if let Some(h) = this.head.take() {
            return this.emit(h);
        }
        loop {
            if this.done {
                this.guard = None;
                return Poll::Ready(None);
            }
            match ready!(poll_with_idle(&mut this.inner, &mut this.idle, cx)) {
                Some(Ok(frame)) => {
                    // Trailers are not forwarded.
                    let Ok(data) = frame.into_data() else { continue };
                    if data.is_empty() {
                        continue;
                    }
                    match this.seal_chunk(data) {
                        Ok(Some(out)) => return this.emit(out),
                        Ok(None) => {}
                        Err(e) => return this.fail(e),
                    }
                }
                Some(Err(e)) => return this.fail(e),
                None => match this.seal_final() {
                    Ok(out) => return this.emit(out),
                    Err(e) => return this.fail(e),
                },
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.head.is_none() && self.done
    }

    fn size_hint(&self) -> SizeHint {
        self.wire_left.map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::test_util::{ctx, keys, Chunks, RawHead, Stalled};
    use crate::body::BodyFailure;
    use http_body_util::BodyExt;
    use std::collections::VecDeque;
    use std::time::Duration;

    #[tokio::test]
    async fn declared_length_mismatch_is_rejected() {
        let (ck, _) = keys();
        for (chunk, declared) in [(&b"abc"[..], 10), (&b"abcdef"[..], 3)] {
            let inner = Chunks { chunks: VecDeque::from([Bytes::from_static(chunk)]), exact: Some(declared) };
            let sealed = SealBody::new(b"", &RawHead(b"h"), inner, Sealer::new(ck.request_keys(2).c2s), ctx(), None, None)
                .unwrap_or_else(|e| panic!("{}", e.error));
            assert!(sealed.collect().await.is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_streams_time_out() {
        let (ck, _) = keys();
        let ctx = StreamCtx { stats: Stats::new("test"), idle_timeout: Some(Duration::from_secs(5)) };
        let mut sealed = SealBody::new(b"", &RawHead(b"h"), Stalled, Sealer::new(ck.request_keys(5).c2s), ctx, None, None)
            .unwrap_or_else(|e| panic!("{}", e.error));
        assert!(sealed.frame().await.unwrap().is_ok(), "head is emitted immediately");
        let started = tokio::time::Instant::now();
        let err = sealed.frame().await.unwrap().unwrap_err();
        assert_eq!(BodyFailure::of(&*err), BodyFailure::Source, "{err}");
        assert!(err.to_string().ends_with("stream idle timeout"), "{err}");
        assert!(started.elapsed() >= Duration::from_secs(5));
    }
}
