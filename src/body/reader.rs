//! Reading a tunnel stream: frames, the message head and the decrypted body.

use std::future::poll_fn;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};

use super::idle::{poll_with_idle, IdleTimer};
use super::{StreamCtx, MAX_BODY_FRAME_CT, STAMP_LEN};
use crate::crypto::{self, Opener, FRAME_HDR_LEN, MAX_FRAME_CT};
use crate::proto::{BoxError, ProtoError, FRAME_SIZE};
use crate::stats::{ActiveGuard, Stats};

/// Frame header the server may send before a response head while the destination is still
/// working, to keep intermediaries' read timers alive.
pub(super) const KEEPALIVE: u32 = 0;

const TRUNCATED: ProtoError = ProtoError("tunnel stream truncated");
const TRAILING_DATA: ProtoError = ProtoError("unexpected data after end of body");

/// Freshness of a request body: the sender's age stamp in the final frame, compared with the
/// server's clock for the same session, must be within `max_age`. Checking the final frame
/// (rather than the head) means a request takes effect at the destination only if its end
/// arrived in time, however the CDN delays or trickles the parts before it.
#[derive(Clone, Copy)]
pub struct Freshness {
    pub session_started: std::time::Instant,
    pub max_age: Duration,
}

impl Freshness {
    /// Splits the stamp off the final frame's plaintext and checks it.
    fn take_stamp(&self, plaintext: Bytes) -> Result<Bytes, BoxError> {
        let split = plaintext.len().checked_sub(STAMP_LEN).ok_or(ProtoError("missing age stamp"))?;
        let sent_ms = u64::from_be_bytes(plaintext[split..].try_into().expect("STAMP_LEN bytes"));
        let delay = self.session_started.elapsed().saturating_sub(Duration::from_millis(sent_ms));
        if delay > self.max_age {
            return Err(StaleRequest { delay }.into());
        }
        Ok(plaintext.slice(..split))
    }
}

/// A request arrived later than `max_request_age_secs` allows; it was not forwarded.
#[derive(Debug)]
pub struct StaleRequest {
    pub delay: Duration,
}

impl std::fmt::Display for StaleRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request was delayed in transit by {}s", self.delay.as_secs())
    }
}

impl std::error::Error for StaleRequest {}

/// The incoming tunnel stream failed (truncated, tampered with, stalled or stale) — a fault of
/// the sender or the CDN, not of whoever the body was being forwarded to.
#[derive(Debug)]
pub struct TunnelBodyError(pub(super) BoxError);

impl std::fmt::Display for TunnelBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "incoming tunnel stream: {}", self.0)
    }
}

impl std::error::Error for TunnelBodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// Incrementally reads the raw (still encrypted) tunnel stream.
pub struct FrameReader<B> {
    inner: B,
    buf: BytesMut,
    eof: bool,
    /// Before the head, keep-alive headers are skipped and the head may be a large frame.
    head_read: bool,
    stats: &'static Stats,
    idle_limit: Option<Duration>,
    /// Armed once the head has arrived; until then the caller's own deadline applies.
    idle: Option<IdleTimer>,
}

impl<B> FrameReader<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    pub fn new(inner: B, ctx: StreamCtx) -> Self {
        Self {
            inner,
            buf: BytesMut::new(),
            eof: false,
            head_read: false,
            stats: ctx.stats,
            idle_limit: ctx.idle_timeout,
            idle: None,
        }
    }

    /// Pulls one more chunk from the inner body into the buffer.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        loop {
            match ready!(poll_with_idle(&mut self.inner, &mut self.idle, cx)) {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if data.is_empty() {
                            continue;
                        }
                        self.stats.add_rx(data.len());
                        self.buf.extend_from_slice(&data);
                        return Poll::Ready(Ok(()));
                    }
                }
                Some(Err(e)) => return Poll::Ready(Err(e)),
                None => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn poll_exact(&mut self, cx: &mut Context<'_>, n: usize) -> Poll<Result<BytesMut, BoxError>> {
        while self.buf.len() < n {
            if self.eof {
                return Poll::Ready(Err(TRUNCATED.into()));
            }
            ready!(self.poll_fill(cx))?;
        }
        Poll::Ready(Ok(self.buf.split_to(n)))
    }

    /// Takes the next complete frame out of the buffer without reading more input.
    fn take_buffered_frame(&mut self) -> Result<Option<(BytesMut, bool)>, ProtoError> {
        loop {
            if self.buf.len() < FRAME_HDR_LEN {
                return Ok(None);
            }
            let hdr = u32::from_be_bytes(self.buf[..FRAME_HDR_LEN].try_into().expect("4 bytes"));
            if hdr == KEEPALIVE && !self.head_read {
                self.buf.advance(FRAME_HDR_LEN);
                continue;
            }
            let (len, last) = crypto::parse_frame_header(hdr)?;
            if len > if self.head_read { MAX_BODY_FRAME_CT } else { MAX_FRAME_CT } {
                return Err(ProtoError("frame exceeds the size limit"));
            }
            let missing = (FRAME_HDR_LEN + len).saturating_sub(self.buf.len());
            if missing > 0 {
                // The length is not authenticated yet: never reserve more than a body frame.
                self.buf.reserve(missing.min(FRAME_HDR_LEN + MAX_BODY_FRAME_CT));
                return Ok(None);
            }
            self.buf.advance(FRAME_HDR_LEN);
            return Ok(Some((self.buf.split_to(len), last)));
        }
    }

    /// Next raw frame `(ciphertext, last)`, or `None` on a clean end of stream.
    fn poll_raw_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<(BytesMut, bool)>, BoxError>> {
        loop {
            if let Some(f) = self.take_buffered_frame()? {
                return Poll::Ready(Ok(Some(f)));
            }
            if self.eof {
                return Poll::Ready(if self.buf.is_empty() { Ok(None) } else { Err(TRUNCATED.into()) });
            }
            ready!(self.poll_fill(cx))?;
        }
    }

    pub async fn read_exact(&mut self, n: usize) -> Result<BytesMut, BoxError> {
        poll_fn(|cx| self.poll_exact(cx, n)).await
    }

    async fn next_frame(&mut self) -> Result<Option<(BytesMut, bool)>, BoxError> {
        poll_fn(|cx| self.poll_raw_frame(cx)).await
    }

    /// Reads and decrypts frame 0, the message head. From here on body frames are size
    /// limited and the stream idle timer runs.
    pub async fn read_head(&mut self, opener: &mut Opener) -> Result<Bytes, BoxError> {
        let head = match self.next_frame().await? {
            Some((ct, false)) => opener.open(ct, false)?,
            Some((_, true)) => return Err(ProtoError("head frame must not be the last frame").into()),
            None => return Err(TRUNCATED.into()),
        };
        self.head_read = true;
        self.idle = IdleTimer::new(self.idle_limit);
        Ok(head)
    }

    /// Reads and verifies the final frame of a body of `len` bytes that fits in it entirely.
    async fn read_final(&mut self, opener: &mut Opener, len: u64, freshness: Option<&Freshness>) -> Result<Bytes, BoxError> {
        let (ct, last) = self.next_frame().await?.ok_or(TRUNCATED)?;
        if !last {
            return Err(ProtoError("body length does not match the announced length").into());
        }
        let mut plaintext = opener.open(ct, true)?;
        if let Some(f) = freshness {
            plaintext = f.take_stamp(plaintext)?;
        }
        if plaintext.len() as u64 != len {
            return Err(ProtoError("body length does not match the announced length").into());
        }
        if !self.buf.is_empty() {
            return Err(TRAILING_DATA.into());
        }
        Ok(plaintext)
    }

    /// The raw tunnel stream, e.g. to drain what is left of it.
    pub fn into_inner(self) -> B {
        self.inner
    }
}

impl<B> FrameReader<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    /// The decrypted body following the head. A body announced as empty, and a request body
    /// announced with at most FRAME_SIZE bytes (which the sender puts in the final frame), is
    /// read and verified here, so nothing of such a request is forwarded before its freshness
    /// is established. Other bodies are streamed; their last bytes come only with the verified
    /// final frame. The stream idle timer (armed by `read_head`) bounds the wait.
    pub async fn into_body(
        mut self,
        mut opener: Opener,
        body_len: Option<u64>,
        guard: Option<ActiveGuard>,
        freshness: Option<Freshness>,
    ) -> Result<TunnelBody<B>, BoxError> {
        let fits_final = |n: u64| n == 0 || (freshness.is_some() && n <= FRAME_SIZE as u64);
        if let Some(len) = body_len.filter(|&n| fits_final(n)) {
            let body = self.read_final(&mut opener, len, freshness.as_ref()).await.map_err(TunnelBodyError)?;
            return Ok(if len == 0 { TunnelBody::Empty } else { TunnelBody::Full(Some(body)) });
        }
        Ok(TunnelBody::Open(OpenBody { reader: self, opener, remaining: body_len, freshness, done: false, guard }))
    }
}

/// Decrypted body of a tunnelled message.
#[allow(clippy::large_enum_variant, reason = "boxed into OutBody right after construction")]
pub enum TunnelBody<B> {
    Empty,
    /// Already received and verified completely.
    Full(Option<Bytes>),
    Open(OpenBody<B>),
}

impl<B> Body for TunnelBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.get_mut() {
            Self::Empty => Poll::Ready(None),
            Self::Full(data) => Poll::Ready(data.take().map(|d| Ok(Frame::data(d)))),
            Self::Open(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Full(data) => data.is_none(),
            Self::Open(body) => body.done,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty => SizeHint::with_exact(0),
            Self::Full(data) => SizeHint::with_exact(data.as_ref().map_or(0, |d| d.len() as u64)),
            Self::Open(body) => body.remaining.map_or_else(SizeHint::default, SizeHint::with_exact),
        }
    }
}

/// Decrypting body: yields the plaintext of the frames that follow the head.
pub struct OpenBody<B> {
    reader: FrameReader<B>,
    opener: Opener,
    /// Plaintext bytes still expected, when the sender announced an exact length.
    remaining: Option<u64>,
    /// Requests only: the final frame's age stamp must be fresh.
    freshness: Option<Freshness>,
    done: bool,
    guard: Option<ActiveGuard>,
}

impl<B> OpenBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    fn fail(&mut self, e: BoxError) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.done = true;
        self.guard = None;
        Poll::Ready(Some(Err(TunnelBodyError(e).into())))
    }

    /// Decrypts one frame and checks it against the announced length (and, for the final
    /// frame, the age stamp — the last body bytes are released only if it is fresh).
    fn open_frame(&mut self, ct: BytesMut, last: bool) -> Result<Bytes, BoxError> {
        let mut plaintext = self.opener.open(ct, last)?;
        if last {
            if let Some(f) = &self.freshness {
                plaintext = f.take_stamp(plaintext)?;
            }
        }
        if let Some(rem) = self.remaining.as_mut() {
            let n = plaintext.len() as u64;
            if n > *rem || (last && n != *rem) || (!last && n == *rem) {
                return Err(ProtoError("body length does not match the announced length").into());
            }
            *rem -= n;
        }
        if last {
            if !self.reader.buf.is_empty() {
                return Err(TRAILING_DATA.into());
            }
            self.done = true;
            self.guard = None;
        }
        Ok(plaintext)
    }
}

impl<B> Body for OpenBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            let (ct, last) = match ready!(this.reader.poll_raw_frame(cx)) {
                Ok(Some(f)) => f,
                Ok(None) => return this.fail(TRUNCATED.into()),
                Err(e) => return this.fail(e),
            };
            match this.open_frame(ct, last) {
                Ok(pt) if pt.is_empty() => {}
                Ok(pt) => return Poll::Ready(Some(Ok(Frame::data(pt)))),
                Err(e) => return this.fail(e),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        self.remaining.map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::test_util::{ctx, keys, pseudo_random, split, Chunks, RawHead, ThenStall};
    use crate::body::{BodyFailure, SealBody};
    use crate::crypto::{Sealer, FRAME_OVERHEAD};
    use crate::proto::FRAME_SIZE;
    use http_body_util::BodyExt;
    use std::collections::VecDeque;

    fn fresh(max_age: Duration) -> Freshness {
        Freshness { session_started: std::time::Instant::now(), max_age }
    }

    fn seal(inner: Chunks, key: ring::aead::LessSafeKey, stamp: Option<std::time::Instant>) -> SealBody<Chunks> {
        SealBody::new(b"PFX", &RawHead(b"head-bytes"), inner, Sealer::new(key), ctx(), None, stamp)
            .unwrap_or_else(|e| panic!("{}", e.error))
    }

    /// Decodes a sealed stream (prefix "PFX").
    async fn open_stream(
        wire: VecDeque<Bytes>,
        key: ring::aead::LessSafeKey,
        len: Option<u64>,
        freshness: Option<Freshness>,
    ) -> Result<Bytes, BoxError> {
        let mut reader = FrameReader::new(Chunks { chunks: wire, exact: None }, ctx());
        assert_eq!(&reader.read_exact(3).await?[..], b"PFX");
        let mut opener = Opener::new(key);
        assert_eq!(&reader.read_head(&mut opener).await?[..], b"head-bytes");
        Ok(reader.into_body(opener, len, None, freshness).await?.collect().await?.to_bytes())
    }

    #[tokio::test]
    async fn roundtrip_sizes_modes_and_stamps() {
        let sizes = [0usize, 1, 100, FRAME_SIZE - 1, FRAME_SIZE, FRAME_SIZE + 1, 3 * FRAME_SIZE, 1_000_003];
        for (i, n) in sizes.into_iter().enumerate() {
            let data = pseudo_random(n, i as u64 + 1);
            for exact in [true, false] {
                for stamped in [false, true] {
                    let (ck, sk) = keys();
                    let inner = Chunks { chunks: split(&data, i as u64), exact: exact.then_some(n as u64) };
                    let sealed = seal(inner, ck.request_keys(1).c2s, stamped.then(std::time::Instant::now));
                    let announced = sealed.wire_len();
                    assert_eq!(announced.is_some(), exact || n == 0, "an empty body always has a known length");
                    let wire = sealed.collect().await.unwrap().to_bytes();
                    if let Some(len) = announced {
                        assert_eq!(len, wire.len() as u64, "announced wire length must be exact (n={n})");
                    }
                    let len = (exact || n == 0).then_some(n as u64);
                    let freshness = stamped.then(|| fresh(Duration::from_secs(60)));
                    let out = open_stream(split(&wire, i as u64 + 7), sk.request_keys(1).c2s, len, freshness).await;
                    assert_eq!(out.unwrap(), data, "n={n} exact={exact} stamped={stamped}");
                }
            }
        }
    }

    #[tokio::test]
    async fn last_body_bytes_travel_in_the_final_frame() {
        // Exactly one frame of data: it must be sent as the final frame, so nothing completes
        // the body before the (stamped) final frame has been verified.
        let (ck, _) = keys();
        let data = pseudo_random(FRAME_SIZE, 3);
        let inner = Chunks { chunks: VecDeque::from([Bytes::from(data)]), exact: Some(FRAME_SIZE as u64) };
        let wire = seal(inner, ck.request_keys(1).c2s, Some(std::time::Instant::now())).collect().await.unwrap().to_bytes();
        let head_frame = FRAME_OVERHEAD + b"head-bytes".len();
        assert_eq!(wire.len(), 3 + head_frame + FRAME_OVERHEAD + FRAME_SIZE + STAMP_LEN, "a single stamped final frame");
    }

    #[tokio::test]
    async fn streamed_requests_end_with_body_bytes() {
        // Unknown length, stamped: the last piece of data must travel in the final frame.
        let (ck, sk) = keys();
        let mut sealed = seal(
            Chunks { chunks: VecDeque::from([Bytes::from_static(b"{\"a\":"), Bytes::from_static(b"1}")]), exact: None },
            ck.request_keys(3).c2s,
            Some(std::time::Instant::now()),
        );
        let mut wire = Vec::new();
        while let Some(frame) = sealed.frame().await {
            wire.push(frame.unwrap().into_data().unwrap());
        }
        let mut reader = FrameReader::new(Chunks { chunks: wire.into(), exact: None }, ctx());
        reader.read_exact(3).await.unwrap();
        let mut opener = Opener::new(sk.request_keys(3).c2s);
        reader.read_head(&mut opener).await.unwrap();
        let mut frames = Vec::new();
        while let Some((ct, last)) = reader.next_frame().await.unwrap() {
            frames.push((opener.open(ct, last).unwrap(), last));
        }
        // Every chunk moves at once except its last byte, which travels with the next one.
        let data: Vec<&[u8]> = frames.iter().map(|(pt, _)| &pt[..]).collect();
        assert_eq!(data[..2], [&b"{\"a\""[..], b":1"]);
        let (final_pt, last) = frames.last().unwrap();
        assert!(*last && frames.len() == 3);
        assert_eq!(&final_pt[..final_pt.len() - STAMP_LEN], b"}", "final frame = last byte + stamp");
    }

    #[tokio::test]
    async fn small_request_bodies_are_verified_before_release() {
        let (ck, sk) = keys();
        let data = pseudo_random(1000, 5);
        let inner = Chunks { chunks: split(&data, 1), exact: Some(1000) };
        let wire = seal(inner, ck.request_keys(4).c2s, Some(std::time::Instant::now())).collect().await.unwrap().to_bytes();
        let mut reader = FrameReader::new(Chunks { chunks: VecDeque::from([wire]), exact: None }, ctx());
        reader.read_exact(3).await.unwrap();
        let mut opener = Opener::new(sk.request_keys(4).c2s);
        reader.read_head(&mut opener).await.unwrap();
        let body = reader.into_body(opener, Some(1000), None, Some(fresh(Duration::from_secs(60)))).await.unwrap();
        assert!(matches!(body, TunnelBody::Full(_)), "verified before being handed on");
        assert_eq!(body.collect().await.unwrap().to_bytes(), data);
    }

    #[tokio::test]
    async fn stale_final_frames_are_rejected() {
        let (ck, sk) = keys();
        // The sender's session clock started 10 s after the server's: a 10 s delay.
        let server_started = std::time::Instant::now() - Duration::from_secs(10);
        let data = pseudo_random(5000, 4);
        for exact in [true, false] {
            let inner = Chunks { chunks: split(&data, 2), exact: exact.then_some(5000) };
            let wire = seal(inner, ck.request_keys(9).c2s, Some(std::time::Instant::now())).collect().await.unwrap().to_bytes();
            let strict = Freshness { session_started: server_started, max_age: Duration::from_secs(5) };
            let err = open_stream(VecDeque::from([wire.clone()]), sk.request_keys(9).c2s, exact.then_some(5000), Some(strict))
                .await
                .unwrap_err();
            assert!(matches!(BodyFailure::of(&*err), BodyFailure::Stale(d) if d >= Duration::from_secs(9)), "{err}");
            let lenient = Freshness { session_started: server_started, max_age: Duration::from_secs(30) };
            let ok = open_stream(VecDeque::from([wire]), sk.request_keys(9).c2s, exact.then_some(5000), Some(lenient));
            assert_eq!(ok.await.unwrap(), data);
        }
        // Empty bodies carry only the stamp.
        let empty = Chunks { chunks: VecDeque::new(), exact: Some(0) };
        let wire = seal(empty, ck.request_keys(10).c2s, Some(std::time::Instant::now())).collect().await.unwrap().to_bytes();
        let strict = Freshness { session_started: server_started, max_age: Duration::from_secs(5) };
        let err = open_stream(VecDeque::from([wire]), sk.request_keys(10).c2s, Some(0), Some(strict)).await.unwrap_err();
        assert!(matches!(BodyFailure::of(&*err), BodyFailure::Stale(_)), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn missing_final_frames_stall_under_the_idle_timer() {
        let (ck, sk) = keys();
        let mut sealer = Sealer::new(ck.request_keys(6).c2s);
        let mut wire = BytesMut::from(&b"PFX"[..]);
        sealer.seal_into(&mut wire, [b"head-bytes", b"", b""], false).unwrap();
        let idle = StreamCtx { stats: Stats::new("test"), idle_timeout: Some(Duration::from_secs(7)) };
        let mut reader = FrameReader::new(ThenStall(VecDeque::from([wire.freeze()])), idle);
        reader.read_exact(3).await.unwrap();
        let mut opener = Opener::new(sk.request_keys(6).c2s);
        reader.read_head(&mut opener).await.unwrap();
        let started = tokio::time::Instant::now();
        let err = reader.into_body(opener, Some(10), None, Some(fresh(Duration::from_secs(60)))).await.err().unwrap();
        assert_eq!(BodyFailure::of(&*err), BodyFailure::TunnelStalled);
        assert_eq!(started.elapsed(), Duration::from_secs(7));
    }

    #[tokio::test]
    async fn truncation_and_tampering_are_detected() {
        let (ck, sk) = keys();
        let data = pseudo_random(100_000, 9);
        let wire = seal(Chunks { chunks: split(&data, 3), exact: None }, ck.request_keys(1).c2s, None)
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let open = |w: Bytes, key| open_stream(VecDeque::from([w]), key, None, None);
        // Failures after the head are faults of the incoming tunnel stream.
        let broken = |r: Result<Bytes, BoxError>| r.err().is_some_and(|e| BodyFailure::of(&*e) == BodyFailure::TunnelBroken);
        let head_end = 3 + FRAME_OVERHEAD + b"head-bytes".len();
        assert_eq!(open(wire.clone(), sk.request_keys(1).c2s).await.unwrap(), data);
        assert!(open(wire.clone(), sk.request_keys(2).c2s).await.is_err(), "keys of another request");
        for cut in [wire.len() - 1, wire.len() - FRAME_OVERHEAD, wire.len() / 2, 40] {
            assert!(broken(open(wire.slice(..cut), sk.request_keys(1).c2s).await), "cut={cut}");
        }
        for pos in [3usize, 8, 40, wire.len() / 2, wire.len() - 1] {
            let mut t = wire.to_vec();
            t[pos] ^= 0x01;
            let result = open(Bytes::from(t), sk.request_keys(1).c2s).await;
            assert!(result.is_err(), "pos={pos}");
            assert!(pos < head_end || broken(result), "pos={pos}");
        }
        let mut t = wire.to_vec();
        t.extend_from_slice(b"junk");
        assert!(broken(open(Bytes::from(t), sk.request_keys(1).c2s).await), "appended garbage");
    }

    #[tokio::test]
    async fn keepalives_are_skipped_only_before_the_head() {
        let (ck, sk) = keys();
        let wire = seal(Chunks { chunks: VecDeque::from([Bytes::from_static(b"body")]), exact: None }, ck.request_keys(5).c2s, None)
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let mut with_keepalives = BytesMut::from(&wire[..3]);
        with_keepalives.extend_from_slice(&[0; 12]);
        with_keepalives.extend_from_slice(&wire[3..]);
        let out = open_stream(VecDeque::from([with_keepalives.freeze()]), sk.request_keys(5).c2s, None, None);
        assert_eq!(&out.await.unwrap()[..], b"body");
        // After the head a zero header is an error.
        let head_end = 3 + FRAME_OVERHEAD + b"head-bytes".len();
        let mut late = BytesMut::from(&wire[..head_end]);
        late.extend_from_slice(&[0; 4]);
        late.extend_from_slice(&wire[head_end..]);
        assert!(open_stream(VecDeque::from([late.freeze()]), sk.request_keys(5).c2s, None, None).await.is_err());
    }

    #[tokio::test]
    async fn oversized_body_frames_are_rejected_before_buffering() {
        let (ck, sk) = keys();
        let mut wire = BytesMut::from(&b"PFX"[..]);
        let mut sealer = Sealer::new(ck.request_keys(4).c2s);
        sealer.seal_into(&mut wire, [b"head-bytes", b"", b""], false).unwrap();
        wire.extend_from_slice(&((MAX_BODY_FRAME_CT + 1) as u32).to_be_bytes());
        let err = open_stream(VecDeque::from([wire.freeze()]), sk.request_keys(4).c2s, None, None).await.unwrap_err();
        assert!(err.to_string().contains("size limit"), "{err}");
    }
}
