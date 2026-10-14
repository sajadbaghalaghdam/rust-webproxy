//! Streaming encryption / decryption of HTTP bodies and the body adapters around it.
//!
//! All adapters are pull-based `http_body::Body` implementations: nothing is spawned and
//! nothing is buffered beyond one frame, so back-pressure flows end to end and dropping
//! either side releases everything.

mod buffered;
mod idle;
mod limit;
mod progress;
mod reader;
mod seal;

pub use buffered::ChunkList;
pub use limit::{discard, CappedBody};
pub use progress::{ProgressBody, SendProgress};
pub use reader::{Freshness, FrameReader};
pub use seal::{SealBody, SealError};

use std::error::Error;
use std::time::Duration;

use bytes::Bytes;
use http_body::Body;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};

use crate::proto::{BoxError, FRAME_SIZE};
use crate::stats::Stats;

/// Body type of every request/response webproxy produces.
pub type OutBody = UnsyncBoxBody<Bytes, BoxError>;

/// Requests end with the sender's age on the session clock (milliseconds, u64 BE) inside the
/// authenticated final frame; see [`Freshness`].
const STAMP_LEN: usize = 8;
/// Largest ciphertext of a body frame (frame 0, the head, may be larger).
const MAX_BODY_FRAME_CT: usize = FRAME_SIZE + STAMP_LEN + crate::crypto::TAG_LEN;

pub fn full_body(b: impl Into<Bytes>) -> OutBody {
    Full::new(b.into()).map_err(|never| match never {}).boxed_unsync()
}

/// Exact body length when it is known before streaming.
pub fn known_len(body: &impl Body) -> Option<u64> {
    if body.is_end_stream() {
        Some(0)
    } else {
        body.size_hint().exact()
    }
}

/// Why reading or forwarding a body failed, found in an error's source chain.
#[derive(Debug, PartialEq, Eq)]
pub enum BodyFailure {
    /// The body exceeded `max_request_body_mb`.
    TooLarge,
    /// The request's final frame arrived later than `max_request_age_secs` allows.
    Stale(Duration),
    /// The incoming tunnel stream stopped moving.
    TunnelStalled,
    /// The incoming tunnel stream was truncated, malformed or tampered with.
    TunnelBroken,
    /// A body being sent into the tunnel failed at its source (the sender's own side).
    Source,
    /// Anything else, e.g. the destination's side of the exchange.
    Other,
}

impl BodyFailure {
    pub fn of(err: &(dyn Error + 'static)) -> Self {
        let chain = || source_chain(err);
        if chain().any(|e| e.is::<limit::BodyTooLarge>()) {
            return Self::TooLarge;
        }
        if let Some(delay) = chain().find_map(|e| e.downcast_ref::<reader::StaleRequest>().map(|s| s.delay)) {
            return Self::Stale(delay);
        }
        if chain().any(|e| e.is::<reader::TunnelBodyError>()) {
            return if chain().any(idle::is_idle_timeout) { Self::TunnelStalled } else { Self::TunnelBroken };
        }
        if chain().any(|e| e.is::<seal::SourceError>()) {
            return Self::Source;
        }
        Self::Other
    }
}

/// `err` followed by its sources.
fn source_chain<'a>(err: &'a (dyn Error + 'static)) -> impl Iterator<Item = &'a (dyn Error + 'static)> {
    std::iter::successors(Some(err), |&e| e.source())
}

/// Settings shared by the streaming adapters.
#[derive(Clone, Copy)]
pub struct StreamCtx {
    pub stats: &'static Stats,
    /// Fail a body that makes no progress for this long (`None` = never).
    pub idle_timeout: Option<Duration>,
}

#[cfg(test)]
pub(crate) mod test_util {
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use bytes::{Bytes, BytesMut};
    use http_body::{Body, Frame, SizeHint};
    use ring::rand::SystemRandom;

    use super::StreamCtx;
    use crate::crypto::{client_finish, client_hello, server_accept, PairingKey, SessionKeys};
    use crate::proto::{EncodeHead, ProtoError};
    use crate::stats::Stats;

    /// Test body yielding predefined chunks, optionally with a declared exact size.
    pub struct Chunks {
        pub chunks: VecDeque<Bytes>,
        pub exact: Option<u64>,
    }

    impl Body for Chunks {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.chunks.pop_front().map(|c| Ok(Frame::data(c))))
        }
        fn is_end_stream(&self) -> bool {
            self.chunks.is_empty()
        }
        fn size_hint(&self) -> SizeHint {
            self.exact.map_or_else(SizeHint::default, SizeHint::with_exact)
        }
    }

    /// Body that never produces anything.
    pub struct Stalled;

    impl Body for Stalled {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Pending
        }
    }

    /// Head used by the tests: raw bytes.
    pub struct RawHead(pub &'static [u8]);

    impl EncodeHead for RawHead {
        fn encode_into(&self, buf: &mut BytesMut) -> Result<(), ProtoError> {
            buf.extend_from_slice(self.0);
            Ok(())
        }
    }

    pub fn ctx() -> StreamCtx {
        StreamCtx { stats: Stats::new("test"), idle_timeout: None }
    }

    pub fn keys() -> (SessionKeys, SessionKeys) {
        let secret = [7u8; 32];
        let (c, s) = (PairingKey::new(&secret), PairingKey::new(&secret));
        let rng = SystemRandom::new();
        let p = client_hello(&c, &rng, 0).unwrap();
        let (resp, se) = server_accept(&s, p.message(), &rng, 60).unwrap();
        let ce = client_finish(&c, p, &resp).unwrap();
        (ce.keys, se.keys)
    }

    pub fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    /// Body yielding its chunks, then never anything more.
    pub struct ThenStall(pub VecDeque<Bytes>);

    impl Body for ThenStall {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            match self.0.pop_front() {
                Some(c) => Poll::Ready(Some(Ok(Frame::data(c)))),
                None => Poll::Pending,
            }
        }
    }

    /// Body yielding `chunks` with `every` between them (for tests with paused time).
    pub struct Trickle {
        pub chunks: VecDeque<Bytes>,
        pub every: std::time::Duration,
        pub sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl Body for Trickle {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            let every = self.every;
            let sleep = self.sleep.get_or_insert_with(|| Box::pin(tokio::time::sleep(every)));
            std::task::ready!(sleep.as_mut().poll(cx));
            self.sleep = None;
            Poll::Ready(self.chunks.pop_front().map(|c| Ok(Frame::data(c))))
        }
    }

    /// Splits `data` into chunks of varying sizes.
    pub fn split(data: &[u8], seed: u64) -> VecDeque<Bytes> {
        let sizes = pseudo_random(64, seed);
        let mut out = VecDeque::new();
        let mut i = 0;
        let mut k = 0;
        while i < data.len() {
            let n = (sizes[k % sizes.len()] as usize * 997 + 1).min(data.len() - i);
            out.push_back(Bytes::copy_from_slice(&data[i..i + n]));
            i += n;
            k += 1;
        }
        out
    }
}
