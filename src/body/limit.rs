//! `max_request_body_mb`: capping uploads without resetting the uploader's connection.

use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::time::Instant;

use crate::proto::BoxError;

/// Bytes of an over-limit upload that are still read and discarded, so the sender finishes
/// and sees the 413 answer instead of a reset connection (like nginx's lingering close).
const DRAIN_LIMIT: u64 = 64 << 20;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// A request body exceeded `max_request_body_mb` (see [`super::BodyFailure`]).
#[derive(Debug)]
pub(super) struct BodyTooLarge;

impl std::fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body too large")
    }
}

impl std::error::Error for BodyTooLarge {}

/// Reads and discards an unwanted body, within DRAIN_LIMIT / DRAIN_TIMEOUT.
pub async fn discard<B>(mut body: B)
where
    B: Body + Unpin,
{
    let drain = async {
        let mut left = DRAIN_LIMIT;
        while let Some(Ok(frame)) = body.frame().await {
            if let Some(data) = frame.data_ref() {
                match left.checked_sub(data.remaining() as u64) {
                    Some(l) => left = l,
                    None => return,
                }
            }
        }
    };
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, drain).await;
}

/// Passes a body through while it stays within `limit` bytes. Past the limit nothing more is
/// forwarded: the rest is drained (within DRAIN_LIMIT and the drain timeout) and the body then
/// fails with [`BodyTooLarge`].
pub struct CappedBody<B> {
    inner: B,
    remaining: u64,
    drain_timeout: Duration,
    /// Set once the limit was exceeded.
    drain: Option<Drain>,
}

struct Drain {
    bytes_left: u64,
    deadline: Instant,
}

impl<B> CappedBody<B> {
    /// `reader_idle`: the idle timeout of a reader that sees no progress while this body drains
    /// internally; the drain then ends well within it, so the 413 is not overtaken by a stall.
    pub fn new(inner: B, limit: Option<u64>, reader_idle: Option<Duration>) -> Self {
        let drain_timeout = reader_idle.map_or(DRAIN_TIMEOUT, |idle| (idle / 2).min(DRAIN_TIMEOUT));
        Self { inner, remaining: limit.unwrap_or(u64::MAX), drain_timeout, drain: None }
    }
}

impl<B> Body for CappedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        loop {
            let frame = match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => frame,
                Some(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
                None if this.drain.is_some() => return Poll::Ready(Some(Err(BodyTooLarge.into()))),
                None => return Poll::Ready(None),
            };
            let n = frame.data_ref().map_or(0, |d| d.len() as u64);
            match this.drain.as_mut() {
                Some(drain) => match drain.bytes_left.checked_sub(n) {
                    Some(left) if Instant::now() < drain.deadline => drain.bytes_left = left,
                    _ => return Poll::Ready(Some(Err(BodyTooLarge.into()))),
                },
                None if n > this.remaining => {
                    this.drain = Some(Drain { bytes_left: DRAIN_LIMIT, deadline: Instant::now() + this.drain_timeout });
                }
                None => {
                    this.remaining -= n;
                    return Poll::Ready(Some(Ok(frame)));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::test_util::{Chunks, Trickle};
    use crate::body::BodyFailure;

    #[tokio::test]
    async fn capped_body_drains_then_fails() {
        let chunks = || Chunks { chunks: (0..10).map(|_| Bytes::from(vec![1u8; 1000])).collect(), exact: None };
        let within = CappedBody::new(chunks(), Some(10_000), None).collect().await.unwrap().to_bytes();
        assert_eq!(within.len(), 10_000);
        let mut over = CappedBody::new(chunks(), Some(2_500), None);
        let mut forwarded = 0;
        let err = loop {
            match over.frame().await.unwrap() {
                Ok(frame) => forwarded += frame.into_data().unwrap().len(),
                Err(e) => break e,
            }
        };
        assert_eq!(forwarded, 2_000, "only whole chunks within the limit are forwarded");
        assert_eq!(BodyFailure::of(&*err), BodyFailure::TooLarge);
        assert!(over.inner.chunks.is_empty(), "the rest of the body was drained");
    }

    #[tokio::test(start_paused = true)]
    async fn slow_drains_end_within_the_reader_idle_timeout() {
        let every = Duration::from_secs(2);
        let trickle = Trickle { chunks: (0..100).map(|_| Bytes::from(vec![1u8; 1000])).collect(), every, sleep: None };
        let started = Instant::now();
        let mut over = CappedBody::new(trickle, Some(500), Some(Duration::from_secs(20)));
        let err = over.frame().await.unwrap().unwrap_err();
        assert_eq!(BodyFailure::of(&*err), BodyFailure::TooLarge);
        let took = started.elapsed();
        assert!(took >= Duration::from_secs(10) && took < Duration::from_secs(20), "{took:?}");
        assert!(!over.inner.chunks.is_empty(), "the drain gave up before the end");
    }
}
