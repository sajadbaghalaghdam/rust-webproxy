//! Progress of an outgoing request body, so callers can bound how long sending may stall
//! and start answer timeouts only once the request has been sent completely.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use http_body::{Body, Frame, SizeHint};
use tokio::sync::Notify;
use tokio::time::Instant;

/// Shared view of how far a request body has been sent.
pub struct SendProgress {
    started: Instant,
    /// Milliseconds after `started` of the last frame handed to the connection.
    last_ms: AtomicU64,
    done: AtomicBool,
    finished: Notify,
}

impl SendProgress {
    /// Time since the body last produced a frame (or since it was created).
    pub fn idle_for(&self) -> Duration {
        let last = self.started + Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        last.elapsed()
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Resolves once the body has been sent completely, failed or been dropped.
    pub async fn finished(&self) {
        loop {
            // Registered before the check, so a concurrent `finish` cannot be missed.
            let notified = self.finished.notified();
            if self.is_done() {
                return;
            }
            notified.await;
        }
    }

    fn touch(&self) {
        self.last_ms.store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn finish(&self) {
        if !self.done.swap(true, Ordering::AcqRel) {
            self.finished.notify_waiters();
        }
    }
}

/// Body wrapper that reports its progress to a [`SendProgress`].
pub struct ProgressBody<B> {
    inner: B,
    progress: Arc<SendProgress>,
}

impl<B> ProgressBody<B> {
    pub fn new(inner: B) -> (Self, Arc<SendProgress>) {
        let progress = Arc::new(SendProgress {
            started: Instant::now(),
            last_ms: AtomicU64::new(0),
            done: AtomicBool::new(false),
            finished: Notify::new(),
        });
        (Self { inner, progress: Arc::clone(&progress) }, progress)
    }
}

impl<B: Body + Unpin> Body for ProgressBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
        let this = self.get_mut();
        let frame = ready!(Pin::new(&mut this.inner).poll_frame(cx));
        this.progress.touch();
        if matches!(frame, None | Some(Err(_))) || this.inner.is_end_stream() {
            this.progress.finish();
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for ProgressBody<B> {
    fn drop(&mut self) {
        // A dropped body will not send anything more.
        self.progress.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};

    #[tokio::test]
    async fn reports_completion_and_drop() {
        let (body, progress) = ProgressBody::new(Full::new(Bytes::from_static(b"x")));
        assert!(!progress.is_done());
        assert_eq!(&body.collect().await.unwrap().to_bytes()[..], b"x");
        progress.finished().await;

        let (body, progress) = ProgressBody::new(Full::new(Bytes::from_static(b"y")));
        drop(body);
        assert!(progress.is_done());
    }
}
