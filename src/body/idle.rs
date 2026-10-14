//! Inactivity deadline for streamed bodies.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame};
use tokio::time::{Instant, Sleep};

use crate::proto::{BoxError, ProtoError};

const IDLE_TIMEOUT: ProtoError = ProtoError("stream idle timeout");

/// True if `err` is the error of an expired idle timer.
pub(super) fn is_idle_timeout(err: &(dyn std::error::Error + 'static)) -> bool {
    err.downcast_ref::<ProtoError>() == Some(&IDLE_TIMEOUT)
}

/// Deadline that is only re-armed when the stream actually waits, not on every chunk.
pub(super) struct IdleTimer {
    limit: Duration,
    last_progress: Instant,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl IdleTimer {
    pub(super) fn new(limit: Option<Duration>) -> Option<Self> {
        limit.map(|limit| Self { limit, last_progress: Instant::now(), sleep: None })
    }

    fn progress(&mut self) {
        self.last_progress = Instant::now();
    }

    /// Called when the inner stream is pending; `Ready` once it has been idle for too long.
    fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let deadline = self.last_progress + self.limit;
        match &mut self.sleep {
            Some(sleep) if sleep.deadline() == deadline => {}
            Some(sleep) => sleep.as_mut().reset(deadline),
            None => self.sleep = Some(Box::pin(tokio::time::sleep_until(deadline))),
        }
        self.sleep.as_mut().expect("armed above").as_mut().poll(cx)
    }
}

/// Polls `inner` for the next frame, failing it when it stays idle beyond the timer.
pub(super) fn poll_with_idle<B>(
    inner: &mut B,
    idle: &mut Option<IdleTimer>,
    cx: &mut Context<'_>,
) -> Poll<Option<Result<Frame<Bytes>, BoxError>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    match Pin::new(inner).poll_frame(cx) {
        Poll::Ready(frame) => {
            if let Some(t) = idle {
                t.progress();
            }
            Poll::Ready(frame.map(|f| f.map_err(Into::into)))
        }
        Poll::Pending => match idle.as_mut().map(|t| t.poll_expired(cx)) {
            Some(Poll::Ready(())) => Poll::Ready(Some(Err(IDLE_TIMEOUT.into()))),
            _ => Poll::Pending,
        },
    }
}
