//! A complete body held in memory.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::sync::SemaphorePermit;

use crate::proto::{BoxError, ProtoError};

/// Chunks smaller than this are copied into shared blocks, so tiny frames do not each keep a
/// receive buffer (and a queue entry) alive.
const SMALL_CHUNK: usize = 4 * 1024;
const BLOCK: usize = 64 * 1024;

/// A body kept as the chunks it arrived in (small ones gathered into blocks), so buffering it
/// needs no copy into one contiguous buffer.
pub struct ChunkList {
    chunks: VecDeque<Bytes>,
    /// Bytes not yet handed out.
    len: u64,
    /// The buffer slot this body occupies until it has been sent (or dropped).
    _slot: SemaphorePermit<'static>,
}

impl ChunkList {
    /// Reads all of `body` (trailers are dropped), failing once it exceeds `limit` bytes.
    pub async fn read<B>(mut body: B, limit: u64, slot: SemaphorePermit<'static>) -> Result<Self, BoxError>
    where
        B: Body<Data = Bytes> + Unpin,
        B::Error: Into<BoxError>,
    {
        let mut list = Self { chunks: VecDeque::new(), len: 0, _slot: slot };
        let mut block = BytesMut::new();
        while let Some(frame) = body.frame().await {
            let Ok(data) = frame.map_err(Into::into)?.into_data() else { continue };
            list.len += data.len() as u64;
            if list.len > limit {
                return Err(ProtoError("body exceeds the buffer limit").into());
            }
            if data.len() >= SMALL_CHUNK {
                list.push(std::mem::take(&mut block));
                list.chunks.push_back(data);
            } else {
                if block.capacity() - block.len() < data.len() {
                    list.push(std::mem::replace(&mut block, BytesMut::with_capacity(BLOCK)));
                }
                block.extend_from_slice(&data);
            }
        }
        list.push(block);
        Ok(list)
    }

    fn push(&mut self, block: BytesMut) {
        if !block.is_empty() {
            self.chunks.push_back(block.freeze());
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }
}

impl Body for ChunkList {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        Poll::Ready(this.chunks.pop_front().map(|data| {
            this.len -= data.len() as u64;
            Ok(Frame::data(data))
        }))
    }

    fn is_end_stream(&self) -> bool {
        self.chunks.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::test_util::Chunks;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn keeps_chunks_and_its_slot() {
        let slots: &'static Semaphore = crate::util::leak(Semaphore::new(2));
        // Chunks of SMALL_CHUNK bytes or more are kept as they are.
        let chunks = || Chunks { chunks: (0..3).map(|i| Bytes::from(vec![i; 5000])).collect(), exact: None };
        let mut list = ChunkList::read(chunks(), 15_000, slots.try_acquire().unwrap()).await.unwrap();
        assert_eq!((list.len(), list.size_hint().exact()), (15_000, Some(15_000)));
        let first = list.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!((first.len(), list.size_hint().exact()), (5000, Some(10_000)));
        assert!(ChunkList::read(chunks(), 14_999, slots.try_acquire().unwrap()).await.is_err());
        assert_eq!(slots.available_permits(), 1, "held until the body is dropped");
        drop(list);
        assert_eq!(slots.available_permits(), 2);
    }

    #[tokio::test]
    async fn tiny_chunks_are_gathered_into_blocks() {
        let slots: &'static Semaphore = crate::util::leak(Semaphore::new(1));
        let data: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        let tiny = Chunks { chunks: data.iter().map(|&b| Bytes::copy_from_slice(&[b])).collect(), exact: None };
        let list = ChunkList::read(tiny, 1 << 20, slots.try_acquire().unwrap()).await.unwrap();
        assert_eq!(list.chunks.len(), 2, "100 000 one-byte chunks in 64 KiB blocks");
        assert_eq!(list.collect().await.unwrap().to_bytes(), data);
    }
}
