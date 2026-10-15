//! Connection-level protection against clients that connect and then send nothing.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How long a new connection may stay silent before its first request bytes arrive. Later idle
/// periods between requests are covered by hyper's header read timeout.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);

/// Wraps a stream so that reads fail with `TimedOut` if nothing arrives before the deadline.
/// The deadline is dropped once the first bytes are read.
pub struct FirstByteDeadline<T> {
    inner: T,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<T> FirstByteDeadline<T> {
    pub fn new(inner: T, timeout: Duration) -> Self {
        FirstByteDeadline { inner, deadline: Some(Box::pin(tokio::time::sleep(timeout))) }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FirstByteDeadline<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(r) => {
                if buf.filled().len() > before {
                    this.deadline = None;
                }
                Poll::Ready(r)
            }
            Poll::Pending => {
                if let Some(d) = &mut this.deadline
                    && d.as_mut().poll(cx).is_ready()
                {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "no request received")));
                }
                Poll::Pending
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FirstByteDeadline<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn silent_peers_time_out_and_talking_ones_do_not() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut s = FirstByteDeadline::new(a, Duration::from_millis(50));
        let mut buf = [0u8; 4];
        let e = s.read(&mut buf).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);

        let (a, mut b2) = tokio::io::duplex(64);
        let mut s = FirstByteDeadline::new(a, Duration::from_millis(50));
        b2.write_all(b"GET ").await.unwrap();
        assert_eq!(s.read(&mut buf).await.unwrap(), 4);
        // After the first bytes, waiting longer than the deadline is fine.
        let late = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            b2.write_all(b"/ HT").await.unwrap();
            b2
        });
        assert_eq!(s.read(&mut buf).await.unwrap(), 4);
        drop(late.await);
        b.shutdown().await.unwrap();
    }
}
