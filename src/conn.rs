//! Connection-level protection against clients that go quiet: ones that connect and send
//! nothing, and ones that stop reading what the server sends.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How long a new connection may stay silent before its first request bytes arrive. Later idle
/// periods between requests are covered by hyper's header read timeout.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a write may wait for the client to accept data before the connection is closed.
pub const WRITE_IDLE: Duration = Duration::from_secs(120);

/// Wraps a stream so that reads fail with `TimedOut` if nothing arrives before the first-byte
/// deadline (dropped once the first bytes are read), and writes fail with `TimedOut` if the
/// peer accepts nothing for `WRITE_IDLE`. Either error makes hyper close the connection, which
/// also ends whatever response was streaming.
pub struct FirstByteDeadline<T> {
    inner: T,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    write_stall: Option<Pin<Box<tokio::time::Sleep>>>,
    write_idle: Duration,
}

impl<T> FirstByteDeadline<T> {
    pub fn new(inner: T, timeout: Duration) -> Self {
        FirstByteDeadline {
            inner,
            deadline: Some(Box::pin(tokio::time::sleep(timeout))),
            write_stall: None,
            write_idle: WRITE_IDLE,
        }
    }

    #[cfg(test)]
    fn with_write_idle(mut self, d: Duration) -> Self {
        self.write_idle = d;
        self
    }

    /// Track a write attempt: progress clears the stall timer; waiting arms it and fails once
    /// it runs out.
    fn write_progress<R>(&mut self, cx: &mut Context<'_>, r: Poll<io::Result<R>>) -> Poll<io::Result<R>> {
        match r {
            Poll::Ready(r) => {
                self.write_stall = None;
                Poll::Ready(r)
            }
            Poll::Pending => {
                let idle = self.write_idle;
                let stall = self.write_stall.get_or_insert_with(|| Box::pin(tokio::time::sleep(idle)));
                if stall.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "the client stopped reading")));
                }
                Poll::Pending
            }
        }
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
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.write_progress(cx, r)
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.write_progress(cx, r)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_flush(cx);
        self.write_progress(cx, r)
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

    #[tokio::test]
    async fn peers_that_stop_reading_time_out() {
        let (a, mut b) = tokio::io::duplex(1024);
        let mut s = FirstByteDeadline::new(a, Duration::from_secs(5)).with_write_idle(Duration::from_millis(50));
        // The peer reads nothing: once the pipe is full, writes stall and then fail.
        let chunk = [0u8; 512];
        let err = loop {
            match s.write(&chunk).await {
                Ok(_) => continue,
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // A peer that keeps reading, however slowly, is fine.
        let (a, mut b2) = tokio::io::duplex(1024);
        let mut s = FirstByteDeadline::new(a, Duration::from_secs(5)).with_write_idle(Duration::from_millis(100));
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            for _ in 0..40 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if b2.read(&mut buf).await.unwrap() == 0 {
                    break;
                }
            }
        });
        for _ in 0..10 {
            s.write_all(&chunk).await.unwrap();
        }
        drop(s);
        reader.await.unwrap();
        let mut sink = [0u8; 16];
        let _ = b.read(&mut sink).await;
    }
}
