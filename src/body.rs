//! Response body type: empty, a single buffer, or a stream fed by a blocking reader thread.

use bytes::Bytes;
use http_body::{Frame, SizeHint};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

pub enum Body {
    Empty,
    Full(Option<Bytes>),
    Stream { rx: mpsc::Receiver<io::Result<Bytes>>, remaining: u64 },
}

impl Body {
    pub fn full(b: impl Into<Bytes>) -> Self {
        let b = b.into();
        if b.is_empty() { Body::Empty } else { Body::Full(Some(b)) }
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match &mut *self {
            Body::Empty => Poll::Ready(None),
            Body::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Body::Stream { rx, remaining } => match rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(b))) => {
                    *remaining = remaining.saturating_sub(b.len() as u64);
                    Poll::Ready(Some(Ok(Frame::data(b))))
                }
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
                Poll::Ready(None) if *remaining > 0 => {
                    Poll::Ready(Some(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "object data ended early"))))
                }
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Body::Empty => true,
            Body::Full(b) => b.is_none(),
            Body::Stream { remaining, .. } => *remaining == 0,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Body::Empty => SizeHint::with_exact(0),
            Body::Full(b) => SizeHint::with_exact(b.as_ref().map_or(0, |b| b.len() as u64)),
            Body::Stream { remaining, .. } => SizeHint::with_exact(*remaining),
        }
    }
}
