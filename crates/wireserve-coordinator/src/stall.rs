//! Closing a connection whose writes have stopped moving.
//!
//! Nothing else bounds how long a response may take to send: a reader that
//! stops reading, or a node that vanished without closing its connection,
//! would keep what is being sent to it (a whole directory, and its turn among
//! the few sent at once) for as long as TCP keeps the connection up, which is
//! as long as the other end answers its probes. A write that has been waiting
//! for [`WRITE_STALL`] fails instead, and the connection is closed. Reading is
//! left alone: an agent's connection sits idle between polls by design.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Sleep;

/// How long a write may wait for the other end to take any of it.
pub const WRITE_STALL: Duration = Duration::from_secs(30);

/// A listener whose connections are [`Guarded`].
pub struct StallGuarded(pub TcpListener);

impl axum::serve::Listener for StallGuarded {
    type Io = Guarded<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (io, addr) = axum::serve::Listener::accept(&mut self.0).await;
        (Guarded::new(io, WRITE_STALL), addr)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

/// A connection whose writes fail once they have waited for `limit`.
pub struct Guarded<T> {
    inner: T,
    limit: Duration,
    /// Running while a write is waiting; gone once one goes through.
    waiting: Option<Pin<Box<Sleep>>>,
}

impl<T> Guarded<T> {
    pub fn new(inner: T, limit: Duration) -> Self {
        Self { inner, limit, waiting: None }
    }

    /// What a write that went through or is still waiting comes to.
    fn watch<R>(&mut self, cx: &mut Context<'_>, result: Poll<io::Result<R>>) -> Poll<io::Result<R>> {
        if result.is_ready() {
            self.waiting = None;
            return result;
        }
        let limit = self.limit;
        let timer = self.waiting.get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)));
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "the other end stopped reading")));
        }
        Poll::Pending
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Guarded<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Guarded<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.watch(cx, result)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.watch(cx, result)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        self.watch(cx, result)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.watch(cx, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_write_nobody_reads_fails_once_it_has_waited_long_enough() {
        let (near, _far) = tokio::io::duplex(16);
        let mut guarded = Guarded::new(near, Duration::from_millis(50));
        let err = guarded.write_all(&[0; 1024]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_slow_reader_that_keeps_reading_is_never_cut_off() {
        let (near, mut far) = tokio::io::duplex(16);
        let reader = tokio::spawn(async move {
            let mut got = 0;
            let mut buf = [0; 16];
            while got < 256 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                got += far.read(&mut buf).await.unwrap();
            }
        });
        // Each write waits on the reader, never for as long as the limit.
        let mut guarded = Guarded::new(near, Duration::from_millis(40));
        guarded.write_all(&[0; 256]).await.unwrap();
        reader.await.unwrap();
    }

    #[tokio::test]
    async fn an_idle_connection_is_left_alone() {
        let (near, mut far) = tokio::io::duplex(16);
        let mut guarded = Guarded::new(near, Duration::from_millis(20));
        tokio::time::sleep(Duration::from_millis(60)).await;
        far.write_all(b"hi").await.unwrap();
        let mut buf = [0; 2];
        guarded.read_exact(&mut buf).await.unwrap();
        guarded.write_all(b"ok").await.unwrap();
    }
}
