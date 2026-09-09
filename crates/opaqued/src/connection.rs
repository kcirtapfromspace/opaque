//! Owned connection accounting and bounded IPC transport stages.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::{Sink, SinkExt, StreamExt};
use tokio::net::UnixStream;
use tokio::sync::{OwnedSemaphorePermit, watch};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Guard {
    counter: Arc<AtomicUsize>,
    _permit: OwnedSemaphorePermit,
}

impl Guard {
    pub fn new(counter: Arc<AtomicUsize>, permit: OwnedSemaphorePermit) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self {
            counter,
            _permit: permit,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

pub async fn read_handshake(
    framed: &mut Framed<UnixStream, LengthDelimitedCodec>,
    shutdown: &mut watch::Receiver<bool>,
) -> io::Result<Option<BytesMut>> {
    if *shutdown.borrow() {
        return Ok(None);
    }
    tokio::select! {
        biased;
        _ = shutdown.changed() => Ok(None),
        result = tokio::time::timeout(HANDSHAKE_TIMEOUT, framed.next()) => {
            result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
                .transpose()
        }
    }
}

pub async fn send<S>(sink: &mut S, bytes: Bytes) -> io::Result<()>
where
    S: Sink<Bytes, Error = io::Error> + Unpin,
{
    tokio::time::timeout(WRITE_TIMEOUT, sink.send(bytes))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "response write timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    struct BackpressuredSink {
        ready: bool,
    }
    impl Sink<Bytes> for BackpressuredSink {
        type Error = io::Error;
        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if self.ready {
                std::task::Poll::Ready(Ok(()))
            } else {
                std::task::Poll::Pending
            }
        }
        fn start_send(self: std::pin::Pin<&mut Self>, _: Bytes) -> io::Result<()> {
            Ok(())
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn response_deadline_bounds_both_sink_readiness_and_flush() {
        for ready in [false, true] {
            let started = tokio::time::Instant::now();
            let error = send(
                &mut BackpressuredSink { ready },
                Bytes::from_static(b"response"),
            )
            .await
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(started.elapsed(), WRITE_TIMEOUT);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn incomplete_handshakes_have_one_deadline_for_the_entire_frame() {
        for prefix in [vec![], vec![0, 0], vec![0, 0, 0, 3, b'{']] {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.write_all(&prefix).await.unwrap();
            let (_tx, mut shutdown) = watch::channel(false);
            let mut framed = Framed::new(server, LengthDelimitedCodec::new());
            let result = read_handshake(&mut framed, &mut shutdown).await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        }
    }

    #[tokio::test]
    async fn shutdown_interrupts_partial_handshake_and_valid_frames_are_unchanged() {
        let (client, server) = UnixStream::pair().unwrap();
        let mut client = Framed::new(client, LengthDelimitedCodec::new());
        let mut server = Framed::new(server, LengthDelimitedCodec::new());
        let (tx, mut shutdown) = watch::channel(false);
        client.send(Bytes::from_static(b"hello")).await.unwrap();
        assert_eq!(
            read_handshake(&mut server, &mut shutdown)
                .await
                .unwrap()
                .unwrap(),
            &b"hello"[..]
        );
        let waiter = tokio::spawn(async move { read_handshake(&mut server, &mut shutdown).await });
        tx.send(true).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn all_capacity_and_accounting_return_after_cancellation_or_panic() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(64));
        let count = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..64 {
            let guard = Guard::new(
                count.clone(),
                semaphore.clone().try_acquire_owned().unwrap(),
            );
            tasks.push(tokio::spawn(async move {
                let _guard = guard;
                std::future::pending::<()>().await;
            }));
        }
        assert_eq!(count.load(Ordering::SeqCst), 64);
        assert!(semaphore.clone().try_acquire_owned().is_err());
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        let guard = Guard::new(
            count.clone(),
            semaphore.clone().try_acquire_owned().unwrap(),
        );
        let failed = tokio::spawn(async move {
            let _guard = guard;
            panic!("fixture failure");
        });
        assert!(failed.await.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(semaphore.available_permits(), 64);
    }
}
