//! Bounded, fail-closed durable logging without filesystem waits on async workers.
use std::{
    fs::File,
    io::{self, Write},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc as sync_mpsc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

const CAPACITY: usize = 32;
const DEADLINE: Duration = Duration::from_secs(5);
const MAX_RECORD_BYTES: usize = 64 * 1024;
type Outcome = Result<(), &'static str>;

/// The lock outlives the gateway if a cancelled write still owns custody.
struct StateLock(File);
impl Drop for StateLock {
    fn drop(&mut self) {
        // SAFETY: this is the final owner of the still-live descriptor.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

enum Acknowledgment {
    Async(oneshot::Sender<Outcome>),
    Blocking(sync_mpsc::SyncSender<Outcome>),
}
impl Acknowledgment {
    fn cancelled(&self) -> bool {
        matches!(self, Self::Async(sender) if sender.is_closed())
    }
    fn send(self, result: Outcome) {
        match self {
            Self::Async(sender) => {
                let _ = sender.send(result);
            }
            Self::Blocking(sender) => {
                let _ = sender.send(result);
            }
        }
    }
}
struct Record {
    bytes: Vec<u8>,
    acknowledgment: Acknowledgment,
    custody: Option<Arc<StateLock>>,
}

pub(crate) struct AuditWriter {
    sender: mpsc::Sender<Record>,
    failed: Arc<AtomicBool>,
    custody: Option<Arc<StateLock>>,
    deadline: Duration,
}
impl AuditWriter {
    pub(crate) fn new(mut file: File, state_lock: File) -> Result<Self, String> {
        Self::start(
            move |bytes| {
                file.write_all(bytes)?;
                file.sync_data()
            },
            Some(Arc::new(StateLock(state_lock))),
            CAPACITY,
            DEADLINE,
        )
    }
    fn start(
        mut persist: impl FnMut(&[u8]) -> io::Result<()> + Send + 'static,
        custody: Option<Arc<StateLock>>,
        capacity: usize,
        deadline: Duration,
    ) -> Result<Self, String> {
        let (sender, mut receiver) = mpsc::channel::<Record>(capacity);
        let failed = Arc::new(AtomicBool::new(false));
        let health = failed.clone();
        std::thread::Builder::new()
            .name("metrics-audit".into())
            .spawn(move || {
                while let Some(record) = receiver.blocking_recv() {
                    if record.acknowledgment.cancelled() {
                        continue;
                    }
                    let outcome = if health.load(Ordering::Acquire) {
                        Err("audit writer unavailable")
                    } else if persist(&record.bytes).is_err() {
                        // A partial append cannot be followed by another record as
                        // though the log were intact. Recovery requires an operator.
                        health.store(true, Ordering::Release);
                        Err("audit persistence failed")
                    } else {
                        Ok(())
                    };
                    drop(record.custody);
                    record.acknowledgment.send(outcome);
                }
            })
            .map_err(|_| "audit worker unavailable".to_string())?;
        Ok(Self {
            sender,
            failed,
            custody,
            deadline,
        })
    }
    fn submit(
        &self,
        record: &serde_json::Value,
        acknowledgment: Acknowledgment,
    ) -> Result<(), String> {
        if self.failed.load(Ordering::Acquire) {
            return Err("audit writer unavailable".into());
        }
        let mut bytes = serde_json::to_vec(record).map_err(|_| "audit encoding failed")?;
        if bytes.len() >= MAX_RECORD_BYTES {
            return Err("audit record exceeded limit".into());
        }
        bytes.push(b'\n');
        self.sender
            .try_send(Record {
                bytes,
                acknowledgment,
                custody: self.custody.clone(),
            })
            .map_err(|_| "audit writer unavailable or at capacity".into())
    }
    pub(crate) async fn append(&self, record: &serde_json::Value) -> Result<(), String> {
        let (sender, receiver) = oneshot::channel();
        self.submit(record, Acknowledgment::Async(sender))?;
        tokio::time::timeout(self.deadline, receiver)
            .await
            .map_err(|_| "audit acknowledgment timed out")?
            .map_err(|_| "audit worker stopped")?
            .map_err(str::to_owned)
    }
    /// For atomic organization transitions already running on a blocking worker.
    pub(crate) fn append_blocking(&self, record: &serde_json::Value) -> Result<(), String> {
        let (sender, receiver) = sync_mpsc::sync_channel(1);
        self.submit(record, Acknowledgment::Blocking(sender))?;
        receiver
            .recv_timeout(self.deadline)
            .map_err(|_| "audit acknowledgment unavailable or timed out")?
            .map_err(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn slow_storage_does_not_block_runtime_and_saturation_fails_closed() {
        let (entered, seen) = sync_mpsc::sync_channel(1);
        let (release, gate) = sync_mpsc::sync_channel(1);
        let writer = AuditWriter::start(
            move |_| {
                let _ = entered.try_send(());
                gate.recv().map_err(io::Error::other)
            },
            None,
            1,
            Duration::from_millis(100),
        )
        .unwrap();
        let first_record = json!({"record":1});
        let first = writer.append(&first_record);
        tokio::pin!(first);
        tokio::select! {
            _ = &mut first => panic!("storage has not acknowledged"),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {},
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while seen.try_recv().is_err() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let (ack, receiver) = oneshot::channel();
        writer
            .submit(&json!({"record":2}), Acknowledgment::Async(ack))
            .unwrap();
        assert!(
            writer
                .append(&json!({"record":3}))
                .await
                .unwrap_err()
                .contains("capacity")
        );
        assert!(first.await.unwrap_err().contains("timed out"));
        // A canceled queued record is skipped; only the running write needs release.
        drop(receiver);
        release.send(()).unwrap();
    }

    #[tokio::test]
    async fn failed_persistence_is_never_acknowledged_or_followed_by_more_writes() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let writer = AuditWriter::start(
            move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("injected storage failure"))
            },
            None,
            2,
            DEADLINE,
        )
        .unwrap();
        assert!(writer.append(&json!({"record":1})).await.is_err());
        assert!(writer.append(&json!({"record":2})).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelled_in_progress_write_keeps_state_custody_until_io_finishes() {
        let path =
            std::env::temp_dir().join(format!("metrics-audit-lock-{}", uuid::Uuid::new_v4()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        // SAFETY: each flock receives a live, privately owned file descriptor.
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let (entered, seen) = sync_mpsc::sync_channel(1);
        let (release, gate) = sync_mpsc::sync_channel(1);
        let writer = AuditWriter::start(
            move |_| {
                entered.send(()).unwrap();
                gate.recv().map_err(io::Error::other)
            },
            Some(Arc::new(StateLock(file))),
            1,
            DEADLINE,
        )
        .unwrap();
        let (acknowledgment, receipt) = oneshot::channel();
        writer
            .submit(&json!({"record":1}), Acknowledgment::Async(acknowledgment))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while seen.try_recv().is_err() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        drop(receipt);
        drop(writer);
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_ne!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        drop(contender);
        std::fs::remove_file(path).unwrap();
    }
}
