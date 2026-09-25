use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};

pub struct Shutdown {
    requested: Arc<AtomicBool>,
    wake: Receiver<()>,
}

impl Shutdown {
    pub fn install() -> Result<Self, ctrlc::Error> {
        let requested = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&requested);
        let (sender, wake) = mpsc::sync_channel(1);
        ctrlc::set_handler(move || {
            flag.store(true, Ordering::SeqCst);
            let _ = sender.try_send(());
        })?;
        Ok(Self { requested, wake })
    }

    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    pub fn wait(&self, delay: Duration) -> io::Result<bool> {
        if self.requested() {
            return Ok(true);
        }
        match self.wake.recv_timeout(delay) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => Ok(self.requested()),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::Error::other("shutdown handler disconnected"))
            }
        }
    }
}

/// One bounded, serial publisher per stream. Never join a potentially blocked writer.
pub struct Publisher {
    name: &'static str,
    input: SyncSender<Vec<u8>>,
    completion: Receiver<io::Result<()>>,
    failed: bool,
}

impl Publisher {
    pub fn new(name: &'static str, mut sink: impl Write + Send + 'static) -> io::Result<Self> {
        let (input, requests) = mpsc::sync_channel::<Vec<u8>>(1);
        let (ack, completion) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name(format!("{name}-publisher"))
            .spawn(move || {
                while let Ok(bytes) = requests.recv() {
                    let result = sink.write_all(&bytes).and_then(|()| sink.flush());
                    let failed = result.is_err();
                    if ack.send(result).is_err() || failed {
                        break;
                    }
                }
            })?;
        Ok(Self {
            name,
            input,
            completion,
            failed: false,
        })
    }

    pub fn publish(
        &mut self,
        bytes: Vec<u8>,
        timeout: Duration,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other(format!(
                "{} publisher already failed",
                self.name
            )));
        }
        // Poison before enqueueing, so no error path can retry a stalled stream.
        self.failed = true;
        if cancelled() {
            return Err(self.error(io::ErrorKind::Interrupted));
        }
        let deadline = Instant::now() + timeout;
        self.input
            .try_send(bytes)
            .map_err(|error| io::Error::other(format!("{} publication: {error}", self.name)))?;
        loop {
            // An acknowledged write+flush is successful even if a signal just arrived.
            let result = match self.completion.try_recv() {
                Ok(result) => result,
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(self.error(io::ErrorKind::BrokenPipe));
                }
                Err(mpsc::TryRecvError::Empty) => {
                    if cancelled() {
                        return Err(self.error(io::ErrorKind::Interrupted));
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(self.error(io::ErrorKind::TimedOut));
                    }
                    match self
                        .completion
                        .recv_timeout(remaining.min(Duration::from_millis(20)))
                    {
                        Ok(result) => result,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Err(self.error(io::ErrorKind::BrokenPipe));
                        }
                    }
                }
            };
            result.map_err(|error| {
                io::Error::new(error.kind(), format!("{} publication: {error}", self.name))
            })?;
            self.failed = false;
            return Ok(());
        }
    }

    fn error(&self, kind: io::ErrorKind) -> io::Error {
        io::Error::new(
            kind,
            format!("{} publication did not complete: {kind}", self.name),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct GatedSink {
        entered: SyncSender<()>,
        release: Receiver<()>,
        exited: SyncSender<()>,
        block_flush: bool,
    }

    impl GatedSink {
        fn block(&self) {
            self.entered.send(()).unwrap();
            self.release.recv().unwrap();
        }
    }

    impl Write for GatedSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.block_flush {
                self.block();
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.block_flush {
                self.block();
            }
            Ok(())
        }
    }

    impl Drop for GatedSink {
        fn drop(&mut self) {
            self.exited.send(()).unwrap();
        }
    }

    #[test]
    fn stalled_write_and_flush_time_out_and_cannot_be_retried() {
        for block_flush in [false, true] {
            let (entered_tx, entered) = mpsc::sync_channel(1);
            let (release, release_rx) = mpsc::sync_channel(1);
            let (exited_tx, exited) = mpsc::sync_channel(1);
            let mut publisher = Publisher::new(
                "fake",
                GatedSink {
                    entered: entered_tx,
                    release: release_rx,
                    exited: exited_tx,
                    block_flush,
                },
            )
            .unwrap();
            let started = Instant::now();
            let result = publisher.publish(vec![1], Duration::from_millis(100), || false);
            entered.recv_timeout(Duration::from_secs(2)).unwrap();
            let retry_started = Instant::now();
            let retry = publisher.publish(vec![2], Duration::from_secs(10), || false);
            let retry_elapsed = retry_started.elapsed();
            release.send(()).unwrap();
            drop(publisher);
            exited.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert!(started.elapsed() < Duration::from_secs(2));
            assert!(retry.is_err());
            assert!(retry_elapsed < Duration::from_millis(100));
        }
    }

    #[test]
    fn shutdown_is_sticky_across_waits_and_publication() {
        let (sender, wake) = mpsc::sync_channel(1);
        let shutdown = Shutdown {
            requested: Arc::new(AtomicBool::new(true)),
            wake,
        };
        sender.send(()).unwrap();
        assert!(shutdown.wait(Duration::ZERO).unwrap());
        assert!(shutdown.wait(Duration::from_secs(60)).unwrap());
        let mut publisher = Publisher::new("fake", io::sink()).unwrap();
        assert_eq!(
            publisher
                .publish(vec![1], Duration::from_secs(10), || shutdown.requested())
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert!(shutdown.requested());
    }

    #[test]
    fn interrupt_cancels_an_unacknowledged_write() {
        let (entered_tx, entered) = mpsc::sync_channel(1);
        let (release, release_rx) = mpsc::sync_channel(1);
        let (exited_tx, exited) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        let interrupt = thread::spawn(move || {
            entered.recv_timeout(Duration::from_secs(2)).unwrap();
            flag.store(true, Ordering::SeqCst);
        });
        let mut publisher = Publisher::new(
            "fake",
            GatedSink {
                entered: entered_tx,
                release: release_rx,
                exited: exited_tx,
                block_flush: false,
            },
        )
        .unwrap();
        let started = Instant::now();
        let result = publisher.publish(vec![1], Duration::from_secs(10), || {
            cancelled.load(Ordering::SeqCst)
        });
        release.send(()).unwrap();
        drop(publisher);
        interrupt.join().unwrap();
        exited.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn worker_errors_and_flush_failures_are_propagated() {
        struct BrokenSink(bool);
        impl Write for BrokenSink {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.0 {
                    Ok(bytes.len())
                } else {
                    Err(io::ErrorKind::BrokenPipe.into())
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        for flush_only in [false, true] {
            let mut publisher = Publisher::new("fake", BrokenSink(flush_only)).unwrap();
            assert_eq!(
                publisher
                    .publish(vec![1], Duration::from_secs(1), || false)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
        }
        let mut publisher = Publisher::new("fake", io::sink()).unwrap();
        for _ in 0..10 {
            publisher
                .publish(vec![1], Duration::from_secs(1), || false)
                .unwrap();
        }
    }
}
