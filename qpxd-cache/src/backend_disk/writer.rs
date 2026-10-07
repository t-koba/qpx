use anyhow::{Context, Result, anyhow};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use tokio::sync::mpsc;

type WriteTask = Box<dyn FnOnce() + Send>;

pub(super) struct DiskWriter {
    sender: Option<mpsc::Sender<WriteTask>>,
    workers: Vec<JoinHandle<()>>,
}

impl DiskWriter {
    pub(super) fn new(parallelism: usize) -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<WriteTask>(parallelism);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut writer = Self {
            sender: Some(sender),
            workers: Vec::with_capacity(parallelism),
        };
        for index in 0..parallelism {
            let receiver = receiver.clone();
            writer.workers.push(
                std::thread::Builder::new()
                    .name(format!("qpx-cache-writer-{index}"))
                    .spawn(move || {
                        loop {
                            // Release queue ownership before executing filesystem work.
                            let task = receiver
                                .lock()
                                .expect("cache writer queue poisoned")
                                .blocking_recv();
                            let Some(task) = task else { break };
                            task();
                        }
                    })
                    .context("failed to start disk cache writer")?,
            );
        }
        Ok(writer)
    }

    pub(super) async fn submit(&self, task: WriteTask) -> Result<()> {
        self.sender
            .as_ref()
            .expect("borrowed cache writer remains open")
            .send(task)
            .await
            .map_err(|_| anyhow!("disk cache writer queue closed"))
    }
}

impl Drop for DiskWriter {
    fn drop(&mut self) {
        // Closing admission drains all accepted work before backend shutdown.
        drop(self.sender.take());
        for worker in self.workers.drain(..) {
            if let Err(error) = worker.join() {
                tracing::error!(error = ?error, "disk cache writer panicked");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DiskWriter;

    #[tokio::test]
    async fn independent_filesystem_work_does_not_hold_queue_ownership() {
        let directory = super::super::tests::temp_dir("writer-parallel");
        let first_path = directory.join("first");
        let second_path = directory.join("second");
        let writer = DiskWriter::new(2).expect("create two writers");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        writer
            .submit(Box::new(move || {
                started_tx.send(()).expect("notify first writer start");
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("release first filesystem write");
                std::fs::write(first_path, b"first").expect("write first real file");
            }))
            .await
            .expect("accept first write");
        started_rx.await.expect("first writer starts");
        let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
        let output = second_path.clone();
        writer
            .submit(Box::new(move || {
                completed_tx
                    .send(std::fs::write(output, b"second"))
                    .expect("report independent filesystem result");
            }))
            .await
            .expect("accept independent write");
        tokio::time::timeout(std::time::Duration::from_secs(2), completed_rx)
            .await
            .expect("second write completes while first is paused")
            .expect("receive second result")
            .expect("write second real file");
        assert_eq!(
            std::fs::read(second_path).expect("read second file"),
            b"second"
        );
        release_tx.send(()).expect("release first writer");
        drop(writer);
        assert_eq!(
            std::fs::read(directory.join("first")).expect("read first file"),
            b"first"
        );
        std::fs::remove_dir_all(directory).expect("remove filesystem fixture");
    }

    #[tokio::test]
    async fn shutdown_finishes_accepted_filesystem_work() {
        let directory = super::super::tests::temp_dir("writer-shutdown");
        let path = directory.join("completed");
        let output = path.clone();
        let writer = DiskWriter::new(1).expect("create writer");
        let (sender, receiver) = tokio::sync::oneshot::channel();
        writer
            .submit(Box::new(move || {
                sender
                    .send(std::fs::write(output, b"accepted filesystem work"))
                    .expect("report filesystem result");
            }))
            .await
            .expect("accept write");
        drop(writer);
        receiver
            .await
            .expect("writer completes before shutdown returns")
            .expect("write actual file");
        assert_eq!(
            std::fs::read(path).expect("read accepted write"),
            b"accepted filesystem work"
        );
        std::fs::remove_dir_all(directory).expect("remove filesystem fixture");
    }
}
