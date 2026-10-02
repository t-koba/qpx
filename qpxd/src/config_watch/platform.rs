use anyhow::Result;
use notify::Watcher;
use std::path::Path;

pub(crate) struct ConfigFileWatcher {
    receiver: tokio::sync::mpsc::Receiver<notify::Result<notify::Event>>,
    watcher: notify::RecommendedWatcher,
}

impl ConfigFileWatcher {
    pub(crate) fn new() -> Result<Self> {
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let watcher = notify::recommended_watcher(move |event| {
            // Receiver shutdown means the owning control loop has stopped.
            let _ = sender.blocking_send(event);
        })?;
        Ok(Self { receiver, watcher })
    }

    pub(crate) fn watch(&mut self, path: &Path) -> Result<()> {
        self.watcher
            .watch(path, notify::RecursiveMode::NonRecursive)?;
        Ok(())
    }

    pub(crate) fn unwatch(&mut self, path: &Path) -> Result<()> {
        if let Err(error) = self.watcher.unwatch(path) {
            // Atomic replacement may already have removed the native watch.
            if !matches!(error.kind, notify::ErrorKind::WatchNotFound) {
                return Err(error.into());
            }
        }
        Ok(())
    }

    pub(crate) async fn next_event(&mut self) -> Option<notify::Result<notify::Event>> {
        self.receiver.recv().await
    }
}
