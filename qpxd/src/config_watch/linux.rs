use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use inotify::{EventMask, EventStream, Inotify, WatchDescriptor, WatchMask};
use notify::event::{EventKind, Flag};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub(crate) struct ConfigFileWatcher {
    inotify: Inotify,
    events: EventStream<Vec<u8>>,
    watches: HashMap<PathBuf, WatchDescriptor>,
}

impl ConfigFileWatcher {
    pub(crate) fn new() -> Result<Self> {
        let mut inotify = Inotify::init()?;
        // Register the existing inotify descriptor with the process runtime.
        // No additional poller, wake descriptor, or watcher thread is needed.
        let events = inotify.event_stream(vec![0; 4096])?;
        Ok(Self {
            inotify,
            events,
            watches: HashMap::new(),
        })
    }

    pub(crate) fn watch(&mut self, path: &Path) -> Result<()> {
        let mask = WatchMask::ATTRIB
            | WatchMask::CREATE
            | WatchMask::DELETE
            | WatchMask::CLOSE_WRITE
            | WatchMask::MODIFY
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO
            | WatchMask::DELETE_SELF
            | WatchMask::MOVE_SELF;
        let descriptor = self.inotify.add_watch(path, mask)?;
        self.watches.insert(path.to_path_buf(), descriptor);
        Ok(())
    }

    pub(crate) fn unwatch(&mut self, path: &Path) -> Result<()> {
        let descriptor = self
            .watches
            .remove(path)
            .ok_or_else(|| anyhow!("configuration path is not watched: {}", path.display()))?;
        // Different source paths can name the same inode. Keep its watch while
        // another source still owns the descriptor.
        if !self.watches.values().any(|other| *other == descriptor) {
            if let Err(error) = self.inotify.rm_watch(descriptor) {
                // Atomic replacement can already have removed the inode watch.
                if error.raw_os_error() != Some(libc::EINVAL) {
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn next_event(&mut self) -> Option<notify::Result<notify::Event>> {
        loop {
            match self.events.next().await? {
                Err(error) => return Some(Err(notify::Error::io(error))),
                Ok(event) if event.mask.contains(EventMask::Q_OVERFLOW) => {
                    // Overflow requires a complete configuration reload and
                    // fresh watches instead of assuming no change occurred.
                    return Some(Ok(
                        notify::Event::new(EventKind::Other).set_flag(Flag::Rescan)
                    ));
                }
                Ok(event) => {
                    let paths: Vec<_> = self
                        .watches
                        .iter()
                        .filter(|(_, descriptor)| **descriptor == event.wd)
                        .map(|(path, _)| path.clone())
                        .collect();
                    // Explicit unwatch queues an IGNORED event for the old
                    // descriptor. It must not retrigger reload after refresh.
                    if paths.is_empty() {
                        continue;
                    }
                    let mut notification = notify::Event::new(EventKind::Any);
                    notification.paths = paths;
                    return Some(Ok(notification));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn change_event(watcher: &mut ConfigFileWatcher) -> notify::Event {
        tokio::time::timeout(Duration::from_secs(5), watcher.next_event())
            .await
            .expect("configuration event deadline")
            .expect("configuration event stream")
            .expect("configuration change event")
    }

    async fn drain(watcher: &mut ConfigFileWatcher) {
        while tokio::time::timeout(Duration::from_millis(20), watcher.next_event())
            .await
            .is_ok()
        {}
    }

    #[tokio::test]
    async fn real_file_writes_atomic_replacement_and_rewatch_are_detected() {
        let directory = tempfile::tempdir().expect("real configuration directory");
        let path = directory.path().join("config.yaml");
        std::fs::write(&path, "revision: 1").expect("initial configuration");
        let mut watcher = ConfigFileWatcher::new().expect("runtime configuration watcher");
        watcher.watch(&path).expect("watch configuration");
        std::fs::write(&path, "revision: 2").expect("update configuration");
        assert!(change_event(&mut watcher).await.paths.contains(&path));
        drain(&mut watcher).await;
        let replacement = directory.path().join("replacement.yaml");
        std::fs::write(&replacement, "revision: 3").expect("replacement configuration");
        std::fs::rename(&replacement, &path).expect("atomic configuration replacement");
        assert!(change_event(&mut watcher).await.paths.contains(&path));
        // The old inode watch may already have been removed by the kernel.
        watcher.unwatch(&path).expect("remove replaced inode watch");
        watcher.watch(&path).expect("watch replacement inode");
        drain(&mut watcher).await;
        std::fs::write(&path, "revision: 4").expect("update replacement configuration");
        assert!(change_event(&mut watcher).await.paths.contains(&path));
        watcher
            .unwatch(&path)
            .expect("remove live configuration watch");
        drain(&mut watcher).await;
        std::fs::write(&path, "revision: 5").expect("update unwatched configuration");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), watcher.next_event())
                .await
                .is_err()
        );
    }
}
