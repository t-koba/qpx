//! Stable advisory locks, separate from evictable cache objects. Never unlink a
//! lock file: replacing its inode would split coordination between processes.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub(super) struct CommitLocks {
    directory: File,
    stripes: usize,
    timeout: Duration,
}

impl CommitLocks {
    pub(super) fn new(root: &Path, stripes: usize, timeout: Duration) -> Result<Self> {
        let path = root.join(".qpx-commit-locks");
        ensure_private_dir(&path)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        check_private(&directory)?;
        let locks = Self {
            directory,
            stripes,
            timeout,
        };
        // Pin the stripe mapping for this root. A different count cannot silently
        // create an overlapping but incompatible locking domain. This small file
        // is lock state, not a cache-object format change.
        let mut layout = locks.open("stripes")?;
        layout
            .try_lock()
            .map_err(|e| anyhow!("disk commit lock setup: {e}"))?;
        let mut stored = String::new();
        layout.read_to_string(&mut stored)?;
        if stored.is_empty() {
            write!(layout, "{stripes}")?;
            layout.sync_all()?;
        } else if stored != stripes.to_string() {
            return Err(anyhow!(
                "disk commit_lock_stripes differs from this root's lock layout"
            ));
        }
        Ok(locks)
    }

    fn open(&self, name: &str) -> Result<File> {
        let name = std::ffi::CString::new(name)?;
        // SAFETY: directory is an owned directory fd and name is NUL-terminated.
        // openat anchors lookup to that fd even if the directory path is moved.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_CREAT
                    | libc::O_RDWR
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new descriptor, transferred exactly once.
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(anyhow!(
                "disk commit lock must be a regular file with exactly one link"
            ));
        }
        check_private(&file)?;
        Ok(file)
    }

    pub(super) async fn lock(&self, namespace: &str, primary: &str) -> Result<File> {
        // SHA-256 and this byte encoding are stable across processes/platforms;
        // never use the process-randomised Hash implementation for lock stripes.
        let mut hash = Sha256::new();
        hash.update((namespace.len() as u64).to_be_bytes());
        hash.update(namespace.as_bytes());
        hash.update(primary.as_bytes());
        let digest = hash.finalize();
        let mut prefix = [0; 8];
        prefix.copy_from_slice(&digest[..8]);
        let stripe = u64::from_be_bytes(prefix) % self.stripes as u64;
        self.lock_stripe(&format!("{stripe}.lock")).await
    }

    pub(super) async fn lock_object(&self, id: DiskCacheFileId) -> Result<File> {
        let mut prefix = [0; 8];
        prefix.copy_from_slice(&id.0[..8]);
        let stripe = u64::from_be_bytes(prefix) % self.stripes as u64;
        // Separate bounded lock domains: a primary may hash to the same stripe
        // as its object. Never acquire a primary while holding an object lock.
        self.lock_stripe(&format!("{stripe}.object.lock")).await
    }

    async fn lock_stripe(&self, name: &str) -> Result<File> {
        let file = self.open(name)?;
        // Only nonblocking OS calls: cancellation drops the fd immediately, not
        // a detached blocking lock waiter. Retry cadence scales with timeout.
        let retry_delay = (self.timeout / 64).max(Duration::from_millis(1));
        timeout(self.timeout, async {
            loop {
                match file.try_lock() {
                    Ok(()) => return Ok(file),
                    Err(std::fs::TryLockError::WouldBlock) => {
                        tokio::time::sleep(retry_delay).await;
                    }
                    Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
                }
            }
        })
        .await
        .map_err(|_| anyhow!("disk commit lock timed out"))?
    }
}

// Cache files are replaced by rename, never rewritten except for retirement.
// Include ctime at filesystem precision as well as device/inode so reuse of a
// deleted inode cannot make a stale per-instance eviction candidate current.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    device: u64,
    inode: u64,
    changed: (i64, i64),
}

impl FileIdentity {
    pub(super) fn of(meta: &fs::Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

fn check_private(file: &File) -> Result<()> {
    let meta = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(anyhow!(
            "disk commit lock state must be private to the current user"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    fn config(root: &Path) -> CacheBackendConfig {
        serde_json::from_value(serde_json::json!({
            "name": "shared", "kind": "disk", "path": root, "max_bytes": 8388608,
            "writer_mode": "shared", "commit_lock_stripes": 1, "timeout_ms": 32
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn independent_lock_contention_timeout_cancellation_and_layout_are_fail_closed() {
        let root = std::env::temp_dir().join(format!("qpx-shared-lock-{}", uuid::Uuid::new_v4()));
        let cfg = config(&root);
        let first = DiskCacheBackend::new(cfg.clone()).unwrap();
        let second = DiskCacheBackend::new(cfg.clone()).unwrap();
        let index_key = crate::vary::index_storage_key("primary");
        let index_bytes = br#"{"variants":[]}"#;
        first.put("ns", &index_key, index_bytes, 60).await.unwrap();
        let owner = first.lock_commit("ns", "primary").await.unwrap();
        let mut waiter = Box::pin(second.lock_commit("ns", "primary"));
        poll_fn(|cx| {
            assert!(waiter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(waiter); // cancellation must leave no blocking OS waiter behind
        let error = crate::invalidate::invalidate_primary(&second, "ns", "primary")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert_eq!(
            second
                .get("ns", &index_key)
                .await
                .unwrap()
                .unwrap()
                .as_ref(),
            index_bytes
        );
        drop(owner); // closes the lock fd, not its persistent inode
        drop(second.lock_commit("ns", "primary").await.unwrap());
        // A deletion error must not be reported as a successful invalidation.
        // Replacing the index with a directory gives a deterministic unlink
        // failure without depending on this test process's filesystem privileges.
        let index_path = second.path_for("ns", &index_key);
        fs::remove_file(&index_path).unwrap();
        fs::create_dir(&index_path).unwrap();
        assert!(
            crate::invalidate::invalidate_primary(&second, "ns", "primary")
                .await
                .is_err()
        );
        let mut mismatch = cfg.clone();
        mismatch.commit_lock_stripes = 2;
        assert!(
            DiskCacheBackend::new(mismatch)
                .err()
                .unwrap()
                .to_string()
                .contains("commit_lock_stripes")
        );
        mismatch = cfg;
        mismatch.commit_lock_stripes = 0;
        assert!(DiskCacheBackend::new(mismatch).is_err());
        // One layout file and bounded primary/object stripe domains, regardless
        // of how many different primary keys or object paths were locked.
        for primary in ["other", "third"] {
            drop(second.lock_commit("ns", primary).await.unwrap());
        }
        assert_eq!(
            fs::read_dir(root.join(".qpx-commit-locks"))
                .unwrap()
                .count(),
            3
        );
        drop((first, second));
        fs::remove_dir_all(root).unwrap();
    }

    fn foreground_backend(root: &Path) -> DiskCacheBackend {
        let cfg = config(root);
        // Construct outside a runtime so the startup task cannot compete with
        // explicit stale-state setup or consume the cleanup interleaving.
        let backend = std::thread::spawn(move || DiskCacheBackend::new(cfg).unwrap())
            .join()
            .unwrap();
        backend
            .background_sweep_started
            .store(true, Ordering::Release);
        backend
    }

    #[tokio::test]
    async fn stale_expiry_and_capacity_entries_cannot_unlink_a_replacement() {
        let root = std::env::temp_dir().join(format!("qpx-stale-cleanup-{}", uuid::Uuid::new_v4()));
        let mut first = foreground_backend(&root);
        let second = foreground_backend(&root);
        first.ensure_indexed().await.unwrap();
        first.put("ns", "key", b"old", 0).await.unwrap();
        second.put("ns", "key", b"fresh", 60).await.unwrap();
        first.sweep_expired().await;
        assert_eq!(first.get("ns", "key").await.unwrap().unwrap(), "fresh");

        // Keep stale capacity data but make its length/expiry match the new
        // object: neither value is an identity for atomic replacements.
        let path = first.path_for("ns", "key");
        first.put("ns", "key", b"older", 60).await.unwrap();
        let id = cache_file_id_from_path(&root, &path).unwrap();
        let old = first.state.lock().await.entries[&id].clone();
        second.put("ns", "key", b"fresh", 60).await.unwrap();
        let current = read_disk_cache_header_sync(&path).unwrap();
        {
            let mut state = first.state.lock().await;
            let stale = state.entries.get_mut(&id).unwrap();
            stale.total_len = current.total_len;
            stale.expires_at_ms = current.header.expires_at_ms;
            assert_eq!(stale.identity, old.identity);
            assert_ne!(
                stale.identity,
                Some(FileIdentity::of(&current.file.metadata().unwrap()))
            );
            state.total_bytes = current.total_len;
        }
        first.max_bytes = 0; // force selection of the sole stale candidate
        first.evict_if_needed().await.unwrap();
        assert_eq!(second.get("ns", "key").await.unwrap().unwrap(), "fresh");
        assert!(first.state.lock().await.entries.is_empty());
        // A known current generation still can be evicted normally.
        first.max_bytes = 8388608;
        first.put("ns", "key", b"current", 60).await.unwrap();
        first.max_bytes = 0;
        first.evict_if_needed().await.unwrap();
        assert!(second.get("ns", "key").await.unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn indexing_and_open_cleanup_read_after_the_publication_lock() {
        let root = std::env::temp_dir().join(format!("qpx-index-cleanup-{}", uuid::Uuid::new_v4()));
        let publisher = foreground_backend(&root);
        // Exercise both invalid-file indexing and open-time expiration. Hold
        // the publisher's object stripe at its pre-rename boundary; explicitly
        // polling the cleaner proves it cannot inspect/delete the old file.
        for indexing in [true, false] {
            let cleaner = foreground_backend(&root);
            let path = publisher.path_for("ns", "key");
            publisher.put("ns", "key", b"expired", 0).await.unwrap();
            if indexing {
                fs::write(&path, b"invalid header").unwrap();
            } else {
                cleaner.indexed_flag.store(true, Ordering::Release);
            }
            let object = publisher.lock_object(&path).await.unwrap();
            let mut cleanup = Box::pin(async {
                if indexing {
                    cleaner.ensure_indexed().await.unwrap();
                } else {
                    assert!(cleaner.open_valid(path.clone()).await.unwrap().is_some());
                }
            });
            poll_fn(|cx| {
                assert!(cleanup.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            // Private setup completes the publisher's rename under its guard.
            write_cached_bytes_sync(&path, Bytes::from_static(b"fresh"), 60).unwrap();
            drop(object);
            cleanup.await;
            assert_eq!(cleaner.get("ns", "key").await.unwrap().unwrap(), "fresh");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn object_locks_bound_cancelled_writers_and_deletes_and_pin_readers() {
        let root = std::env::temp_dir().join(format!("qpx-object-lock-{}", uuid::Uuid::new_v4()));
        let first = foreground_backend(&root);
        let second = foreground_backend(&root);
        first.put("ns", "key", b"original", 60).await.unwrap();
        let path = first.path_for("ns", "key");
        let object = first.lock_object(&path).await.unwrap();
        let mut writer = Box::pin(second.put("ns", "key", b"replacement", 60));
        poll_fn(|cx| {
            assert!(writer.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(writer);
        assert!(
            second
                .delete("ns", "key")
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        drop(object);
        let read = first.open_valid(path.clone()).await.unwrap().unwrap();
        second.delete("ns", "key").await.unwrap();
        second.put("ns", "key", b"replacement", 60).await.unwrap();
        let mut file = read.file;
        file.seek(std::io::SeekFrom::Start(read.body_offset))
            .unwrap();
        let mut original = Vec::new();
        file.read_to_end(&mut original).unwrap();
        assert_eq!(original, b"original");
        assert_eq!(
            first.get("ns", "key").await.unwrap().unwrap(),
            "replacement"
        );
        let key = cache_body_storage_key("variant");
        let original = vec![b'x'; DISK_CACHE_ZERO_COPY_MIN_BYTES as usize];
        first.put("ns", &key, &original, 60).await.unwrap();
        let mut stream = first
            .get_object_stream("ns", &key, original.len() as u64, None)
            .await
            .unwrap()
            .unwrap();
        second.delete("ns", &key).await.unwrap();
        second
            .put("ns", &key, &vec![b'y'; original.len()], 60)
            .await
            .unwrap();
        let region = stream.body.take_file_region_without_trailers().unwrap();
        let mut bytes = vec![0; region.len() as usize];
        std::os::unix::fs::FileExt::read_exact_at(region.file(), &mut bytes, region.offset())
            .unwrap();
        assert!(
            bytes == original,
            "zero-copy source must retain the original body"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn lock_files_reject_symlinks_and_nonprivate_state() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = std::env::temp_dir().join(format!("qpx-unsafe-lock-{}", uuid::Uuid::new_v4()));
        let cfg = config(&root);
        let backend = DiskCacheBackend::new(cfg.clone()).unwrap();
        let directory = root.join(".qpx-commit-locks");
        let target = root.join("unrelated");
        fs::write(&target, "untouched").unwrap();
        symlink(&target, directory.join("0.lock")).unwrap();
        assert!(backend.lock_commit("ns", "primary").await.is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        fs::remove_file(directory.join("0.lock")).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(DiskCacheBackend::new(cfg).is_err());
        drop(backend);
        fs::remove_dir_all(root).unwrap();
    }
}
