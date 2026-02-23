use anyhow::{anyhow, Result};
use memmap2::MmapMut;
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const HEADER_SIZE: usize = 80; // Ring header size (bytes)
const READ_IDX_OFFSET: usize = 0; // 8 bytes for read_idx (AtomicUsize)
const WRITE_IDX_OFFSET: usize = 8; // 8 bytes for write_idx (AtomicUsize)
const QUEUE_SIZE_OFFSET: usize = 16; // 8 bytes for queue capacity (AtomicUsize)
const INIT_STATE_OFFSET: usize = 24; // 4 bytes for init state (AtomicU32)
const MAGIC_OFFSET: usize = 32; // 8 bytes magic
const VERSION_OFFSET: usize = 40; // 4 bytes version (u32 LE)
const HEADER_LEN_OFFSET: usize = 44; // 4 bytes header size (u32 LE)
const MAX_MSG_BYTES_OFFSET: usize = 48; // 8 bytes max message size (AtomicUsize)
const CONSUMER_WAITING_OFFSET: usize = 56; // 4 bytes (AtomicU32)
const PRODUCER_WAITING_OFFSET: usize = 60; // 4 bytes (AtomicU32)
const PRODUCER_NEED_BYTES_OFFSET: usize = 64; // 8 bytes (AtomicUsize)

const INIT_STATE_UNINIT: u32 = 0;
const INIT_STATE_INITING: u32 = 1;
const INIT_STATE_READY: u32 = 2;

const SHM_MAGIC: [u8; 8] = *b"QPXSHM2\0";
const SHM_VERSION: u32 = 2;

/// Prevent pathological allocations if the ring gets corrupted or incorrectly sized.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MiB

pub struct ShmRingBuffer {
    mmap: MmapMut,
    capacity: usize,
    data_doorbell: ShmDoorbell,
    space_doorbell: ShmDoorbell,
}

impl Drop for ShmRingBuffer {
    fn drop(&mut self) {
        // Best-effort cancellation safety: wake any blocked waiters so aborted tasks don't leave
        // blocking threads stuck in sem_wait/WaitForSingleObject indefinitely.
        let _ = self.data_doorbell.signal();
        let _ = self.space_doorbell.signal();
    }
}

impl ShmRingBuffer {
    pub fn default_shm_dir() -> PathBuf {
        std::env::temp_dir().join("qpx")
    }

    pub fn default_capture_shm_path() -> PathBuf {
        Self::default_shm_dir().join("capture.shm")
    }

    pub fn create_or_open<P: AsRef<Path>>(path: P, size_bytes: usize) -> Result<Self> {
        if size_bytes <= HEADER_SIZE {
            return Err(anyhow!(
                "size_bytes must be larger than HEADER_SIZE ({})",
                HEADER_SIZE
            ));
        }

        let path = path.as_ref();
        let file = open_shm_file(path)?;
        let current_len = file.metadata()?.len() as usize;

        let capacity = size_bytes - HEADER_SIZE;

        if current_len == 0 {
            file.set_len(size_bytes as u64)?;
        } else if current_len != size_bytes {
            return Err(anyhow!(
                "Shared memory file size mismatch. Expected {}, found {}: {}",
                size_bytes,
                current_len,
                path.display()
            ));
        }

        let mut mmap = unsafe { MmapMut::map_mut(&file)? };
        init_or_validate_header(&mut mmap, capacity)?;
        let data_doorbell = ShmDoorbell::create_or_open(path, DoorbellKind::Data)?;
        let space_doorbell = ShmDoorbell::create_or_open(path, DoorbellKind::Space)?;
        Ok(Self {
            mmap,
            capacity,
            data_doorbell,
            space_doorbell,
        })
    }

    fn read_idx(&self) -> &AtomicUsize {
        unsafe { &*(self.mmap.as_ptr().add(READ_IDX_OFFSET) as *const AtomicUsize) }
    }

    fn write_idx(&self) -> &AtomicUsize {
        unsafe { &*(self.mmap.as_ptr().add(WRITE_IDX_OFFSET) as *const AtomicUsize) }
    }

    fn max_msg_bytes(&self) -> &AtomicUsize {
        unsafe { &*(self.mmap.as_ptr().add(MAX_MSG_BYTES_OFFSET) as *const AtomicUsize) }
    }

    fn consumer_waiting(&self) -> &AtomicU32 {
        unsafe { &*(self.mmap.as_ptr().add(CONSUMER_WAITING_OFFSET) as *const AtomicU32) }
    }

    fn producer_waiting(&self) -> &AtomicU32 {
        unsafe { &*(self.mmap.as_ptr().add(PRODUCER_WAITING_OFFSET) as *const AtomicU32) }
    }

    fn producer_need_bytes(&self) -> &AtomicUsize {
        unsafe { &*(self.mmap.as_ptr().add(PRODUCER_NEED_BYTES_OFFSET) as *const AtomicUsize) }
    }

    /// Try to write data to the ring buffer. Returns Ok(true) if successful, Ok(false) if full.
    pub fn try_push(&mut self, data: &[u8]) -> Result<bool> {
        let msg_len = data.len();
        let required_space = msg_len
            .checked_add(4)
            .ok_or_else(|| anyhow!("message length overflow"))?; // 4 bytes for length prefix + payload

        let max_msg = self.max_msg_bytes().load(Ordering::Relaxed);
        if msg_len > max_msg {
            return Err(anyhow!(
                "Message too large for ring buffer (len={} max={})",
                msg_len,
                max_msg
            ));
        }
        if msg_len > u32::MAX as usize {
            return Err(anyhow!("Message length exceeds u32: {}", msg_len));
        }

        if required_space > self.capacity {
            return Err(anyhow!("Message is larger than ring buffer capacity"));
        }

        let r = self.read_idx().load(Ordering::Acquire);
        let mut w = self.write_idx().load(Ordering::Acquire);
        let was_empty = r == w;

        let available_space = available_space(self.capacity, r, w);

        if available_space < required_space {
            return Ok(false); // Buffer is full
        }

        // We have enough space. Let's write the length prefix (4 bytes, little-endian)
        let len_bytes = (msg_len as u32).to_le_bytes();
        self.write_bytes_at(w, &len_bytes);
        w = (w + 4) % self.capacity;

        // Write the payload
        self.write_bytes_at(w, data);
        w = (w + msg_len) % self.capacity;

        // Publish the new write index
        self.write_idx().store(w, Ordering::Release);

        if was_empty && self.consumer_waiting().swap(0, Ordering::AcqRel) == 1 {
            self.data_doorbell.signal()?;
        }

        Ok(true)
    }

    /// Try to read a message from the ring buffer. Returns Ok(Some(data)) if successful, Ok(None) if empty.
    pub fn try_pop(&mut self) -> Result<Option<Vec<u8>>> {
        let r = self.read_idx().load(Ordering::Acquire);
        let w = self.write_idx().load(Ordering::Acquire);

        if r == w {
            return Ok(None); // Buffer is empty
        }

        let unread_bytes = if w >= r { w - r } else { self.capacity - r + w };

        // We have data, first read the 4-byte length prefix
        let mut len_bytes = [0u8; 4];
        self.read_bytes_at(r, &mut len_bytes);
        let msg_len = u32::from_le_bytes(len_bytes) as usize;

        let max_msg = self.max_msg_bytes().load(Ordering::Relaxed);
        if msg_len > max_msg {
            return Err(anyhow!(
                "Corrupted ring buffer: message length {} exceeds max {}",
                msg_len,
                max_msg
            ));
        }
        if msg_len > self.capacity.saturating_sub(4) {
            return Err(anyhow!(
                "Corrupted ring buffer: message length {} exceeds capacity {}",
                msg_len,
                self.capacity
            ));
        }
        let required = 4usize
            .checked_add(msg_len)
            .ok_or_else(|| anyhow!("message length overflow"))?;
        if unread_bytes < required {
            return Err(anyhow!(
                "Corrupted ring buffer: truncated message (need {} bytes, have {})",
                required,
                unread_bytes
            ));
        }

        let mut new_r = (r + 4) % self.capacity;

        // Read the payload
        let mut data = vec![0u8; msg_len];
        self.read_bytes_at(new_r, &mut data);
        new_r = (new_r + msg_len) % self.capacity;

        // Publish the new read index
        self.read_idx().store(new_r, Ordering::Release);

        if self.producer_waiting().load(Ordering::Acquire) != 0 {
            let w2 = self.write_idx().load(Ordering::Acquire);
            let available_space = available_space(self.capacity, new_r, w2);
            let need = self.producer_need_bytes().load(Ordering::Acquire);
            if available_space >= need && self.producer_waiting().swap(0, Ordering::AcqRel) == 1 {
                self.space_doorbell.signal()?;
            }
        }

        Ok(Some(data))
    }

    pub async fn wait_for_data(&self) -> Result<()> {
        loop {
            let r = self.read_idx().load(Ordering::Acquire);
            let w = self.write_idx().load(Ordering::Acquire);
            if r != w {
                self.consumer_waiting().store(0, Ordering::Release);
                return Ok(());
            }

            self.consumer_waiting().store(1, Ordering::Release);

            let r2 = self.read_idx().load(Ordering::Acquire);
            let w2 = self.write_idx().load(Ordering::Acquire);
            if r2 != w2 {
                self.consumer_waiting().store(0, Ordering::Release);
                return Ok(());
            }

            self.data_doorbell.wait().await?;
        }
    }

    pub async fn wait_for_space(&self, msg_len: usize) -> Result<()> {
        let required_space = msg_len
            .checked_add(4)
            .ok_or_else(|| anyhow!("message length overflow"))?;

        let max_msg = self.max_msg_bytes().load(Ordering::Relaxed);
        if msg_len > max_msg {
            return Err(anyhow!(
                "Message too large for ring buffer (len={} max={})",
                msg_len,
                max_msg
            ));
        }
        if required_space > self.capacity {
            return Err(anyhow!("Message is larger than ring buffer capacity"));
        }

        loop {
            let r = self.read_idx().load(Ordering::Acquire);
            let w = self.write_idx().load(Ordering::Acquire);
            if available_space(self.capacity, r, w) >= required_space {
                self.producer_waiting().store(0, Ordering::Release);
                return Ok(());
            }

            self.producer_need_bytes()
                .store(required_space, Ordering::Release);
            self.producer_waiting().store(1, Ordering::Release);

            let r2 = self.read_idx().load(Ordering::Acquire);
            let w2 = self.write_idx().load(Ordering::Acquire);
            if available_space(self.capacity, r2, w2) >= required_space {
                self.producer_waiting().store(0, Ordering::Release);
                return Ok(());
            }

            self.space_doorbell.wait().await?;
        }
    }

    pub fn unlink_doorbells(&self) -> Result<()> {
        self.data_doorbell.unlink()?;
        self.space_doorbell.unlink()?;
        Ok(())
    }

    fn write_bytes_at(&mut self, offset: usize, data: &[u8]) {
        let end_idx = offset + data.len();
        let payload_ptr = unsafe { self.mmap.as_mut_ptr().add(HEADER_SIZE) };
        let payload_slice = unsafe { std::slice::from_raw_parts_mut(payload_ptr, self.capacity) };

        if end_idx <= self.capacity {
            // Contiguous write
            payload_slice[offset..end_idx].copy_from_slice(data);
        } else {
            // Write wraps around
            let chunk1_len = self.capacity - offset;
            payload_slice[offset..].copy_from_slice(&data[..chunk1_len]);
            payload_slice[..data.len() - chunk1_len].copy_from_slice(&data[chunk1_len..]);
        }
    }

    fn read_bytes_at(&self, offset: usize, out_buf: &mut [u8]) {
        let end_idx = offset + out_buf.len();
        let payload_ptr = unsafe { self.mmap.as_ptr().add(HEADER_SIZE) };
        let payload_slice = unsafe { std::slice::from_raw_parts(payload_ptr, self.capacity) };

        if end_idx <= self.capacity {
            // Contiguous read
            out_buf.copy_from_slice(&payload_slice[offset..end_idx]);
        } else {
            // Read wraps around
            let chunk1_len = self.capacity - offset;
            let (out1, out2) = out_buf.split_at_mut(chunk1_len);
            out1.copy_from_slice(&payload_slice[offset..]);
            out2.copy_from_slice(&payload_slice[..out2.len()]);
        }
    }
}

fn available_space(capacity: usize, r: usize, w: usize) -> usize {
    // The condition w >= r means the unread data is contiguous from r to w.
    // If w < r, the unread data wraps around the end of the buffer.
    if w >= r {
        capacity - w + r - 1
    } else {
        r - w - 1
    }
}

#[derive(Clone, Copy, Debug)]
enum DoorbellKind {
    Data,
    Space,
}

impl DoorbellKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Space => "space",
        }
    }
}

fn doorbell_name(path: &Path, kind: DoorbellKind) -> String {
    let mut h = DefaultHasher::new();
    path.to_string_lossy().hash(&mut h);
    kind.suffix().hash(&mut h);
    let hash = h.finish();

    #[cfg(unix)]
    {
        // sem_open names must start with '/' and must not contain other slashes.
        format!("/qpxshm_{hash:016x}_{}", kind.suffix())
    }

    #[cfg(windows)]
    {
        // Use the local namespace (session-scoped) to avoid requiring global object privileges.
        format!("Local\\qpxshm_{hash:016x}_{}", kind.suffix())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = hash;
        let _ = kind;
        "qpxshm_unsupported".to_string()
    }
}

#[cfg(unix)]
struct ShmDoorbell {
    // Store as an integer to keep the type `Send` (raw pointers are not `Send` on all platforms).
    sem: usize,
    name: std::ffi::CString,
}

#[cfg(unix)]
impl ShmDoorbell {
    fn create_or_open(path: &Path, kind: DoorbellKind) -> Result<Self> {
        let name = std::ffi::CString::new(doorbell_name(path, kind))?;
        let sem = unsafe { libc::sem_open(name.as_ptr(), libc::O_CREAT, 0o600, 0) };
        if sem as isize == -1 {
            return Err(anyhow!(
                "failed to open shared memory doorbell semaphore: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            sem: sem as usize,
            name,
        })
    }

    fn signal(&self) -> Result<()> {
        let sem = self.sem as *mut libc::sem_t;
        if unsafe { libc::sem_post(sem) } != 0 {
            return Err(anyhow!(
                "failed to signal shared memory doorbell semaphore: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    async fn wait(&self) -> Result<()> {
        let sem = self.sem;
        tokio::task::spawn_blocking(move || {
            let sem = sem as *mut libc::sem_t;
            loop {
                if unsafe { libc::sem_wait(sem) } == 0 {
                    return Ok(());
                }
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(anyhow!("failed waiting on shared memory doorbell: {}", err));
            }
        })
        .await
        .map_err(|e| anyhow!("doorbell wait join failed: {e}"))?
    }

    fn unlink(&self) -> Result<()> {
        if unsafe { libc::sem_unlink(self.name.as_ptr()) } == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        Err(anyhow!("failed to unlink shared memory doorbell: {}", err))
    }
}

#[cfg(unix)]
impl Drop for ShmDoorbell {
    fn drop(&mut self) {
        let sem = self.sem as *mut libc::sem_t;
        unsafe {
            libc::sem_close(sem);
        }
    }
}

#[cfg(windows)]
struct ShmDoorbell {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl ShmDoorbell {
    fn create_or_open(path: &Path, kind: DoorbellKind) -> Result<Self> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::Threading::CreateEventW;

        let name: Vec<u16> = OsStr::new(doorbell_name(path, kind).as_str())
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // Auto-reset event (manual_reset = FALSE) with initial_state = FALSE.
        let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(anyhow!(
                "failed to create/open shared memory doorbell event: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { handle })
    }

    fn signal(&self) -> Result<()> {
        use windows_sys::Win32::System::Threading::SetEvent;
        if unsafe { SetEvent(self.handle) } == 0 {
            return Err(anyhow!(
                "failed to signal shared memory doorbell event: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    async fn wait(&self) -> Result<()> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};

        // HANDLE is a raw pointer type and not Send; capture as usize for spawn_blocking.
        let handle = self.handle as usize;
        tokio::task::spawn_blocking(move || {
            let handle = handle as windows_sys::Win32::Foundation::HANDLE;
            let rc = unsafe { WaitForSingleObject(handle, INFINITE) };
            if rc != WAIT_OBJECT_0 {
                return Err(anyhow!(
                    "failed waiting on shared memory doorbell event: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        })
        .await
        .map_err(|e| anyhow!("doorbell wait join failed: {e}"))?
    }

    fn unlink(&self) -> Result<()> {
        // Windows named kernel objects are automatically released when all handles are closed.
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ShmDoorbell {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

fn open_shm_file(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        let existed = parent.exists();
        ensure_not_symlink_under_default_dir(parent, "shared memory directory")?;
        ensure_not_symlink(parent, "shared memory directory")?;
        fs::create_dir_all(parent).map_err(|e| {
            anyhow!(
                "failed to create shared memory directory {}: {e}",
                parent.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let enforce = parent.starts_with(ShmRingBuffer::default_shm_dir());
            if !existed {
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| {
                    anyhow!(
                        "failed to set permissions on shared memory directory {}: {e}",
                        parent.display()
                    )
                })?;
            } else if enforce {
                let mode = fs::metadata(parent)?.permissions().mode() & 0o777;
                if (mode & 0o077) != 0 {
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| {
                        anyhow!(
                            "shared memory directory permissions are too open (mode={:o}) for {}; failed to set to 0700: {e}",
                            mode,
                            parent.display()
                        )
                    })?;
                }
            }
        }
    }

    // Best-effort protection: do not open through a symlink.
    // (On Unix we also use O_NOFOLLOW for the final path component.)
    ensure_not_symlink_under_default_dir(path, "shared memory file")?;
    ensure_not_symlink(path, "shared memory file")?;

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        file
    };

    #[cfg(not(unix))]
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;

    Ok(file)
}

fn init_or_validate_header(mmap: &mut MmapMut, capacity: usize) -> Result<()> {
    let init_state = unsafe { &*(mmap.as_ptr().add(INIT_STATE_OFFSET) as *const AtomicU32) };
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match init_state.load(Ordering::Acquire) {
            INIT_STATE_READY => {
                if validate_header(mmap, capacity).is_ok() {
                    return Ok(());
                }
                // Upgrade/recovery path: if the header does not match (e.g. binary upgraded),
                // re-initialize the ring buffer header and drop any existing data.
                if init_state
                    .compare_exchange(
                        INIT_STATE_READY,
                        INIT_STATE_INITING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    init_header(mmap, capacity)?;
                    init_state.store(INIT_STATE_READY, Ordering::Release);
                    return Ok(());
                }
            }
            INIT_STATE_UNINIT => {
                if init_state
                    .compare_exchange(
                        INIT_STATE_UNINIT,
                        INIT_STATE_INITING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    init_header(mmap, capacity)?;
                    init_state.store(INIT_STATE_READY, Ordering::Release);
                    return Ok(());
                }
            }
            INIT_STATE_INITING => {}
            other => return Err(anyhow!("invalid shared memory init state: {}", other)),
        }

        if Instant::now() >= deadline {
            // Crash recovery: if the initializer died while holding INITING, reset and retry.
            let _ = init_state.compare_exchange(
                INIT_STATE_INITING,
                INIT_STATE_UNINIT,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            if init_state.load(Ordering::Acquire) == INIT_STATE_UNINIT {
                continue;
            }
            return Err(anyhow!(
                "timeout waiting for shared memory ring initialization"
            ));
        }

        std::thread::sleep(Duration::from_millis(1));
    }
}

fn init_header(mmap: &mut MmapMut, capacity: usize) -> Result<()> {
    unsafe {
        let read_idx_ptr = mmap.as_mut_ptr().add(READ_IDX_OFFSET) as *mut AtomicUsize;
        let write_idx_ptr = mmap.as_mut_ptr().add(WRITE_IDX_OFFSET) as *mut AtomicUsize;
        let size_ptr = mmap.as_mut_ptr().add(QUEUE_SIZE_OFFSET) as *mut AtomicUsize;
        let max_msg_ptr = mmap.as_mut_ptr().add(MAX_MSG_BYTES_OFFSET) as *mut AtomicUsize;
        let consumer_wait_ptr = mmap.as_mut_ptr().add(CONSUMER_WAITING_OFFSET) as *mut AtomicU32;
        let producer_wait_ptr = mmap.as_mut_ptr().add(PRODUCER_WAITING_OFFSET) as *mut AtomicU32;
        let producer_need_ptr =
            mmap.as_mut_ptr().add(PRODUCER_NEED_BYTES_OFFSET) as *mut AtomicUsize;

        (*read_idx_ptr).store(0, Ordering::Relaxed);
        (*write_idx_ptr).store(0, Ordering::Relaxed);
        (*size_ptr).store(capacity, Ordering::Relaxed);
        (*max_msg_ptr).store(
            MAX_MESSAGE_BYTES.min(capacity.saturating_sub(4)),
            Ordering::Relaxed,
        );
        (*consumer_wait_ptr).store(0, Ordering::Relaxed);
        (*producer_wait_ptr).store(0, Ordering::Relaxed);
        (*producer_need_ptr).store(0, Ordering::Relaxed);
    }

    mmap[MAGIC_OFFSET..MAGIC_OFFSET + SHM_MAGIC.len()].copy_from_slice(&SHM_MAGIC);
    mmap[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&SHM_VERSION.to_le_bytes());
    mmap[HEADER_LEN_OFFSET..HEADER_LEN_OFFSET + 4]
        .copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    Ok(())
}

fn validate_header(mmap: &MmapMut, expected_capacity: usize) -> Result<()> {
    let stored_capacity = unsafe {
        let size_ptr = mmap.as_ptr().add(QUEUE_SIZE_OFFSET) as *const AtomicUsize;
        (*size_ptr).load(Ordering::Acquire)
    };
    if stored_capacity != expected_capacity {
        return Err(anyhow!(
            "Shared memory capacity mismatch. Expected {}, found {}",
            expected_capacity,
            stored_capacity
        ));
    }

    if mmap[MAGIC_OFFSET..MAGIC_OFFSET + SHM_MAGIC.len()] != SHM_MAGIC {
        return Err(anyhow!("Shared memory ring magic mismatch"));
    }

    let version = u32::from_le_bytes(
        mmap[VERSION_OFFSET..VERSION_OFFSET + 4]
            .try_into()
            .expect("version bytes"),
    );
    if version != SHM_VERSION {
        return Err(anyhow!(
            "Unsupported shared memory ring version {} (expected {})",
            version,
            SHM_VERSION
        ));
    }
    let header_len = u32::from_le_bytes(
        mmap[HEADER_LEN_OFFSET..HEADER_LEN_OFFSET + 4]
            .try_into()
            .expect("header_len bytes"),
    ) as usize;
    if header_len != HEADER_SIZE {
        return Err(anyhow!(
            "Unsupported shared memory ring header size {} (expected {})",
            header_len,
            HEADER_SIZE
        ));
    }
    Ok(())
}

fn ensure_not_symlink(path: &Path, label: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(anyhow!("{label} must not be a symlink: {}", path.display()));
        }
    }
    Ok(())
}

fn ensure_not_symlink_under_default_dir(path: &Path, label: &str) -> Result<()> {
    let base = ShmRingBuffer::default_shm_dir();
    if !path.starts_with(&base) {
        return Ok(());
    }
    ensure_not_symlink(&base, "shared memory base directory")?;
    let rel = path.strip_prefix(&base).unwrap_or(path);
    let mut cur = base;
    for comp in rel.components() {
        cur.push(comp);
        ensure_not_symlink(&cur, label)?;
    }
    Ok(())
}

// Add simple tests
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_shm_ring_buffer() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();

        let mut ring = ShmRingBuffer::create_or_open(path, 1024)?;

        assert_eq!(ring.try_pop()?, None);

        let msg1 = b"Hello, world!";
        assert!(ring.try_push(msg1)?);

        let msg2 = b"Another message";
        assert!(ring.try_push(msg2)?);

        assert_eq!(ring.try_pop()?.as_deref(), Some(msg1.as_slice()));
        assert_eq!(ring.try_pop()?.as_deref(), Some(msg2.as_slice()));
        assert_eq!(ring.try_pop()?, None);

        Ok(())
    }

    #[test]
    fn test_shm_ring_buffer_wrap() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();

        let mut ring = ShmRingBuffer::create_or_open(path, HEADER_SIZE + 20)?;

        let msg1 = b"0123456789"; // 10 bytes + 4 = 14
        assert!(ring.try_push(msg1)?);

        assert_eq!(ring.try_pop()?.as_deref(), Some(msg1.as_slice()));

        // Buffer capacity is 20. Read and Write indices should both be 14 now.
        // Let's write another 10-byte message (costs 14 bytes). It will wrap.
        let msg2 = b"ABCDEFGHIJ";
        assert!(ring.try_push(msg2)?);

        assert_eq!(ring.try_pop()?.as_deref(), Some(msg2.as_slice()));

        Ok(())
    }
}
