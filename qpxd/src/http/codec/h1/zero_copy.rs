#[cfg(target_os = "linux")]
mod diagnostics;

#[cfg(target_os = "linux")]
use crate::http::codec::lazy_timeout::ReusablePendingTimeout;
use qpx_http::body::FileRegion;
use std::io;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
#[cfg(target_os = "linux")]
use tokio::time::{Duration, sleep};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::io::Interest;
#[cfg(target_os = "linux")]
const LOW_CONTENTION_ZERO_COPY_QUANTUM: u64 = 8 * 1024 * 1024;
#[cfg(target_os = "linux")]
const BALANCED_ZERO_COPY_QUANTUM: u64 = 1024 * 1024;
// A single readiness event may move up to 1 MiB: sendfile returns partial
// writes as soon as the socket buffer fills, so the bound only limits
// syscall count, never worker occupancy.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const LOW_CONTENTION_FILE_ZERO_COPY_QUANTUM: u64 = 1024 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const CONTENDED_FILE_ZERO_COPY_QUANTUM: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const FILE_NOTSENT_LOWAT: u32 = 64 * 1024;
#[cfg(target_os = "linux")]
const SOCKET_NOTSENT_LOWAT: u32 = BALANCED_ZERO_COPY_QUANTUM as u32;
#[cfg(target_os = "linux")]
const MAX_SPLICE_SOCKET_BATCH: usize = 48 * 1024;

// Buffered body relays move up to one read buffer per readiness event. The
// same fairness rule as the zero-copy path applies under concurrent transfer
// pressure: shrink the per-poll quantum so one connection cannot monopolize a
// worker and inflate every peer's scheduler queue delay.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const CONTENDED_FILE_TRANSFER_THRESHOLD: usize = 4;
#[cfg(any(target_os = "linux", target_os = "macos"))]
static ACTIVE_ZERO_COPY_TRANSFERS: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct ZeroCopyTransferGuard;

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ZeroCopyTransferGuard {
    fn begin() -> Self {
        ACTIVE_ZERO_COPY_TRANSFERS.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for ZeroCopyTransferGuard {
    fn drop(&mut self) {
        ACTIVE_ZERO_COPY_TRANSFERS.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn zero_copy_scheduling_quantum(transfer_kind: ZeroCopyTransferKind) -> u64 {
    zero_copy_scheduling_quantum_for(
        ACTIVE_ZERO_COPY_TRANSFERS.load(Ordering::Acquire),
        transfer_kind,
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy)]
enum ZeroCopyTransferKind {
    File,
    #[cfg(target_os = "linux")]
    Socket,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn zero_copy_scheduling_quantum_for(
    active_transfers: usize,
    transfer_kind: ZeroCopyTransferKind,
) -> u64 {
    match transfer_kind {
        #[cfg(target_os = "linux")]
        ZeroCopyTransferKind::Socket if active_transfers <= 1 => LOW_CONTENTION_ZERO_COPY_QUANTUM,
        #[cfg(target_os = "linux")]
        ZeroCopyTransferKind::Socket => BALANCED_ZERO_COPY_QUANTUM,
        ZeroCopyTransferKind::File if active_transfers > CONTENDED_FILE_TRANSFER_THRESHOLD => {
            CONTENDED_FILE_ZERO_COPY_QUANTUM
        }
        ZeroCopyTransferKind::File => LOW_CONTENTION_FILE_ZERO_COPY_QUANTUM,
    }
}

pub(super) type FileRegionSender<W> =
    for<'a> fn(&'a mut W, &'a FileRegion) -> futures_util::future::BoxFuture<'a, io::Result<()>>;

pub(super) fn tcp_file_region_sender() -> Option<FileRegionSender<TcpStream>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return Some(|stream, region| Box::pin(send_file(stream, region)));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

pub(super) fn split_tcp_file_region_sender()
-> Option<FileRegionSender<tokio::net::tcp::OwnedWriteHalf>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return Some(|writer, region| {
        Box::pin(async move { send_file(writer.as_ref(), region).await })
    });
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) async fn send_file(stream: &TcpStream, region: &FileRegion) -> io::Result<()> {
    let _phase = crate::perf_diagnostics::phase_timer!("file_body_send");
    #[cfg(target_os = "linux")]
    let mut send_queue = ZeroCopySendQueueGuard::begin(stream, FILE_NOTSENT_LOWAT)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::future::{Future, poll_fn};

        let _transfer = ZeroCopyTransferGuard::begin();
        let file_fd = region.file().as_raw_fd();
        let mut offset = region.offset();
        let end = offset
            .checked_add(region.len())
            .ok_or_else(|| io::Error::other("file region overflow"))?;
        // Reuse the writer's reactor registration instead of duplicating
        // and registering its descriptor for every file response.
        let mut bytes_since_yield = 0_u64;
        let sampled_scheduling = _phase.is_sampled();
        let mut io_pending_polls = 0_u64;
        let mut explicit_yields = 0_u64;
        while offset < end {
            let scheduling_quantum = zero_copy_scheduling_quantum(ZeroCopyTransferKind::File);
            let remaining = (end - offset).min(scheduling_quantum);
            let written = if sampled_scheduling {
                let transfer = stream.async_io(Interest::WRITABLE, || {
                    sendfile_once(file_fd, stream.as_raw_fd(), offset, remaining)
                });
                tokio::pin!(transfer);
                poll_fn(|cx| {
                    let result = transfer.as_mut().poll(cx);
                    if result.is_pending() {
                        io_pending_polls += 1;
                    }
                    result
                })
                .await?
            } else {
                stream
                    .async_io(Interest::WRITABLE, || {
                        sendfile_once(file_fd, stream.as_raw_fd(), offset, remaining)
                    })
                    .await?
            };
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "sendfile made no progress",
                ));
            }
            offset = offset.saturating_add(written as u64);
            bytes_since_yield = bytes_since_yield.saturating_add(written as u64);
            if offset < end && bytes_since_yield >= scheduling_quantum {
                bytes_since_yield = 0;
                if ACTIVE_ZERO_COPY_TRANSFERS.load(Ordering::Acquire)
                    > CONTENDED_FILE_TRANSFER_THRESHOLD
                {
                    // Cooperative budget accounting alone can defer the
                    // handoff for many quanta. Enforce the file quantum
                    // while peers are actively competing for the worker.
                    if sampled_scheduling {
                        explicit_yields += 1;
                    }
                    tokio::task::yield_now().await;
                } else {
                    tokio::task::consume_budget().await;
                }
            }
        }
        #[cfg(target_os = "macos")]
        if sampled_scheduling {
            tracing::debug!(target: "qpx_perf_phase", io_pending_polls, explicit_yields,
                body_bytes = region.len(), sample_interval = 1024,
                "file body scheduling sampled");
        }
        #[cfg(target_os = "linux")]
        if sampled_scheduling {
            match socket_send_queue(stream) {
                Ok((queued_bytes, unsent_bytes)) => {
                    tracing::debug!(target: "qpx_perf_phase", queued_bytes, unsent_bytes,
                        body_bytes = region.len(), sample_interval = 1024,
                        io_pending_polls, explicit_yields,
                        "file socket queue sampled");
                }
                Err(error) => {
                    tracing::error!(target: "qpx_perf_phase", error = %error,
                        "file socket queue sampling failed");
                }
            }
        }
        #[cfg(target_os = "linux")]
        send_queue.restore()?;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (stream, region);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sendfile is unavailable on this platform",
        ))
    }
}

#[cfg(target_os = "linux")]
struct ZeroCopySendQueueGuard<'a> {
    stream: &'a TcpStream,
    original: u32,
    restored: bool,
}

#[cfg(target_os = "linux")]
impl<'a> ZeroCopySendQueueGuard<'a> {
    fn begin(stream: &'a TcpStream, notsent_lowat: u32) -> io::Result<Self> {
        let socket = socket2::SockRef::from(stream);
        let original = socket.tcp_notsent_lowat()?;
        // Bound data waiting for transmission, not the socket's total buffer.
        // This makes readiness reflect client progress before a complete large
        // response can sit in the kernel behind the other active transfers.
        socket.set_tcp_notsent_lowat(notsent_lowat)?;
        Ok(Self {
            stream,
            original,
            restored: false,
        })
    }

    fn restore(&mut self) -> io::Result<()> {
        socket2::SockRef::from(self.stream).set_tcp_notsent_lowat(self.original)?;
        self.restored = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for ZeroCopySendQueueGuard<'_> {
    fn drop(&mut self) {
        if !self.restored
            && let Err(error) = self.restore()
        {
            tracing::error!(error = %error, "failed to restore zero-copy transfer send queue limit");
        }
    }
}

#[cfg(target_os = "linux")]
fn socket_send_queue(stream: &TcpStream) -> io::Result<(u32, u32)> {
    let mut queued: libc::c_int = 0;
    let mut unsent: libc::c_int = 0;
    // SAFETY: TIOCOUTQ writes one initialized integer and the borrowed stream
    // keeps the descriptor alive for the entire operation.
    if unsafe { libc::ioctl(stream.as_raw_fd(), libc::TIOCOUTQ, &mut queued) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SIOCOUTQNSD writes one initialized integer and the borrowed stream
    // keeps the descriptor alive for the entire operation.
    if unsafe { libc::ioctl(stream.as_raw_fd(), libc::SIOCOUTQNSD as _, &mut unsent) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        queued.try_into().map_err(io::Error::other)?,
        unsent.try_into().map_err(io::Error::other)?,
    ))
}

#[cfg(target_os = "linux")]
pub(super) async fn splice_tcp_exact(
    source: &TcpStream,
    destination: &TcpStream,
    mut remaining: u64,
    read_timeout: Duration,
    write_timeout: Duration,
) -> io::Result<()> {
    let _transfer = ZeroCopyTransferGuard::begin();
    let mut send_queue = ZeroCopySendQueueGuard::begin(destination, SOCKET_NOTSENT_LOWAT)?;
    let pipe = SplicePipe::new()?;
    let mut counters = diagnostics::SpliceTransferCounters::begin(
        pipe.read_fd,
        remaining,
        MAX_SPLICE_SOCKET_BATCH,
    )?;
    let pending_timer = sleep(Duration::ZERO);
    tokio::pin!(pending_timer);
    let mut pending_timeout = ReusablePendingTimeout::new(pending_timer.as_mut());
    let mut bytes_since_yield = 0_u64;
    let mut waited_for_io = false;
    while remaining > 0 {
        let scheduling_quantum = zero_copy_scheduling_quantum(ZeroCopyTransferKind::Socket);
        let requested = usize::try_from(remaining.min(scheduling_quantum))
            .unwrap_or(scheduling_quantum as usize);
        let moved = pending_timeout
            .timeout_after_pending_with(
                read_timeout,
                async {
                    loop {
                        match source.try_io(Interest::READABLE, || {
                            splice_once(source.as_raw_fd(), pipe.write_fd, requested)
                        }) {
                            Ok(moved) => return Ok(moved),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                if let Some(counters) = counters.as_mut() {
                                    counters.source_pending();
                                }
                                if bytes_since_yield > 0 {
                                    // Re-applying TCP_NODELAY explicitly pushes any partial splice
                                    // batch before an upstream pause can leave it to the TCP flush timer.
                                    destination.set_nodelay(true)?;
                                }
                                source.readable().await?;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                },
                || waited_for_io = true,
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "splice source read timed out")
            })??;
        if moved == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "splice source closed before content-length completed",
            ));
        }

        if let Some(counters) = counters.as_mut() {
            counters.read(moved);
        }
        remaining -= moved as u64;
        bytes_since_yield = bytes_since_yield.saturating_add(moved as u64);
        let mut buffered = moved;
        while buffered > 0 {
            if buffered < MAX_SPLICE_SOCKET_BATCH
                && remaining > 0
                && bytes_since_yield < scheduling_quantum
            {
                // Merge a pipe tail with already readable upstream bytes. Never wait
                // for another source fragment while destination bytes are buffered;
                // paused sources and full pipes must flush their current tail.
                let requested = remaining.min(scheduling_quantum - bytes_since_yield) as usize;
                match source.try_io(Interest::READABLE, || {
                    splice_once(source.as_raw_fd(), pipe.write_fd, requested)
                }) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "splice source closed before content-length completed",
                        ));
                    }
                    Ok(moved) => {
                        if let Some(counters) = counters.as_mut() {
                            counters.read(moved);
                        }
                        buffered += moved;
                        remaining -= moved as u64;
                        bytes_since_yield = bytes_since_yield.saturating_add(moved as u64);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
            let written = pending_timeout
                .timeout_after_pending_with(
                    write_timeout,
                    async {
                        loop {
                            match destination.try_io(Interest::WRITABLE, || {
                                // Keep uncorked submissions below the large loopback MSS.
                                // Large spliced packets can exhaust the receiver's initial
                                // memory budget and leave a dropped packet waiting
                                // for the retransmission timer.
                                splice_once(
                                    pipe.read_fd,
                                    destination.as_raw_fd(),
                                    buffered.min(MAX_SPLICE_SOCKET_BATCH),
                                )
                            }) {
                                Ok(written) => return Ok(written),
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                    if let Some(counters) = counters.as_mut() {
                                        counters.destination_pending();
                                    }
                                    destination.writable().await?;
                                }
                                Err(error) => return Err(error),
                            }
                        }
                    },
                    || waited_for_io = true,
                )
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "splice destination write timed out",
                    )
                })??;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "splice destination made no progress",
                ));
            }
            if let Some(counters) = counters.as_mut() {
                counters.write(buffered.min(MAX_SPLICE_SOCKET_BATCH), written);
            }
            buffered -= written;
        }
        if remaining > 0 && bytes_since_yield >= scheduling_quantum {
            bytes_since_yield = 0;
            if !waited_for_io {
                // Readiness may complete immediately even after WouldBlock.
                // Only a real Pending poll has handed this worker to its peers;
                // otherwise enforce the byte quantum without deferring it for
                // another full cooperative task budget.
                tokio::task::yield_now().await;
            }
            waited_for_io = false;
        }
    }
    send_queue.restore()?;
    Ok(())
}

#[cfg(target_os = "linux")]
struct SplicePipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

#[cfg(target_os = "linux")]
impl SplicePipe {
    fn new() -> io::Result<Self> {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors points to storage for both descriptors returned by pipe2.
        let result =
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if let Err(error) = grow_splice_pipe(descriptors[0]) {
            // SAFETY: both descriptors were returned by pipe2 above and remain owned here.
            unsafe {
                libc::close(descriptors[0]);
                libc::close(descriptors[1]);
            }
            return Err(error);
        }
        Ok(Self {
            read_fd: descriptors[0],
            write_fd: descriptors[1],
        })
    }
}

#[cfg(target_os = "linux")]
fn grow_splice_pipe(read_fd: RawFd) -> io::Result<()> {
    // A larger pipe coalesces adjacent upstream writes and reduces source/destination
    // readiness cycles. Unprivileged limits vary by host, so retain the largest size
    // the kernel accepts instead of abandoning growth after one oversized request.
    // SAFETY: read_fd is the live read endpoint returned by pipe2.
    let current = unsafe { libc::fcntl(read_fd, libc::F_GETPIPE_SZ) };
    if current < 0 {
        let error = io::Error::last_os_error();
        if optional_pipe_resize_rejection(&error) {
            return Ok(());
        }
        return Err(error);
    }
    for requested in [1024 * 1024, 512 * 1024, 256 * 1024, 128 * 1024, 64 * 1024] {
        if requested <= current {
            return Ok(());
        }
        // SAFETY: read_fd is a live pipe endpoint and requested is a positive i32 size.
        if unsafe { libc::fcntl(read_fd, libc::F_SETPIPE_SZ, requested) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !optional_pipe_resize_rejection(&error) {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn optional_pipe_resize_rejection(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code)
        if code == libc::EPERM
            || code == libc::EINVAL
            || code == libc::ENOMEM
            || code == libc::ENOSYS)
}

#[cfg(target_os = "linux")]
impl Drop for SplicePipe {
    fn drop(&mut self) {
        // SAFETY: this type exclusively owns both descriptors returned by pipe2.
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

#[cfg(target_os = "linux")]
fn splice_once(source_fd: RawFd, destination_fd: RawFd, count: usize) -> io::Result<usize> {
    loop {
        // Flush each pipe batch to a socket. SPLICE_F_MORE can retain the last
        // partial packet until Linux's flush timer when the upstream pauses.
        let flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;
        // SAFETY: both descriptors are live, at least one descriptor is a pipe endpoint,
        // and socket and pipe descriptors do not use file offsets.
        let moved = unsafe {
            libc::splice(
                source_fd,
                std::ptr::null_mut(),
                destination_fd,
                std::ptr::null_mut(),
                count,
                flags,
            )
        };
        if moved >= 0 {
            return Ok(moved as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(target_os = "linux")]
fn sendfile_once(
    file_fd: RawFd,
    socket_fd: RawFd,
    offset: u64,
    remaining: u64,
) -> io::Result<usize> {
    let mut offset = libc::off_t::try_from(offset)
        .map_err(|_| io::Error::other("sendfile offset exceeds off_t"))?;
    let count = usize::try_from(remaining.min(0x7fff_f000)).unwrap_or(0x7fff_f000);
    loop {
        // SAFETY: both descriptors are live and offset points to writable storage.
        let written = unsafe { libc::sendfile(socket_fd, file_fd, &mut offset, count) };
        if written >= 0 {
            return Ok(written as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(target_os = "macos")]
fn sendfile_once(
    file_fd: RawFd,
    socket_fd: RawFd,
    offset: u64,
    remaining: u64,
) -> io::Result<usize> {
    let offset = libc::off_t::try_from(offset)
        .map_err(|_| io::Error::other("sendfile offset exceeds off_t"))?;
    loop {
        let mut written =
            libc::off_t::try_from(remaining.min(i64::MAX as u64)).unwrap_or(libc::off_t::MAX);
        // SAFETY: both descriptors are live and written points to writable storage.
        let result = unsafe {
            libc::sendfile(
                file_fd,
                socket_fd,
                offset,
                &mut written,
                std::ptr::null_mut(),
                0,
            )
        };
        if written > 0 {
            return Ok(written as usize);
        }
        if result == 0 {
            return Ok(0);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use http::{Method, Response, Version};
    use qpx_http::body::Body;
    use std::io::Write;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn scheduling_quantum_adapts_to_active_transfer_pressure() {
        #[cfg(target_os = "linux")]
        assert_eq!(
            zero_copy_scheduling_quantum_for(1, ZeroCopyTransferKind::Socket),
            LOW_CONTENTION_ZERO_COPY_QUANTUM
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            zero_copy_scheduling_quantum_for(2, ZeroCopyTransferKind::Socket),
            BALANCED_ZERO_COPY_QUANTUM
        );
        assert_eq!(
            zero_copy_scheduling_quantum_for(1, ZeroCopyTransferKind::File),
            LOW_CONTENTION_FILE_ZERO_COPY_QUANTUM
        );
        assert_eq!(
            zero_copy_scheduling_quantum_for(256, ZeroCopyTransferKind::File),
            CONTENDED_FILE_ZERO_COPY_QUANTUM
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            zero_copy_scheduling_quantum_for(32, ZeroCopyTransferKind::Socket),
            BALANCED_ZERO_COPY_QUANTUM
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn splices_exact_socket_payload_without_consuming_following_bytes() {
        let payload: Vec<u8> = (0..2 * 1024 * 1024 + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        let source_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind source");
        let source_address = source_listener.local_addr().expect("source address");
        let source_payload = payload.clone();
        let source_task = tokio::spawn(async move {
            let (mut source, _) = source_listener.accept().await.expect("accept source");
            source
                .write_all(&source_payload)
                .await
                .expect("write source payload");
            source.write_all(b"NEXT").await.expect("write sentinel");
        });
        let mut source = TcpStream::connect(source_address)
            .await
            .expect("connect source");

        let destination_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind destination");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address");
        let mut destination_client = TcpStream::connect(destination_address)
            .await
            .expect("connect destination");
        let (destination, _) = destination_listener
            .accept()
            .await
            .expect("accept destination");
        destination
            .set_nodelay(true)
            .expect("set destination nodelay");
        socket2::SockRef::from(&destination_client)
            .set_recv_buffer_size(64 * 1024)
            .expect("limit receiver memory");
        socket2::SockRef::from(&destination)
            .set_tcp_notsent_lowat(512 * 1024)
            .expect("set original destination send queue limit");
        let payload_length = payload.len();
        let destination_task = tokio::spawn(async move {
            let mut received = vec![0; payload_length];
            for chunk in received.chunks_mut(4096) {
                destination_client
                    .read_exact(chunk)
                    .await
                    .expect("read destination payload");
                sleep(Duration::from_millis(1)).await;
            }
            received
        });

        splice_tcp_exact(
            &source,
            &destination,
            payload.len() as u64,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .expect("splice payload");
        assert_eq!(
            socket2::SockRef::from(&destination)
                .tcp_notsent_lowat()
                .expect("read restored destination send queue limit"),
            512 * 1024,
        );
        assert_eq!(destination_task.await.expect("destination task"), payload);
        let mut sentinel = [0; 4];
        source
            .read_exact(&mut sentinel)
            .await
            .expect("read sentinel");
        assert_eq!(&sentinel, b"NEXT");
        source_task.await.expect("source task");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn splice_flushes_pipe_tail_before_a_paused_source_continues() {
        let payload: Vec<u8> = (0..256 * 1024 + 31)
            .map(|index| (index % 251) as u8)
            .collect();
        let first_fragment = 17 * 1024;
        let source_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind source");
        let source_address = source_listener.local_addr().expect("source address");
        let destination_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind destination");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address");
        let (delivered, observed) = tokio::sync::oneshot::channel();
        let source_payload = payload.clone();
        let source_task = tokio::spawn(async move {
            let (mut peer, _) = source_listener.accept().await.expect("accept source");
            peer.write_all(&source_payload[..first_fragment])
                .await
                .expect("write first fragment");
            tokio::time::timeout(Duration::from_secs(3), observed)
                .await
                .expect("pipe tail must arrive while source is paused")
                .expect("observe first fragment");
            peer.write_all(&source_payload[first_fragment..])
                .await
                .expect("write remaining payload");
        });
        let source = TcpStream::connect(source_address)
            .await
            .expect("connect source");
        let mut client = TcpStream::connect(destination_address)
            .await
            .expect("connect destination");
        let (destination, _) = destination_listener
            .accept()
            .await
            .expect("accept destination");
        let payload_len = payload.len();
        let receiver = tokio::spawn(async move {
            let mut received = vec![0; payload_len];
            client
                .read_exact(&mut received[..first_fragment])
                .await
                .expect("read first fragment");
            delivered.send(()).expect("acknowledge delivered fragment");
            client
                .read_exact(&mut received[first_fragment..])
                .await
                .expect("read remaining payload");
            received
        });
        splice_tcp_exact(
            &source,
            &destination,
            payload.len() as u64,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .expect("splice paused payload");
        assert_eq!(receiver.await.expect("receiver task"), payload);
        source_task.await.expect("source task");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancelled_and_failed_splice_restore_original_socket_setting() {
        let source_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind source");
        let source = TcpStream::connect(source_listener.local_addr().expect("source address"))
            .await
            .expect("connect source");
        let (mut source_peer, _) = source_listener.accept().await.expect("accept source");
        let destination_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind destination");
        let destination = TcpStream::connect(
            destination_listener
                .local_addr()
                .expect("destination address"),
        )
        .await
        .expect("connect destination");
        let (_destination_peer, _) = destination_listener
            .accept()
            .await
            .expect("accept destination");
        let socket = socket2::SockRef::from(&destination);
        let original = 512 * 1024;
        socket
            .set_tcp_notsent_lowat(original)
            .expect("set original send queue limit");
        {
            let transfer = splice_tcp_exact(
                &source,
                &destination,
                1024,
                Duration::from_secs(1),
                Duration::from_secs(1),
            );
            tokio::pin!(transfer);
            tokio::select! {
                biased;
                result = transfer.as_mut() => panic!("empty live source completed: {result:?}"),
                () = tokio::task::yield_now() => {}
            }
            assert_eq!(
                socket
                    .tcp_notsent_lowat()
                    .expect("read active send queue limit"),
                SOCKET_NOTSENT_LOWAT,
            );
        }
        assert_eq!(
            socket
                .tcp_notsent_lowat()
                .expect("read cancelled send queue limit"),
            original,
        );
        source_peer
            .shutdown()
            .await
            .expect("close source write half");
        let error = splice_tcp_exact(
            &source,
            &destination,
            1024,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .expect_err("closed source must not complete the payload");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            socket
                .tcp_notsent_lowat()
                .expect("read failed send queue limit"),
            original,
        );
    }

    #[tokio::test]
    async fn sends_the_exact_file_region_over_a_real_tcp_socket() {
        let (mut file, path) =
            qpx_core::secure_file::create_secure_temp_file("qpx-sendfile-test", ".body")
                .expect("create file");
        file.write_all(b"prefix-payload-suffix")
            .expect("write file");
        file.flush().expect("flush file");
        let file = Arc::new(file);
        let mut body =
            Body::from(bytes::Bytes::from_static(b"payload")).with_file_region(file, 7, 7);
        let region = body
            .take_file_region_without_trailers()
            .expect("file region");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        #[cfg(target_os = "linux")]
        {
            socket2::SockRef::from(&server)
                .set_tcp_notsent_lowat(512 * 1024)
                .expect("set original socket send queue limit");
        }
        send_file(&server, &region).await.expect("send file");
        #[cfg(target_os = "linux")]
        assert_eq!(
            socket2::SockRef::from(&server)
                .tcp_notsent_lowat()
                .expect("read socket send queue limit"),
            512 * 1024,
            "completed file transfer did not restore the original socket setting"
        );

        let mut received = [0_u8; 7];
        let mut client = client;
        client
            .read_exact(&mut received)
            .await
            .expect("read payload");
        assert_eq!(&received, b"payload");
        drop(server);
        drop(client);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn failed_file_transfer_restores_socket_send_queue_limit() {
        let file = tempfile::tempfile().expect("create empty transfer file");
        let mut body = Body::empty().with_file_region_for_zero_copy(Arc::new(file), 0, 1024);
        let region = body
            .take_file_region_without_trailers()
            .expect("file region");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let client = TcpStream::connect(listener.local_addr().expect("listener address"))
            .await
            .expect("connect client");
        let (server, _) = listener.accept().await.expect("accept client");
        socket2::SockRef::from(&server)
            .set_tcp_notsent_lowat(512 * 1024)
            .expect("set original socket send queue limit");
        let error = send_file(&server, &region)
            .await
            .expect_err("empty file must not satisfy the declared region");
        assert_eq!(error.kind(), std::io::ErrorKind::WriteZero);
        assert_eq!(
            socket2::SockRef::from(&server)
                .tcp_notsent_lowat()
                .expect("read restored send queue limit"),
            512 * 1024,
            "failed file transfer did not restore the original socket setting"
        );
        drop(server);
        drop(client);
    }

    #[tokio::test]
    async fn http1_response_uses_file_region_after_a_satisfied_body_limit() {
        let (mut file, path) =
            qpx_core::secure_file::create_secure_temp_file("qpx-sendfile-response-test", ".body")
                .expect("create file");
        file.write_all(b"prefix-payload-suffix")
            .expect("write file");
        file.flush().expect("flush file");
        let body = Body::from(bytes::Bytes::from_static(b"ignored"))
            .with_file_region(Arc::new(file), 7, 7)
            .limit_bytes(7);
        let response = Response::builder()
            .status(200)
            .header("content-length", "7")
            .body(body)
            .expect("response");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let mut client = TcpStream::connect(address).await.expect("connect");
        let (mut server, _) = listener.accept().await.expect("accept");
        let zero_copy = tcp_file_region_sender().expect("zero-copy sender");
        let mut head = BytesMut::new();
        super::super::response::send_http1_response_with_interim_zero_copy(
            &mut server,
            Version::HTTP_11,
            &Method::GET,
            response,
            &[],
            false,
            std::time::Duration::from_secs(1),
            &mut head,
            Some(zero_copy),
        )
        .await
        .expect("send response");
        server.shutdown().await.expect("shutdown server");

        let mut received = Vec::new();
        client
            .read_to_end(&mut received)
            .await
            .expect("read response");
        assert!(
            received.ends_with(b"payload"),
            "response did not use file region"
        );
        assert!(!received.ends_with(b"ignored"));
        let _ = std::fs::remove_file(path);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn file_transfer_reuses_original_socket_descriptor_under_backpressure() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;

        let file = tempfile::tempfile().expect("create transfer file");
        file.set_len(4 * 1024 * 1024).expect("extend transfer file");
        let mut body =
            Body::empty().with_file_region_for_zero_copy(Arc::new(file), 0, 4 * 1024 * 1024);
        let region = body
            .take_file_region_without_trailers()
            .expect("file region");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let client = TcpStream::connect(listener.local_addr().expect("listener address"))
            .await
            .expect("connect client");
        let (server, _) = listener.accept().await.expect("accept client");
        socket2::SockRef::from(&server)
            .set_send_buffer_size(4 * 1024 * 1024)
            .expect("allow a large server send buffer");
        let original_limit = socket2::SockRef::from(&server)
            .tcp_notsent_lowat()
            .expect("read original send queue limit");
        let socket_target = std::fs::read_link(format!("/proc/self/fd/{}", server.as_raw_fd()))
            .expect("socket descriptor identity");
        let mut transfer = Box::pin(send_file(&server, &region));
        assert!(
            poll_fn(|cx| Poll::Ready(matches!(transfer.as_mut().poll(cx), Poll::Pending))).await,
            "file transfer must wait for the slow client's receive window"
        );
        let matching_descriptors = std::fs::read_dir("/proc/self/fd")
            .expect("process descriptors")
            .map(|entry| entry.expect("descriptor entry").path())
            .filter(|path| std::fs::read_link(path).is_ok_and(|target| target == socket_target))
            .count();
        assert_eq!(
            matching_descriptors, 1,
            "file transfer duplicated its socket descriptor"
        );
        let (queued, unsent) = socket_send_queue(&server).expect("read real TCP send queue");
        assert!(unsent <= queued, "unsent bytes exceed the total send queue");
        assert!(
            unsent < 1024 * 1024,
            "file sender queued an entire large response before client progress: {unsent} bytes"
        );
        drop(transfer);
        assert_eq!(
            socket2::SockRef::from(&server)
                .tcp_notsent_lowat()
                .expect("read restored send queue limit"),
            original_limit,
            "cancelled file transfer did not restore the original socket setting"
        );
        drop(server);
        drop(client);
    }
}
