#[cfg(target_os = "linux")]
use crate::http::codec::lazy_timeout::timeout_after_pending;
use qpx_http::body::FileRegion;
use std::io;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
#[cfg(target_os = "linux")]
use tokio::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::io::Interest;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::io::unix::AsyncFd;

#[cfg(target_os = "linux")]
const LOW_CONTENTION_ZERO_COPY_QUANTUM: u64 = 8 * 1024 * 1024;
#[cfg(target_os = "linux")]
const BALANCED_ZERO_COPY_QUANTUM: u64 = 1024 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const LOW_CONTENTION_FILE_ZERO_COPY_QUANTUM: u64 = 1024 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const CONTENDED_FILE_ZERO_COPY_QUANTUM: u64 = 256 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const LOW_CONTENTION_FILE_TRANSFER_LIMIT: usize = 64;
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
    match (transfer_kind, active_transfers) {
        #[cfg(target_os = "linux")]
        (ZeroCopyTransferKind::Socket, 0..=1) => LOW_CONTENTION_ZERO_COPY_QUANTUM,
        #[cfg(target_os = "linux")]
        (ZeroCopyTransferKind::Socket, _) => BALANCED_ZERO_COPY_QUANTUM,
        (ZeroCopyTransferKind::File, 0..=LOW_CONTENTION_FILE_TRANSFER_LIMIT) => {
            LOW_CONTENTION_FILE_ZERO_COPY_QUANTUM
        }
        (ZeroCopyTransferKind::File, _) => CONTENDED_FILE_ZERO_COPY_QUANTUM,
    }
}

pub(super) struct ZeroCopySocket {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    source_fd: RawFd,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    socket: Option<AsyncFd<OwnedSocketFd>>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct OwnedSocketFd(RawFd);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl AsRawFd for OwnedSocketFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for OwnedSocketFd {
    fn drop(&mut self) {
        // SAFETY: this type exclusively owns the descriptor returned by dup.
        unsafe {
            libc::close(self.0);
        }
    }
}

impl ZeroCopySocket {
    pub(super) fn for_tcp(stream: &TcpStream) -> Option<Self> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            Some(Self {
                source_fd: stream.as_raw_fd(),
                socket: None,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = stream;
            None
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn socket(&mut self) -> io::Result<&AsyncFd<OwnedSocketFd>> {
        if self.socket.is_none() {
            // SAFETY: source_fd belongs to the live TcpStream for this connection.
            let fd = unsafe { libc::dup(self.source_fd) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let owned = OwnedSocketFd(fd);
            self.socket = Some(AsyncFd::new(owned)?);
        }
        self.socket
            .as_ref()
            .ok_or_else(|| io::Error::other("zero-copy socket initialization failed"))
    }

    pub(super) async fn send_file(&mut self, region: &FileRegion) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let _transfer = ZeroCopyTransferGuard::begin();
            let file_fd = region.file().as_raw_fd();
            let mut offset = region.offset();
            let end = offset
                .checked_add(region.len())
                .ok_or_else(|| io::Error::other("file region overflow"))?;
            let socket = self.socket()?;
            let mut bytes_since_yield = 0_u64;
            while offset < end {
                let scheduling_quantum = zero_copy_scheduling_quantum(ZeroCopyTransferKind::File);
                let remaining = (end - offset).min(scheduling_quantum);
                let written = socket
                    .async_io(Interest::WRITABLE, |_| {
                        sendfile_once(file_fd, socket.get_ref().as_raw_fd(), offset, remaining)
                    })
                    .await?;
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
                    tokio::task::yield_now().await;
                }
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = region;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "sendfile is unavailable on this platform",
            ))
        }
    }
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
    let pipe = SplicePipe::new()?;
    let mut bytes_since_yield = 0_u64;
    let mut waited_for_io = false;
    while remaining > 0 {
        let scheduling_quantum = zero_copy_scheduling_quantum(ZeroCopyTransferKind::Socket);
        let requested = usize::try_from(remaining.min(scheduling_quantum))
            .unwrap_or(scheduling_quantum as usize);
        let moved = timeout_after_pending(read_timeout, async {
            loop {
                match source.try_io(Interest::READABLE, || {
                    splice_once(source.as_raw_fd(), pipe.write_fd, requested)
                }) {
                    Ok(moved) => return Ok(moved),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if bytes_since_yield > 0 {
                            // Re-applying TCP_NODELAY explicitly pushes any partial splice
                            // batch before an upstream pause can leave it to the TCP flush timer.
                            destination.set_nodelay(true)?;
                        }
                        waited_for_io = true;
                        source.readable().await?;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "splice source read timed out"))??;
        if moved == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "splice source closed before content-length completed",
            ));
        }

        let mut buffered = moved;
        while buffered > 0 {
            let written = timeout_after_pending(write_timeout, async {
                loop {
                    match destination.try_io(Interest::WRITABLE, || {
                        splice_once(pipe.read_fd, destination.as_raw_fd(), buffered)
                    }) {
                        Ok(written) => return Ok(written),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            waited_for_io = true;
                            destination.writable().await?;
                        }
                        Err(error) => return Err(error),
                    }
                }
            })
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
            buffered -= written;
        }
        remaining -= moved as u64;
        bytes_since_yield = bytes_since_yield.saturating_add(moved as u64);
        if remaining > 0 && bytes_since_yield >= scheduling_quantum {
            bytes_since_yield = 0;
            if !waited_for_io {
                tokio::task::yield_now().await;
            }
            waited_for_io = false;
        }
    }
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
        // A larger pipe lets splice coalesce adjacent upstream writes instead of forcing a
        // source-read / destination-write wakeup at the kernel's small default pipe capacity.
        // The requested size is an optimization only; kernels may reject it for an ordinary
        // unprivileged process, while unrelated errors still indicate a broken pipe setup.
        // SAFETY: descriptors[0] is the open read endpoint returned by pipe2 above.
        let resize = unsafe {
            libc::fcntl(
                descriptors[0],
                libc::F_SETPIPE_SZ,
                1024_i32.saturating_mul(1024),
            )
        };
        if resize < 0 {
            let error = io::Error::last_os_error();
            let optional_resize_rejection = matches!(error.raw_os_error(), Some(code)
                if code == libc::EPERM || code == libc::EINVAL || code == libc::ENOMEM);
            if !optional_resize_rejection {
                // SAFETY: both descriptors were returned by pipe2 above and remain owned here.
                unsafe {
                    libc::close(descriptors[0]);
                    libc::close(descriptors[1]);
                }
                return Err(error);
            }
        }
        Ok(Self {
            read_fd: descriptors[0],
            write_fd: descriptors[1],
        })
    }
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
            zero_copy_scheduling_quantum_for(32, ZeroCopyTransferKind::File),
            LOW_CONTENTION_FILE_ZERO_COPY_QUANTUM
        );
        assert_eq!(
            zero_copy_scheduling_quantum_for(
                LOW_CONTENTION_FILE_TRANSFER_LIMIT + 1,
                ZeroCopyTransferKind::File,
            ),
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
        let payload = vec![b'x'; 256 * 1024];
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
        let payload_length = payload.len();
        let destination_task = tokio::spawn(async move {
            let mut received = vec![0; payload_length];
            destination_client
                .read_exact(&mut received)
                .await
                .expect("read destination payload");
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
        assert_eq!(destination_task.await.expect("destination task"), payload);
        let mut sentinel = [0; 4];
        source
            .read_exact(&mut sentinel)
            .await
            .expect("read sentinel");
        assert_eq!(&sentinel, b"NEXT");
        source_task.await.expect("source task");
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
        let mut zero_copy = ZeroCopySocket::for_tcp(&server).expect("zero-copy socket");
        zero_copy.send_file(&region).await.expect("send file");

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
        let mut zero_copy = ZeroCopySocket::for_tcp(&server).expect("zero-copy socket");
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
            Some(&mut zero_copy),
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
}
