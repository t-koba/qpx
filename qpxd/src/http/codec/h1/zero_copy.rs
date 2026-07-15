use qpx_http::body::FileRegion;
use std::io;
use tokio::net::TcpStream;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::io::Interest;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::io::unix::AsyncFd;

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
            let file_fd = region.file().as_raw_fd();
            let mut offset = region.offset();
            let end = offset
                .checked_add(region.len())
                .ok_or_else(|| io::Error::other("file region overflow"))?;
            let socket = self.socket()?;
            while offset < end {
                let remaining = end - offset;
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
