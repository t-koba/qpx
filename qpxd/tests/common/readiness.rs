//! Test-side receiver for qpxd's existing upgrade readiness protocol.
use std::io::{self, Read};
use std::process::{Child, Command};

#[cfg(unix)]
pub(super) struct Readiness(std::io::PipeReader);

#[cfg(unix)]
impl Readiness {
    pub(super) fn spawn(mut command: Command) -> io::Result<(Child, Self)> {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;

        // std creates both ends CLOEXEC. Never clear it in the parent: parallel
        // children must not keep another child's readiness writer alive.
        let (reader, writer) = std::io::pipe()?;
        let read_fd = reader.as_raw_fd();
        // SAFETY: reader owns a valid descriptor; fcntl only changes its flags.
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: reader still owns read_fd; retain the existing status flags.
        if unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
            return Err(io::Error::last_os_error());
        }
        let write_fd = writer.as_raw_fd();
        command.env("QPX_UPGRADE_READY_FD", write_fd.to_string());
        // SAFETY: only async-signal-safe fcntl runs between fork and exec. The
        // writer remains owned here until spawn returns. Only this child clears
        // CLOEXEC; the parent and every other child retain it.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(write_fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        drop(writer);
        Ok((child, Self(reader)))
    }

    pub(super) fn is_ready(&mut self) -> io::Result<bool> {
        let mut byte = [0];
        match self.0.read(&mut byte) {
            Ok(1) if byte[0] == b'1' => Ok(true),
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "child closed readiness pipe",
            )),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid child readiness notification",
            )),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(windows)]
pub(super) struct Readiness {
    listener: std::net::TcpListener,
    stream: Option<std::net::TcpStream>,
    expected: Vec<u8>,
    received: Vec<u8>,
    filled: usize,
}

#[cfg(windows)]
impl Readiness {
    pub(super) fn spawn(mut command: Command) -> io::Result<(Child, Self)> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let token = uuid::Uuid::new_v4().to_string();
        command.env("QPX_UPGRADE_READY_ADDR", listener.local_addr()?.to_string());
        command.env("QPX_UPGRADE_READY_TOKEN", &token);
        // Match upgrade/windows.rs: big-endian u16 length followed by token.
        let mut expected = (token.len() as u16).to_be_bytes().to_vec();
        expected.extend_from_slice(token.as_bytes());
        let received = vec![0; expected.len()];
        let child = command.spawn()?;
        Ok((
            child,
            Self {
                listener,
                stream: None,
                expected,
                received,
                filled: 0,
            },
        ))
    }

    pub(super) fn is_ready(&mut self) -> io::Result<bool> {
        if self.stream.is_none() {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    self.stream = Some(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        let stream = self.stream.as_mut().expect("accepted readiness stream");
        match stream.read(&mut self.received[self.filled..]) {
            // Unlike Unix pipe EOF on startup unwind, a connection closed
            // before its complete token is an invalid Windows protocol frame.
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "child closed readiness connection",
            )),
            Ok(n) => {
                self.filled += n;
                // Fail closed on any mismatch, including the framed length.
                if self.received[..self.filled] != self.expected[..self.filled] {
                    return Err(io::Error::other("invalid child readiness token"));
                }
                Ok(self.filled == self.expected.len())
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }
}
