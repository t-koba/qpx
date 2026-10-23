// Include at the target root to exercise private helper seams without exposing
// test-only controls from the shared support or rerunning these in every target.
include!("common/mod.rs");

fn config(port: u16) -> String {
    format!(
        "runtime:\n  reuse_port: false\nedges:\n- kind: forward\n  name: test\n  listen: 127.0.0.1:{port}\n  default_action:\n    type: direct\n"
    )
}

#[test]
fn real_child_retries_collision_then_signals_own_readiness() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("qpxd.yaml");
    let wrong_peer = std::net::TcpListener::bind("127.0.0.1:0")?;
    let occupied = wrong_peer.local_addr()?.port();
    let attempts = std::cell::Cell::new(0);
    let (port, mut handle) = spawn_qpxd_on_random_port_with(
        &config_path,
        dir.path().join("qpxd.log"),
        config,
        || {
            let attempt = attempts.get();
            attempts.set(attempt + 1);
            if attempt == 0 {
                Ok(occupied)
            } else {
                pick_free_tcp_port()
            }
        },
        "port",
    )?;
    assert!(attempts.get() >= 2, "must retry the real bind collision");
    assert_ne!(port, occupied);
    assert!(handle.child.try_wait()?.is_none());
    // Traffic connectivity is checked only after child-owned readiness passed.
    let _connection = std::net::TcpStream::connect(("127.0.0.1", port))?;
    Ok(())
}

fn fixture(mode: &str) -> Result<(QpxdHandle, Readiness)> {
    use std::io::Read;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", "readiness_child_fixture", "--nocapture"])
        .env("QPX_TEST_READY_MODE", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let (child, readiness) = Readiness::spawn(command)?;
    let mut handle = QpxdHandle::new(child);
    // Synchronize with the live fixture, with a bounded wait rather than a
    // guessed startup sleep. Killing/reaping on failure also unblocks the reader.
    let mut stdout = handle.child.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let result = (|| {
            let mut byte = [0];
            loop {
                stdout.read_exact(&mut byte)?;
                if byte == *b"!" {
                    return std::io::Result::Ok(());
                }
            }
        })();
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(15));
    if !matches!(result, Ok(Ok(()))) {
        let _ = handle.child.kill();
        let _ = handle.child.wait();
    }
    reader.join().unwrap();
    result??;
    Ok((handle, readiness))
}

#[test]
fn wrong_peer_cannot_make_live_or_exited_child_ready() -> Result<()> {
    let wrong_peer = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = wrong_peer.local_addr()?.port();
    let dir = tempfile::tempdir()?;
    let (mut live, mut readiness) = fixture("held")?;
    assert!(live.child.try_wait()?.is_none());
    assert!(
        !readiness.is_ready()?,
        "wrong peer cannot signal for a live child"
    );
    for mode in ["closed", "invalid", "exited"] {
        let (mut handle, mut readiness) = fixture(mode)?;
        let log_path = dir.path().join("fixture.log");
        fs::write(&log_path, "synthetic readiness child log")?;
        handle.log_path = Some(log_path);
        if mode == "exited" {
            handle.child.wait()?;
        } else if mode == "invalid" {
            assert!(handle.child.try_wait()?.is_none());
        }
        let error = wait_for_qpxd(&mut handle, || readiness.is_ready(), port).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(&format!("127.0.0.1:{port}")), "{message}");
        assert!(message.contains("child status"), "{message}");
        assert!(
            message.contains("synthetic readiness child log"),
            "{message}"
        );
        assert!(
            handle.child.try_wait()?.is_some(),
            "failed child must be reaped"
        );
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_readiness_requires_complete_matching_token() -> Result<()> {
    for mode in ["valid", "wrong-token", "truncated"] {
        let (mut handle, mut readiness) = fixture(mode)?;
        let result = wait_for_qpxd(&mut handle, || readiness.is_ready(), 0);
        if mode == "valid" {
            result?;
            assert!(handle.child.try_wait()?.is_none());
        } else {
            assert!(result.is_err(), "must reject {mode}");
            assert!(handle.child.try_wait()?.is_some());
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn unrelated_child_does_not_inherit_readiness_writer() -> Result<()> {
    let (mut first, mut readiness) = fixture("held")?;
    let (mut other, _other_readiness) = fixture("held")?;
    first.child.kill()?;
    first.child.wait()?;
    // EOF must be observable while the unrelated child is still alive. This
    // would be WouldBlock if that child retained the first child's writer.
    assert!(other.child.try_wait()?.is_none());
    assert_eq!(
        readiness.is_ready().unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof,
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn eof_waits_for_final_bind_error_and_preserves_retry() -> Result<()> {
    use std::io::Write;

    let dir = tempfile::tempdir()?;
    let log_path = dir.path().join("fixture.log");
    let (mut handle, mut readiness) = fixture("late-bind-error")?;
    handle.log_path = Some(log_path.clone());
    let mut input = handle.child.stdin.take().unwrap();
    let mut eof_polls = 0;
    let error = wait_for_qpxd(
        &mut handle,
        || {
            let result = readiness.is_ready();
            if matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof) {
                eof_polls += 1;
                if eof_polls == 2 {
                    // Only release the final log/exit after the helper has
                    // continued polling past EOF. No startup/stabilization sleep.
                    writeln!(input, "{}", log_path.display())?;
                }
            }
            result
        },
        0,
    )
    .unwrap_err();
    assert!(eof_polls >= 2, "helper must not kill on initial EOF");
    assert_eq!(handle.child.try_wait()?.unwrap().code(), Some(1));
    let message = error.to_string();
    assert!(message.contains("Address already in use"), "{message}");
    assert!(
        is_retryable_bind_error_text(&message),
        "the final diagnostic must reach the existing bind retry: {message}"
    );
    Ok(())
}

#[test]
fn readiness_child_fixture() -> Result<()> {
    use std::io::{Read, Write};
    let Ok(mode) = std::env::var("QPX_TEST_READY_MODE") else {
        return Ok(());
    };
    #[cfg(unix)]
    let mut notifier = {
        use std::os::fd::FromRawFd;
        let fd = std::env::var("QPX_UPGRADE_READY_FD")?.parse()?;
        // SAFETY: only this subprocess owns the descriptor inherited by spawn.
        unsafe { fs::File::from_raw_fd(fd) }
    };
    #[cfg(windows)]
    let mut notifier = std::net::TcpStream::connect(std::env::var("QPX_UPGRADE_READY_ADDR")?)?;
    if mode == "invalid" {
        // Neither the Unix byte protocol nor Windows's framed token accepts it.
        notifier.write_all(b"xx")?;
    }
    #[cfg(windows)]
    if matches!(mode.as_str(), "valid" | "wrong-token" | "truncated") {
        let token = std::env::var("QPX_UPGRADE_READY_TOKEN")?;
        notifier.write_all(&(token.len() as u16).to_be_bytes())?;
        match mode.as_str() {
            "valid" => notifier.write_all(token.as_bytes())?,
            "wrong-token" => notifier.write_all(&vec![b'x'; token.len()])?,
            "truncated" => notifier.write_all(&token.as_bytes()[..3])?,
            _ => unreachable!(),
        }
    }
    if mode != "held" {
        drop(notifier);
    }
    print!("!");
    std::io::stdout().flush()?;
    if matches!(mode.as_str(), "closed" | "exited") {
        std::process::exit(1);
    }
    if mode == "late-bind-error" {
        let mut path = String::new();
        std::io::stdin().read_line(&mut path)?;
        fs::write(
            path.trim_end(),
            "Error: Address already in use (synthetic bind error)",
        )?;
        std::process::exit(1);
    }
    // Keep the child alive until killed or its parent closes stdin.
    let _ = std::io::stdin().read(&mut [0])?;
    Ok(())
}
