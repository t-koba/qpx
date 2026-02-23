#[cfg(unix)]
mod cgi_tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    use qpx_core::shm_ring::ShmRingBuffer;

    fn create_cgi_script(dir: &std::path::Path) -> std::path::PathBuf {
        let script_path = dir.join("hello.sh");
        let mut f = std::fs::File::create(&script_path).unwrap();
        writeln!(f, "#!/bin/sh").unwrap();
        writeln!(f, "echo 'Content-Type: text/plain'").unwrap();
        writeln!(f, "echo 'Status: 200 OK'").unwrap();
        writeln!(f, "echo ''").unwrap();
        writeln!(f, "echo \"Hello from CGI! METHOD=$REQUEST_METHOD\"").unwrap();
        drop(f);
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        script_path
    }

    fn create_qpxf_config(dir: &std::path::Path, listen: &str) -> std::path::PathBuf {
        let cgi_root = dir.to_str().unwrap();
        let config_path = dir.join("qpxf.yaml");
        let config = format!(
            r#"listen: "{listen}"
workers: 1
handlers:
  - match:
      path_prefix: "/"
    backend:
      type: cgi
      root: "{cgi_root}"
      timeout_ms: 5000
      env_passthrough: []
"#
        );
        std::fs::write(&config_path, config).unwrap();
        config_path
    }

    /// Test: start qpxf with a CGI handler, send an IPC request, verify response.
    #[tokio::test]
    async fn test_cgi_executor_via_ipc() {
        let tmp = tempdir();
        let _script = create_cgi_script(&tmp);

        // Find a free port by binding, getting the port, then closing.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        // Brief sleep to ensure OS fully releases the port.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let listen_addr = format!("127.0.0.1:{}", port);
        let config_path = create_qpxf_config(&tmp, &listen_addr);

        // Build qpxf binary path.
        let qpxf_bin = std::path::Path::new(env!("CARGO_BIN_EXE_qpxf"));

        // Start qpxf — pass --listen to override the config to avoid conflict
        // with the default CLI value.
        let mut child = tokio::process::Command::new(qpxf_bin)
            .args([
                "--config",
                config_path.to_str().unwrap(),
                "--listen",
                &listen_addr,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to start qpxf");

        // Wait for qpxf to be ready (retry connection).
        let mut connected = false;
        for _ in 0..20 {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            if TcpStream::connect(&listen_addr).await.is_ok() {
                connected = true;
                break;
            }
        }
        if !connected {
            // Read stderr to diagnose.
            let _ = child.kill().await;
            let output = child.wait_with_output().await.unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("qpxf did not start in time. stderr: {}", stderr);
        }

        // Connect and send IPC request.
        let result = send_ipc_request(&listen_addr, "/hello.sh", "GET").await;

        // Cleanup.
        child.kill().await.ok();

        let (_status, body) = result.expect("IPC request failed");
        assert!(body.contains("Hello from CGI!"), "body was: {}", body);
        assert!(body.contains("METHOD=GET"), "body was: {}", body);
    }

    /// Test: SHM IPC should support multiple sequential requests on the same connection (keep-alive).
    #[tokio::test]
    async fn test_cgi_executor_via_ipc_shm_keepalive() {
        let tmp = tempdir();
        let _script = create_cgi_script(&tmp);

        // Find a free port by binding, getting the port, then closing.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let listen_addr = format!("127.0.0.1:{}", port);
        let config_path = create_qpxf_config(&tmp, &listen_addr);
        let qpxf_bin = std::path::Path::new(env!("CARGO_BIN_EXE_qpxf"));

        let mut child = tokio::process::Command::new(qpxf_bin)
            .args([
                "--config",
                config_path.to_str().unwrap(),
                "--listen",
                &listen_addr,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to start qpxf");

        let mut connected = false;
        for _ in 0..20 {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            if TcpStream::connect(&listen_addr).await.is_ok() {
                connected = true;
                break;
            }
        }
        if !connected {
            let _ = child.kill().await;
            let output = child.wait_with_output().await.unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("qpxf did not start in time. stderr: {}", stderr);
        }

        let result = send_two_ipc_requests_shm_keepalive(&tmp, &listen_addr).await;
        child.kill().await.ok();

        let (body1, body2) = result.expect("IPC SHM request failed");
        assert!(body1.contains("Hello from CGI!"), "body1 was: {}", body1);
        assert!(body1.contains("METHOD=GET"), "body1 was: {}", body1);
        assert!(body2.contains("Hello from CGI!"), "body2 was: {}", body2);
        assert!(body2.contains("METHOD=POST"), "body2 was: {}", body2);
    }

    async fn send_two_ipc_requests_shm_keepalive(
        tmp: &std::path::Path,
        addr: &str,
    ) -> Result<(String, String), String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect: {}", e))?;

        let body1 = send_ipc_request_over_stream_shm(tmp, &mut stream, "/hello.sh", "GET").await?;
        let body2 = send_ipc_request_over_stream_shm(tmp, &mut stream, "/hello.sh", "POST").await?;
        Ok((body1, body2))
    }

    async fn send_ipc_request_over_stream_shm(
        _tmp: &std::path::Path,
        stream: &mut TcpStream,
        script_name: &str,
        method: &str,
    ) -> Result<String, String> {
        let shm_dir = ShmRingBuffer::default_shm_dir().join("ipc");
        std::fs::create_dir_all(&shm_dir).map_err(|e| format!("create shm dir: {e}"))?;
        #[cfg(unix)]
        {
            let _ = std::fs::set_permissions(&shm_dir, std::fs::Permissions::from_mode(0o700));
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let req_token = format!("ipc_req_{}_{}_{}.shm", method, std::process::id(), nonce);
        let res_token = format!("ipc_res_{}_{}_{}.shm", method, std::process::id(), nonce);
        let req_path = shm_dir.join(&req_token);
        let res_path = shm_dir.join(&res_token);
        let ring_size = 1024 * 1024;

        let mut req_ring = ShmRingBuffer::create_or_open(&req_path, ring_size)
            .map_err(|e| format!("create req ring: {}", e))?;
        let mut res_ring = ShmRingBuffer::create_or_open(&res_path, ring_size)
            .map_err(|e| format!("create res ring: {}", e))?;

        let mut params = std::collections::HashMap::new();
        params.insert("REMOTE_ADDR".to_string(), "127.0.0.1".to_string());
        params.insert("REMOTE_PORT".to_string(), "12345".to_string());

        let meta = qpx_core::ipc::meta::IpcRequestMeta {
            method: method.to_string(),
            uri: script_name.to_string(),
            headers: vec![("Host".to_string(), "localhost".to_string())],
            params,
            req_body_shm_path: Some(req_token),
            req_body_shm_size_bytes: Some(ring_size),
            res_body_shm_path: Some(res_token),
            res_body_shm_size_bytes: Some(ring_size),
        };

        qpx_core::ipc::protocol::write_frame(stream, &meta)
            .await
            .map_err(|e| format!("write meta: {}", e))?;

        // Empty body, signal EOF
        req_ring
            .try_push(&[])
            .map_err(|e| format!("push EOF: {}", e))?;

        let res_meta: qpx_core::ipc::meta::IpcResponseMeta =
            qpx_core::ipc::protocol::read_frame(stream)
                .await
                .map_err(|e| format!("read meta: {}", e))?;
        if res_meta.status != 200 {
            return Err(format!("unexpected status: {}", res_meta.status));
        }

        let mut body_bytes = Vec::new();
        loop {
            match res_ring.try_pop().map_err(|e| format!("pop: {}", e))? {
                Some(chunk) => {
                    if chunk.is_empty() {
                        break;
                    }
                    body_bytes.extend_from_slice(&chunk);
                }
                None => {
                    res_ring
                        .wait_for_data()
                        .await
                        .map_err(|e| format!("wait: {}", e))?;
                }
            }
        }

        let body = String::from_utf8_lossy(&body_bytes).to_string();
        Ok(body)
    }

    async fn send_ipc_request(
        addr: &str,
        script_name: &str,
        method: &str,
    ) -> Result<(u16, String), String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect: {}", e))?;

        let mut params = std::collections::HashMap::new();
        params.insert("REMOTE_ADDR".to_string(), "127.0.0.1".to_string());
        params.insert("REMOTE_PORT".to_string(), "12345".to_string());

        let meta = qpx_core::ipc::meta::IpcRequestMeta {
            method: method.to_string(),
            uri: script_name.to_string(),
            headers: vec![("Host".to_string(), "localhost".to_string())],
            params,
            req_body_shm_path: None,
            req_body_shm_size_bytes: None,
            res_body_shm_path: None,
            res_body_shm_size_bytes: None,
        };

        qpx_core::ipc::protocol::write_frame(&mut stream, &meta)
            .await
            .map_err(|e| format!("write meta: {}", e))?;

        // Empty body, signal EOF
        stream
            .shutdown()
            .await
            .map_err(|e| format!("shutdown: {}", e))?;

        let res_meta: qpx_core::ipc::meta::IpcResponseMeta =
            qpx_core::ipc::protocol::read_frame(&mut stream)
                .await
                .map_err(|e| format!("read meta: {}", e))?;

        let mut body_bytes = Vec::new();
        stream
            .read_to_end(&mut body_bytes)
            .await
            .map_err(|e| format!("read body: {}", e))?;

        let body = String::from_utf8_lossy(&body_bytes).to_string();

        Ok((res_meta.status, body))
    }

    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("qpxf-test-cgi-{}-{}-{}", std::process::id(), ts, n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
