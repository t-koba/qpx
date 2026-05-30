#[cfg(unix)]
mod cgi_tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::net::UnixStream;
    use tokio::sync::Semaphore;

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
allow_insecure_tcp: true
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

        let socket_path = tmp.join("qpxf.sock");
        let listen_addr = format!("unix://{}", socket_path.display());
        let config_path = create_qpxf_config(&tmp, &listen_addr);
        let server = spawn_test_server(&config_path, &socket_path).await;

        // Connect and send IPC request.
        let result = send_ipc_request(&socket_path, "/hello.sh", "GET").await;

        // Cleanup.
        server.abort();

        let (_status, body) = result.expect("IPC request failed");
        assert!(body.contains("Hello from CGI!"), "body was: {}", body);
        assert!(body.contains("METHOD=GET"), "body was: {}", body);
    }

    /// Test: SHM IPC should support multiple sequential requests on the same connection (keep-alive).
    #[tokio::test]
    async fn test_cgi_executor_via_ipc_shm_keepalive() {
        let tmp = tempdir();
        let _script = create_cgi_script(&tmp);

        let socket_path = tmp.join("qpxf.sock");
        let listen_addr = format!("unix://{}", socket_path.display());
        let config_path = create_qpxf_config(&tmp, &listen_addr);
        let server = spawn_test_server(&config_path, &socket_path).await;

        let result = send_two_ipc_requests_shm_keepalive(&tmp, &socket_path).await;
        server.abort();

        let (body1, body2) = result.expect("IPC SHM request failed");
        assert!(body1.contains("Hello from CGI!"), "body1 was: {}", body1);
        assert!(body1.contains("METHOD=GET"), "body1 was: {}", body1);
        assert!(body2.contains("Hello from CGI!"), "body2 was: {}", body2);
        assert!(body2.contains("METHOD=POST"), "body2 was: {}", body2);
    }

    async fn spawn_test_server(
        config_path: &std::path::Path,
        socket_path: &std::path::Path,
    ) -> tokio::task::JoinHandle<()> {
        let cfg = qpxf::config::load_config(config_path).expect("qpxf config");
        cfg.validate().expect("qpxf config validation");
        let router = Arc::new(qpxf::router::Router::new(&cfg).expect("qpxf router"));
        let semaphore = Arc::new(Semaphore::new(cfg.workers));
        let listener = UnixListener::bind(socket_path).expect("bind qpxf test socket");
        let ctx = qpxf::server::ConnectionContext {
            router,
            semaphore,
            allow_shm_reuse: true,
            input_idle: tokio::time::Duration::from_millis(cfg.input_idle_timeout_ms),
            conn_idle: tokio::time::Duration::from_millis(cfg.conn_idle_timeout_ms),
            max_requests_per_connection: cfg.max_requests_per_connection,
            max_params_bytes: cfg.max_params_bytes,
            max_stdin_bytes: cfg.max_stdin_bytes,
        };

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _ = qpxf::server::handle_connection(stream, ctx).await;
                });
            }
        })
    }

    async fn send_two_ipc_requests_shm_keepalive(
        tmp: &std::path::Path,
        socket_path: &std::path::Path,
    ) -> Result<(String, String), String> {
        let mut stream = UnixStream::connect(socket_path)
            .await
            .map_err(|e| format!("connect: {}", e))?;

        let body1 = send_ipc_request_over_stream_shm(tmp, &mut stream, "/hello.sh", "GET").await?;
        let body2 = send_ipc_request_over_stream_shm(tmp, &mut stream, "/hello.sh", "POST").await?;
        Ok((body1, body2))
    }

    async fn send_ipc_request_over_stream_shm(
        _tmp: &std::path::Path,
        stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
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
            server_protocol: "HTTP/3".to_string(),
            headers: vec![("Host".to_string(), "localhost".to_string())],
            params,
            req_body_shm_path: Some(req_token),
            req_body_shm_size_bytes: Some(ring_size),
            res_body_shm_path: Some(res_token),
            res_body_shm_size_bytes: Some(ring_size),
            shm_reusable: false,
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
        socket_path: &std::path::Path,
        script_name: &str,
        method: &str,
    ) -> Result<(u16, String), String> {
        let mut stream = UnixStream::connect(socket_path)
            .await
            .map_err(|e| format!("connect: {}", e))?;

        let mut params = std::collections::HashMap::new();
        params.insert("REMOTE_ADDR".to_string(), "127.0.0.1".to_string());
        params.insert("REMOTE_PORT".to_string(), "12345".to_string());

        let meta = qpx_core::ipc::meta::IpcRequestMeta {
            method: method.to_string(),
            uri: script_name.to_string(),
            server_protocol: "HTTP/3".to_string(),
            headers: vec![("Host".to_string(), "localhost".to_string())],
            params,
            req_body_shm_path: None,
            req_body_shm_size_bytes: None,
            res_body_shm_path: None,
            res_body_shm_size_bytes: None,
            shm_reusable: false,
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
