#[cfg(unix)]
mod regression {
    use qpx_core::ipc::meta::{IpcRequestMeta, IpcResponseMeta};
    use qpx_core::ipc::protocol::{read_frame, write_frame};
    use qpx_core::shm_ring::ShmRingBuffer;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Semaphore;
    use tokio::time::timeout;
    use tracing::warn;

    fn tempdir(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_script(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(body.as_bytes()).unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    async fn spawn_qpxf(
        root: &std::path::Path,
        workers: usize,
        max_stdin_bytes: usize,
        input_idle_timeout_ms: u64,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg_yaml = format!(
            r#"listen: "127.0.0.1:{}"
workers: {}
max_stdin_bytes: {}
input_idle_timeout_ms: {}
conn_idle_timeout_ms: 1000
handlers:
  - match:
      path_prefix: "/"
    backend:
      type: cgi
      root: "{}"
      timeout_ms: 5000
      env_passthrough: []
"#,
            addr.port(),
            workers,
            max_stdin_bytes,
            input_idle_timeout_ms,
            root.display()
        );
        let cfg: qpxf::config::QpxfConfig = serde_yaml::from_str(&cfg_yaml).unwrap();
        let router = Arc::new(qpxf::router::Router::new(&cfg).unwrap());
        let semaphore = Arc::new(Semaphore::new(cfg.workers));
        let input_idle = Duration::from_millis(cfg.input_idle_timeout_ms);
        let conn_idle = Duration::from_millis(cfg.conn_idle_timeout_ms);
        let max_requests_per_connection = cfg.max_requests_per_connection;
        let max_params_bytes = cfg.max_params_bytes;
        let max_stdin_bytes = cfg.max_stdin_bytes;

        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let router = Arc::clone(&router);
                let semaphore = Arc::clone(&semaphore);
                tokio::spawn(async move {
                    if let Err(err) = qpxf::server::handle_connection(
                        stream,
                        qpxf::server::ConnectionContext {
                            router,
                            semaphore,
                            input_idle,
                            conn_idle,
                            max_requests_per_connection,
                            max_params_bytes,
                            max_stdin_bytes,
                        },
                    )
                    .await
                    {
                        warn!(error = ?err, "qpxf regression test connection failed");
                    }
                });
            }
        });
        (format!("127.0.0.1:{}", addr.port()), task)
    }

    fn ipc_meta(script_name: &str, method: &str) -> IpcRequestMeta {
        let mut params = std::collections::HashMap::new();
        params.insert("REMOTE_ADDR".to_string(), "127.0.0.1".to_string());
        params.insert("REMOTE_PORT".to_string(), "12345".to_string());
        IpcRequestMeta {
            method: method.to_string(),
            uri: script_name.to_string(),
            headers: vec![("Host".to_string(), "localhost".to_string())],
            params,
            req_body_shm_path: None,
            req_body_shm_size_bytes: None,
            res_body_shm_path: None,
            res_body_shm_size_bytes: None,
        }
    }

    async fn send_tcp_ipc_request(
        addr: &str,
        script_name: &str,
        method: &str,
    ) -> Result<(u16, Vec<u8>), String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|err| format!("connect: {err}"))?;
        write_frame(&mut stream, &ipc_meta(script_name, method))
            .await
            .map_err(|err| format!("write meta: {err}"))?;
        stream
            .shutdown()
            .await
            .map_err(|err| format!("shutdown: {err}"))?;
        let res_meta: IpcResponseMeta = read_frame(&mut stream)
            .await
            .map_err(|err| format!("read meta: {err}"))?;
        let mut body = Vec::new();
        stream
            .read_to_end(&mut body)
            .await
            .map_err(|err| format!("read body: {err}"))?;
        Ok((res_meta.status, body))
    }

    async fn send_tcp_partial_body_ipc_request(
        addr: &str,
        script_name: &str,
        declared_len: usize,
        body_prefix: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|err| format!("connect: {err}"))?;
        let mut meta = ipc_meta(script_name, "POST");
        meta.headers
            .push(("Content-Length".to_string(), declared_len.to_string()));
        write_frame(&mut stream, &meta)
            .await
            .map_err(|err| format!("write meta: {err}"))?;
        stream
            .write_all(body_prefix)
            .await
            .map_err(|err| format!("write partial body: {err}"))?;
        let res_meta: IpcResponseMeta = timeout(Duration::from_secs(2), read_frame(&mut stream))
            .await
            .map_err(|_| "read meta timeout".to_string())?
            .map_err(|err| format!("read meta: {err}"))?;
        let mut body = Vec::new();
        stream
            .read_to_end(&mut body)
            .await
            .map_err(|err| format!("read body: {err}"))?;
        Ok((res_meta.status, body))
    }

    async fn send_tcp_body_without_content_length(
        addr: &str,
        script_name: &str,
        body_bytes: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|err| format!("connect: {err}"))?;
        write_frame(&mut stream, &ipc_meta(script_name, "POST"))
            .await
            .map_err(|err| format!("write meta: {err}"))?;
        stream
            .write_all(body_bytes)
            .await
            .map_err(|err| format!("write body: {err}"))?;
        stream
            .shutdown()
            .await
            .map_err(|err| format!("shutdown: {err}"))?;
        let res_meta: IpcResponseMeta = read_frame(&mut stream)
            .await
            .map_err(|err| format!("read meta: {err}"))?;
        let mut body = Vec::new();
        stream
            .read_to_end(&mut body)
            .await
            .map_err(|err| format!("read body: {err}"))?;
        Ok((res_meta.status, body))
    }

    struct ShmRequest {
        _stream: TcpStream,
        _req_ring: ShmRingBuffer,
        _res_ring: ShmRingBuffer,
        req_path: std::path::PathBuf,
        res_path: std::path::PathBuf,
    }

    impl Drop for ShmRequest {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.req_path);
            let _ = std::fs::remove_file(&self.res_path);
        }
    }

    async fn start_shm_request(
        addr: &str,
        script_name: &str,
        ring_size: usize,
    ) -> Result<(ShmRequest, IpcResponseMeta), String> {
        let shm_dir = ShmRingBuffer::default_shm_dir().join("ipc");
        std::fs::create_dir_all(&shm_dir).map_err(|err| format!("create shm dir: {err}"))?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let req_token = format!("ipc_req_regression_{}_{}.shm", std::process::id(), nonce);
        let res_token = format!("ipc_res_regression_{}_{}.shm", std::process::id(), nonce);
        let req_path = shm_dir.join(&req_token);
        let res_path = shm_dir.join(&res_token);
        let mut req_ring = ShmRingBuffer::create_or_open(&req_path, ring_size)
            .map_err(|err| format!("create req ring: {err}"))?;
        let res_ring = ShmRingBuffer::create_or_open(&res_path, ring_size)
            .map_err(|err| format!("create res ring: {err}"))?;

        let mut meta = ipc_meta(script_name, "GET");
        meta.req_body_shm_path = Some(req_token);
        meta.req_body_shm_size_bytes = Some(ring_size);
        meta.res_body_shm_path = Some(res_token);
        meta.res_body_shm_size_bytes = Some(ring_size);

        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|err| format!("connect: {err}"))?;
        write_frame(&mut stream, &meta)
            .await
            .map_err(|err| format!("write meta: {err}"))?;
        req_ring
            .try_push(&[])
            .map_err(|err| format!("push eof: {err}"))?;
        let res_meta: IpcResponseMeta = read_frame(&mut stream)
            .await
            .map_err(|err| format!("read meta: {err}"))?;

        Ok((
            ShmRequest {
                _stream: stream,
                _req_ring: req_ring,
                _res_ring: res_ring,
                req_path,
                res_path,
            },
            res_meta,
        ))
    }

    async fn send_shm_body_without_content_length(
        addr: &str,
        script_name: &str,
        body_bytes: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let shm_dir = ShmRingBuffer::default_shm_dir().join("ipc");
        std::fs::create_dir_all(&shm_dir).map_err(|err| format!("create shm dir: {err}"))?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let req_token = format!(
            "ipc_req_body_regression_{}_{}.shm",
            std::process::id(),
            nonce
        );
        let res_token = format!(
            "ipc_res_body_regression_{}_{}.shm",
            std::process::id(),
            nonce
        );
        let req_path = shm_dir.join(&req_token);
        let res_path = shm_dir.join(&res_token);
        let mut req_ring = ShmRingBuffer::create_or_open(&req_path, 4096)
            .map_err(|err| format!("create req ring: {err}"))?;
        let mut res_ring = ShmRingBuffer::create_or_open(&res_path, 4096)
            .map_err(|err| format!("create res ring: {err}"))?;

        let mut meta = ipc_meta(script_name, "POST");
        meta.req_body_shm_path = Some(req_token);
        meta.req_body_shm_size_bytes = Some(4096);
        meta.res_body_shm_path = Some(res_token);
        meta.res_body_shm_size_bytes = Some(4096);

        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|err| format!("connect: {err}"))?;
        write_frame(&mut stream, &meta)
            .await
            .map_err(|err| format!("write meta: {err}"))?;
        req_ring
            .try_push(body_bytes)
            .map_err(|err| format!("push body: {err}"))?;
        req_ring
            .try_push(&[])
            .map_err(|err| format!("push eof: {err}"))?;
        let res_meta: IpcResponseMeta = read_frame(&mut stream)
            .await
            .map_err(|err| format!("read meta: {err}"))?;
        let mut response_body = Vec::new();
        loop {
            match res_ring.try_pop() {
                Ok(Some(data)) if data.is_empty() => break,
                Ok(Some(data)) => response_body.extend_from_slice(&data),
                Ok(None) => {
                    timeout(Duration::from_secs(2), res_ring.wait_for_data())
                        .await
                        .map_err(|_| "response body timeout".to_string())?
                        .map_err(|err| format!("wait response body: {err}"))?;
                }
                Err(err) => return Err(format!("read response body: {err}")),
            }
        }
        let _ = std::fs::remove_file(&req_path);
        let _ = std::fs::remove_file(&res_path);
        Ok((res_meta.status, response_body))
    }

    #[tokio::test]
    async fn tcp_over_limit_body_after_response_does_not_hold_worker() {
        let tmp = tempdir("qpxf-regression-tcp");
        write_script(
            &tmp,
            "fast.sh",
            "#!/bin/sh\nprintf 'Status: 200 OK\\r\\n'\nprintf 'Content-Type: text/plain\\r\\n'\nprintf 'Content-Length: 2\\r\\n\\r\\n'\nprintf 'OK'\n",
        );
        let (addr, server_task) = spawn_qpxf(&tmp, 1, 32, 150).await;

        let mut first = TcpStream::connect(&addr).await.unwrap();
        let mut meta = ipc_meta("/fast.sh", "POST");
        meta.headers
            .push(("Content-Length".to_string(), "1".to_string()));
        write_frame(&mut first, &meta).await.unwrap();
        first.write_all(b"x").await.unwrap();

        let res_meta: IpcResponseMeta = read_frame(&mut first).await.unwrap();
        assert_eq!(res_meta.status, 200);
        let mut body = [0u8; 2];
        first.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"OK");

        let _ = first.write_all(&[b'a'; 128]).await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let (status, body) = loop {
            let (status, body) = timeout(
                Duration::from_secs(2),
                send_tcp_ipc_request(&addr, "/fast.sh", "GET"),
            )
            .await
            .expect("second request timeout")
            .expect("second request failed");
            if status == 200 || tokio::time::Instant::now() >= deadline {
                break (status, body);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(
            status,
            200,
            "unexpected status with body {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(body, b"OK");

        drop(first);
        server_task.abort();
    }

    #[tokio::test]
    async fn tcp_partial_body_timeout_returns_408_without_running_handler() {
        let tmp = tempdir("qpxf-regression-tcp-timeout");
        write_script(
            &tmp,
            "wait.sh",
            "#!/bin/sh\ncat >/dev/null\nprintf 'Status: 200 OK\\r\\n'\nprintf 'Content-Type: text/plain\\r\\n'\nprintf 'Content-Length: 2\\r\\n\\r\\n'\nprintf 'OK'\n",
        );
        let (addr, server_task) = spawn_qpxf(&tmp, 1, 1024, 100).await;

        let (status, body) = send_tcp_partial_body_ipc_request(&addr, "/wait.sh", 10, b"x")
            .await
            .expect("partial body request");

        assert_eq!(status, 408);
        assert_eq!(body, b"request body timed out");
        server_task.abort();
    }

    #[tokio::test]
    async fn body_without_content_length_reaches_handler() {
        let tmp = tempdir("qpxf-regression-unknown-body");
        write_script(
            &tmp,
            "echo-stdin.sh",
            "#!/bin/sh\nbody=$(cat)\nprintf 'Status: 200 OK\\r\\n'\nprintf 'Content-Type: text/plain\\r\\n'\nprintf 'Content-Length: %s\\r\\n\\r\\n' \"${#body}\"\nprintf '%s' \"$body\"\n",
        );
        let (addr, server_task) = spawn_qpxf(&tmp, 2, 1024, 300).await;

        let (tcp_status, tcp_body) =
            send_tcp_body_without_content_length(&addr, "/echo-stdin.sh", b"tcp-body")
                .await
                .expect("tcp body request");
        assert_eq!(tcp_status, 200);
        assert_eq!(tcp_body, b"tcp-body");

        let (shm_status, shm_body) =
            send_shm_body_without_content_length(&addr, "/echo-stdin.sh", b"shm-body")
                .await
                .expect("shm body request");
        assert_eq!(shm_status, 200);
        assert_eq!(shm_body, b"shm-body");

        server_task.abort();
    }

    #[tokio::test]
    async fn body_without_content_length_over_limit_rejects_before_fast_response() {
        let tmp = tempdir("qpxf-regression-unknown-over-limit");
        write_script(
            &tmp,
            "fast.sh",
            "#!/bin/sh\nprintf 'Status: 200 OK\\r\\n'\nprintf 'Content-Type: text/plain\\r\\n'\nprintf 'Content-Length: 2\\r\\n\\r\\n'\nprintf 'OK'\n",
        );
        let (addr, server_task) = spawn_qpxf(&tmp, 2, 32, 300).await;
        let body = vec![b'x'; 128];

        let (tcp_status, tcp_body) = send_tcp_body_without_content_length(&addr, "/fast.sh", &body)
            .await
            .expect("tcp over-limit request");
        assert_eq!(tcp_status, 413);
        assert_eq!(tcp_body, b"request body too large");

        let (shm_status, shm_body) = send_shm_body_without_content_length(&addr, "/fast.sh", &body)
            .await
            .expect("shm over-limit request");
        assert_eq!(shm_status, 413);
        assert_eq!(shm_body, b"request body too large");

        server_task.abort();
    }

    #[tokio::test]
    async fn shm_response_backpressure_timeout_releases_worker() {
        let tmp = tempdir("qpxf-regression-shm");
        let chunk = "x".repeat(512);
        write_script(
            &tmp,
            "stream.sh",
            format!(
                "#!/bin/sh\nprintf 'Status: 200 OK\\r\\n'\nprintf 'Content-Type: text/plain\\r\\n\\r\\n'\nchunk='{}'\ni=0\nwhile [ \"$i\" -lt 16 ]; do\n  printf '%s' \"$chunk\"\n  sleep 0.02\n  i=$((i + 1))\ndone\n",
                chunk
            )
            .as_str(),
        );
        write_script(
            &tmp,
            "fast.sh",
            "#!/bin/sh\nprintf 'Status: 200 OK\\r\\n'\nprintf 'Content-Type: text/plain\\r\\n'\nprintf 'Content-Length: 2\\r\\n\\r\\n'\nprintf 'OK'\n",
        );
        let (addr, server_task) = spawn_qpxf(&tmp, 1, 1024, 150).await;

        let (stalled_request, res_meta) = start_shm_request(&addr, "/stream.sh", 2048)
            .await
            .expect("start shm request");
        assert_eq!(res_meta.status, 200);

        tokio::time::sleep(Duration::from_millis(500)).await;

        let (status, body) = timeout(
            Duration::from_secs(2),
            send_tcp_ipc_request(&addr, "/fast.sh", "GET"),
        )
        .await
        .expect("second request timeout")
        .expect("second request failed");
        assert_eq!(
            status,
            200,
            "unexpected status with body {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(body, b"OK");

        drop(stalled_request);
        server_task.abort();
    }
}
