#[cfg(unix)]
mod cgi_tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const FCGI_VERSION: u8 = 1;
    const FCGI_BEGIN_REQUEST: u8 = 1;
    const FCGI_END_REQUEST: u8 = 3;
    const FCGI_PARAMS: u8 = 4;
    const FCGI_STDIN: u8 = 5;
    const FCGI_STDOUT: u8 = 6;
    const FCGI_RESPONDER: u16 = 1;

    fn encode_record(record_type: u8, request_id: u16, content: &[u8]) -> Vec<u8> {
        let padding = (8 - (content.len() % 8)) % 8;
        let mut buf = Vec::with_capacity(8 + content.len() + padding);
        buf.push(FCGI_VERSION);
        buf.push(record_type);
        buf.push((request_id >> 8) as u8);
        buf.push((request_id & 0xff) as u8);
        buf.push((content.len() >> 8) as u8);
        buf.push((content.len() & 0xff) as u8);
        buf.push(padding as u8);
        buf.push(0);
        buf.extend_from_slice(content);
        buf.extend(std::iter::repeat_n(0u8, padding));
        buf
    }

    fn encode_nv_pair(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        if name.len() < 128 {
            buf.push(name.len() as u8);
        } else {
            buf.extend_from_slice(&((name.len() as u32) | 0x8000_0000).to_be_bytes());
        }
        if value.len() < 128 {
            buf.push(value.len() as u8);
        } else {
            buf.extend_from_slice(&((value.len() as u32) | 0x8000_0000).to_be_bytes());
        }
        buf.extend_from_slice(name);
        buf.extend_from_slice(value);
        buf
    }

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

    /// Test: start qpxf with a CGI handler, send a FastCGI request, verify response.
    #[tokio::test]
    async fn test_cgi_executor_via_fastcgi() {
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

        // Connect and send FastCGI request.
        let result = send_fcgi_request(&listen_addr, "/hello.sh", "GET").await;

        // Cleanup.
        child.kill().await.ok();

        let (_status, body) = result.expect("FastCGI request failed");
        assert!(body.contains("Hello from CGI!"), "body was: {}", body);
        assert!(body.contains("METHOD=GET"), "body was: {}", body);
    }

    async fn send_fcgi_request(
        addr: &str,
        script_name: &str,
        method: &str,
    ) -> Result<(u16, String), String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect: {}", e))?;

        let request_id: u16 = 1;

        // BEGIN_REQUEST
        let mut begin_body = [0u8; 8];
        begin_body[0] = (FCGI_RESPONDER >> 8) as u8;
        begin_body[1] = (FCGI_RESPONDER & 0xff) as u8;
        stream
            .write_all(&encode_record(FCGI_BEGIN_REQUEST, request_id, &begin_body))
            .await
            .map_err(|e| format!("write begin: {}", e))?;

        // PARAMS
        let mut params = Vec::new();
        params.extend_from_slice(&encode_nv_pair(b"REQUEST_METHOD", method.as_bytes()));
        params.extend_from_slice(&encode_nv_pair(b"SCRIPT_NAME", script_name.as_bytes()));
        params.extend_from_slice(&encode_nv_pair(b"QUERY_STRING", b""));
        params.extend_from_slice(&encode_nv_pair(b"SERVER_NAME", b"localhost"));
        params.extend_from_slice(&encode_nv_pair(b"SERVER_PORT", b"80"));
        stream
            .write_all(&encode_record(FCGI_PARAMS, request_id, &params))
            .await
            .map_err(|e| format!("write params: {}", e))?;
        stream
            .write_all(&encode_record(FCGI_PARAMS, request_id, &[]))
            .await
            .map_err(|e| format!("write empty params: {}", e))?;

        // STDIN (empty)
        stream
            .write_all(&encode_record(FCGI_STDIN, request_id, &[]))
            .await
            .map_err(|e| format!("write stdin: {}", e))?;

        stream.flush().await.map_err(|e| format!("flush: {}", e))?;

        // Read response.
        let mut stdout_buf = Vec::new();
        loop {
            let mut hdr = [0u8; 8];
            stream
                .read_exact(&mut hdr)
                .await
                .map_err(|e| format!("read hdr: {}", e))?;
            let rtype = hdr[1];
            let content_len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
            let padding_len = hdr[6] as usize;
            let total = content_len + padding_len;
            let mut body = vec![0u8; total];
            if total > 0 {
                stream
                    .read_exact(&mut body)
                    .await
                    .map_err(|e| format!("read body: {}", e))?;
            }
            match rtype {
                FCGI_STDOUT => {
                    if content_len > 0 {
                        stdout_buf.extend_from_slice(&body[..content_len]);
                    }
                }
                FCGI_END_REQUEST => break,
                _ => {}
            }
        }

        // Parse CGI output.
        let output = String::from_utf8_lossy(&stdout_buf).to_string();
        // Extract status from CGI output.
        let mut status = 200u16;
        let mut body_start = 0;
        if let Some(pos) = output.find("\r\n\r\n") {
            let headers = &output[..pos];
            for line in headers.lines() {
                if line.to_lowercase().starts_with("status:") {
                    let val = line.split_once(':').unwrap().1.trim();
                    if let Some(code) = val.split_whitespace().next() {
                        status = code.parse().unwrap_or(200);
                    }
                }
            }
            body_start = pos + 4;
        } else if let Some(pos) = output.find("\n\n") {
            let headers = &output[..pos];
            for line in headers.lines() {
                if line.to_lowercase().starts_with("status:") {
                    let val = line.split_once(':').unwrap().1.trim();
                    if let Some(code) = val.split_whitespace().next() {
                        status = code.parse().unwrap_or(200);
                    }
                }
            }
            body_start = pos + 2;
        }

        let body = if body_start < output.len() {
            output[body_start..].to_string()
        } else {
            String::new()
        };

        Ok((status, body))
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("qpxf-test-cgi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
