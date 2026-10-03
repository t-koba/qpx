use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_combined_log_preserves_downstream_headers_on_reused_generic_requests() -> Result<()>
{
    verify_reused_generic_request_combined_log(false).await?;
    if cfg!(unix) {
        verify_reused_generic_request_combined_log(true).await?;
    }
    Ok(())
}

async fn verify_reused_generic_request_combined_log(use_file_log: bool) -> Result<()> {
    let dir = fs::canonicalize(temp_dir("qpxd-reverse-combined-log-e2e")?)?;
    let cfg = dir.join("reverse.yaml");
    let access_path = dir.join("access.log");
    let process_log_path = dir.join("qpxd.log");
    // File logging requires the Unix directory-protection implementation.
    // Other platforms exercise the same combined writer through stdout.
    let access_path_config = if use_file_log {
        format!("    path: {}\n", yaml_quote_path(&access_path))
    } else {
        String::new()
    };
    let captured_access_path = if use_file_log {
        &access_path
    } else {
        &process_log_path
    };
    let (origin_addr, origin_hits) = start_text_backend("OK", Vec::new()).await?;
    let (port, qpxd) = spawn_qpxd_on_random_port(&cfg, process_log_path.clone(), |port| {
        format!(
            r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
telemetry:
  access_log:
    enabled: true
    format: combined
{access_path_config}    rotation: never
    redact:
      query_keys: [token]
upstreams:
- name: origin
  url: http://{origin_addr}
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: rewritten
    match: {{}}
    headers:
      request_set:
        User-Agent: upstream-agent
        Referer: https://upstream.example/rewritten
    target:
      type: upstream
      upstreams: [origin]
"#
        )
    })?;
    let mut client = TcpStream::connect(("127.0.0.1", port)).await?;
    client
        .write_all(concat!(
            "GET /asset?token=first HTTP/1.1\r\nHost: reverse.test\r\nUser-Agent: downstream-one\r\nReferer: https://client.example/one?token=secret-one\r\n\r\n",
            "GET /asset?token=first HTTP/1.1\r\nHost: reverse.test\r\nUser-Agent: downstream-one\r\nReferer: https://client.example/one?token=secret-one\r\n\r\n",
            "GET /other?token=other HTTP/1.1\r\nHost: reverse.test\r\nUser-Agent: downstream-two\r\nReferer: https://client.example/two?token=secret-two\r\n\r\n",
        ).as_bytes())
        .await?;
    timeout(Duration::from_secs(5), async {
        let mut response = Vec::new();
        let mut chunk = [0_u8; 4096];
        while response
            .windows(12)
            .filter(|value| *value == b"HTTP/1.1 200")
            .count()
            < 3
        {
            let read = client.read(&mut chunk).await?;
            anyhow::ensure!(read > 0, "connection closed before all responses");
            response.extend_from_slice(&chunk[..read]);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("response timeout")??;
    let log = timeout(Duration::from_secs(5), async {
        loop {
            let log = fs::read_to_string(captured_access_path)?;
            let log = log
                .lines()
                .filter(|line| {
                    line.contains("\"GET /asset?token=") || line.contains("\"GET /other?token=")
                })
                .collect::<Vec<_>>()
                .join("\n");
            if log.lines().count() >= 3 {
                return Ok::<_, anyhow::Error>(log);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("access log flush timeout")??;
    let lines: Vec<_> = log.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "each request must produce exactly one access record"
    );
    for line in &lines[..2] {
        assert!(
            line.contains("GET /asset?token=<redacted> HTTP/1.1"),
            "{line}"
        );
        assert!(
            line.contains("https://client.example/one?token=<redacted>"),
            "{line}"
        );
        assert!(line.contains("downstream-one"), "{line}");
    }
    assert!(
        lines[2].contains("GET /other?token=<redacted> HTTP/1.1"),
        "{}",
        lines[2]
    );
    assert!(
        lines[2].contains("https://client.example/two?token=<redacted>"),
        "{}",
        lines[2]
    );
    assert!(lines[2].contains("downstream-two"), "{}", lines[2]);
    assert!(!log.contains("upstream-agent"));
    assert!(!log.contains("upstream.example"));
    assert!(!log.contains("secret-one"));
    assert!(!log.contains("secret-two"));
    assert_eq!(origin_hits.load(Ordering::Relaxed), 3);
    client.shutdown().await?;
    drop(qpxd);
    fs::remove_dir_all(dir)?;
    Ok(())
}

fn qpxd_log_tail(dir: &std::path::Path) -> String {
    let log = std::fs::read_to_string(dir.join("reverse-cache.log")).unwrap_or_default();
    let lines: Vec<&str> = log.lines().rev().take(20).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_cache_uses_http_backend_store() -> Result<()> {
    let dir = temp_dir("qpxd-reverse-cache-e2e")?;
    let cfg = dir.join("reverse-cache.yaml");
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cache_state = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
    let cache_ops = Arc::new(AtomicUsize::new(0));
    let cache_addr = start_http_cache_backend(cache_state.clone(), cache_ops.clone()).await?;
    let origin_headers = vec![
        (
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("public, max-age=60"),
        ),
        (
            http::header::DATE,
            http::HeaderValue::from_str(&httpdate::fmt_http_date(SystemTime::now()))?,
        ),
    ];
    let (origin_addr, origin_hits) = start_text_backend("CACHE", origin_headers).await?;

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("reverse-cache.log"), |port| {
        let state_dir_yaml = yaml_quote_path(&state_dir);
        format!(
            r#"upstreams:
- name: origin
  url: http://{origin_addr}
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
caches:
- name: http-cache
  kind: http
  endpoint: http://{cache_addr}
  timeout_ms: 10000
  max_object_bytes: 1048576
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: cache
    match:
      host:
      - cache.local
      path:
      - /cache
    cache:
      enabled: true
      backend: http-cache
      namespace: reverse-cache
      default_ttl_secs: 60
      max_object_bytes: 1048576
    target:
      type: upstream
      upstreams:
      - origin"#,
            state_dir_yaml = state_dir_yaml
        )
    })?;

    let client = test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/cache").parse()?;
    let first = client
        .request(
            Request::builder()
                .method("GET")
                .uri(uri.clone())
                .header("host", "cache.local")
                .body(empty_body())?,
        )
        .await
        .with_context(|| format!("first request connection failed{}", _qpxd.log_tail()))?;
    if first.status() != StatusCode::OK {
        let status = first.status();
        let body = collect_body(first.into_body()).await?;
        panic!(
            "first request failed with {status}: {} (qpxd log: {})",
            String::from_utf8_lossy(&body),
            qpxd_log_tail(&dir)
        );
    }
    assert_eq!(&collect_body(first.into_body()).await?[..], b"CACHE");
    wait_for_counter(&cache_ops, 2).await?;

    let second = client
        .request(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("host", "cache.local")
                .body(empty_body())?,
        )
        .await
        .with_context(|| format!("cached request connection failed{}", _qpxd.log_tail()))?;
    if second.status() != StatusCode::OK {
        let status = second.status();
        let body = collect_body(second.into_body()).await?;
        panic!(
            "second (cached) request failed with {status}: {} (qpxd log: {})",
            String::from_utf8_lossy(&body),
            qpxd_log_tail(&dir)
        );
    }
    assert_eq!(&collect_body(second.into_body()).await?[..], b"CACHE");

    assert!(
        cache_ops.load(Ordering::Relaxed) >= 3,
        "expected cache GET/PUT/GET flow"
    );
    let cache_entries = cache_state.lock().await;
    assert!(
        !cache_entries.is_empty(),
        "cache backend should contain entries"
    );
    assert!(
        origin_hits.load(Ordering::Relaxed) >= 1,
        "origin should have been contacted at least once"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_preserves_http1_early_hints() -> Result<()> {
    let dir = temp_dir("qpxd-reverse-hints-e2e")?;
    let cfg = dir.join("reverse-hints.yaml");
    let backend_addr = start_raw_backend(
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".to_vec(),
    )
    .await?;

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("reverse-hints.log"), |port| {
        format!(
            r#"upstreams:
- name: hints
  url: http://{backend_addr}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: hints
    match:
      host:
      - hints.local
      path:
      - /hints
    target:
      type: upstream
      upstreams:
      - hints"#
        )
    })?;

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;
    stream
        .write_all(b"GET /hints HTTP/1.1\r\nHost: hints.local\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut raw)).await??;
    let raw = String::from_utf8_lossy(&raw);
    assert!(
        raw.contains("HTTP/1.1 103"),
        "missing early hints response:\n{raw}"
    );
    assert!(
        raw.contains("HTTP/1.1 200 OK"),
        "missing final response:\n{raw}"
    );
    assert!(
        raw.to_ascii_lowercase()
            .contains("link: </style.css>; rel=preload; as=style"),
        "missing Link header:\n{raw}"
    );
    Ok(())
}
