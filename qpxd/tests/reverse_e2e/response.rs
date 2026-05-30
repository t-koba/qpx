use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_cache_uses_http_backend_store() -> Result<()> {
    let dir = temp_dir("qpxd-reverse-cache-e2e")?;
    let cfg = dir.join("reverse-cache.yaml");
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cache_state = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
    let cache_ops = Arc::new(AtomicUsize::new(0));
    let cache_addr = start_http_cache_backend(cache_state.clone(), cache_ops.clone())?;
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
    let (origin_addr, origin_hits) = start_text_backend("CACHE", origin_headers)?;

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("reverse-cache.log"), |port| {
        let state_dir_yaml = yaml_quote_path(&state_dir);
        format!(
            r#"upstreams:
- name: origin
  url: http://{origin_addr}
state_dir:
  {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
caches:
- name: http-cache
  kind: http
  endpoint: http://{cache_addr}
  timeout_ms: 1000
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
        .await?;
    assert_eq!(first.status(), StatusCode::OK);
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
        .await?;
    assert_eq!(second.status(), StatusCode::OK);
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
