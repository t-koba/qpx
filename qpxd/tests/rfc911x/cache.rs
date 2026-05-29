use super::*;
use anyhow::anyhow;

pub(crate) async fn cache_contract() -> Result<()> {
    let dir = temp_dir("qpxd-rfc911x-cache")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("create state dir {}", state_dir.display()))?;

    // Origin server: returns cacheable responses for /cacheable, and Set-Cookie for /cookie.
    let origin_hits = Arc::new(AtomicUsize::new(0));
    let (origin_addr, _origin_shutdown) = start_origin_server(origin_hits.clone()).await?;

    // HTTP cache backend: simple in-memory object store.
    let (cache_addr, _cache_shutdown, cache_store) = start_http_cache_backend().await?;

    let cfg_path = dir.join("qpxd-cache-forward.yaml");
    let (forward_port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg_path, dir.join("qpxd-cache-forward.log"), |port| {
            let state_dir_yaml = yaml_quote_path(&state_dir);
            format!(
                r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules: []
  cache:
    enabled: true
    backend: http-cache
    namespace: contract
    default_ttl_secs: 60
    max_object_bytes: 1048576
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
caches:
- name: http-cache
  kind: http
  endpoint: http://{cache_addr}
  timeout_ms: 1500
  max_object_bytes: 1048576"#,
                state_dir_yaml = state_dir_yaml
            )
        })?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;

    // Cacheable path: first request is MISS and calls origin; second is HIT and does not.
    let origin_uri = format!("http://{origin_addr}/cacheable");
    let h1_req = format!("GET {origin_uri} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
    let (_, headers1, _) = send_http1_and_read_response(proxy_addr, h1_req.as_bytes()).await?;
    assert_header_present_contains(&headers1, "x-qpx-cache", "MISS");
    if origin_hits.load(Ordering::SeqCst) != 1 {
        return Err(anyhow!("expected exactly 1 origin hit after first request"));
    }
    wait_for_cache_store_entries(cache_store.clone(), 3).await?;
    let (_, headers2, _) = send_http1_and_read_response(proxy_addr, h1_req.as_bytes()).await?;
    assert_header_present_contains(&headers2, "x-qpx-cache", "HIT");
    if origin_hits.load(Ordering::SeqCst) != 1 {
        return Err(anyhow!("expected cache HIT to avoid origin"));
    }

    // Set-Cookie responses are not stored by default (RFC 9111 shared-cache safety).
    let cookie_uri = format!("http://{origin_addr}/cookie");
    let cookie_req = format!("GET {cookie_uri} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
    let (_, headers3, _) = send_http1_and_read_response(proxy_addr, cookie_req.as_bytes()).await?;
    assert_header_present_contains(&headers3, "x-qpx-cache", "MISS");
    let (_, headers4, _) = send_http1_and_read_response(proxy_addr, cookie_req.as_bytes()).await?;
    assert_header_present_contains(&headers4, "x-qpx-cache", "MISS");
    if origin_hits.load(Ordering::SeqCst) < 3 {
        return Err(anyhow!(
            "expected Set-Cookie responses to bypass storage and hit origin twice"
        ));
    }

    Ok(())
}
