use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_route_retries_and_mirrors() -> Result<()> {
    let dir = temp_dir("qpxd-reverse-route-e2e")?;
    let cfg = dir.join("reverse-route.yaml");
    let (live_addr, live_hits) = start_text_backend("LIVE", vec![]).await?;
    // A literal destination port 0 cannot identify a listener: binding port 0
    // asks the OS to choose an ephemeral port. Connecting here fails fast with
    // connection-refused without a picked-then-released port reuse race.
    let (mirror_addr, mirror_hits) = start_text_backend("MIRROR", vec![]).await?;

    let (port, mut qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("reverse-route.log"), |port| {
            format!(
                r#"upstreams:
- name: dead
  url: http://127.0.0.1:0
- name: live
  url: http://{live_addr}
- name: mirror
  url: http://{mirror_addr}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: app
    streaming_requirement: preferred
    match:
      host:
      - reverse.local
      path:
      - /app/*
    resilience:
      retry:
        attempts: 2
        backoff_ms: 10
    timeout_ms: 1000
    mirrors:
    - percent: 100
      upstreams:
      - mirror
    target:
      type: upstream
      upstreams:
      - dead
      - live"#
            )
        })?;

    let client = test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/app/test").parse()?;
    let response = client
        .request(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("host", "reverse.local")
                .body(empty_body())?,
        )
        .await
        .with_context(|| {
            format!(
                "reverse request to 127.0.0.1:{port}; child status: {:?}{}",
                qpxd.child.try_wait(),
                qpxd.log_tail(),
            )
        })?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = collect_body(response.into_body()).await?;
    assert_eq!(&body[..], b"LIVE");
    assert_eq!(live_hits.load(Ordering::Relaxed), 1);
    wait_for_counter(&mirror_hits, 1).await?;
    Ok(())
}

#[tokio::test]
async fn reverse_reloads_valid_atomic_config_after_rejected_replacement() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let cfg = dir.path().join("reverse.yaml");
    let log = dir.path().join("qpxd.log");
    let state_dir = yaml_quote_path(&dir.path().join("state"));
    let config = |port, body| {
        format!(
            r#"state_dir: {state_dir}
runtime:
  worker_threads: 1
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - match:
      path:
      - /
    target:
      type: local_response
      response:
        status: 200
        body: {body}"#
        )
    };
    let (port, mut qpxd) =
        spawn_qpxd_on_random_port(&cfg, log.clone(), |port| config(port, "before"))?;
    let client = test_client();
    let deadline = Duration::from_secs(5);
    let response_body = || async {
        timeout(deadline, async {
            let response = client
                .request(
                    Request::builder()
                        .uri(format!("http://127.0.0.1:{port}/"))
                        .body(empty_body())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            collect_body(response.into_body()).await
        })
        .await?
    };
    let replace = |contents: &str| -> Result<()> {
        let replacement = cfg.with_extension("tmp");
        fs::write(&replacement, contents)?;
        fs::rename(replacement, &cfg)?;
        Ok(())
    };

    assert_eq!(response_body().await?.as_ref(), b"before");
    replace("edges: [")?;
    timeout(deadline, async {
        while !fs::read_to_string(&log)?.contains("config reload parse failed") {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .with_context(|| {
        format!(
            "qpxd did not observe the rejected config{}",
            qpxd.log_tail()
        )
    })??;
    assert_eq!(response_body().await?.as_ref(), b"before");

    replace(&config(port, "after"))?;
    timeout(deadline, async {
        loop {
            let body = response_body().await?;
            if body.as_ref() == b"after" {
                return Ok::<_, anyhow::Error>(());
            }
            assert_eq!(body.as_ref(), b"before");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .with_context(|| format!("qpxd did not apply the valid config{}", qpxd.log_tail()))??;
    assert!(qpxd.child.try_wait()?.is_none());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn reverse_reloads_valid_atomic_config_symlink_after_rejected_replacement() -> Result<()> {
    use std::os::unix::fs::symlink;
    use std::path::Path;

    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let cfg = root.join("reverse.yaml");
    let log = root.join("qpxd.log");
    // Use different parent directories for the symlink and its targets.
    let targets = root.join("targets");
    fs::create_dir(&targets)?;
    symlink(targets.join("v1.yaml"), &cfg)?;
    let invalid = targets.join("invalid.yaml");
    fs::write(&invalid, "edges: [")?;
    let v2 = targets.join("v2.yaml");
    let state_dir = yaml_quote_path(&root.join("state"));
    let config = |port, body| {
        format!(
            r#"state_dir: {state_dir}
runtime:
  worker_threads: 1
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - match:
      path:
      - /
    target:
      type: local_response
      response:
        status: 200
        body: {body}"#
        )
    };
    let (port, mut qpxd) =
        spawn_qpxd_on_random_port(&cfg, log.clone(), |port| config(port, "before"))?;
    fs::write(&v2, config(port, "after"))?;
    let client = test_client();
    let deadline = Duration::from_secs(5);
    let response_body = || async {
        timeout(deadline, async {
            let response = client
                .request(
                    Request::builder()
                        .uri(format!("http://127.0.0.1:{port}/"))
                        .body(empty_body())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            collect_body(response.into_body()).await
        })
        .await?
    };
    let repoint = |target: &Path| -> Result<()> {
        let replacement = cfg.with_extension("tmp");
        symlink(target, &replacement)?;
        fs::rename(replacement, &cfg)?;
        Ok(())
    };

    assert_eq!(response_body().await?.as_ref(), b"before");
    repoint(&invalid)?;
    timeout(deadline, async {
        while !fs::read_to_string(&log)?.contains("config reload parse failed") {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .with_context(|| {
        format!(
            "qpxd did not observe the rejected symlink{}",
            qpxd.log_tail()
        )
    })??;
    assert_eq!(response_body().await?.as_ref(), b"before");

    repoint(&v2)?;
    timeout(deadline, async {
        loop {
            let body = response_body().await?;
            if body.as_ref() == b"after" {
                return Ok::<_, anyhow::Error>(());
            }
            assert_eq!(body.as_ref(), b"before");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .with_context(|| format!("qpxd did not apply the valid symlink{}", qpxd.log_tail()))??;
    assert!(qpxd.child.try_wait()?.is_none());
    Ok(())
}
