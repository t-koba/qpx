use super::*;
use std::os::unix::fs::PermissionsExt;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::warn;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_ipc_executor_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-ipc-executor-perf")?;
    let _script = create_cgi_script(&dir)?;
    let qpxf_listener = TcpListener::bind("127.0.0.1:0").await?;
    let qpxf_addr = qpxf_listener.local_addr()?;
    let qpxf_cfg: qpxf::config::QpxfConfig = serde_yaml::from_str(&qpxf_config_yaml(&dir))?;
    let router = Arc::new(qpxf::router::Router::new(&qpxf_cfg)?);
    let semaphore = Arc::new(Semaphore::new(qpxf_cfg.workers));
    let input_idle = Duration::from_millis(qpxf_cfg.input_idle_timeout_ms);
    let conn_idle = Duration::from_millis(qpxf_cfg.conn_idle_timeout_ms);
    let max_requests_per_connection = qpxf_cfg.max_requests_per_connection;
    let max_params_bytes = qpxf_cfg.max_params_bytes;
    let max_stdin_bytes = qpxf_cfg.max_stdin_bytes;
    let qpxf_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = qpxf_listener.accept().await else {
                break;
            };
            let router = router.clone();
            let semaphore = semaphore.clone();
            tokio::spawn(async move {
                if let Err(err) = qpxf::server::handle_connection(
                    stream,
                    qpxf::server::ConnectionContext {
                        router,
                        semaphore,
                        allow_shm_reuse: true,
                        input_idle,
                        conn_idle,
                        max_requests_per_connection,
                        max_params_bytes,
                        max_stdin_bytes,
                    },
                )
                .await
                {
                    warn!(error = ?err, "qpxf perf connection failed");
                }
            });
        }
    });

    let cfg = dir.join("ipc-executor-perf.yaml");
    let qpxf_addr = qpxf_addr.to_string();
    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("ipc-executor-perf.log"), |port| {
            format!(
                r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: ipc-perf
  listen: 127.0.0.1:{port}
  routes:
  - name: ipc
    match:
      path:
      - /hello.sh
    target:
      type: ipc
      endpoint: '{qpxf_addr}'
      mode: tcp
      timeout_ms: 5000"#
            )
        })?;

    let client = test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/hello.sh").parse()?;
    let op: PerfOperation = Arc::new(move || {
        let client = client.clone();
        let uri = uri.clone();
        Box::pin(async move {
            let response = client
                .request(
                    Request::builder()
                        .method("GET")
                        .uri(uri.clone())
                        .body(empty_body())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await?.to_bytes();
            if !body.as_ref().starts_with(b"Hello from CGI!") {
                return Err(anyhow!("unexpected ipc response body"));
            }
            Ok(())
        })
    });
    let result = measure_parallel_perf(
        "reverse_ipc_executor",
        32,
        4,
        PerfThresholds {
            min_req_per_sec: 8.0,
            max_p95: Duration::from_millis(700),
        },
        op,
    )
    .await;
    qpxf_task.abort();
    result
}

fn create_cgi_script(dir: &Path) -> Result<PathBuf> {
    let script_path = dir.join("hello.sh");
    let mut file = fs::File::create(&script_path)?;
    writeln!(file, "#!/bin/sh")?;
    writeln!(file, "echo 'Content-Type: text/plain'")?;
    writeln!(file, "echo 'Status: 200 OK'")?;
    writeln!(file, "echo ''")?;
    writeln!(file, "echo 'Hello from CGI!'")?;
    drop(file);
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))?;
    Ok(script_path)
}

fn qpxf_config_yaml(root: &Path) -> String {
    format!(
        r#"workers: 16
handlers:
  - match:
      path_prefix: "/"
    backend:
      type: cgi
      root: "{}"
      timeout_ms: 5000
      env_passthrough: []
"#,
        root.display()
    )
}
