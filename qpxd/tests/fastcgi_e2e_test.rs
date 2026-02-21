#[cfg(unix)]
mod e2e {
    use hyper::{Body, Client, Request};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Semaphore;
    use tokio::time::timeout;
    use tracing::warn;

    fn tempdir(prefix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
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

    fn write_qpxd_config(path: &std::path::Path, qpxd_listen: &str, qpxf_addr: &str) {
        let config = format!(
            r#"version: 1
reverse:
  - name: "e2e"
    listen: "{qpxd_listen}"
    routes:
      - match:
          path: ["/*"]
        fastcgi:
          address: "{qpxf_addr}"
          timeout_ms: 5000
"#,
        );
        std::fs::write(path, config).unwrap();
    }

    fn qpxf_config_yaml(root: &std::path::Path) -> String {
        let root = root.to_str().unwrap();
        format!(
            r#"workers: 2
handlers:
  - match:
      path_prefix: "/"
    backend:
      type: cgi
      root: "{root}"
      timeout_ms: 5000
      env_passthrough: []
"#
        )
    }

    #[tokio::test]
    async fn test_qpxd_to_qpxf_e2e_cgi() {
        let tmp = tempdir("qpxd-qpxf-e2e");
        let _script = create_cgi_script(&tmp);

        // Start qpxf server in-process (library), bound to a random local port.
        let qpxf_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let qpxf_addr = qpxf_listener.local_addr().unwrap();
        let qpxf_addr_str = format!("127.0.0.1:{}", qpxf_addr.port());

        let qpxf_cfg: qpxf::config::QpxfConfig =
            serde_yaml::from_str(qpxf_config_yaml(&tmp).as_str()).unwrap();
        let router = std::sync::Arc::new(qpxf::router::Router::new(&qpxf_cfg).unwrap());
        let semaphore = std::sync::Arc::new(Semaphore::new(qpxf_cfg.workers));
        let limits = std::sync::Arc::new(qpxf::fastcgi::RequestLimits {
            max_params_bytes: qpxf_cfg.max_params_bytes,
            max_stdin_bytes: qpxf_cfg.max_stdin_bytes,
        });
        let input_idle = Duration::from_millis(qpxf_cfg.input_idle_timeout_ms);
        let conn_idle = Duration::from_millis(qpxf_cfg.conn_idle_timeout_ms);
        let max_conns = qpxf_cfg.max_connections;
        let max_reqs_per_conn = qpxf_cfg.max_requests_per_connection;

        let qpxf_task = tokio::spawn(async move {
            loop {
                let (stream, _) = qpxf_listener.accept().await.unwrap();
                let router = router.clone();
                let sem = semaphore.clone();
                let lim = limits.clone();
                tokio::spawn(async move {
                    if let Err(err) = qpxf::server::handle_connection(
                        stream,
                        router,
                        sem,
                        lim,
                        input_idle,
                        conn_idle,
                        max_conns,
                        max_reqs_per_conn,
                    )
                    .await
                    {
                        warn!(error = ?err, "qpxf connection failed");
                    }
                });
            }
        });

        // Start qpxd binary with a reverse config that targets qpxf via typed fastcgi config.
        let qpxd_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let qpxd_port = qpxd_listener.local_addr().unwrap().port();
        drop(qpxd_listener);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let qpxd_listen = format!("127.0.0.1:{qpxd_port}");
        let qpxd_cfg_path = tmp.join("qpxd.yaml");
        write_qpxd_config(&qpxd_cfg_path, &qpxd_listen, &qpxf_addr_str);

        let qpxd_bin = std::path::Path::new(env!("CARGO_BIN_EXE_qpxd"));
        let mut qpxd_child = tokio::process::Command::new(qpxd_bin)
            .args(["run", "--config", qpxd_cfg_path.to_str().unwrap()])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to start qpxd");

        // Wait for qpxd to be ready.
        let mut ready = false;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if TcpStream::connect(&qpxd_listen).await.is_ok() {
                ready = true;
                break;
            }
        }
        if !ready {
            let _ = qpxd_child.kill().await;
            let output = qpxd_child.wait_with_output().await.unwrap();
            panic!(
                "qpxd did not start in time: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Send HTTP request to qpxd; it should proxy to qpxf via FastCGI.
        let client = Client::new();
        let uri: hyper::Uri = format!("http://{qpxd_listen}/hello.sh").parse().unwrap();
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = timeout(Duration::from_secs(10), client.request(req))
            .await
            .expect("http timeout")
            .expect("http request failed");
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("Hello from CGI!"),
            "body was: {}",
            body_str
        );
        assert!(body_str.contains("METHOD=GET"), "body was: {}", body_str);

        // Cleanup.
        qpxd_child.kill().await.ok();
        qpxf_task.abort();
    }
}
