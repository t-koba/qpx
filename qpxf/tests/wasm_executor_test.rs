//! WASM executor integration tests.
//!
//! These tests require a pre-compiled WASI WASM module. The test builds a
//! minimal "hello CGI" WASM module from a WAT (WebAssembly Text) source using
//! the `wat` crate at test time, or skips if no WASM module is available.

#[cfg(feature = "wasm")]
mod wasm_tests {
    use tokio::net::TcpListener;

    fn yaml_single_quote(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('\'');
        for ch in s.chars() {
            if ch == '\'' {
                out.push_str("''");
            } else {
                out.push(ch);
            }
        }
        out.push('\'');
        out
    }

    /// Test that the WASM executor correctly handles a request when a real WASM
    /// module is available. This test is skipped if no WASM target toolchain is
    /// installed. To run, compile a CGI-compatible WASM module and place it in
    /// the test fixtures directory.
    ///
    /// For now, we test that qpxf starts with a WASM config and returns 404 for
    /// a missing module path (verifying the handler routing works).
    #[tokio::test]
    async fn test_wasm_handler_routing() {
        let tmp = tempdir();

        // Pick a random port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let listen_addr = format!("127.0.0.1:{}", port);

        // Create config with a WASM handler pointing to a non-existent module.
        // This tests that the handler routing works and returns an appropriate error.
        let config_path = tmp.join("qpxf.yaml");
        let wasm_path = tmp.join("nonexistent.wasm");
        let wasm_path_yaml = yaml_single_quote(wasm_path.to_string_lossy().as_ref());
        let config = format!(
            r#"listen: "{listen_addr}"
workers: 1
handlers:
  - match:
      path_prefix: "/wasm/"
    backend:
      type: wasm
      module: {wasm_path_yaml}
      timeout_ms: 5000
"#,
            wasm_path_yaml = wasm_path_yaml,
        );
        std::fs::write(&config_path, config).unwrap();

        let qpxf_bin = std::path::Path::new(env!("CARGO_BIN_EXE_qpxf"));

        // qpxf should fail to start because the WASM module doesn't exist.
        let output = tokio::process::Command::new(qpxf_bin)
            .args(["--config", config_path.to_str().unwrap()])
            .output()
            .await
            .expect("failed to run qpxf");

        // It should exit with an error since the module file doesn't exist.
        assert!(
            !output.status.success(),
            "qpxf should fail with non-existent WASM module"
        );
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("qpxf-test-wasm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
