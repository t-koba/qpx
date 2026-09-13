use super::*;

#[test]
fn load_config_accepts_reverse_route_cors_policy() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("reverse-cors.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: reverse
  name: api
  listen: 127.0.0.1:19080
  routes:
  - match:
      method: [GET, PUT]
      path: [/api/**]
    http:
      cors:
        allowed_origins: [https://app.example]
        allowed_methods: [GET, PUT]
        allowed_headers: [content-type, x-request-id]
        expose_headers: [etag]
        allow_credentials: true
        max_age_seconds: 600
        allow_private_network: true
    target:
      type: local_response
      response:
        status: 200
        body: ok"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load CORS config");
    fs::remove_dir_all(&dir).ok();
    let cors = loaded.reverse_edge_configs()[0].routes[0]
        .http
        .as_ref()
        .and_then(|http| http.cors.as_ref())
        .expect("CORS policy");
    assert_eq!(cors.allowed_origins, ["https://app.example"]);
    assert_eq!(cors.allowed_methods, ["GET", "PUT"]);
    assert!(cors.allow_credentials);
    assert_eq!(cors.max_age_seconds, Some(600));
    assert!(cors.allow_private_network);
}

#[test]
fn load_config_rejects_credentialed_cors_wildcard() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("credentialed-wildcard.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: reverse
  name: api
  listen: 127.0.0.1:19080
  routes:
  - match:
      path: [/**]
    http:
      cors:
        allowed_origins: ["*"]
        allowed_methods: [GET]
        allow_credentials: true
    target:
      type: local_response
      response:
        status: 204"#,
    )
    .expect("write");

    let error = load_config(&cfg).expect_err("credentialed wildcard must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(error.to_string().contains("wildcard is not allowed"));
}

#[test]
fn load_config_rejects_cors_on_forward_edge() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("forward-cors.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: egress
  listen: 127.0.0.1:18080
  http:
    cors:
      allowed_origins: [https://app.example]
      allowed_methods: [GET]
  default_action:
    type: block"#,
    )
    .expect("write");

    let error = load_config(&cfg).expect_err("forward CORS policy must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(error.to_string().contains("only valid on reverse routes"));
}

#[test]
fn load_config_rejects_cors_route_match_that_preflight_cannot_evaluate() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("cors-identity-match.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: reverse
  name: api
  listen: 127.0.0.1:19080
  routes:
  - match:
      path: [/**]
      identity:
        user: [alice]
    http:
      cors:
        allowed_origins: [https://app.example]
        allowed_methods: [GET]
    target:
      type: local_response
      response:
        status: 204"#,
    )
    .expect("write");

    let error = load_config(&cfg).expect_err("unobservable CORS route match must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        error
            .to_string()
            .contains("match.identity depends on facts unavailable during preflight")
    );
}
