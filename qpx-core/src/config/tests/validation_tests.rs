use super::*;

#[test]
fn load_config_rejects_plain_ldap_without_starttls() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-ldap-starttls.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
security:
  auth:
    ldap:
      url: ldap://ad.example.com:389
      bind_dn: cn=proxy,dc=example,dc=com
      bind_password_env: LDAP_BIND_PASSWORD
      user_base_dn: ou=users,dc=example,dc=com
      group_base_dn: ou=groups,dc=example,dc=com
      require_starttls: false"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("auth.ldap.require_starttls must be true when auth.ldap.url uses ldap://"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_duplicate_upstream_names() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("duplicate-upstreams.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
upstreams:
- name: egress
  url: http://proxy-a.local:3128
- name: egress
  url: http://proxy-b.local:3128"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("duplicate upstream name"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_connection_filter_non_block_action() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-connection-filter-action.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  connection_filter:
  - name: bad-filter
    match:
      src_ip:
      - 127.0.0.1/32
    action:
      type: direct"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("connection_filter rule bad-filter action.type must be block"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_connection_filter_host_match() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-connection-filter-host.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  connection_filter:
  - name: bad-filter
    match:
      host:
      - example.com
    action:
      type: block"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("connection_filter rule bad-filter must not match host"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_unknown_edge_upstream_reference() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("unknown-upstream-ref.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: proxy
  upstream_proxy: typo-egress
upstreams:
- name: corp-egress
  url: http://proxy-a.local:3128"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("references unknown upstream"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_proxy_action_without_upstream_reference() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("missing-upstream-ref.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: proxy"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("action type Proxy requires action.upstream or edges[].upstream_proxy"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_disabled_streaming_requirement() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("disabled-streaming-requirement.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  streaming_requirement: disabled
  default_action:
    type: block"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("streaming_requirement: disabled is not supported"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_tunnel_rule_without_upstream_reference() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("missing-rule-upstream-ref.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  rules:
  - name: tunnel
    match:
      host:
      - example.com
    action:
      type: tunnel"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains(
            "edge forward rule tunnel: action type Tunnel requires action.upstream or edges[].upstream_proxy"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_unknown_keys() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("unknown-keys.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  unknown_edge_key: true
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  rules:
  - name: typo-match
    match:
      hosts:
      - example.com
    action:
      type: direct"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    let error_chain = err
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        error_chain.contains("unknown config keys") || error_chain.contains("unknown field"),
        "unexpected error: {err}"
    );
    assert!(
        error_chain.contains("unknown_edge_key"),
        "unexpected error: {err}"
    );

    fs::remove_dir_all(&dir).ok();
}
