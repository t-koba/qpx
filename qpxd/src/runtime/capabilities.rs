use anyhow::{Result, anyhow};
use qpx_core::config::{
    ActionKind, Config, EdgeConfig, IngressEdgeConfig, IngressEdgeMode, ReverseEdgeConfig,
    RuleConfig, TlsCertConfig,
};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct BuildCapabilities {
    pub(crate) mitm: bool,
    pub(crate) acme: bool,
    pub(crate) auth_basic: bool,
    pub(crate) auth_digest: bool,
    pub(crate) auth_ldap: bool,
    pub(crate) tls_rustls: bool,
    pub(crate) tls_native: bool,
    pub(crate) http3: bool,
    pub(crate) http3_backend_h3: bool,
    pub(crate) http3_backend_qpx: bool,
}

impl BuildCapabilities {
    pub(crate) fn current() -> Self {
        Self {
            mitm: cfg!(feature = "mitm"),
            acme: cfg!(feature = "acme"),
            auth_basic: cfg!(feature = "auth-basic"),
            auth_digest: cfg!(feature = "auth-digest"),
            auth_ldap: cfg!(feature = "auth-ldap"),
            tls_rustls: cfg!(feature = "tls-rustls"),
            tls_native: cfg!(feature = "tls-native"),
            http3: cfg!(feature = "http3"),
            http3_backend_h3: cfg!(feature = "http3-backend-h3"),
            http3_backend_qpx: cfg!(feature = "http3-backend-qpx"),
        }
    }

    pub(crate) fn text_lines(self) -> [(&'static str, bool); 10] {
        [
            ("mitm", self.mitm),
            ("acme", self.acme),
            ("auth_basic", self.auth_basic),
            ("auth_digest", self.auth_digest),
            ("auth_ldap", self.auth_ldap),
            ("tls_rustls", self.tls_rustls),
            ("tls_native", self.tls_native),
            ("http3", self.http3),
            ("http3_backend_h3", self.http3_backend_h3),
            ("http3_backend_qpx", self.http3_backend_qpx),
        ]
    }
}

pub(crate) fn validate_build_capabilities(config: &Config, caps: &BuildCapabilities) -> Result<()> {
    let mut violations = Vec::new();

    validate_auth_capabilities(config, caps, &mut violations);
    validate_acme_capabilities(config, caps, &mut violations);

    for edge in &config.edges {
        match edge {
            EdgeConfig::Forward(edge) | EdgeConfig::Transparent(edge) => {
                validate_ingress_edge_capabilities(edge, caps, &mut violations);
            }
            EdgeConfig::Reverse(edge) => {
                validate_reverse_edge_capabilities(edge, caps, &mut violations);
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "config requires build capabilities that are not enabled:\n{}",
            violations.join("\n")
        ))
    }
}

fn validate_auth_capabilities(
    config: &Config,
    caps: &BuildCapabilities,
    violations: &mut Vec<String>,
) {
    if !caps.auth_basic && !config.security.auth.users.is_empty() {
        violations.push(
            "security.auth.users requires qpxd feature auth-basic for local auth".to_string(),
        );
    }
    if !caps.auth_digest {
        for user in &config.security.auth.users {
            if user.ha1.is_some() {
                violations.push(format!(
                    "security.auth.users {} ha1 requires qpxd feature auth-digest",
                    user.username
                ));
            }
        }
    }
    if !caps.auth_ldap && config.security.auth.ldap.is_some() {
        violations.push("security.auth.ldap requires qpxd feature auth-ldap".to_string());
    }
}

fn validate_acme_capabilities(
    config: &Config,
    caps: &BuildCapabilities,
    violations: &mut Vec<String>,
) {
    if caps.acme {
        return;
    }
    if config.acme.is_some() {
        violations.push("acme config requires qpxd feature acme".to_string());
    }
}

fn validate_ingress_edge_capabilities(
    edge: &IngressEdgeConfig,
    caps: &BuildCapabilities,
    violations: &mut Vec<String>,
) {
    let edge_kind = match edge.mode {
        IngressEdgeMode::Forward => "forward edge",
        IngressEdgeMode::Transparent => "transparent edge",
    };
    let edge_context = format!("{edge_kind} {}", edge.name);

    if edge
        .tls_inspection
        .as_ref()
        .map(|tls| tls.enabled)
        .unwrap_or(false)
        && !caps.mitm
    {
        violations.push(format!(
            "{edge_context} tls_inspection.enabled requires qpxd feature mitm"
        ));
    }

    validate_action_capabilities(&edge_context, &edge.default_action.kind, caps, violations);
    validate_rules_capabilities(&edge_context, edge.rules.as_slice(), caps, violations);

    if edge
        .http3
        .as_ref()
        .map(|http3| http3.enabled)
        .unwrap_or(false)
    {
        validate_http3_listener_capabilities(&edge_context, caps, violations);
        if edge
            .http3
            .as_ref()
            .and_then(|http3| http3.connect_ip.as_ref())
            .is_some_and(|connect_ip| connect_ip.enabled)
            && !caps.http3_backend_qpx
        {
            violations.push(format!(
                "{edge_context} http3.connect_ip.enabled requires qpxd feature http3-backend-qpx"
            ));
        }
        if matches!(edge.mode, IngressEdgeMode::Forward) && !caps.mitm {
            violations.push(format!(
                "{edge_context} http3.enabled currently requires qpxd feature mitm for generated forward HTTP/3 TLS certificates"
            ));
        }
    }
}

fn validate_reverse_edge_capabilities(
    edge: &ReverseEdgeConfig,
    caps: &BuildCapabilities,
    violations: &mut Vec<String>,
) {
    let edge_context = format!("reverse edge {}", edge.name);
    if edge.tls.is_some() && !caps.tls_rustls && !caps.tls_native {
        violations.push(format!(
            "{edge_context} tls requires qpxd feature tls-rustls or tls-native"
        ));
    }

    if let Some(tls) = edge.tls.as_ref() {
        for cert in &tls.certificates {
            validate_reverse_tls_certificate_capabilities(&edge_context, cert, caps, violations);
        }
    }

    if edge
        .http3
        .as_ref()
        .map(|http3| http3.enabled)
        .unwrap_or(false)
    {
        validate_http3_listener_capabilities(&edge_context, caps, violations);
    }
}

fn validate_reverse_tls_certificate_capabilities(
    edge_context: &str,
    cert: &TlsCertConfig,
    caps: &BuildCapabilities,
    violations: &mut Vec<String>,
) {
    if caps.acme {
        return;
    }
    if cert.cert.is_none() && cert.key.is_none() && cert.pkcs12.is_none() {
        violations.push(format!(
            "{edge_context} tls certificate {} uses ACME-managed material and requires qpxd feature acme",
            cert.sni
        ));
    }
}

fn validate_rules_capabilities(
    edge_context: &str,
    rules: &[RuleConfig],
    caps: &BuildCapabilities,
    violations: &mut Vec<String>,
) {
    for rule in rules {
        let rule_context = format!("{edge_context} rule {}", rule.name);
        if let Some(action) = rule.action.as_ref() {
            validate_action_capabilities(&rule_context, &action.kind, caps, violations);
        }
        if let Some(auth) = rule.auth.as_ref() {
            for provider in &auth.require {
                match provider.as_str() {
                    "local" if !caps.auth_basic => violations.push(format!(
                        "{rule_context} auth.require local requires qpxd feature auth-basic"
                    )),
                    "ldap" if !caps.auth_ldap => violations.push(format!(
                        "{rule_context} auth.require ldap requires qpxd feature auth-ldap"
                    )),
                    _ => {}
                }
            }
        }
    }
}

fn validate_action_capabilities(
    context: &str,
    kind: &ActionKind,
    caps: &BuildCapabilities,
    violations: &mut Vec<String>,
) {
    if matches!(kind, ActionKind::Inspect) && !caps.mitm {
        violations.push(format!(
            "{context} action inspect requires qpxd feature mitm"
        ));
    }
}

fn validate_http3_listener_capabilities(
    context: &str,
    caps: &BuildCapabilities,
    violations: &mut Vec<String>,
) {
    if !caps.http3 {
        violations.push(format!(
            "{context} http3.enabled requires qpxd feature http3"
        ));
    }
    if !caps.tls_rustls {
        violations.push(format!(
            "{context} http3.enabled requires qpxd feature tls-rustls"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_all() -> BuildCapabilities {
        BuildCapabilities {
            mitm: true,
            acme: true,
            auth_basic: true,
            auth_digest: true,
            auth_ldap: true,
            tls_rustls: true,
            tls_native: false,
            http3: true,
            http3_backend_h3: true,
            http3_backend_qpx: true,
        }
    }

    fn load_config(yaml: &str) -> Config {
        qpx_core::config::load_config_value(
            serde_yaml::from_str(yaml).expect("yaml"),
            "capability test",
        )
        .expect("config")
    }

    fn assert_rejected(yaml: &str, caps: BuildCapabilities, expected: &str) {
        let config = load_config(yaml);
        let err = validate_build_capabilities(&config, &caps).expect_err("rejected");
        let message = err.to_string();
        assert!(
            message.contains(expected),
            "expected {expected:?} in {message:?}"
        );
    }

    #[test]
    fn accepts_config_when_capabilities_are_present() {
        let config = load_config(
            r#"
security:
  auth:
    users:
    - username: alice
      password: secret
edges:
- kind: forward
  name: egress
  listen: 127.0.0.1:8080
  tls_inspection:
    enabled: true
  default_action:
    type: inspect
"#,
        );
        validate_build_capabilities(&config, &caps_all()).expect("capabilities");
    }

    #[test]
    fn rejects_tls_inspection_without_mitm() {
        let mut caps = caps_all();
        caps.mitm = false;
        assert_rejected(
            r#"
edges:
- kind: forward
  name: egress
  listen: 127.0.0.1:8080
  tls_inspection:
    enabled: true
  default_action:
    type: direct
"#,
            caps,
            "forward edge egress tls_inspection.enabled requires qpxd feature mitm",
        );
    }

    #[test]
    fn rejects_inspect_action_without_mitm() {
        let mut caps = caps_all();
        caps.mitm = false;
        assert_rejected(
            r#"
edges:
- kind: transparent
  name: transparent
  listen: 127.0.0.1:18080
  tls_inspection:
    enabled: true
  default_action:
    type: block
  rules:
  - name: inspect-example
    action:
      type: inspect
"#,
            caps,
            "transparent edge transparent rule inspect-example action inspect requires qpxd feature mitm",
        );
    }

    #[test]
    fn rejects_auth_features_that_are_not_built() {
        let mut caps = caps_all();
        caps.auth_basic = false;
        caps.auth_digest = false;
        caps.auth_ldap = false;
        assert_rejected(
            r#"
security:
  auth:
    users:
    - username: alice
      ha1: "sha-256:6fd6ccb92407d235ad4b54019200940672c20f7f5071111ee9fad443825285d4"
    ldap:
      url: ldaps://ldap.example.com
      bind_dn: cn=proxy,dc=example,dc=com
      bind_password_env: LDAP_BIND_PASSWORD
      user_base_dn: ou=users,dc=example,dc=com
      group_base_dn: ou=groups,dc=example,dc=com
edges:
- kind: forward
  name: egress
  listen: 127.0.0.1:8080
  default_action:
    type: block
  rules:
  - name: require-ldap
    auth:
      require: [ldap]
    action:
      type: direct
"#,
            caps,
            "security.auth.users requires qpxd feature auth-basic",
        );
    }

    #[test]
    fn rejects_acme_without_acme_feature() {
        let mut caps = caps_all();
        caps.acme = false;
        assert_rejected(
            r#"
acme:
  enabled: true
  email: ops@example.com
  terms_of_service_agreed: true
  http01_listen: 127.0.0.1:18081
state_dir: /tmp/qpx-capability-test
edges:
- kind: reverse
  name: site
  listen: 127.0.0.1:8443
  tls:
    certificates:
    - sni: site.example.com
  routes:
  - match:
      host: [site.example.com]
    target:
      type: upstream
      upstreams: [http://127.0.0.1:8080]
"#,
            caps,
            "acme config requires qpxd feature acme",
        );
    }

    #[test]
    fn rejects_http3_without_http3_rustls_and_forward_mitm() {
        let mut caps = caps_all();
        caps.http3 = false;
        caps.tls_rustls = false;
        caps.mitm = false;
        assert_rejected(
            r#"
edges:
- kind: forward
  name: forward-h3
  listen: 127.0.0.1:8080
  default_action:
    type: direct
  http3:
    enabled: true
    listen: 127.0.0.1:8443
"#,
            caps,
            "forward edge forward-h3 http3.enabled requires qpxd feature http3",
        );
    }

    #[test]
    fn rejects_reverse_tls_without_tls_backend() {
        let mut caps = caps_all();
        caps.tls_rustls = false;
        caps.tls_native = false;
        assert_rejected(
            r#"
edges:
- kind: reverse
  name: site
  listen: 127.0.0.1:8443
  tls:
    certificates:
    - sni: site.example.com
      cert: /tmp/site.crt
      key: /tmp/site.key
  routes:
  - match:
      host: [site.example.com]
    target:
      type: upstream
      upstreams: [http://127.0.0.1:8080]
"#,
            caps,
            "reverse edge site tls requires qpxd feature tls-rustls or tls-native",
        );
    }
}
