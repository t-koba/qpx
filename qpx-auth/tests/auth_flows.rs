use http::HeaderMap;
use qpx_auth::{AuthOutcome, Authenticator};
use qpx_core::config::{AuthConfig, LocalUser};

#[cfg(feature = "digest-auth")]
use sha2::{Digest, Sha256};

#[cfg(any(feature = "basic-auth", feature = "digest-auth"))]
fn local_config() -> AuthConfig {
    AuthConfig {
        users: vec![LocalUser {
            username: "alice".to_string(),
            password: Some("wonderland".to_string()),
            ha1: None,
        }],
        ldap: None,
    }
}

#[cfg(feature = "basic-auth")]
#[tokio::test]
async fn basic_auth_allows_valid_local_credentials() {
    let auth = Authenticator::new(&local_config(), "qpx").expect("authenticator");
    let mut headers = HeaderMap::new();
    headers.insert(
        "proxy-authorization",
        http::HeaderValue::from_static("Basic YWxpY2U6d29uZGVybGFuZA=="),
    );

    let outcome = auth
        .authenticate_proxy(None, &headers, &["local".to_string()], "GET", "/resource")
        .await
        .expect("authenticate");
    let AuthOutcome::Allowed(user) = outcome else {
        panic!("valid Basic credentials should be allowed");
    };
    assert_eq!(user.username, "alice");
    assert_eq!(user.provider, "local");
}

#[cfg(feature = "basic-auth")]
#[tokio::test]
async fn basic_auth_challenges_invalid_local_credentials() {
    let auth = Authenticator::new(&local_config(), "qpx").expect("authenticator");
    let mut headers = HeaderMap::new();
    headers.insert(
        "proxy-authorization",
        http::HeaderValue::from_static("Basic YWxpY2U6d3Jvbmc="),
    );

    let outcome = auth
        .authenticate_proxy(None, &headers, &["local".to_string()], "GET", "/resource")
        .await
        .expect("authenticate");
    let AuthOutcome::Challenge(challenge) = outcome else {
        panic!("invalid Basic credentials should be challenged");
    };
    assert!(
        challenge
            .header_values
            .iter()
            .any(|value| value.starts_with("Basic "))
    );
}

#[cfg(feature = "digest-auth")]
#[tokio::test]
async fn digest_auth_allows_rfc7616_sha256_response_from_challenge() {
    let auth = Authenticator::new(&local_config(), "qpx").expect("authenticator");
    let challenge = auth
        .authenticate_proxy(
            None,
            &HeaderMap::new(),
            &["local".to_string()],
            "GET",
            "/resource",
        )
        .await
        .expect("initial challenge");
    let AuthOutcome::Challenge(challenge) = challenge else {
        panic!("missing credentials should return a challenge");
    };
    let digest_challenge = challenge
        .header_values
        .iter()
        .find(|value| value.starts_with("Digest "))
        .expect("digest challenge");
    let params = parse_digest_fields(digest_challenge.trim_start_matches("Digest "));
    let nonce = params.get("nonce").expect("nonce");
    let opaque = params.get("opaque").expect("opaque");
    let cnonce = "client-nonce";
    let nc = "00000001";
    let response = digest_response(DigestResponseInput {
        username: "alice",
        realm: "qpx",
        password: "wonderland",
        method: "GET",
        uri: "/resource",
        nonce,
        nc,
        cnonce,
    });
    let header = format!(
        "Digest username=\"alice\", realm=\"qpx\", nonce=\"{nonce}\", uri=\"/resource\", algorithm=SHA-256, qop=auth, nc={nc}, cnonce=\"{cnonce}\", opaque=\"{opaque}\", response=\"{response}\""
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        "proxy-authorization",
        http::HeaderValue::from_str(&header).expect("authorization header"),
    );

    let outcome = auth
        .authenticate_proxy(None, &headers, &["local".to_string()], "GET", "/resource")
        .await
        .expect("authenticate");
    let AuthOutcome::Allowed(user) = outcome else {
        panic!("valid Digest credentials should be allowed");
    };
    assert_eq!(user.username, "alice");
    assert_eq!(user.provider, "local");
}

#[cfg(feature = "digest-auth")]
struct DigestResponseInput<'a> {
    username: &'a str,
    realm: &'a str,
    password: &'a str,
    method: &'a str,
    uri: &'a str,
    nonce: &'a str,
    nc: &'a str,
    cnonce: &'a str,
}

#[cfg(feature = "digest-auth")]
fn digest_response(input: DigestResponseInput<'_>) -> String {
    let ha1 =
        sha256_hex(format!("{}:{}:{}", input.username, input.realm, input.password).as_bytes());
    let ha2 = sha256_hex(format!("{}:{}", input.method, input.uri).as_bytes());
    sha256_hex(
        format!(
            "{}:{}:{}:{}:auth:{}",
            ha1, input.nonce, input.nc, input.cnonce, ha2
        )
        .as_bytes(),
    )
}

#[cfg(feature = "digest-auth")]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(feature = "digest-auth")]
fn parse_digest_fields(input: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for part in input.split(',') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        out.insert(
            name.trim().to_string(),
            value.trim().trim_matches('"').to_string(),
        );
    }
    out
}

#[cfg(feature = "ldap-auth")]
#[test]
fn ldap_config_builds_without_network_io() {
    let config = AuthConfig {
        users: Vec::new(),
        ldap: Some(qpx_core::config::LdapConfig {
            url: "ldap://127.0.0.1:389".to_string(),
            bind_dn: "cn=service,dc=example,dc=test".to_string(),
            bind_password_env: "PATH".to_string(),
            user_base_dn: "ou=users,dc=example,dc=test".to_string(),
            group_base_dn: "ou=groups,dc=example,dc=test".to_string(),
            timeout_ms: 25,
            require_starttls: true,
            user_filter: "(&(objectClass=person)(uid={username}))".to_string(),
            group_filter: "(&(objectClass=groupOfNames)(member={user_dn}))".to_string(),
            group_attr: "cn".to_string(),
        }),
    };

    let auth = Authenticator::new(&config, "qpx").expect("LDAP config should compile");
    assert_eq!(auth.realm(), "qpx");
}
