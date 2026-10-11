use super::ca::load_or_generate_ca;

#[test]
fn mitm_resolver_prewarm_populates_certificate_cache() {
    crate::tls::init_rustls_crypto_provider().expect("crypto provider");
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = load_or_generate_ca(dir.path()).expect("ca");
    let mitm = ca.mitm_config().expect("mitm");

    assert!(mitm.resolver.prewarm_server_name("example.com"));
    assert!(mitm.resolver.prewarm_server_name("example.com"));
}

#[test]
fn mitm_resolver_cached_lookup_does_not_issue_on_miss() {
    crate::tls::init_rustls_crypto_provider().expect("crypto provider");
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = load_or_generate_ca(dir.path()).expect("ca");
    let mitm = ca.mitm_config().expect("mitm");

    assert!(mitm.resolver.cached_server_name("example.com").is_none());
    assert!(mitm.resolver.prewarm_server_name("example.com"));
    assert!(mitm.resolver.cached_server_name("example.com").is_some());
}

#[test]
fn tls_server_configs_disable_early_data() {
    crate::tls::init_rustls_crypto_provider().expect("crypto provider");
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = load_or_generate_ca(dir.path()).expect("ca");
    let mitm = ca.mitm_config().expect("mitm");
    assert_eq!(
        mitm.server_config.max_early_data_size, 0,
        "MITM server config must keep RFC 8470 early data disabled"
    );
}
