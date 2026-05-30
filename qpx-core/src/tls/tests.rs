use super::ca::load_or_generate_ca;

#[test]
fn mitm_resolver_prewarm_populates_certificate_cache() {
    crate::tls::init_rustls_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = load_or_generate_ca(dir.path()).expect("ca");
    let mitm = ca.mitm_config().expect("mitm");

    assert!(mitm.resolver.prewarm_server_name("example.com"));
    assert!(mitm.resolver.prewarm_server_name("example.com"));
}

#[test]
fn mitm_resolver_cached_lookup_does_not_issue_on_miss() {
    crate::tls::init_rustls_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = load_or_generate_ca(dir.path()).expect("ca");
    let mitm = ca.mitm_config().expect("mitm");

    assert!(mitm.resolver.cached_server_name("example.com").is_none());
    assert!(mitm.resolver.prewarm_server_name("example.com"));
    assert!(mitm.resolver.cached_server_name("example.com").is_some());
}
