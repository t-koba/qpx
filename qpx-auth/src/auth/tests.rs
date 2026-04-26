use super::*;
#[cfg(any(feature = "digest-auth", feature = "ldap-auth"))]
use std::time::Duration;

#[cfg(feature = "ldap-auth")]
#[test]
fn ldap_filter_escape_escapes_reserved_chars() {
    let escaped = ldap_escape_filter_value("*()\\\u{0}");
    assert_eq!(escaped, "\\2a\\28\\29\\5c\\00");
}

#[cfg(feature = "digest-auth")]
#[test]
fn nonce_store_rejects_replayed_nc() {
    let store = NonceStore::new(Duration::from_secs(60));
    let nonce = store.issue_digest_nonce();
    let nc1 = store.parse_digest_nc(&nonce, "00000001").expect("nc1");
    assert!(store.mark_digest_nc_used(&nonce, nc1));
    assert!(store.parse_digest_nc(&nonce, "00000002").is_some());
    assert!(store.parse_digest_nc(&nonce, "00000001").is_none());
    assert!(store.parse_digest_nc(&nonce, "00000000").is_none());
    let nc2 = store.parse_digest_nc(&nonce, "00000002").expect("nc2");
    assert!(store.mark_digest_nc_used(&nonce, nc2));
    assert!(!store.mark_digest_nc_used(&nonce, nc2.saturating_sub(1)));
}

#[cfg(feature = "digest-auth")]
#[test]
fn nonce_store_caps_growth_on_issue() {
    let store = NonceStore::with_max_entries(Duration::from_secs(3600), 4);
    for _ in 0..32 {
        let _ = store.issue_digest_nonce();
    }
    assert!(store.len() <= 4);
}

#[cfg(feature = "ldap-auth")]
#[test]
fn ldap_cache_caps_growth() {
    let cache = LdapCache::with_max_entries(Duration::from_secs(3600), 4);
    for i in 0..32 {
        cache.put(
            format!("user{i}").as_str(),
            format!("pass{i}").as_str(),
            vec!["dev".to_string()],
        );
    }
    assert!(cache.len() <= 4);
}

#[test]
fn quoted_header_escape_escapes_quote_and_backslash() {
    let escaped = escape_quoted_header_value("a\"b\\c");
    assert_eq!(escaped, "a\\\"b\\\\c");
}
