use super::*;

#[test]
fn path_rewrite_strip_prefix() {
    let mut req = make_req("/api/v1/users");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: None,
            regex: None,
        },
    );
    assert_eq!(req.uri().path(), "/users");
}

#[test]
fn path_rewrite_add_prefix() {
    let mut req = make_req("/users");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: None,
            add_prefix: Some("/v2".into()),
            regex: None,
        },
    );
    assert_eq!(req.uri().path(), "/v2/users");
}

#[test]
fn path_rewrite_strip_and_add() {
    let mut req = make_req("/api/v1/users");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: Some("/v2".into()),
            regex: None,
        },
    );
    assert_eq!(req.uri().path(), "/v2/users");
}

#[test]
fn path_rewrite_preserves_query() {
    let mut req = make_req("/api/v1/users?q=foo&limit=10");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: None,
            regex: None,
        },
    );
    assert_eq!(
        req.uri().path_and_query().unwrap().as_str(),
        "/users?q=foo&limit=10"
    );
}

#[test]
fn path_rewrite_root_only() {
    let mut req = make_req("/api/v1");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: None,
            regex: None,
        },
    );
    assert_eq!(req.uri().path(), "/");
}

#[test]
fn path_rewrite_no_match_passthrough() {
    let mut req = make_req("/other/path");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: None,
            regex: None,
        },
    );
    assert_eq!(req.uri().path(), "/other/path");
}

#[test]
fn path_rewrite_regex_replace() {
    let mut req = make_req("/api/v1/users");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: None,
            add_prefix: None,
            regex: Some(CompiledRegexPathRewrite {
                pattern: Regex::new(r"^/api/v1/(.*)$").unwrap(),
                replace: "/v2/$1".to_string(),
            }),
        },
    );
    assert_eq!(req.uri().path(), "/v2/users");
}

#[test]
fn path_rewrite_regex_ensures_leading_slash() {
    let mut req = make_req("/api/v1/users");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: None,
            add_prefix: None,
            regex: Some(CompiledRegexPathRewrite {
                pattern: Regex::new(r"^/api/v1/(.*)$").unwrap(),
                replace: "$1".to_string(),
            }),
        },
    );
    assert_eq!(req.uri().path(), "/users");
}
