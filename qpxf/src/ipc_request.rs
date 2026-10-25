use anyhow::{Result, anyhow};
use http::Uri;
use std::collections::HashMap;
use std::sync::Arc;

use crate::executor::{CgiRequest, Executor};
use crate::router::Router;
use qpx_core::http_content_length::ContentLengthError;
use qpx_core::ipc::meta::{IpcRequestHeaders, IpcRequestMeta, IpcResponseHeaders, IpcResponseMeta};

pub(crate) struct IpcPlainResponse {
    pub(crate) status: u16,
    pub(crate) body: &'static [u8],
}

impl IpcPlainResponse {
    pub(crate) const fn new(status: u16, body: &'static [u8]) -> Self {
        Self { status, body }
    }

    pub(crate) fn meta(&self) -> IpcResponseMeta {
        plaintext_meta(self.status)
    }
}

pub(crate) struct IpcRequestPlan {
    pub(crate) executor: Arc<dyn Executor>,
    pub(crate) cgi_req: CgiRequest,
    pub(crate) expected_stdin_bytes: Option<usize>,
}

pub(crate) fn plaintext_meta(status: u16) -> IpcResponseMeta {
    IpcResponseMeta {
        status,
        headers: IpcResponseHeaders::from_pairs(vec![(
            "Content-Type".to_string(),
            "text/plain".to_string(),
        )]),
    }
}

pub(crate) fn declared_stdin_bytes(headers: &IpcRequestHeaders) -> Result<Option<usize>> {
    let declared = headers.declared_content_length().map_err(|err| match err {
        ContentLengthError::Conflicting => anyhow!("conflicting Content-Length values"),
        ContentLengthError::InvalidValue | ContentLengthError::InvalidHeader => {
            anyhow!("invalid Content-Length value")
        }
    })?;
    let Some(length) = declared else {
        return Ok(None);
    };
    Ok(Some(
        usize::try_from(length).map_err(|_| anyhow!("Content-Length too large"))?,
    ))
}

pub(crate) fn meta_params_bytes(meta: &IpcRequestMeta) -> usize {
    meta.params
        .iter()
        .map(|(k, v)| k.len().saturating_add(v.len()))
        .sum()
}

pub(crate) fn plan_ipc_request(
    meta: IpcRequestMeta,
    router: &Router,
    max_params_bytes: usize,
    max_stdin_bytes: usize,
) -> Result<std::result::Result<IpcRequestPlan, IpcPlainResponse>> {
    if meta_params_bytes(&meta) > max_params_bytes {
        return Ok(Err(IpcPlainResponse::new(413, b"params too large")));
    }

    let uri: Uri = meta
        .uri
        .parse()
        .map_err(|e| anyhow!("invalid IPC request URI: {e}"))?;
    let request_path = uri.path().to_string();
    let query_string = uri.query().unwrap_or("").to_string();
    let route_host = meta.headers.route_host(&uri);

    let (executor, matched_prefix, verified_context) =
        match router.route(request_path.as_str(), route_host.as_deref()) {
            Some(v) => v,
            None => return Ok(Err(IpcPlainResponse::new(404, b"no handler matched"))),
        };
    let (script_name, path_info) =
        split_script_name_path_info(request_path.as_str(), matched_prefix.as_deref());

    let (server_name, server_port) = meta.headers.server_name_and_port(&uri);

    let declared_stdin_bytes = match declared_stdin_bytes(&meta.headers) {
        Ok(value) => value,
        Err(_) => return Ok(Err(IpcPlainResponse::new(400, b"invalid content-length"))),
    };
    let content_type = meta.headers.content_type();
    let remote_addr = meta.params.get("REMOTE_ADDR").cloned();
    let remote_port = meta.params.get("REMOTE_PORT").and_then(|p| p.parse().ok());
    let cgi_req = CgiRequest {
        script_name,
        path_info,
        query_string,
        request_method: meta.method,
        content_type,
        content_length: declared_stdin_bytes.unwrap_or(0),
        declared_content_length: declared_stdin_bytes,
        server_protocol: meta.server_protocol,
        server_name,
        server_port,
        remote_addr,
        remote_port,
        http_headers: meta.headers.into_cgi_headers(),
        matched_prefix,
        identity_env: verified_context_env(
            meta.verified_identity.as_ref(),
            meta.authorization_decision.as_ref(),
            verified_context,
        )?,
    };

    if cgi_req.content_length > max_stdin_bytes {
        return Ok(Err(IpcPlainResponse::new(413, b"request body too large")));
    }

    Ok(Ok(IpcRequestPlan {
        executor,
        cgi_req,
        expected_stdin_bytes: declared_stdin_bytes,
    }))
}

fn verified_context_env(
    identity: Option<&qpx_core::ipc::meta::VerifiedIdentityContext>,
    authorization: Option<&qpx_core::ipc::meta::AuthorizationDecisionContext>,
    mode: crate::config::VerifiedContextMode,
) -> Result<HashMap<String, String>> {
    if mode == crate::config::VerifiedContextMode::None {
        return Ok(HashMap::new());
    }
    let mut env = HashMap::new();
    if let Some(identity) = identity {
        if let Some(subject) = identity.subject.as_ref() {
            env.insert("QPX_VERIFIED_SUBJECT".to_string(), subject.clone());
        }
        if let Some(issuer) = identity.issuer.as_ref() {
            env.insert("QPX_VERIFIED_ISSUER".to_string(), issuer.clone());
        }
        if let Some(tenant) = identity.tenant.as_ref() {
            env.insert("QPX_VERIFIED_TENANT".to_string(), tenant.clone());
        }
        if let Some(assurance) = identity.assurance.as_ref() {
            env.insert("QPX_VERIFIED_ASSURANCE".to_string(), assurance.clone());
        }
        env.insert(
            "QPX_VERIFIED_GROUPS_JSON".to_string(),
            serde_json::to_string(&identity.groups)?,
        );
        env.insert(
            "QPX_VERIFIED_ROLES_JSON".to_string(),
            serde_json::to_string(&identity.roles)?,
        );
        env.insert(
            "QPX_VERIFIED_ENTITLEMENTS_JSON".to_string(),
            serde_json::to_string(&identity.entitlements)?,
        );
    }
    if let Some(authorization) = authorization {
        if let Some(decision_id) = authorization.external_decision_id.as_ref() {
            env.insert("QPX_EXTERNAL_DECISION_ID".to_string(), decision_id.clone());
        }
        if let Some(policy_id) = authorization.policy_id.as_ref() {
            env.insert("QPX_AUTHORIZATION_POLICY_ID".to_string(), policy_id.clone());
        }
        env.insert(
            "QPX_AUTHORIZATION_POLICY_TAGS_JSON".to_string(),
            serde_json::to_string(&authorization.policy_tags)?,
        );
    }
    Ok(env)
}

fn split_script_name_path_info(path: &str, matched_prefix: Option<&str>) -> (String, String) {
    let prefix = matched_prefix.unwrap_or("");
    if !prefix.is_empty() && prefix != "/" && !prefix.ends_with('/') {
        let normalized = prefix.trim_end_matches('/').to_string();
        if path == normalized {
            return (normalized, String::new());
        }
        if let Some(path_info) = path.strip_prefix(normalized.as_str())
            && path_info.starts_with('/')
        {
            return (normalized, path_info.to_string());
        }
    }

    let suffix = path.strip_prefix(prefix).unwrap_or(path);
    let suffix = suffix.strip_prefix('/').unwrap_or(suffix);
    if suffix.is_empty() {
        return (normalize_script_name(prefix, path), String::new());
    }
    let script_tail_end = suffix.find('/').unwrap_or(suffix.len());
    let script_tail = &suffix[..script_tail_end];
    let path_info = suffix[script_tail_end..].to_string();
    let script_name = if prefix.is_empty() || prefix == "/" {
        format!("/{script_tail}")
    } else {
        format!("{}/{}", prefix.trim_end_matches('/'), script_tail)
    };
    (script_name, path_info)
}

fn normalize_script_name(prefix: &str, fallback: &str) -> String {
    if prefix == "/" {
        "/".to_string()
    } else if prefix.is_empty() {
        if fallback.is_empty() {
            "/".to_string()
        } else {
            fallback.to_string()
        }
    } else {
        prefix.trim_end_matches('/').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{declared_stdin_bytes, split_script_name_path_info, verified_context_env};
    use crate::config::VerifiedContextMode;
    use qpx_core::ipc::meta::VerifiedIdentityContext;

    #[test]
    fn invalid_uri_diagnostic_omits_userinfo() {
        let config = serde_json::from_str::<crate::config::QpxfConfig>("{}").unwrap();
        let router = crate::router::Router::new(&config).unwrap();
        let meta = serde_json::from_value(serde_json::json!({
            "method": "GET",
            "uri": "http://synthetic-user:synthetic-pass@host/invalid target",
            "server_protocol": "HTTP/1.1",
            "headers": [], "params": {}
        }))
        .unwrap();
        let err = match super::plan_ipc_request(meta, &router, 1024 * 1024, 1024) {
            Err(err) => err,
            Ok(_) => panic!("invalid URI must fail"),
        };
        let diagnostic = format!("{err:?}");
        assert!(diagnostic.contains("invalid IPC request URI"));
        assert!(!diagnostic.contains("synthetic-user"));
        assert!(!diagnostic.contains("synthetic-pass"));
    }

    #[test]
    fn ipc_plan_preserves_routing_cgi_joins_and_length_validation() {
        let config = serde_json::from_value(serde_json::json!({
            "handlers": [{
                "match": {"path_prefix": "/app", "host": "first.test"},
                "backend": {"type": "scgi", "address": "127.0.0.1:9000"}
            }]
        }))
        .unwrap();
        let router = crate::router::Router::new(&config).unwrap();
        let meta: qpx_core::ipc::meta::IpcRequestMeta = serde_json::from_value(serde_json::json!({
            "method": "POST", "uri": "https://uri.test/app/path?q=1",
            "server_protocol": "HTTP/2", "params": {},
            "headers": [
                ["HOST", "first.test:8080"], ["Host", "ignored.test"],
                ["Content-Type", "text/plain"], ["content-type", "ignored/type"],
                ["X-Dup", "first"], ["x-dup", "second"],
                ["Cookie", "a=1"], ["COOKIE", "b=2"],
                ["Content-Length", "5"], ["content-length", "5, 5"]
            ]
        }))
        .unwrap();
        let plan = match super::plan_ipc_request(meta.clone(), &router, 1024, 1024).unwrap() {
            Ok(plan) => plan,
            Err(response) => panic!("unexpected status {}", response.status),
        };
        assert_eq!(plan.expected_stdin_bytes, Some(5));
        let req = plan.cgi_req;
        assert_eq!(req.script_name, "/app");
        assert_eq!(req.path_info, "/path");
        assert_eq!(req.query_string, "q=1");
        assert_eq!(req.server_name, "first.test");
        assert_eq!(req.server_port, 8080);
        assert_eq!(req.content_type, "text/plain");
        assert_eq!(req.declared_content_length, Some(5));
        let env = req.cgi_environment().into_variables();
        assert_eq!(env["HTTP_HOST"], "first.test:8080, ignored.test");
        assert_eq!(env["HTTP_X_DUP"], "first, second");
        assert_eq!(env["HTTP_COOKIE"], "a=1; b=2");
        assert_eq!(env["CONTENT_TYPE"], "text/plain");
        assert_eq!(env["CONTENT_LENGTH"], "5");
        for invalid in ["6", "+5", "nope"] {
            let mut rejected = meta.clone();
            rejected
                .headers
                .push(("Content-Length".into(), invalid.into()));
            match super::plan_ipc_request(rejected, &router, 1024, 1024).unwrap() {
                Err(response) => assert_eq!(response.status, 400),
                Ok(_) => panic!("invalid length accepted"),
            }
        }
    }

    #[test]
    fn declared_content_length_accepts_repeated_equal_values() {
        let headers = vec![
            ("Content-Length".to_string(), "5".to_string()),
            ("content-length".to_string(), "5, 5".to_string()),
        ];
        assert_eq!(
            declared_stdin_bytes(&qpx_core::ipc::meta::IpcRequestHeaders::from_pairs(headers))
                .expect("length"),
            Some(5)
        );
    }

    #[test]
    fn declared_content_length_rejects_conflicting_values() {
        let headers = vec![
            ("Content-Length".to_string(), "5".to_string()),
            ("content-length".to_string(), "6".to_string()),
        ];
        assert!(
            declared_stdin_bytes(&qpx_core::ipc::meta::IpcRequestHeaders::from_pairs(headers))
                .is_err()
        );
    }

    #[test]
    fn declared_content_length_rejects_invalid_values() {
        let headers = vec![("Content-Length".to_string(), "nope".to_string())];
        assert!(
            declared_stdin_bytes(&qpx_core::ipc::meta::IpcRequestHeaders::from_pairs(headers))
                .is_err()
        );
    }

    #[test]
    fn declared_content_length_rejects_a_signed_value() {
        // The owner's grammar is `1*DIGIT`, so a leading plus sign names no
        // length and the request is refused.
        let headers = vec![("Content-Length".to_string(), "+5".to_string())];
        assert!(
            declared_stdin_bytes(&qpx_core::ipc::meta::IpcRequestHeaders::from_pairs(headers))
                .is_err()
        );
    }

    #[test]
    fn splits_script_name_and_path_info_after_matched_prefix() {
        let (script_name, path_info) =
            split_script_name_path_info("/cgi-bin/app/foo/bar", Some("/cgi-bin/"));
        assert_eq!(script_name, "/cgi-bin/app");
        assert_eq!(path_info, "/foo/bar");
    }

    #[test]
    fn treats_non_slash_terminated_prefix_as_script_name() {
        let (script_name, path_info) =
            split_script_name_path_info("/cgi-bin/nested/app/foo", Some("/cgi-bin/nested/app"));
        assert_eq!(script_name, "/cgi-bin/nested/app");
        assert_eq!(path_info, "/foo");
    }

    #[test]
    fn exact_non_slash_terminated_prefix_is_script_name() {
        let (script_name, path_info) =
            split_script_name_path_info("/cgi-bin/nested/app", Some("/cgi-bin/nested/app"));
        assert_eq!(script_name, "/cgi-bin/nested/app");
        assert_eq!(path_info, "");
    }

    #[test]
    fn splits_without_matched_prefix() {
        let (script_name, path_info) = split_script_name_path_info("/app/foo", None);
        assert_eq!(script_name, "/app");
        assert_eq!(path_info, "/foo");
    }

    #[test]
    fn verified_identity_requires_explicit_handler_opt_in() {
        let identity = VerifiedIdentityContext {
            subject: Some("alice".to_string()),
            groups: vec!["finance".to_string()],
            ..Default::default()
        };
        assert!(
            verified_context_env(Some(&identity), None, VerifiedContextMode::None)
                .unwrap()
                .is_empty()
        );
        let env = verified_context_env(Some(&identity), None, VerifiedContextMode::CgiEnv).unwrap();
        assert_eq!(env["QPX_VERIFIED_SUBJECT"], "alice");
        assert_eq!(env["QPX_VERIFIED_GROUPS_JSON"], "[\"finance\"]");
    }
}
