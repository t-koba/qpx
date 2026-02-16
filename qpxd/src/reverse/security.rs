use super::router::normalize_host_for_match;
use anyhow::{anyhow, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use hyper::{Body, Request};
use qpx_core::config::ReverseConfig;

#[derive(Clone)]
pub(crate) struct ReverseTlsHostPolicy {
    enforce_sni_host_match: bool,
    exception_globs: Option<GlobSet>,
}

impl ReverseTlsHostPolicy {
    pub(super) fn from_config(reverse: &ReverseConfig) -> Result<Self> {
        let exception_globs = if reverse.sni_host_exceptions.is_empty() {
            None
        } else {
            let mut builder = GlobSetBuilder::new();
            for pattern in &reverse.sni_host_exceptions {
                builder.add(Glob::new(pattern)?);
            }
            Some(builder.build()?)
        };
        Ok(Self {
            enforce_sni_host_match: reverse.enforce_sni_host_match,
            exception_globs,
        })
    }

    pub(super) fn validate_request(
        &self,
        req: &Request<Body>,
        tls_sni: Option<&str>,
        tls_terminated: bool,
    ) -> Result<()> {
        if !self.enforce_sni_host_match {
            return Ok(());
        }
        if !tls_terminated {
            return Ok(());
        }

        let Some(host) = request_host(req) else {
            return Ok(());
        };
        let Some(sni_raw) = tls_sni else {
            return Err(anyhow!("missing TLS SNI"));
        };
        let sni = normalize_host_for_match(sni_raw);
        if sni.is_empty() {
            return Err(anyhow!("missing TLS SNI"));
        }

        if host == sni {
            return Ok(());
        }
        if self
            .exception_globs
            .as_ref()
            .map(|set| set.is_match(host.as_str()) && set.is_match(sni.as_str()))
            .unwrap_or(false)
        {
            return Ok(());
        }

        Err(anyhow!("SNI/Host mismatch"))
    }
}

fn request_host(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .map(normalize_host_for_match)
        .filter(|h| !h.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use globset::{Glob, GlobSetBuilder};
    use hyper::Request;

    fn req_with_host(host: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("https://{host}/"))
            .header(http::header::HOST, host)
            .body(Body::empty())
            .expect("request")
    }

    #[test]
    fn tls_enforces_sni_host_match() {
        let policy = ReverseTlsHostPolicy {
            enforce_sni_host_match: true,
            exception_globs: None,
        };
        let req = req_with_host("example.com");
        assert!(policy
            .validate_request(&req, Some("example.com"), true)
            .is_ok());
        assert!(policy
            .validate_request(&req, Some("other.example"), true)
            .is_err());
    }

    #[test]
    fn plain_http_skips_sni_host_enforcement() {
        let policy = ReverseTlsHostPolicy {
            enforce_sni_host_match: true,
            exception_globs: None,
        };
        let req = req_with_host("example.com");
        assert!(policy.validate_request(&req, None, false).is_ok());
    }

    #[test]
    fn exception_pattern_allows_mismatch() {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new("*.example.com").expect("glob"));
        let policy = ReverseTlsHostPolicy {
            enforce_sni_host_match: true,
            exception_globs: Some(builder.build().expect("glob set")),
        };
        let req = req_with_host("api.example.com");
        assert!(policy
            .validate_request(&req, Some("edge.example.com"), true)
            .is_ok());
    }

    #[test]
    fn sni_only_exception_does_not_bypass_host_check() {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new("*.example.com").expect("glob"));
        let policy = ReverseTlsHostPolicy {
            enforce_sni_host_match: true,
            exception_globs: Some(builder.build().expect("glob set")),
        };
        let req = req_with_host("internal.local");
        assert!(policy
            .validate_request(&req, Some("edge.example.com"), true)
            .is_err());
    }
}
