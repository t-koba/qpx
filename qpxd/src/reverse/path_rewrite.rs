use crate::http::body::Body;
use hyper::Request;
use metrics::counter;
use tracing::warn;

use crate::reverse::router::CompiledPathRewrite;

pub(super) fn apply_path_rewrite(req: &mut Request<Body>, rewrite: &CompiledPathRewrite) {
    let pq = req.uri().path_and_query();
    let path = pq.map(|pq| pq.path()).unwrap_or("/");
    let query = pq.and_then(|pq| pq.query());

    let mut new_path = path.to_string();
    if let Some(prefix) = &rewrite.strip_prefix {
        if let Some(rest) = new_path.strip_prefix(prefix.as_str()) {
            new_path = if rest.is_empty() || !rest.starts_with('/') {
                format!("/{rest}")
            } else {
                rest.to_string()
            };
        }
    }
    if let Some(prefix) = &rewrite.add_prefix {
        new_path = format!("{prefix}{new_path}");
    }
    if let Some(regex) = rewrite.regex.as_ref() {
        new_path = regex
            .pattern
            .replace(new_path.as_str(), regex.replace.as_str())
            .to_string();
        if new_path.is_empty() {
            new_path = "/".to_string();
        } else if !new_path.starts_with('/') {
            new_path = format!("/{new_path}");
        }
    }
    if let Some(q) = query {
        new_path = format!("{new_path}?{q}");
    }
    match new_path.parse::<http::Uri>() {
        Ok(new_uri) => {
            *req.uri_mut() = new_uri;
        }
        Err(err) => {
            counter!(crate::runtime::metric_names()
                .reverse_path_rewrite_invalid_total
                .clone())
            .increment(1);
            warn!(
                error = ?err,
                "reverse path_rewrite produced invalid URI; keeping original"
            );
        }
    }
}
