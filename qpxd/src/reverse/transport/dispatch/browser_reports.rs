use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_core::http_message::{Headers, OrdinaryHeaderName, Request as OwnerRequest};
use qpx_core::redaction::redact_uri_query_keys;
use qpx_http::body::Body;

pub(super) async fn collect_browser_reports(
    req: OwnerRequest<Body>,
    config: &qpx_core::config::ReportingCollectorConfig,
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
    route_headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    redact_query_keys: &[String],
) -> Result<Response<Body>> {
    if request_method != http::Method::POST {
        let mut response = reporting_problem_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Browser report method is not allowed",
            "Reporting endpoints accept POST requests only",
        )?;
        response
            .headers_mut()
            .insert(http::header::ALLOW, http::HeaderValue::from_static("POST"));
        return Ok(crate::http::protocol::l7::finalize_response_with_headers(
            request_method,
            request_version,
            proxy_name,
            response,
            route_headers,
            false,
        ));
    }
    if req.headers().contains_key(
        &OrdinaryHeaderName::try_from(http::header::CONTENT_ENCODING).expect("ordinary header"),
    ) {
        return Ok(crate::http::protocol::l7::finalize_response_with_headers(
            request_method,
            request_version,
            proxy_name,
            reporting_problem_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Encoded browser report is not supported",
                "Content-Encoding is not accepted by the report collector",
            )?,
            route_headers,
            false,
        ));
    }
    let content_type = match single_media_type(req.headers()) {
        Ok(content_type) => content_type,
        Err(error) => {
            return Ok(crate::http::protocol::l7::finalize_response_with_headers(
                request_method,
                request_version,
                proxy_name,
                reporting_problem_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid browser report Content-Type",
                    error.to_string().as_str(),
                )?,
                route_headers,
                false,
            ));
        }
    };
    let legacy = match content_type.as_str() {
        "application/reports+json" => false,
        "application/csp-report" if config.accept_legacy_csp_reports => true,
        _ => {
            return Ok(crate::http::protocol::l7::finalize_response_with_headers(
                request_method,
                request_version,
                proxy_name,
                reporting_problem_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Unsupported browser report media type",
                    "Expected application/reports+json",
                )?,
                route_headers,
                false,
            ));
        }
    };
    let bytes = match collect_bounded_report_body(req.into_head_and_body().1, config.max_body_bytes)
        .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(crate::http::protocol::l7::finalize_response_with_headers(
                request_method,
                request_version,
                proxy_name,
                reporting_problem_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Browser report body is too large",
                    error.to_string().as_str(),
                )?,
                route_headers,
                false,
            ));
        }
    };
    let payload: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(payload) => payload,
        Err(error) => {
            return Ok(crate::http::protocol::l7::finalize_response_with_headers(
                request_method,
                request_version,
                proxy_name,
                reporting_problem_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid browser report",
                    error.to_string().as_str(),
                )?,
                route_headers,
                false,
            ));
        }
    };
    let report_count = match validate_and_observe_browser_reports(
        &payload,
        legacy,
        config.max_reports,
        redact_query_keys,
    ) {
        Ok((report_count, _)) => report_count,
        Err(error) => {
            return Ok(crate::http::protocol::l7::finalize_response_with_headers(
                request_method,
                request_version,
                proxy_name,
                reporting_problem_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid browser report",
                    error.to_string().as_str(),
                )?,
                route_headers,
                false,
            ));
        }
    };
    crate::reverse::transport::metrics::browser_reports_received(report_count as u64, legacy);
    let response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(Body::empty())?;
    Ok(crate::http::protocol::l7::finalize_response_with_headers(
        request_method,
        request_version,
        proxy_name,
        response,
        route_headers,
        false,
    ))
}

fn single_media_type(headers: &Headers) -> Result<String> {
    let mut values = headers.get_all(
        &OrdinaryHeaderName::try_from(http::header::CONTENT_TYPE).expect("ordinary header"),
    );
    let value = values
        .next()
        .ok_or_else(|| anyhow!("browser report Content-Type is missing"))?;
    if values.next().is_some() {
        return Err(anyhow!("browser report Content-Type must be a singleton"));
    }
    let value = value
        .to_str()
        .map_err(|_| anyhow!("browser report Content-Type is not ASCII"))?;
    let media_type = crate::http::media_type::media_type_without_parameters(value);
    if media_type.is_empty() {
        return Err(anyhow!("browser report Content-Type is empty"));
    }
    Ok(media_type.to_ascii_lowercase())
}

async fn collect_bounded_report_body(mut body: Body, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let next = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("browser report body length overflow"))?;
        if next > limit {
            return Err(anyhow!(
                "browser report body exceeds configured limit of {limit} bytes"
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Validates report payloads and emits one structured event per report.
///
/// Returns the accepted count with the exact redacted URL strings that were
/// emitted, so tests can pin the observability surface without depending on
/// a tracing subscriber.
fn validate_and_observe_browser_reports(
    payload: &serde_json::Value,
    legacy: bool,
    max_reports: usize,
    redact_query_keys: &[String],
) -> Result<(usize, Vec<String>)> {
    if legacy {
        let report = payload
            .as_object()
            .and_then(|object| object.get("csp-report"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| anyhow!("legacy CSP report must contain a csp-report object"))?;
        let document_uri = bounded_report_string(report.get("document-uri"), "document-uri", 4096)?;
        let report_url = redact_uri_query_keys(document_uri, redact_query_keys);
        tracing::info!(
            report_type = "csp-violation",
            report_url = report_url.as_str(),
            "browser report received"
        );
        return Ok((1, vec![report_url]));
    }
    let reports = payload
        .as_array()
        .ok_or_else(|| anyhow!("Reporting API payload must be an array"))?;
    if reports.is_empty() || reports.len() > max_reports {
        return Err(anyhow!(
            "Reporting API payload must contain between 1 and {max_reports} reports"
        ));
    }
    let mut observed_urls = Vec::with_capacity(reports.len());
    for report in reports {
        let report = report
            .as_object()
            .ok_or_else(|| anyhow!("each Reporting API entry must be an object"))?;
        let report_type = bounded_report_string(report.get("type"), "type", 128)?;
        let raw_url = bounded_report_string(report.get("url"), "url", 4096)?;
        if !report.get("body").is_some_and(serde_json::Value::is_object) {
            return Err(anyhow!("Reporting API report body must be an object"));
        }
        let report_url = redact_uri_query_keys(raw_url, redact_query_keys);
        tracing::info!(
            report_type,
            report_url = report_url.as_str(),
            "browser report received"
        );
        observed_urls.push(report_url);
    }
    Ok((reports.len(), observed_urls))
}

fn bounded_report_string<'a>(
    value: Option<&'a serde_json::Value>,
    name: &str,
    max_bytes: usize,
) -> Result<&'a str> {
    let value = value
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("browser report {name} must be a string"))?;
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(anyhow!("browser report {name} is invalid"));
    }
    Ok(value)
}

fn reporting_problem_response(
    status: StatusCode,
    title: &'static str,
    detail: &str,
) -> Result<Response<Body>> {
    let body = qpx_http::problem::ProblemDetails::new(status, title)
        .with_detail(detail)
        .to_json()?;
    Ok(Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))?)
}

#[cfg(test)]
mod browser_report_tests {
    use super::*;
    use hyper::Request;

    fn collector() -> qpx_core::config::ReportingCollectorConfig {
        qpx_core::config::ReportingCollectorConfig {
            max_body_bytes: 1024,
            max_reports: 4,
            accept_legacy_csp_reports: false,
        }
    }

    #[test]
    fn media_type_rejects_duplicate_and_non_ascii_fields() {
        let mut headers = Headers::new();
        let name = OrdinaryHeaderName::try_from(http::header::CONTENT_TYPE).unwrap();
        assert!(single_media_type(&headers).is_err());
        headers.append(
            name.clone(),
            http::HeaderValue::from_static("application/reports+json; charset=utf-8"),
        );
        assert_eq!(
            single_media_type(&headers).unwrap(),
            "application/reports+json"
        );
        headers.append(
            name.clone(),
            http::HeaderValue::from_static("application/reports+json"),
        );
        assert!(single_media_type(&headers).is_err());
        headers.remove(&name);
        headers.append(name, http::HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(single_media_type(&headers).is_err());
    }

    #[tokio::test]
    async fn collector_accepts_reporting_api_payload() {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("https://reports.example/.well-known/reports")
            .header(http::header::CONTENT_TYPE, "application/reports+json")
            .body(Body::from(
                r#"[{"type":"csp-violation","url":"https://app.example/","body":{}}]"#,
            ))
            .expect("request");
        let response = collect_browser_reports(
            OwnerRequest::from_http(request),
            &collector(),
            &http::Method::POST,
            http::Version::HTTP_2,
            "qpx",
            None,
            &[],
        )
        .await
        .expect("collect report");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn collector_rejects_invalid_and_oversized_payloads() {
        let invalid = Request::builder()
            .method(http::Method::POST)
            .uri("https://reports.example/.well-known/reports")
            .header(http::header::CONTENT_TYPE, "application/reports+json")
            .body(Body::from(r#"[{"type":"csp-violation"}]"#))
            .expect("request");
        let response = collect_browser_reports(
            OwnerRequest::from_http(invalid),
            &collector(),
            &http::Method::POST,
            http::Version::HTTP_11,
            "qpx",
            None,
            &[],
        )
        .await
        .expect("reject invalid report");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut limits = collector();
        limits.max_body_bytes = 1;
        let oversized = Request::builder()
            .method(http::Method::POST)
            .uri("https://reports.example/.well-known/reports")
            .header(http::header::CONTENT_TYPE, "application/reports+json")
            .body(Body::from("[]"))
            .expect("request");
        let response = collect_browser_reports(
            OwnerRequest::from_http(oversized),
            &limits,
            &http::Method::POST,
            http::Version::HTTP_11,
            "qpx",
            None,
            &[],
        )
        .await
        .expect("reject oversized report");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}

#[cfg(test)]
mod report_redaction_tests {
    use super::*;

    fn redaction_keys() -> Vec<String> {
        vec!["access_token".to_owned(), "custom_secret".to_owned()]
    }

    #[test]
    fn modern_report_url_redacts_configured_query_keys() {
        let payload = serde_json::json!([{
            "type": "csp-violation",
            "url": "https://app.example/callback?access_token=MARKER_TOKEN&custom_secret=MARKER_CUSTOM&next=keep",
            "body": {},
        }]);
        let (count, observed) =
            validate_and_observe_browser_reports(&payload, false, 4, &redaction_keys())
                .expect("valid report");
        assert_eq!(count, 1);
        assert_eq!(observed.len(), 1);
        assert!(
            !observed[0].contains("MARKER_TOKEN") && !observed[0].contains("MARKER_CUSTOM"),
            "observed URL must not carry marker values: {}",
            observed[0]
        );
        assert!(observed[0].contains("access_token=<redacted>"));
        assert!(observed[0].contains("custom_secret=<redacted>"));
        assert!(observed[0].contains("next=keep"));
    }

    #[test]
    fn modern_report_url_redacts_query_like_fragment() {
        let payload = serde_json::json!([{
            "type": "csp-violation",
            "url": "https://app.example/cb#access_token=MARKER_FRAG",
            "body": {},
        }]);
        let (_, observed) =
            validate_and_observe_browser_reports(&payload, false, 4, &redaction_keys())
                .expect("valid report");
        assert!(
            !observed[0].contains("MARKER_FRAG"),
            "observed: {}",
            observed[0]
        );
        assert!(observed[0].contains("#access_token=<redacted>"));
    }

    #[test]
    fn legacy_document_uri_redacts_configured_query_keys() {
        let payload = serde_json::json!({
            "csp-report": {
                "document-uri": "https://app.example/page?access_token=MARKER_LEGACY&ok=1",
            },
        });
        let (count, observed) =
            validate_and_observe_browser_reports(&payload, true, 4, &redaction_keys())
                .expect("valid legacy report");
        assert_eq!(count, 1);
        assert!(
            !observed[0].contains("MARKER_LEGACY"),
            "observed: {}",
            observed[0]
        );
        assert!(observed[0].contains("access_token=<redacted>"));
        assert!(observed[0].contains("ok=1"));
    }

    #[test]
    fn unconfigured_keys_pass_through() {
        let payload = serde_json::json!([{
            "type": "csp-violation",
            "url": "https://app.example/cb?other=MARKER_PLAIN",
            "body": {},
        }]);
        let (_, observed) =
            validate_and_observe_browser_reports(&payload, false, 4, &redaction_keys())
                .expect("valid report");
        assert!(
            observed[0].contains("other=MARKER_PLAIN"),
            "observed: {}",
            observed[0]
        );
    }
}
