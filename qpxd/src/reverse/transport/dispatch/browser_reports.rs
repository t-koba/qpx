use anyhow::{Result, anyhow};
use hyper::{Request, Response, StatusCode};
use qpx_http::body::Body;

pub(super) async fn collect_browser_reports(
    req: Request<Body>,
    config: &qpx_core::config::ReportingCollectorConfig,
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
    route_headers: Option<&qpx_core::rules::CompiledHeaderControl>,
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
    if req.headers().contains_key(http::header::CONTENT_ENCODING) {
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
    let bytes = match collect_bounded_report_body(req.into_body(), config.max_body_bytes).await {
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
    let report_count =
        match validate_and_observe_browser_reports(&payload, legacy, config.max_reports) {
            Ok(report_count) => report_count,
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

fn single_media_type(headers: &http::HeaderMap) -> Result<String> {
    let mut values = headers.get_all(http::header::CONTENT_TYPE).iter();
    let value = values
        .next()
        .ok_or_else(|| anyhow!("browser report Content-Type is missing"))?;
    if values.next().is_some() {
        return Err(anyhow!("browser report Content-Type must be a singleton"));
    }
    let value = value
        .to_str()
        .map_err(|_| anyhow!("browser report Content-Type is not ASCII"))?;
    let media_type = value.split(';').next().unwrap_or_default().trim();
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

fn validate_and_observe_browser_reports(
    payload: &serde_json::Value,
    legacy: bool,
    max_reports: usize,
) -> Result<usize> {
    if legacy {
        let report = payload
            .as_object()
            .and_then(|object| object.get("csp-report"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| anyhow!("legacy CSP report must contain a csp-report object"))?;
        let document_uri = bounded_report_string(report.get("document-uri"), "document-uri", 4096)?;
        tracing::info!(
            report_type = "csp-violation",
            report_url = document_uri,
            "browser report received"
        );
        return Ok(1);
    }
    let reports = payload
        .as_array()
        .ok_or_else(|| anyhow!("Reporting API payload must be an array"))?;
    if reports.is_empty() || reports.len() > max_reports {
        return Err(anyhow!(
            "Reporting API payload must contain between 1 and {max_reports} reports"
        ));
    }
    for report in reports {
        let report = report
            .as_object()
            .ok_or_else(|| anyhow!("each Reporting API entry must be an object"))?;
        let report_type = bounded_report_string(report.get("type"), "type", 128)?;
        let report_url = bounded_report_string(report.get("url"), "url", 4096)?;
        if !report.get("body").is_some_and(serde_json::Value::is_object) {
            return Err(anyhow!("Reporting API report body must be an object"));
        }
        tracing::info!(report_type, report_url, "browser report received");
    }
    Ok(reports.len())
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

    fn collector() -> qpx_core::config::ReportingCollectorConfig {
        qpx_core::config::ReportingCollectorConfig {
            max_body_bytes: 1024,
            max_reports: 4,
            accept_legacy_csp_reports: false,
        }
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
            request,
            &collector(),
            &http::Method::POST,
            http::Version::HTTP_2,
            "qpx",
            None,
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
            invalid,
            &collector(),
            &http::Method::POST,
            http::Version::HTTP_11,
            "qpx",
            None,
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
            oversized,
            &limits,
            &http::Method::POST,
            http::Version::HTTP_11,
            "qpx",
            None,
        )
        .await
        .expect("reject oversized report");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
