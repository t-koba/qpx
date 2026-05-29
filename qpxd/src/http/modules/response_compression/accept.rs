use http::HeaderMap;
use http::header::VARY;

pub(super) fn parse_accept_encoding(headers: &HeaderMap) -> Vec<(String, i32)> {
    let mut out = Vec::new();
    for value in headers.get_all("accept-encoding") {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let mut segments = part.split(';');
            let name = segments
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            let mut q = 1000i32;
            for segment in segments {
                if let Some(raw) = segment.trim().strip_prefix("q=") {
                    q = parse_quality(raw);
                }
            }
            out.push((name, q));
        }
    }
    out
}

pub(super) fn accept_encoding_q(name: &str, values: &[(String, i32)]) -> i32 {
    let wildcard = values
        .iter()
        .find_map(|(value, q)| (value == "*").then_some(*q))
        .unwrap_or(0);
    values
        .iter()
        .find_map(|(value, q)| (value == name).then_some(*q))
        .unwrap_or(wildcard)
}

pub(super) fn append_vary_accept_encoding(headers: &mut HeaderMap) {
    let existing = headers
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if existing.iter().any(|token| token == "accept-encoding") {
        return;
    }
    headers.append(VARY, http::HeaderValue::from_static("Accept-Encoding"));
}

fn parse_quality(raw: &str) -> i32 {
    let raw = raw.trim();
    if raw.eq("1") || raw.eq("1.0") || raw.eq("1.00") || raw.eq("1.000") {
        return 1000;
    }
    if raw.eq("0") || raw.eq("0.0") || raw.eq("0.00") || raw.eq("0.000") {
        return 0;
    }
    let Ok(value) = raw.parse::<f32>() else {
        return 0;
    };
    (value.clamp(0.0, 1.0) * 1000.0) as i32
}
