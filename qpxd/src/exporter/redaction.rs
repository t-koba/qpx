use qpx_core::config::CaptureRedactionConfig;
use qpx_core::redaction::{compile_json_redaction_path, redact_uri_query_keys};
use std::borrow::Cow;
use std::collections::HashSet;

pub(super) struct CaptureRedaction {
    pub(super) headers: HashSet<String>,
    pub(super) query_keys: Vec<String>,
    pub(super) json_paths: Vec<Vec<String>>,
}

impl CaptureRedaction {
    pub(super) fn from_config(config: &CaptureRedactionConfig) -> Self {
        Self {
            headers: config
                .headers
                .iter()
                .map(|header| header.to_ascii_lowercase())
                .collect(),
            query_keys: config
                .query_keys
                .iter()
                .map(|key| key.to_ascii_lowercase())
                .collect(),
            json_paths: compile_json_paths_fail_closed(&config.json_paths),
        }
    }

    pub(super) fn is_noop(&self) -> bool {
        self.headers.is_empty() && self.query_keys.is_empty() && self.json_paths.is_empty()
    }

    pub(super) fn redact_plaintext<'a>(&self, payload: &'a [u8]) -> Cow<'a, [u8]> {
        if self.is_noop() {
            return Cow::Borrowed(payload);
        }
        let Ok(text) = std::str::from_utf8(payload) else {
            return Cow::Borrowed(b"<redacted>");
        };
        let mut out = String::with_capacity(text.len());
        for (idx, line) in text.split_inclusive('\n').enumerate() {
            if idx == 0 {
                out.push_str(self.redact_request_line(line).as_str());
                continue;
            }
            if let Some((name, _)) = line.split_once(':')
                && self.headers.contains(&name.trim().to_ascii_lowercase())
            {
                out.push_str(name);
                out.push_str(": <redacted>\r\n");
                continue;
            }
            if let Some(redacted) = self.redact_uri_header_line(line) {
                out.push_str(redacted.as_str());
                continue;
            }
            out.push_str(line);
        }
        Cow::Owned(self.redact_json_body(out).into_bytes())
    }

    pub(super) fn redact_plaintext_for_export<'a>(
        &self,
        payload: &'a [u8],
        max_plaintext_bytes: Option<usize>,
    ) -> Cow<'a, [u8]> {
        let capped = match max_plaintext_bytes {
            Some(max) => &payload[..payload.len().min(max)],
            None => payload,
        };
        let redacted = self.redact_plaintext(capped);
        match (max_plaintext_bytes, redacted) {
            (Some(max), Cow::Borrowed(bytes)) => Cow::Borrowed(&bytes[..bytes.len().min(max)]),
            (Some(max), Cow::Owned(mut bytes)) => {
                bytes.truncate(max);
                Cow::Owned(bytes)
            }
            (None, redacted) => redacted,
        }
    }

    fn redact_uri_header_line(&self, line: &str) -> Option<String> {
        let (name, value) = line.split_once(':')?;
        if !header_value_may_contain_uri(name.trim()) {
            return None;
        }
        let line_ending = if line.ends_with("\r\n") {
            "\r\n"
        } else if line.ends_with('\n') {
            "\n"
        } else {
            ""
        };
        let value = value.trim_end_matches(['\r', '\n']);
        let leading_ws_len = value.len() - value.trim_start().len();
        let (leading_ws, value) = value.split_at(leading_ws_len);
        let redacted = redact_uri_header_value(name.trim(), value, &self.query_keys);
        Some(format!("{name}:{leading_ws}{redacted}{line_ending}"))
    }

    fn redact_request_line(&self, line: &str) -> String {
        let mut parts = line.splitn(3, ' ');
        let Some(method) = parts.next() else {
            return line.to_string();
        };
        let Some(target) = parts.next() else {
            return line.to_string();
        };
        let redacted_target = redact_uri_query_keys(target, &self.query_keys);
        match parts.next() {
            Some(version) => format!("{method} {redacted_target} {version}"),
            None => format!("{method} {redacted_target}"),
        }
    }

    fn redact_json_body(&self, text: String) -> String {
        if self.json_paths.is_empty() {
            return text;
        }
        let Some((head, body, separator)) = split_http_message(text.as_str()) else {
            if looks_like_http_message_prefix(text.as_str()) {
                return text;
            }
            return self.redact_json_text(text);
        };
        if !head.lines().any(is_json_content_type_header) {
            return text;
        }
        let redacted_body = self.redact_json_text(body.trim_end().to_string());
        if redacted_body == body.trim_end() {
            return text;
        }
        format!("{head}{separator}{redacted_body}")
    }

    fn redact_json_text(&self, text: String) -> String {
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(text.trim_end()) else {
            return "<redacted>".to_string();
        };
        for path in &self.json_paths {
            redact_json_value(&mut value, path);
        }
        let Ok(redacted) = serde_json::to_string(&value) else {
            return text;
        };
        redacted
    }
}

fn compile_json_paths_fail_closed(paths: &[String]) -> Vec<Vec<String>> {
    let mut compiled = Vec::with_capacity(paths.len());
    for path in paths {
        match compile_json_redaction_path(path) {
            Ok(path) => compiled.push(path),
            Err(err) => {
                tracing::error!(
                    error = ?err,
                    path = path.as_str(),
                    "invalid capture json redaction path reached runtime; redacting whole JSON payloads"
                );
                return vec![Vec::new()];
            }
        }
    }
    compiled
}

fn split_http_message(text: &str) -> Option<(&str, &str, &'static str)> {
    if let Some((head, body)) = text.split_once("\r\n\r\n") {
        return Some((head, body, "\r\n\r\n"));
    }
    text.split_once("\n\n")
        .map(|(head, body)| (head, body, "\n\n"))
}

fn looks_like_http_message_prefix(text: &str) -> bool {
    let first_line = text.lines().next().unwrap_or(text);
    first_line.starts_with("HTTP/")
        || first_line
            .split_once(' ')
            .is_some_and(|(method, rest)| is_http_method_token(method) && rest.contains("HTTP/"))
}

fn is_http_method_token(method: &str) -> bool {
    !method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
}

fn is_json_content_type_header(line: &str) -> bool {
    let Some((name, value)) = line.split_once(':') else {
        return false;
    };
    if !name.trim().eq_ignore_ascii_case("content-type") {
        return false;
    }
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

fn redact_json_value(value: &mut serde_json::Value, path: &[String]) {
    let Some((head, tail)) = path.split_first() else {
        *value = serde_json::Value::String("<redacted>".to_string());
        return;
    };
    match value {
        serde_json::Value::Object(map) => {
            if let Some(next) = map.get_mut(head) {
                redact_json_value(next, tail);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_value(item, path);
            }
        }
        _ => {}
    }
}

fn header_value_may_contain_uri(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "location" | "content-location" | "refresh" | "link"
    )
}

fn redact_uri_header_value(name: &str, value: &str, query_keys: &[String]) -> String {
    match name.to_ascii_lowercase().as_str() {
        "location" | "content-location" => redact_uri_query_keys(value, query_keys),
        "refresh" => redact_refresh_header_value(value, query_keys),
        "link" => redact_link_header_value(value, query_keys),
        _ => value.to_string(),
    }
}

fn redact_refresh_header_value(value: &str, query_keys: &[String]) -> String {
    let Some((url_pos, eq_len)) = find_refresh_url_parameter(value) else {
        return value.to_string();
    };
    let value_start = url_pos + eq_len;
    let (prefix, rest) = value.split_at(value_start);
    let trimmed = rest.trim_start();
    let ws = &rest[..rest.len() - trimmed.len()];
    let (quote, uri, suffix) = if let Some(inner) = trimmed.strip_prefix('"') {
        match inner.find('"') {
            Some(end) => ("\"", &inner[..end], &inner[end..]),
            None => ("", trimmed, ""),
        }
    } else {
        ("", trimmed, "")
    };
    format!(
        "{prefix}{ws}{quote}{}{}",
        redact_uri_query_keys(uri, query_keys),
        suffix
    )
}

fn find_refresh_url_parameter(value: &str) -> Option<(usize, usize)> {
    let bytes = value.as_bytes();
    for (idx, window) in bytes.windows(3).enumerate() {
        if !window.eq_ignore_ascii_case(b"url") {
            continue;
        }
        if idx > 0 {
            let before = bytes[idx - 1];
            if before.is_ascii_alphanumeric() || before == b'-' || before == b'_' {
                continue;
            }
        }
        let mut pos = idx + 3;
        while bytes.get(pos).is_some_and(u8::is_ascii_whitespace) {
            pos += 1;
        }
        if bytes.get(pos) != Some(&b'=') {
            continue;
        }
        return Some((idx, pos + 1 - idx));
    }
    None
}

fn redact_link_header_value(value: &str, query_keys: &[String]) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('<') {
        let (before, after_start) = rest.split_at(start + 1);
        out.push_str(before);
        let Some(end) = after_start.find('>') else {
            out.push_str(after_start);
            return out;
        };
        let (uri, after_uri) = after_start.split_at(end);
        out.push_str(redact_uri_query_keys(uri, query_keys).as_str());
        rest = after_uri;
    }
    out.push_str(rest);
    out
}
