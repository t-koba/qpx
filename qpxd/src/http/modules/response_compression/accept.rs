use super::ord;
use http::header::{ACCEPT_ENCODING, VARY};
use qpx_core::http_message::OrdinaryHeaderMut;

pub(super) fn parse_accept_encoding(headers: &impl OrdinaryHeaderMut) -> Vec<(String, i32)> {
    let mut out = Vec::new();
    for part in qpx_core::http_token::value_members(headers.ordinary_values(&ord(ACCEPT_ENCODING)))
    {
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
            if let Some((name, raw)) = segment.trim().split_once('=')
                && name.trim().eq_ignore_ascii_case("q")
            {
                q = parse_quality(raw);
            }
        }
        out.push((name, q));
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

pub(super) fn append_vary_accept_encoding(headers: &mut impl OrdinaryHeaderMut) {
    if qpx_core::http_token::value_members(headers.ordinary_values(&ord(VARY)))
        .any(|member| member.eq_ignore_ascii_case("accept-encoding"))
    {
        return;
    }
    headers.ordinary_append(ord(VARY), http::HeaderValue::from_static("Accept-Encoding"));
}

fn parse_quality(raw: &str) -> i32 {
    // RFC 9110 section 12.4.2: a qvalue has at most three decimal places.
    // Read those places as decimal digits: a float cannot represent 0.251
    // exactly, and truncating its scaled value would rank it equal to 0.250.
    let raw = raw.trim();
    let (whole, fraction) = match raw.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (raw, None),
    };
    let Ok(whole) = whole.parse::<u64>() else {
        return 0;
    };
    let mut thousandths = whole.saturating_mul(1000);
    // A dot with no digits (q=1.) is the same weight as no dot.
    if let Some(fraction) = fraction.filter(|fraction| !fraction.is_empty()) {
        if !fraction.bytes().all(|digit| digit.is_ascii_digit()) {
            return 0;
        }
        let digits = fraction.len().min(3);
        let scale = match digits {
            1 => 100,
            2 => 10,
            3 => 1,
            _ => 0,
        };
        let Ok(part) = fraction[..digits].parse::<u64>() else {
            return 0;
        };
        thousandths = thousandths.saturating_add(part.saturating_mul(scale));
    }
    thousandths.min(1000) as i32
}
