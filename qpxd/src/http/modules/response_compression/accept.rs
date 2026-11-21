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
    // RFC 9110 section 12.4.2: qvalue is `0[.0*3DIGIT]` or `1[.0*3("0")]`.
    // Read the fraction as decimal digits: a float cannot represent 0.251
    // exactly, and truncating its scaled value would rank it equal to 0.250.
    let raw = raw.trim();
    let (whole, fraction) = match raw.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (raw, None),
    };
    let whole = match whole {
        "0" => 0u64,
        "1" => 1u64,
        _ => return 0,
    };
    let Some(fraction) = fraction.filter(|fraction| !fraction.is_empty()) else {
        return (whole * 1000) as i32;
    };
    if fraction.len() > 3 || !fraction.bytes().all(|digit| digit.is_ascii_digit()) {
        return 0;
    }
    if whole == 1 && fraction.bytes().any(|digit| digit != b'0') {
        return 0;
    }
    let part = fraction.parse::<u64>().expect("ASCII digits");
    let scale = match fraction.len() {
        1 => 100,
        2 => 10,
        _ => 1,
    };
    (whole * 1000 + part * scale) as i32
}
