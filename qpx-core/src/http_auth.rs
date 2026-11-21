//! Shared HTTP authentication credential primitives.

/// Normalizes a SHA-256 HA1 value from a bare hex string or a
/// case-insensitively prefixed `sha-256:<hex>` string.
///
/// Prefix detection uses a byte-boundary-safe slice so malformed UTF-8 input
/// is rejected like any other invalid value rather than panicking.
pub fn normalize_sha256_ha1(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let hex = match raw.get(..8) {
        Some(prefix) if prefix.eq_ignore_ascii_case("sha-256:") => &raw[8..],
        _ => raw,
    };
    let hex = hex.trim();
    if hex.len() != 64 || !hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_bare_and_prefixed_sha256_ha1() {
        const HEX: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let expected = HEX.to_ascii_lowercase();
        assert_eq!(
            normalize_sha256_ha1(HEX).as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(
            normalize_sha256_ha1(&format!("SHA-256: {HEX}")).as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(normalize_sha256_ha1(&HEX[..63]), None);
        assert_eq!(normalize_sha256_ha1("1234567é"), None);
    }
}
