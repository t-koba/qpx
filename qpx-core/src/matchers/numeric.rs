use anyhow::anyhow;

use super::Result;

#[derive(Debug, Clone)]
pub(super) struct CompiledNumericMatcher {
    ranges: Vec<NumericRange>,
}

#[derive(Debug, Clone)]
struct NumericRange {
    min: Option<u64>,
    max: Option<u64>,
}

impl CompiledNumericMatcher {
    fn matches(&self, value: u64) -> bool {
        self.ranges.iter().any(|range| {
            range.min.map(|min| value >= min).unwrap_or(true)
                && range.max.map(|max| value <= max).unwrap_or(true)
        })
    }
}

pub(super) fn compile_numeric_matchers(items: &[String]) -> Result<Option<CompiledNumericMatcher>> {
    if items.is_empty() {
        return Ok(None);
    }
    let mut ranges = Vec::with_capacity(items.len());
    for item in items {
        if let Some(range) = parse_numeric_range(item)? {
            ranges.push(range);
        }
    }
    Ok(Some(CompiledNumericMatcher { ranges }))
}

pub(super) fn match_optional_numeric(
    matcher: &Option<CompiledNumericMatcher>,
    value: Option<u64>,
) -> bool {
    match matcher {
        Some(matcher) => value.map(|value| matcher.matches(value)).unwrap_or(false),
        None => true,
    }
}

fn parse_numeric_range(raw: &str) -> Result<Option<NumericRange>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("empty numeric matcher").into());
    }
    if let Some(rest) = raw.strip_prefix(">=") {
        return Ok(Some(NumericRange {
            min: Some(parse_numeric_value(rest)?),
            max: None,
        }));
    }
    if let Some(rest) = raw.strip_prefix('>') {
        let value = parse_numeric_value(rest)?;
        return match value.checked_add(1) {
            Some(min) => Ok(Some(NumericRange {
                min: Some(min),
                max: None,
            })),
            // `>u64::MAX` excludes every `u64`; keep it as an empty member
            // rather than saturating into `>=MAX`.
            None => Ok(None),
        };
    }
    if let Some(rest) = raw.strip_prefix("<=") {
        return Ok(Some(NumericRange {
            min: None,
            max: Some(parse_numeric_value(rest)?),
        }));
    }
    if let Some(rest) = raw.strip_prefix('<') {
        let value = parse_numeric_value(rest)?;
        return match value.checked_sub(1) {
            Some(max) => Ok(Some(NumericRange {
                min: None,
                max: Some(max),
            })),
            // `<0` excludes every `u64`; keep it as an empty member
            // rather than saturating into `<=0`.
            None => Ok(None),
        };
    }
    if let Some((start, end)) = raw.split_once('-') {
        let start = parse_numeric_value(start)?;
        let end = parse_numeric_value(end)?;
        if start > end {
            return Err(anyhow!("numeric range start must be <= end").into());
        }
        return Ok(Some(NumericRange {
            min: Some(start),
            max: Some(end),
        }));
    }
    let value = parse_numeric_value(raw)?;
    Ok(Some(NumericRange {
        min: Some(value),
        max: Some(value),
    }))
}

fn parse_numeric_value(raw: &str) -> Result<u64> {
    let raw = raw.trim();
    let (digits, scale) = match raw.chars().last().unwrap_or_default() {
        'k' | 'K' => (&raw[..raw.len() - 1], 1024u64),
        'm' | 'M' => (&raw[..raw.len() - 1], 1024u64 * 1024),
        'g' | 'G' => (&raw[..raw.len() - 1], 1024u64 * 1024 * 1024),
        _ => (raw, 1u64),
    };
    let value = digits
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow!("invalid numeric matcher"))?;
    Ok(value
        .checked_mul(scale)
        .ok_or_else(|| anyhow!("numeric matcher overflow"))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched(patterns: &[&str], value: u64) -> bool {
        let items: Vec<String> = patterns.iter().map(|item| item.to_string()).collect();
        let matcher = compile_numeric_matchers(&items).expect("compile");
        match_optional_numeric(&matcher, Some(value))
    }

    #[test]
    fn impossible_strict_bounds_never_match() {
        for value in [0, 1, u64::MAX - 1, u64::MAX] {
            assert!(!matched(&["<0"], value), "<0 must never match {value}");
            assert!(
                !matched(&[">18446744073709551615"], value),
                ">u64::MAX must never match {value}"
            );
        }
    }

    #[test]
    fn only_impossible_members_stay_configured_but_never_match() {
        let items = vec!["<0".to_string(), ">18446744073709551615".to_string()];
        let matcher = compile_numeric_matchers(&items).expect("compile");
        assert!(
            matcher.is_some(),
            "only-impossible list must stay a configured matcher"
        );
        for value in [0, 1, u64::MAX] {
            assert!(
                !match_optional_numeric(&matcher, Some(value)),
                "only-impossible list must never match {value}"
            );
        }
    }

    #[test]
    fn neighboring_strict_bounds_match_endpoints() {
        assert!(matched(&["<1"], 0));
        assert!(!matched(&["<1"], 1));
        assert!(matched(&[">18446744073709551614"], u64::MAX));
        assert!(!matched(&[">18446744073709551614"], u64::MAX - 1));
        // Ordinary inclusive and exact forms are unchanged.
        assert!(matched(&[">=5"], 5));
        assert!(!matched(&[">=5"], 4));
        assert!(matched(&["5-10"], 10));
        assert!(!matched(&["5-10"], 11));
    }

    #[test]
    fn or_list_skips_impossible_member() {
        assert!(matched(&["<0", "5"], 5));
        assert!(!matched(&["<0", "5"], 0));
        assert!(!matched(&["<0", "5"], 6));
    }

    #[test]
    fn scale_overflow_still_errors() {
        let items = vec![">18446744073709551615k".to_string()];
        assert!(compile_numeric_matchers(&items).is_err());
    }
}
