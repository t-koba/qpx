use anyhow::{Result, anyhow};

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
        ranges.push(parse_numeric_range(item)?);
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

fn parse_numeric_range(raw: &str) -> Result<NumericRange> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("empty numeric matcher"));
    }
    if let Some(rest) = raw.strip_prefix(">=") {
        return Ok(NumericRange {
            min: Some(parse_numeric_value(rest)?),
            max: None,
        });
    }
    if let Some(rest) = raw.strip_prefix('>') {
        let value = parse_numeric_value(rest)?;
        return Ok(NumericRange {
            min: Some(value.saturating_add(1)),
            max: None,
        });
    }
    if let Some(rest) = raw.strip_prefix("<=") {
        return Ok(NumericRange {
            min: None,
            max: Some(parse_numeric_value(rest)?),
        });
    }
    if let Some(rest) = raw.strip_prefix('<') {
        let value = parse_numeric_value(rest)?;
        return Ok(NumericRange {
            min: None,
            max: Some(value.saturating_sub(1)),
        });
    }
    if let Some((start, end)) = raw.split_once('-') {
        let start = parse_numeric_value(start)?;
        let end = parse_numeric_value(end)?;
        if start > end {
            return Err(anyhow!("numeric range start must be <= end"));
        }
        return Ok(NumericRange {
            min: Some(start),
            max: Some(end),
        });
    }
    let value = parse_numeric_value(raw)?;
    Ok(NumericRange {
        min: Some(value),
        max: Some(value),
    })
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
    value
        .checked_mul(scale)
        .ok_or_else(|| anyhow!("numeric matcher overflow"))
}
