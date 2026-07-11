#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamPriority {
    pub(crate) urgency: u8,
    pub(crate) incremental: bool,
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self {
            urgency: 3,
            incremental: false,
        }
    }
}

pub(crate) fn parse_priority(value: &str) -> StreamPriority {
    let mut priority = StreamPriority::default();
    let Ok(dictionary) = qpx_http::structured_fields::parse_dictionary(value.as_bytes()) else {
        return priority;
    };
    if let Some(qpx_http::structured_fields::ListEntry::Item(item)) = dictionary.get("u")
        && let qpx_http::structured_fields::BareItem::Integer(value) = item.bare_item
        && let Ok(urgency) = u8::try_from(value)
        && urgency <= 7
    {
        priority.urgency = urgency;
    }
    if let Some(qpx_http::structured_fields::ListEntry::Item(item)) = dictionary.get("i")
        && let qpx_http::structured_fields::BareItem::Boolean(incremental) = item.bare_item
    {
        priority.incremental = incremental;
    }
    priority
}

#[cfg(test)]
mod tests {
    use crate::http3::priority::*;

    #[test]
    fn parses_rfc9218_priority_header() {
        assert_eq!(
            parse_priority("u=0, i=?1"),
            StreamPriority {
                urgency: 0,
                incremental: true
            }
        );
        assert_eq!(parse_priority("u=9").urgency, 3);
        assert_eq!(parse_priority("").urgency, 3);
    }
}
