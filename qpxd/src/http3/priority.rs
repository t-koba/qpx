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
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if let Some(raw) = item.strip_prefix("u=") {
            if let Ok(urgency) = raw.parse::<u8>()
                && urgency <= 7
            {
                priority.urgency = urgency;
            }
        } else if item == "i" || item == "i=?1" || item == "i=1" {
            priority.incremental = true;
        } else if item == "i=?0" || item == "i=0" {
            priority.incremental = false;
        }
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
