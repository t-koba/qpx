use anyhow::{Result, anyhow};

pub(crate) const CALDAV_NAMESPACE: &str = "urn:ietf:params:xml:ns:caldav";
pub(crate) const CALENDAR_MARKER: &str = "calendar-collection-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CalendarInstant(pub(crate) i64);

#[derive(Debug, Clone)]
pub(crate) struct CalendarObject {
    pub(crate) component: String,
    pub(crate) start: CalendarInstant,
    pub(crate) end: CalendarInstant,
}

pub(crate) fn validate_calendar(body: &[u8]) -> Result<Vec<CalendarObject>> {
    if body.len() > 4 * 1024 * 1024 {
        return Err(anyhow!("iCalendar body exceeds 4 MiB"));
    }
    let text = std::str::from_utf8(body)?;
    let lines = unfold_lines(text)?;
    if lines.first().map(String::as_str) != Some("BEGIN:VCALENDAR")
        || lines.last().map(String::as_str) != Some("END:VCALENDAR")
    {
        return Err(anyhow!("iCalendar root must be VCALENDAR"));
    }
    if !lines.iter().any(|line| line.starts_with("VERSION:2.0")) {
        return Err(anyhow!("iCalendar VERSION:2.0 is required"));
    }
    let mut objects = Vec::new();
    let mut component = None::<String>;
    let mut start = None;
    let mut end = None;
    for line in lines.iter().skip(1).take(lines.len().saturating_sub(2)) {
        if let Some(name) = line.strip_prefix("BEGIN:") {
            if matches!(name, "VEVENT" | "VTODO" | "VJOURNAL" | "VFREEBUSY") {
                if component.is_some() {
                    return Err(anyhow!("nested iCalendar components are not supported"));
                }
                component = Some(name.to_owned());
                start = None;
                end = None;
            }
        } else if let Some(name) = line.strip_prefix("END:") {
            if component.as_deref() == Some(name) {
                let start = start.ok_or_else(|| anyhow!("calendar component has no DTSTART"))?;
                let end = end.unwrap_or(start);
                if end < start {
                    return Err(anyhow!("calendar component ends before it starts"));
                }
                objects.push(CalendarObject {
                    component: name.to_owned(),
                    start,
                    end,
                });
                component = None;
            }
        } else if component.is_some() {
            if property_name(line) == Some("DTSTART") {
                start = Some(parse_datetime(property_value(line)?)?);
            } else if matches!(property_name(line), Some("DTEND" | "DUE")) {
                end = Some(parse_datetime(property_value(line)?)?);
            }
        }
    }
    if component.is_some() || objects.is_empty() {
        return Err(anyhow!("iCalendar component is incomplete or missing"));
    }
    Ok(objects)
}

fn unfold_lines(text: &str) -> Result<Vec<String>> {
    if text.contains('\0') || text.contains('\r') && text.contains("\r\r") {
        return Err(anyhow!("iCalendar contains invalid control data"));
    }
    let mut lines = Vec::<String>::new();
    for raw in text.replace("\r\n", "\n").split('\n') {
        if raw.starts_with([' ', '\t']) {
            let previous = lines
                .last_mut()
                .ok_or_else(|| anyhow!("iCalendar folding has no preceding line"))?;
            previous.push_str(&raw[1..]);
        } else if !raw.is_empty() {
            if raw.bytes().any(|byte| byte < 0x20 && byte != b'\t') {
                return Err(anyhow!("iCalendar contains a control character"));
            }
            lines.push(raw.to_owned());
        }
    }
    Ok(lines)
}

fn property_name(line: &str) -> Option<&str> {
    let head = line.split_once(':')?.0;
    Some(head.split_once(';').map_or(head, |(name, _)| name))
}

fn property_value(line: &str) -> Result<&str> {
    line.split_once(':')
        .map(|(_, value)| value)
        .ok_or_else(|| anyhow!("iCalendar property has no value"))
}

pub(crate) fn parse_datetime(value: &str) -> Result<CalendarInstant> {
    let digits = value.strip_suffix('Z').unwrap_or(value);
    if digits.len() != 15 || digits.as_bytes().get(8) != Some(&b'T') {
        return Err(anyhow!("iCalendar date-time must use YYYYMMDDTHHMMSS[Z]"));
    }
    let number =
        |range: std::ops::Range<usize>| -> Result<i64> { Ok(digits[range].parse::<i64>()?) };
    let year = number(0..4)?;
    let month = number(4..6)?;
    let day = number(6..8)?;
    let hour = number(9..11)?;
    let minute = number(11..13)?;
    let second = number(13..15)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(anyhow!("iCalendar date-time is outside valid field ranges"));
    }
    Ok(CalendarInstant(
        (((((year * 13 + month) * 32 + day) * 24 + hour) * 60 + minute) * 61) + second,
    ))
}

pub(crate) fn format_datetime(value: CalendarInstant) -> String {
    let mut remaining = value.0;
    let second = remaining.rem_euclid(61);
    remaining = remaining.div_euclid(61);
    let minute = remaining.rem_euclid(60);
    remaining = remaining.div_euclid(60);
    let hour = remaining.rem_euclid(24);
    remaining = remaining.div_euclid(24);
    let day = remaining.rem_euclid(32);
    remaining = remaining.div_euclid(32);
    let month = remaining.rem_euclid(13);
    let year = remaining.div_euclid(13);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_unfolds_calendar_objects() {
        let objects = validate_calendar(
            b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nDTSTART:20260711T010000Z\r\nDTEND:20260711T020000Z\r\nSUMMARY:long\r\n value\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        )
        .unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].component, "VEVENT");
        assert!(objects[0].end > objects[0].start);
    }
}
