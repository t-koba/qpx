use anyhow::Result;
#[cfg(test)]
use bytes::Bytes;
use qpx_core::config::HttpGuardProfileConfig;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::fmt;

#[cfg(test)]
use super::bad_request;
use super::{HttpGuardReject, payload_too_large};

#[cfg(test)]
pub(super) fn validate_json_limits(
    bytes: &Bytes,
    content_type: Option<&str>,
    profile: &HttpGuardProfileConfig,
) -> Option<HttpGuardReject> {
    if profile.json.max_depth.is_none() && profile.json.max_fields.is_none() {
        return None;
    }
    let content_type = content_type?;
    if !(content_type.starts_with("application/json") || content_type.contains("+json")) {
        return None;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes.as_ref()) else {
        return Some(bad_request("invalid JSON body for http_guard profile"));
    };
    let (depth, fields) = json_stats(&value, 1);
    if let Some(limit) = profile.json.max_depth
        && depth > limit
    {
        return Some(payload_too_large("JSON depth exceeds http_guard limit"));
    }
    if let Some(limit) = profile.json.max_fields
        && fields > limit
    {
        return Some(payload_too_large(
            "JSON field count exceeds http_guard limit",
        ));
    }
    None
}

pub(super) async fn validate_json_limits_reader(
    body: &crate::http::body::size::ObservedBodyReader,
    content_type: Option<&str>,
    profile: HttpGuardProfileConfig,
) -> Result<Option<HttpGuardReject>> {
    if profile.json.max_depth.is_none() && profile.json.max_fields.is_none() {
        return Ok(None);
    }
    let Some(content_type) = content_type else {
        return Ok(None);
    };
    if !(content_type.starts_with("application/json") || content_type.contains("+json")) {
        return Ok(None);
    }
    body.with_blocking_reader(move |reader| {
        let mut de = serde_json::Deserializer::from_reader(reader);
        let stats = JsonStatsSeed.deserialize(&mut de)?;
        de.end()?;
        if let Some(limit) = profile.json.max_depth
            && stats.depth > limit
        {
            return Ok(Some(payload_too_large(
                "JSON depth exceeds http_guard limit",
            )));
        }
        if let Some(limit) = profile.json.max_fields
            && stats.fields > limit
        {
            return Ok(Some(payload_too_large(
                "JSON field count exceeds http_guard limit",
            )));
        }
        Ok(None)
    })
    .await
}

#[derive(Debug, Clone, Copy, Default)]
struct JsonStats {
    depth: usize,
    fields: usize,
}

struct JsonStatsSeed;

impl<'de> DeserializeSeed<'de> for JsonStatsSeed {
    type Value = JsonStats;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonStatsVisitor { depth: 1 })
    }
}

struct JsonStatsVisitor {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for JsonStatsVisitor {
    type Value = JsonStats;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonStatsVisitor {
    type Value = JsonStats;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _v: bool) -> std::result::Result<Self::Value, E> {
        Ok(JsonStats {
            depth: self.depth,
            fields: 0,
        })
    }

    fn visit_i64<E>(self, _v: i64) -> std::result::Result<Self::Value, E> {
        Ok(JsonStats {
            depth: self.depth,
            fields: 0,
        })
    }

    fn visit_u64<E>(self, _v: u64) -> std::result::Result<Self::Value, E> {
        Ok(JsonStats {
            depth: self.depth,
            fields: 0,
        })
    }

    fn visit_f64<E>(self, _v: f64) -> std::result::Result<Self::Value, E> {
        Ok(JsonStats {
            depth: self.depth,
            fields: 0,
        })
    }

    fn visit_str<E>(self, _v: &str) -> std::result::Result<Self::Value, E> {
        Ok(JsonStats {
            depth: self.depth,
            fields: 0,
        })
    }

    fn visit_string<E>(self, _v: String) -> std::result::Result<Self::Value, E> {
        Ok(JsonStats {
            depth: self.depth,
            fields: 0,
        })
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(JsonStats {
            depth: self.depth,
            fields: 0,
        })
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(JsonStats {
            depth: self.depth,
            fields: 0,
        })
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut stats = JsonStats {
            depth: self.depth,
            fields: 0,
        };
        while let Some(child) = seq.next_element_seed(JsonStatsVisitor {
            depth: self.depth + 1,
        })? {
            stats.depth = stats.depth.max(child.depth);
            stats.fields += child.fields;
        }
        Ok(stats)
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut stats = JsonStats {
            depth: self.depth,
            fields: 0,
        };
        while map.next_key::<IgnoredAny>()?.is_some() {
            stats.fields += 1;
            let child = map.next_value_seed(JsonStatsVisitor {
                depth: self.depth + 1,
            })?;
            stats.depth = stats.depth.max(child.depth);
            stats.fields += child.fields;
        }
        Ok(stats)
    }
}

#[cfg(test)]
fn json_stats(value: &serde_json::Value, depth: usize) -> (usize, usize) {
    match value {
        serde_json::Value::Array(items) => items.iter().fold((depth, 0usize), |acc, item| {
            let (child_depth, child_fields) = json_stats(item, depth + 1);
            (acc.0.max(child_depth), acc.1 + child_fields)
        }),
        serde_json::Value::Object(map) => map.values().fold((depth, map.len()), |acc, item| {
            let (child_depth, child_fields) = json_stats(item, depth + 1);
            (acc.0.max(child_depth), acc.1 + child_fields)
        }),
        _ => (depth, 0),
    }
}
