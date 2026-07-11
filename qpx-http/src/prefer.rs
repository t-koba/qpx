//! RFC 7240 Prefer and Preference-Applied field codec.

use http::HeaderValue;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preference {
    pub token: String,
    pub value: Option<String>,
    pub parameters: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PreferError {
    #[error("Prefer field contains invalid bytes")]
    InvalidBytes,
    #[error("Prefer field contains a malformed preference")]
    InvalidPreference,
    #[error("Prefer field contains a duplicate preference: {0}")]
    DuplicatePreference(String),
}

pub fn parse_prefer(value: &HeaderValue) -> Result<Vec<Preference>, PreferError> {
    let source = value.to_str().map_err(|_| PreferError::InvalidBytes)?;
    let mut preferences = Vec::new();
    let mut seen = BTreeMap::new();
    for member in split_quoted(source, ',')? {
        let components = split_quoted(member, ';')?;
        let first = components
            .first()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .ok_or(PreferError::InvalidPreference)?;
        let (token, value) = parse_pair(first)?;
        let token = token.to_ascii_lowercase();
        if seen.insert(token.clone(), ()).is_some() {
            return Err(PreferError::DuplicatePreference(token));
        }
        let mut parameters = BTreeMap::new();
        for component in components.iter().skip(1) {
            let (name, value) = parse_pair(component.trim())?;
            let name = name.to_ascii_lowercase();
            if parameters.insert(name, value).is_some() {
                return Err(PreferError::InvalidPreference);
            }
        }
        preferences.push(Preference {
            token,
            value,
            parameters,
        });
    }
    if preferences.is_empty() {
        return Err(PreferError::InvalidPreference);
    }
    Ok(preferences)
}

pub fn serialize_preference_applied(
    preferences: &[Preference],
) -> Result<HeaderValue, PreferError> {
    if preferences.is_empty() {
        return Err(PreferError::InvalidPreference);
    }
    let mut members = Vec::with_capacity(preferences.len());
    for preference in preferences {
        if !is_token(&preference.token) || !preference.parameters.is_empty() {
            return Err(PreferError::InvalidPreference);
        }
        let mut member = preference.token.to_ascii_lowercase();
        if let Some(value) = preference.value.as_deref() {
            member.push('=');
            member.push_str(&encode_value(value));
        }
        members.push(member);
    }
    HeaderValue::from_str(&members.join(", ")).map_err(|_| PreferError::InvalidBytes)
}

fn parse_pair(value: &str) -> Result<(&str, Option<String>), PreferError> {
    let (name, value) = match value.split_once('=') {
        Some((name, value)) => (name.trim(), Some(decode_value(value.trim())?)),
        None => (value.trim(), None),
    };
    if !is_token(name) {
        return Err(PreferError::InvalidPreference);
    }
    Ok((name, value))
}

fn decode_value(value: &str) -> Result<String, PreferError> {
    if let Some(value) = value.strip_prefix('"') {
        let value = value
            .strip_suffix('"')
            .ok_or(PreferError::InvalidPreference)?;
        let mut output = String::new();
        let mut escaped = false;
        for character in value.chars() {
            if escaped {
                output.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' || character.is_control() {
                return Err(PreferError::InvalidPreference);
            } else {
                output.push(character);
            }
        }
        if escaped {
            return Err(PreferError::InvalidPreference);
        }
        Ok(output)
    } else if is_token(value) {
        Ok(value.to_string())
    } else {
        Err(PreferError::InvalidPreference)
    }
}

fn encode_value(value: &str) -> String {
    if is_token(value) {
        value.to_string()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn split_quoted(value: &str, separator: char) -> Result<Vec<&str>, PreferError> {
    let mut output = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == separator && !quoted {
            output.push(&value[start..index]);
            start = index + character.len_utf8();
        }
    }
    if quoted || escaped {
        return Err(PreferError::InvalidPreference);
    }
    output.push(&value[start..]);
    Ok(output)
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wait_and_return_preferences() {
        let parsed = parse_prefer(&HeaderValue::from_static(
            "respond-async, wait=10; handling=strict, return=representation",
        ))
        .unwrap();
        assert_eq!(parsed[0].token, "respond-async");
        assert_eq!(parsed[1].value.as_deref(), Some("10"));
        assert_eq!(parsed[1].parameters["handling"].as_deref(), Some("strict"));
    }

    #[test]
    fn duplicate_preferences_are_rejected() {
        assert!(matches!(
            parse_prefer(&HeaderValue::from_static("wait=1, WAIT=2")),
            Err(PreferError::DuplicatePreference(_))
        ));
    }
}
