//! RFC 7239 `Forwarded` field codec.

use http::{HeaderMap, HeaderValue};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedElement {
    parameters: Vec<(String, String)>,
}

impl ForwardedElement {
    pub fn new(
        parameters: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ForwardedError> {
        let parameters = parameters.into_iter().collect::<Vec<_>>();
        validate_parameters(&parameters)?;
        Ok(Self { parameters })
    }

    pub fn parameters(&self) -> &[(String, String)] {
        &self.parameters
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ForwardedError {
    #[error("Forwarded field is not valid ASCII")]
    NonAscii,
    #[error("Forwarded field contains an empty element or parameter")]
    Empty,
    #[error("Forwarded parameter name is not an HTTP token: {0}")]
    InvalidName(String),
    #[error("Forwarded parameter is missing '='")]
    MissingEquals,
    #[error("Forwarded parameter value is malformed")]
    InvalidValue,
    #[error("Forwarded element repeats parameter {0}")]
    DuplicateParameter(String),
    #[error("Forwarded field cannot be represented as an HTTP field value")]
    InvalidHeaderValue,
}

pub fn parse_forwarded(headers: &HeaderMap) -> Result<Vec<ForwardedElement>, ForwardedError> {
    let mut elements = Vec::new();
    for value in headers.get_all("forwarded") {
        let value = value.to_str().map_err(|_| ForwardedError::NonAscii)?;
        for raw_element in split_quoted(value, b',')? {
            let raw_element = raw_element.trim();
            if raw_element.is_empty() {
                return Err(ForwardedError::Empty);
            }
            let mut parameters = Vec::new();
            for raw_parameter in split_quoted(raw_element, b';')? {
                let raw_parameter = raw_parameter.trim();
                if raw_parameter.is_empty() {
                    return Err(ForwardedError::Empty);
                }
                let (name, raw_value) = raw_parameter
                    .split_once('=')
                    .ok_or(ForwardedError::MissingEquals)?;
                let name = name.trim().to_ascii_lowercase();
                if !is_token(&name) {
                    return Err(ForwardedError::InvalidName(name));
                }
                let value = parse_value(raw_value.trim())?;
                parameters.push((name, value));
            }
            validate_parameters(&parameters)?;
            elements.push(ForwardedElement { parameters });
        }
    }
    Ok(elements)
}

pub fn serialize_forwarded(elements: &[ForwardedElement]) -> Result<HeaderValue, ForwardedError> {
    if elements.is_empty() {
        return Err(ForwardedError::Empty);
    }
    let mut output = String::new();
    for (element_index, element) in elements.iter().enumerate() {
        validate_parameters(&element.parameters)?;
        if element.parameters.is_empty() {
            return Err(ForwardedError::Empty);
        }
        if element_index != 0 {
            output.push_str(", ");
        }
        for (parameter_index, (name, value)) in element.parameters.iter().enumerate() {
            if parameter_index != 0 {
                output.push(';');
            }
            output.push_str(&name.to_ascii_lowercase());
            output.push('=');
            if is_token(value) {
                output.push_str(value);
            } else {
                output.push('"');
                for character in value.chars() {
                    if character == '"' || character == '\\' {
                        output.push('\\');
                    }
                    output.push(character);
                }
                output.push('"');
            }
        }
    }
    HeaderValue::from_str(&output).map_err(|_| ForwardedError::InvalidHeaderValue)
}

fn validate_parameters(parameters: &[(String, String)]) -> Result<(), ForwardedError> {
    let mut names = HashSet::new();
    for (name, value) in parameters {
        if !is_token(name) {
            return Err(ForwardedError::InvalidName(name.clone()));
        }
        let normalized = name.to_ascii_lowercase();
        if !names.insert(normalized.clone()) {
            return Err(ForwardedError::DuplicateParameter(normalized));
        }
        if value.is_empty()
            || !value.is_ascii()
            || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(ForwardedError::InvalidValue);
        }
    }
    Ok(())
}

fn parse_value(raw: &str) -> Result<String, ForwardedError> {
    if is_token(raw) {
        return Ok(raw.to_string());
    }
    let bytes = raw.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return Err(ForwardedError::InvalidValue);
    }
    let mut output = String::new();
    let mut escaped = false;
    for byte in bytes[1..bytes.len() - 1].iter().copied() {
        if escaped {
            if byte != b'"' && byte != b'\\' {
                return Err(ForwardedError::InvalidValue);
            }
            output.push(char::from(byte));
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' || byte < 0x20 || byte == 0x7f || !byte.is_ascii() {
            return Err(ForwardedError::InvalidValue);
        } else {
            output.push(char::from(byte));
        }
    }
    if escaped || output.is_empty() {
        return Err(ForwardedError::InvalidValue);
    }
    Ok(output)
}

fn split_quoted(value: &str, separator: u8) -> Result<Vec<&str>, ForwardedError> {
    if !value.is_ascii() {
        return Err(ForwardedError::NonAscii);
    }
    let bytes = value.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            current if current == separator && !quoted => {
                parts.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || escaped {
        return Err(ForwardedError::InvalidValue);
    }
    parts.push(&value[start..]);
    Ok(parts)
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
    fn parses_multiple_field_lines_and_quoted_nodes() {
        let mut headers = HeaderMap::new();
        headers.append(
            "forwarded",
            HeaderValue::from_static("for=192.0.2.43;proto=https;by=203.0.113.60"),
        );
        headers.append(
            "forwarded",
            HeaderValue::from_static("for=\"[2001:db8:cafe::17]:4711\";host=example.com"),
        );
        let parsed = parse_forwarded(&headers).expect("valid Forwarded field");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].get("proto"), Some("https"));
        assert_eq!(parsed[1].get("for"), Some("[2001:db8:cafe::17]:4711"));
    }

    #[test]
    fn serialization_quotes_values_that_are_not_tokens() {
        let element = ForwardedElement::new([
            ("for".to_string(), "[2001:db8::1]".to_string()),
            ("proto".to_string(), "https".to_string()),
        ])
        .expect("element");
        let value = serialize_forwarded(&[element]).expect("serialize");
        assert_eq!(value, "for=\"[2001:db8::1]\";proto=https");
    }

    #[test]
    fn rejects_duplicate_parameters_and_broken_quotes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            HeaderValue::from_static("for=192.0.2.1;For=192.0.2.2"),
        );
        assert!(matches!(
            parse_forwarded(&headers),
            Err(ForwardedError::DuplicateParameter(_))
        ));

        headers.insert("forwarded", HeaderValue::from_static("for=\"192.0.2.1"));
        assert_eq!(parse_forwarded(&headers), Err(ForwardedError::InvalidValue));
    }
}
