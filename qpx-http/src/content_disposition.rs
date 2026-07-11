//! RFC 6266 Content-Disposition field codec.

use http::HeaderValue;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDisposition {
    pub disposition: String,
    pub parameters: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ContentDispositionError {
    #[error("Content-Disposition is not visible ASCII")]
    InvalidBytes,
    #[error("Content-Disposition disposition type is invalid")]
    InvalidDisposition,
    #[error("Content-Disposition parameter is malformed")]
    InvalidParameter,
    #[error("Content-Disposition contains a duplicate parameter: {0}")]
    DuplicateParameter(String),
    #[error("Content-Disposition extended parameter uses an unsupported charset")]
    UnsupportedCharset,
    #[error("Content-Disposition extended parameter is malformed")]
    InvalidExtendedValue,
}

impl ContentDisposition {
    pub fn parse(value: &HeaderValue) -> Result<Self, ContentDispositionError> {
        let source = value
            .to_str()
            .map_err(|_| ContentDispositionError::InvalidBytes)?;
        let parts = split_quoted(source, ';')?;
        let disposition = parts
            .first()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| is_token(value))
            .ok_or(ContentDispositionError::InvalidDisposition)?;
        let mut parameters = BTreeMap::new();
        for part in parts.iter().skip(1) {
            let (name, raw_value) = part
                .split_once('=')
                .ok_or(ContentDispositionError::InvalidParameter)?;
            let name = name.trim().to_ascii_lowercase();
            if !is_token(&name) {
                return Err(ContentDispositionError::InvalidParameter);
            }
            let decoded = if name.ends_with('*') {
                decode_extended(raw_value.trim())?
            } else {
                decode_value(raw_value.trim())?
            };
            if parameters.insert(name.clone(), decoded).is_some() {
                return Err(ContentDispositionError::DuplicateParameter(name));
            }
        }
        Ok(Self {
            disposition,
            parameters,
        })
    }

    pub fn filename(&self) -> Option<&str> {
        self.parameters
            .get("filename*")
            .or_else(|| self.parameters.get("filename"))
            .map(String::as_str)
    }

    pub fn to_header_value(&self) -> Result<HeaderValue, ContentDispositionError> {
        if !is_token(&self.disposition) {
            return Err(ContentDispositionError::InvalidDisposition);
        }
        let mut output = self.disposition.to_ascii_lowercase();
        for (name, value) in &self.parameters {
            if !is_token(name) || name.ends_with('*') {
                return Err(ContentDispositionError::InvalidParameter);
            }
            output.push_str("; ");
            output.push_str(name);
            output.push_str("=\"");
            for character in value.chars() {
                if matches!(character, '\\' | '"') {
                    output.push('\\');
                }
                output.push(character);
            }
            output.push('"');
        }
        HeaderValue::from_str(&output).map_err(|_| ContentDispositionError::InvalidBytes)
    }
}

fn decode_extended(value: &str) -> Result<String, ContentDispositionError> {
    let value = decode_value(value)?;
    let mut parts = value.splitn(3, '\'');
    let charset = parts.next().unwrap_or_default();
    let _language = parts
        .next()
        .ok_or(ContentDispositionError::InvalidExtendedValue)?;
    let encoded = parts
        .next()
        .ok_or(ContentDispositionError::InvalidExtendedValue)?;
    if !charset.eq_ignore_ascii_case("utf-8") {
        return Err(ContentDispositionError::UnsupportedCharset);
    }
    let bytes = percent_decode(encoded)?;
    String::from_utf8(bytes).map_err(|_| ContentDispositionError::InvalidExtendedValue)
}

fn percent_decode(value: &str) -> Result<Vec<u8>, ContentDispositionError> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(ContentDispositionError::InvalidExtendedValue);
            }
            let high = hex(bytes[index + 1])?;
            let low = hex(bytes[index + 2])?;
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    Ok(output)
}

fn hex(value: u8) -> Result<u8, ContentDispositionError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ContentDispositionError::InvalidExtendedValue),
    }
}

fn decode_value(value: &str) -> Result<String, ContentDispositionError> {
    if let Some(quoted) = value.strip_prefix('"') {
        let quoted = quoted
            .strip_suffix('"')
            .ok_or(ContentDispositionError::InvalidParameter)?;
        let mut output = String::new();
        let mut escaped = false;
        for character in quoted.chars() {
            if escaped {
                output.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' || character.is_control() {
                return Err(ContentDispositionError::InvalidParameter);
            } else {
                output.push(character);
            }
        }
        if escaped {
            return Err(ContentDispositionError::InvalidParameter);
        }
        Ok(output)
    } else if is_token(value) {
        Ok(value.to_string())
    } else {
        Err(ContentDispositionError::InvalidParameter)
    }
}

fn split_quoted(value: &str, separator: char) -> Result<Vec<&str>, ContentDispositionError> {
    let mut parts = Vec::new();
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
            parts.push(&value[start..index]);
            start = index + character.len_utf8();
        }
    }
    if quoted || escaped {
        return Err(ContentDispositionError::InvalidParameter);
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
    fn extended_filename_takes_precedence() {
        let parsed = ContentDisposition::parse(&HeaderValue::from_static(
            "attachment; filename=report.txt; filename*=UTF-8''r%C3%A9sum%C3%A9.txt",
        ))
        .unwrap();
        assert_eq!(parsed.filename(), Some("résumé.txt"));
    }

    #[test]
    fn duplicate_parameter_is_rejected() {
        assert!(matches!(
            ContentDisposition::parse(&HeaderValue::from_static(
                "attachment; filename=a; filename=b"
            )),
            Err(ContentDispositionError::DuplicateParameter(_))
        ));
    }
}
