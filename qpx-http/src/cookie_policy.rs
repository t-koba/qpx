use anyhow::{Result, anyhow};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookiePair {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCookie {
    pub name: String,
    pub value: String,
    pub expires: Option<String>,
    pub max_age: Option<i64>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
}

impl SetCookie {
    pub fn parse(value: &str) -> Result<Self> {
        let mut parts = value.split(';');
        let pair = parse_cookie_pair(parts.next().unwrap_or_default().trim())?;
        let mut cookie = Self {
            name: pair.name,
            value: pair.value,
            expires: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        let mut seen = HashSet::new();
        for attribute in parts {
            let (name, value) = attribute
                .trim()
                .split_once('=')
                .map_or((attribute.trim(), None), |(name, value)| {
                    (name.trim(), Some(value.trim()))
                });
            let normalized = name.to_ascii_lowercase();
            if !seen.insert(normalized.clone()) {
                return Err(anyhow!("duplicate Set-Cookie attribute: {name}"));
            }
            match normalized.as_str() {
                "expires" => {
                    let value = require_attribute_value(name, value)?;
                    httpdate::parse_http_date(value)
                        .map_err(|_| anyhow!("invalid Expires attribute"))?;
                    cookie.expires = Some(value.to_string());
                }
                "max-age" => {
                    cookie.max_age = Some(require_attribute_value(name, value)?.parse()?);
                }
                "domain" => {
                    let domain = require_attribute_value(name, value)?
                        .trim_start_matches('.')
                        .to_ascii_lowercase();
                    if domain.is_empty()
                        || domain.bytes().any(|byte| {
                            !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
                        })
                    {
                        return Err(anyhow!("invalid Domain attribute"));
                    }
                    cookie.domain = Some(domain);
                }
                "path" => {
                    let path = require_attribute_value(name, value)?;
                    if !path.starts_with('/') || path.chars().any(char::is_control) {
                        return Err(anyhow!("invalid Path attribute"));
                    }
                    cookie.path = Some(path.to_string());
                }
                "secure" if value.is_none() => cookie.secure = true,
                "httponly" if value.is_none() => cookie.http_only = true,
                "samesite" => {
                    cookie.same_site = Some(
                        match require_attribute_value(name, value)?
                            .to_ascii_lowercase()
                            .as_str()
                        {
                            "strict" => SameSite::Strict,
                            "lax" => SameSite::Lax,
                            "none" => SameSite::None,
                            _ => return Err(anyhow!("invalid SameSite attribute")),
                        },
                    );
                }
                _ => return Err(anyhow!("unsupported Set-Cookie attribute: {name}")),
            }
        }
        cookie.validate()?;
        Ok(cookie)
    }

    pub fn validate(&self) -> Result<()> {
        validate_cookie_name(&self.name)?;
        validate_cookie_value(&self.value)?;
        if self.name.starts_with("__Secure-") && !self.secure {
            return Err(anyhow!("__Secure- cookies require Secure"));
        }
        if self.name.starts_with("__Host-")
            && (!self.secure || self.domain.is_some() || self.path.as_deref() != Some("/"))
        {
            return Err(anyhow!(
                "__Host- cookies require Secure, Path=/, and no Domain"
            ));
        }
        if self.same_site == Some(SameSite::None) && !self.secure {
            return Err(anyhow!("SameSite=None cookies require Secure"));
        }
        Ok(())
    }

    pub fn serialize(&self) -> Result<String> {
        self.validate()?;
        let mut output = format!("{}={}", self.name, self.value);
        if let Some(expires) = &self.expires {
            httpdate::parse_http_date(expires).map_err(|_| anyhow!("invalid Expires attribute"))?;
            output.push_str("; Expires=");
            output.push_str(expires);
        }
        if let Some(max_age) = self.max_age {
            output.push_str(&format!("; Max-Age={max_age}"));
        }
        if let Some(domain) = &self.domain {
            output.push_str("; Domain=");
            output.push_str(domain);
        }
        if let Some(path) = &self.path {
            output.push_str("; Path=");
            output.push_str(path);
        }
        if self.secure {
            output.push_str("; Secure");
        }
        if self.http_only {
            output.push_str("; HttpOnly");
        }
        if let Some(same_site) = self.same_site {
            output.push_str("; SameSite=");
            output.push_str(match same_site {
                SameSite::Strict => "Strict",
                SameSite::Lax => "Lax",
                SameSite::None => "None",
            });
        }
        Ok(output)
    }
}

pub fn parse_cookie_header(value: &str) -> Result<Vec<CookiePair>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(';')
        .map(|pair| parse_cookie_pair(pair.trim()))
        .collect()
}

fn parse_cookie_pair(value: &str) -> Result<CookiePair> {
    let (name, value) = value
        .split_once('=')
        .ok_or_else(|| anyhow!("cookie-pair is missing '='"))?;
    validate_cookie_name(name)?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    validate_cookie_value(value)?;
    Ok(CookiePair {
        name: name.to_string(),
        value: value.to_string(),
    })
}

fn validate_cookie_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.bytes().any(|byte| {
            byte <= 0x20
                || byte >= 0x7f
                || matches!(
                    byte,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
    {
        return Err(anyhow!("invalid cookie name"));
    }
    Ok(())
}

fn validate_cookie_value(value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| !matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))
    {
        return Err(anyhow!("invalid cookie value"));
    }
    Ok(())
}

fn require_attribute_value<'a>(name: &str, value: Option<&'a str>) -> Result<&'a str> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Set-Cookie attribute {name} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cookie_header_without_owning_a_cookie_jar() {
        let cookies = parse_cookie_header("sid=abc; theme=dark").unwrap();
        assert_eq!(cookies[0].name, "sid");
        assert_eq!(cookies[1].value, "dark");
    }

    #[test]
    fn set_cookie_round_trips_security_attributes() {
        let raw = "__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax";
        assert_eq!(SetCookie::parse(raw).unwrap().serialize().unwrap(), raw);
    }

    #[test]
    fn rejects_unsafe_cookie_prefix_configuration() {
        assert!(SetCookie::parse("__Host-session=abc; Path=/").is_err());
        assert!(SetCookie::parse("sid=abc; SameSite=None").is_err());
    }
}
