use anyhow::{Result, anyhow};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const PROBLEM_JSON: &str = "application/problem+json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(flatten)]
    pub extensions: Map<String, Value>,
}

impl ProblemDetails {
    pub fn new(status: StatusCode, title: impl Into<String>) -> Self {
        Self {
            type_uri: "about:blank".to_string(),
            title: title.into(),
            status: status.as_u16(),
            detail: None,
            instance: None,
            extensions: Map::new(),
        }
    }

    pub fn with_type(mut self, type_uri: impl Into<String>) -> Result<Self> {
        let type_uri = type_uri.into();
        validate_uri_reference(&type_uri, "problem type")?;
        self.type_uri = type_uri;
        Ok(self)
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_instance(mut self, instance: impl Into<String>) -> Result<Self> {
        let instance = instance.into();
        validate_uri_reference(&instance, "problem instance")?;
        self.instance = Some(instance);
        Ok(self)
    }

    pub fn with_extension(mut self, name: impl Into<String>, value: Value) -> Result<Self> {
        let name = name.into();
        if matches!(
            name.as_str(),
            "type" | "title" | "status" | "detail" | "instance"
        ) || name.is_empty()
        {
            return Err(anyhow!("problem extension name is reserved or empty"));
        }
        self.extensions.insert(name, value);
        Ok(self)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        if StatusCode::from_u16(self.status).is_err() {
            return Err(anyhow!("problem status is not a valid HTTP status"));
        }
        validate_uri_reference(&self.type_uri, "problem type")?;
        if let Some(instance) = self.instance.as_deref() {
            validate_uri_reference(instance, "problem instance")?;
        }
        Ok(serde_json::to_vec(self)?)
    }
}

fn validate_uri_reference(value: &str, field: &str) -> Result<()> {
    if value == "about:blank" || value.starts_with('/') || url::Url::parse(value).is_ok() {
        return Ok(());
    }
    Err(anyhow!("{field} is not a valid URI reference"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_rfc9457_problem_details() {
        let problem = ProblemDetails::new(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded")
            .with_type("https://qpx.example/problems/rate-limit")
            .unwrap()
            .with_detail("The route quota was exhausted")
            .with_instance("/requests/123")
            .unwrap()
            .with_extension("retry_after", serde_json::json!(30))
            .unwrap();
        let value: Value = serde_json::from_slice(&problem.to_json().unwrap()).unwrap();
        assert_eq!(value["status"], 429);
        assert_eq!(value["retry_after"], 30);
    }

    #[test]
    fn rejects_reserved_extension_names() {
        assert!(
            ProblemDetails::new(StatusCode::BAD_REQUEST, "Bad request")
                .with_extension("status", Value::Null)
                .is_err()
        );
    }
}
