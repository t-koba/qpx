use super::{DecodedRequestHead, errors::HeaderDecodeError};
use crate::H3Result as Result;
use crate::qpack_fields::{append_header, validate_h3_regular_field};
use anyhow::anyhow;
use http::{HeaderMap, Method, Uri};

pub(crate) fn decode_request_head_from_fields(
    fields: Vec<(String, Vec<u8>)>,
) -> std::result::Result<DecodedRequestHead, HeaderDecodeError> {
    let mut method: Option<Method> = None;
    let mut scheme: Option<String> = None;
    let mut authority: Option<String> = None;
    let mut path: Option<String> = None;
    let mut protocol: Option<String> = None;
    let mut headers = HeaderMap::new();
    let mut regular_seen = false;

    for (name, value) in fields {
        let is_pseudo = name.starts_with(':');
        if is_pseudo && regular_seen {
            return Err(HeaderDecodeError::message(format!(
                "pseudo header {name} appeared after a regular header"
            )));
        }
        match name.as_str() {
            ":method" => {
                if method.is_some() {
                    return Err(HeaderDecodeError::message(
                        "duplicate :method pseudo header",
                    ));
                }
                method = Some(
                    Method::from_bytes(value.as_slice())
                        .map_err(|err| HeaderDecodeError::message(err.to_string()))?,
                )
            }
            ":scheme" => {
                if scheme
                    .replace(pseudo_value_to_string(&name, value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message(
                        "duplicate :scheme pseudo header",
                    ));
                }
            }
            ":authority" => {
                if authority
                    .replace(pseudo_value_to_string(&name, value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message(
                        "duplicate :authority pseudo header",
                    ));
                }
            }
            ":path" => {
                if path
                    .replace(pseudo_value_to_string(&name, value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message("duplicate :path pseudo header"));
                }
            }
            ":protocol" => {
                if protocol
                    .replace(pseudo_value_to_string(&name, value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message(
                        "duplicate :protocol pseudo header",
                    ));
                }
            }
            other if other.starts_with(':') => {
                return Err(HeaderDecodeError::message(format!(
                    "unsupported pseudo header {other}"
                )));
            }
            _ => {
                regular_seen = true;
                validate_h3_regular_field(&name, &value)?;
                append_header(&mut headers, &name, &value)
                    .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
            }
        }
    }

    let method = method.ok_or_else(|| HeaderDecodeError::message("missing :method"))?;
    if protocol.is_some() && method != Method::CONNECT {
        return Err(HeaderDecodeError::message(
            ":protocol is only valid on CONNECT requests",
        ));
    }
    if method == Method::CONNECT && protocol.is_none() {
        if authority.is_none() {
            return Err(HeaderDecodeError::message(
                "traditional CONNECT requires :authority",
            ));
        }
        if scheme.is_some() || path.is_some() {
            return Err(HeaderDecodeError::message(
                "traditional CONNECT must not include :scheme or :path",
            ));
        }
    } else {
        if scheme.is_none() {
            return Err(HeaderDecodeError::message("missing :scheme"));
        }
        if path.is_none() {
            return Err(HeaderDecodeError::message("missing :path"));
        }
    }
    let uri = build_uri(
        scheme.as_deref(),
        authority.as_deref(),
        path.as_deref(),
        method == Method::CONNECT && protocol.is_none(),
    )
    .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(())
        .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
    *request.headers_mut() = headers;
    Ok(DecodedRequestHead { request, protocol })
}

fn build_uri(
    scheme: Option<&str>,
    authority: Option<&str>,
    path: Option<&str>,
    authority_only: bool,
) -> Result<Uri> {
    if authority_only {
        let authority = authority.ok_or_else(|| anyhow!("CONNECT requires :authority"))?;
        return Uri::builder()
            .authority(authority)
            .build()
            .map_err(Into::into);
    }

    let mut builder = Uri::builder();
    if let Some(scheme) = scheme {
        builder = builder.scheme(scheme);
    }
    if let Some(authority) = authority {
        builder = builder.authority(authority);
    }
    if let Some(path) = path {
        builder = builder.path_and_query(path);
    }
    builder.build().map_err(Into::into)
}

pub(super) fn pseudo_value_to_string(
    name: &str,
    value: Vec<u8>,
) -> std::result::Result<String, HeaderDecodeError> {
    String::from_utf8(value)
        .map_err(|err| HeaderDecodeError::message(format!("invalid UTF-8 {name} value: {err}")))
}
