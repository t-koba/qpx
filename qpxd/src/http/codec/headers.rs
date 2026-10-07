use anyhow::Result;
use http::header::COOKIE;

pub(crate) fn h1_headers_to_http(src: &::http::HeaderMap) -> Result<http::HeaderMap> {
    if src.get_all(COOKIE).iter().count() <= 1 {
        return Ok(src.clone());
    }
    let mut headers = http::HeaderMap::with_capacity(src.len());
    let mut merged_cookie = Vec::new();
    let mut cookie_seen = false;
    for (name, value) in src {
        if name == COOKIE {
            if cookie_seen {
                merged_cookie.extend_from_slice(b"; ");
            }
            cookie_seen = true;
            merged_cookie.extend_from_slice(value.as_bytes());
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    if cookie_seen {
        headers.insert(COOKIE, http::HeaderValue::from_bytes(&merged_cookie)?);
    }
    Ok(headers)
}

pub(crate) fn h1_headers_into_http(src: ::http::HeaderMap) -> Result<http::HeaderMap> {
    if src.get_all(COOKIE).iter().count() <= 1 {
        return Ok(src);
    }
    h1_headers_to_http(&src)
}

pub(crate) fn http_headers_to_h1(src: &http::HeaderMap) -> Result<::http::HeaderMap> {
    Ok(src.clone())
}

#[cfg(test)]
mod tests {
    use super::h1_headers_to_http;
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn cookie_join_preserves_empty_field_boundaries() {
        let mut headers = HeaderMap::new();
        for value in ["", "a=1", ""] {
            headers.append("cookie", HeaderValue::from_static(value));
        }
        let joined = h1_headers_to_http(&headers).expect("join cookie fields");
        assert_eq!(joined["cookie"], "; a=1; ");
        assert_eq!(joined.get_all("cookie").iter().count(), 1);
    }
}
