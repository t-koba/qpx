use crate::http::protocol::common::trim_http_ows;
use hyper_util::rt::TokioIo;
use qpx_core::http_token::{header_value_members, header_values_contain_token, is_http_token};
use qpx_http::body::Body;
use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;
use tokio::time::timeout;

pub(crate) fn is_websocket_upgrade(
    method: &http::Method,
    headers: &http::HeaderMap,
) -> anyhow::Result<bool> {
    let websocket = header_values_contain_token(headers, &http::header::UPGRADE, "websocket");
    let connection_upgrade =
        header_values_contain_token(headers, &http::header::CONNECTION, "upgrade");
    if !websocket && !connection_upgrade {
        return Ok(false);
    }
    if !websocket || !connection_upgrade {
        return Err(anyhow::anyhow!("incomplete WebSocket upgrade handshake"));
    }
    if method != http::Method::GET {
        return Err(anyhow::anyhow!("WebSocket upgrade requires GET"));
    }
    let mut versions = headers.get_all("sec-websocket-version").iter();
    let version = versions
        .next()
        .ok_or_else(|| anyhow::anyhow!("WebSocket version must occur exactly once"))?;
    if versions.next().is_some() {
        return Err(anyhow::anyhow!("WebSocket version must occur exactly once"));
    }
    let version = version
        .to_str()
        .map_err(|_| anyhow::anyhow!("WebSocket version is not ASCII"))?;
    if trim_http_ows(version) != "13" {
        return Err(anyhow::anyhow!("WebSocket version must be exactly 13"));
    }
    let mut keys = headers.get_all("sec-websocket-key").iter();
    let key = keys
        .next()
        .ok_or_else(|| anyhow::anyhow!("WebSocket key is missing"))?;
    if keys.next().is_some() {
        return Err(anyhow::anyhow!("WebSocket key must occur exactly once"));
    }
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key.as_bytes())
        .map_err(|_| anyhow::anyhow!("WebSocket key is not valid base64"))?;
    if decoded.len() != 16 {
        return Err(anyhow::anyhow!("WebSocket key must decode to 16 bytes"));
    }
    let _ = parse_websocket_subprotocol_offers(headers)?;
    Ok(true)
}

/// Validate the combined, case-sensitive list of client subprotocol offers.
fn parse_websocket_subprotocol_offers(headers: &http::HeaderMap) -> anyhow::Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut protocols = Vec::new();
    for value in headers.get_all("sec-websocket-protocol") {
        let value = value
            .to_str()
            .map_err(|_| anyhow::anyhow!("WebSocket subprotocol is not ASCII"))?;
        for token in value.split(',').map(trim_http_ows) {
            if !is_http_token(token) {
                return Err(anyhow::anyhow!("WebSocket subprotocol token is invalid"));
            }
            if !seen.insert(token) {
                return Err(anyhow::anyhow!(
                    "WebSocket subprotocol offers must be unique"
                ));
            }
            protocols.push(token.to_owned());
        }
    }
    Ok(protocols)
}

pub(crate) fn websocket_response_expectation(
    headers: &http::HeaderMap,
) -> anyhow::Result<(String, Vec<String>)> {
    let key = headers
        .get("sec-websocket-key")
        .ok_or_else(|| anyhow::anyhow!("WebSocket key is missing"))?;
    let mut material = Vec::with_capacity(key.as_bytes().len() + 36);
    material.extend_from_slice(key.as_bytes());
    material.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &material);
    use base64::Engine as _;
    let accept = base64::engine::general_purpose::STANDARD.encode(digest.as_ref());
    let protocol_header = http::header::HeaderName::from_static("sec-websocket-protocol");
    let protocols = header_value_members(headers, &protocol_header)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    Ok((accept, protocols))
}

pub(crate) fn validate_extended_connect_websocket_request(
    protocol: &str,
    headers: &http::HeaderMap,
) -> anyhow::Result<Option<Vec<String>>> {
    if !protocol.eq_ignore_ascii_case("websocket") {
        return Ok(None);
    }
    if headers.contains_key(http::header::CONNECTION)
        || headers.contains_key(http::header::UPGRADE)
        || headers.contains_key("sec-websocket-key")
    {
        return Err(anyhow::anyhow!(
            "extended CONNECT WebSocket request contains HTTP/1.1 handshake fields"
        ));
    }
    let versions = headers
        .get_all("sec-websocket-version")
        .iter()
        .map(|value| value.to_str().map(trim_http_ows))
        .collect::<Result<Vec<_>, _>>()?;
    if versions.as_slice() != ["13"] {
        return Err(anyhow::anyhow!("WebSocket version must be exactly 13"));
    }
    let protocols = parse_websocket_subprotocol_offers(headers)?;
    Ok(Some(protocols))
}

pub(crate) fn validate_extended_connect_websocket_response(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    offered_protocols: &[String],
) -> anyhow::Result<()> {
    if !status.is_success() {
        return Ok(());
    }
    if headers.contains_key(http::header::CONNECTION)
        || headers.contains_key(http::header::UPGRADE)
        || headers.contains_key("sec-websocket-accept")
    {
        return Err(anyhow::anyhow!(
            "extended CONNECT WebSocket response contains HTTP/1.1 handshake fields"
        ));
    }
    let mut selected = headers.get_all("sec-websocket-protocol").iter();
    if let Some(protocol) = selected.next() {
        let protocol = protocol
            .to_str()
            .map_err(|_| anyhow::anyhow!("WebSocket selected subprotocol is not ASCII"))?;
        if selected.next().is_some()
            || !is_http_token(protocol)
            || !offered_protocols.iter().any(|offered| offered == protocol)
        {
            return Err(anyhow::anyhow!(
                "WebSocket selected subprotocol was not offered"
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_websocket_switching_response(
    response: &http::Response<Body>,
    expected_accept: &str,
    offered_protocols: &[String],
) -> anyhow::Result<()> {
    if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        return Ok(());
    }
    if !header_values_contain_token(response.headers(), &http::header::UPGRADE, "websocket")
        || !header_values_contain_token(response.headers(), &http::header::CONNECTION, "upgrade")
    {
        return Err(anyhow::anyhow!(
            "WebSocket switching response is missing Upgrade fields"
        ));
    }
    let mut accepts = response.headers().get_all("sec-websocket-accept").iter();
    let accept = accepts
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("WebSocket accept is missing"))?;
    if accepts.next().is_some() || accept != expected_accept {
        return Err(anyhow::anyhow!(
            "WebSocket accept does not match request key"
        ));
    }
    let mut selected = response.headers().get_all("sec-websocket-protocol").iter();
    if let Some(protocol) = selected.next() {
        let protocol = protocol
            .to_str()
            .map_err(|_| anyhow::anyhow!("WebSocket selected subprotocol is not ASCII"))?;
        if selected.next().is_some()
            || !is_http_token(protocol)
            || !offered_protocols.iter().any(|offered| offered == protocol)
        {
            return Err(anyhow::anyhow!(
                "WebSocket selected subprotocol was not offered"
            ));
        }
    }
    Ok(())
}

pub(crate) fn spawn_upgrade_tunnel<F, I, E>(
    response: &mut hyper::Response<Body>,
    client_upgrade: F,
    context: &'static str,
    upgrade_wait_timeout: Duration,
    idle_timeout: Duration,
) where
    F: Future<Output = Result<I, E>> + Send + 'static,
    E: Into<anyhow::Error> + Send + 'static,
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if response.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
        return;
    }
    let server_upgrade = hyper::upgrade::on(response);
    tokio::spawn(async move {
        let client = timeout(upgrade_wait_timeout, client_upgrade).await;
        let server = timeout(upgrade_wait_timeout, server_upgrade).await;
        match (client, server) {
            (Ok(Ok(client)), Ok(Ok(server))) => {
                let mut client = client;
                let mut server = TokioIo::new(server);
                if let Err(err) = crate::tunnel::relay_tcp_tunnel(
                    &mut client,
                    &mut server,
                    crate::tunnel::TunnelPolicy::tcp(Some(idle_timeout), None, None),
                )
                .await
                {
                    tracing::warn!(error = ?err, %context, "websocket tunnel timed out");
                }
            }
            (Ok(Err(err)), _) => {
                let err: anyhow::Error = err.into();
                tracing::warn!(error = ?err, %context, "websocket upgrade failed");
            }
            (_, Ok(Err(err))) => {
                tracing::warn!(error = ?err, %context, "websocket upgrade failed");
            }
            (Err(_), _) | (_, Err(_)) => {
                tracing::warn!(%context, "websocket upgrade timed out");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{
        is_websocket_upgrade, validate_extended_connect_websocket_request,
        validate_extended_connect_websocket_response, websocket_response_expectation,
    };
    use http::HeaderMap;

    fn valid_h1_websocket_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(http::header::CONNECTION, "upgrade".parse().unwrap());
        headers.insert("sec-websocket-version", "13".parse().unwrap());
        headers.insert(
            "sec-websocket-key",
            "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
        );
        headers
    }

    #[test]
    fn websocket_upgrade_accepts_list_and_repeated_connection_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, "h2c, websocket".parse().unwrap());
        headers.append(http::header::CONNECTION, "keep-alive".parse().unwrap());
        headers.append(http::header::CONNECTION, "Upgrade".parse().unwrap());

        headers.insert("sec-websocket-version", "13".parse().unwrap());
        headers.insert(
            "sec-websocket-key",
            "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
        );
        assert!(is_websocket_upgrade(&http::Method::GET, &headers).unwrap());
    }

    #[test]
    fn websocket_response_expectation_preserves_readable_members_and_omits_empty_values() {
        let mut headers = HeaderMap::new();
        headers.insert("sec-websocket-key", "key".parse().unwrap());
        headers.append(
            "sec-websocket-protocol",
            " chat, superchat ".parse().unwrap(),
        );
        headers.append("sec-websocket-protocol", ", ,".parse().unwrap());
        headers.append("sec-websocket-protocol", "Chat".parse().unwrap());
        headers.append(
            "sec-websocket-protocol",
            http::HeaderValue::from_bytes(b"\xff").unwrap(),
        );

        let (_, protocols) = websocket_response_expectation(&headers).unwrap();
        assert_eq!(protocols, ["chat", "superchat", "Chat"]);
    }

    #[test]
    fn websocket_upgrade_rejects_invalid_key_and_version() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(http::header::CONNECTION, "upgrade".parse().unwrap());
        headers.insert("sec-websocket-version", "12".parse().unwrap());
        headers.insert("sec-websocket-key", "invalid".parse().unwrap());
        assert!(is_websocket_upgrade(&http::Method::GET, &headers).is_err());
    }

    #[test]
    fn extended_connect_websocket_uses_rfc8441_fields() {
        let mut headers = HeaderMap::new();
        headers.insert("sec-websocket-version", "13".parse().unwrap());
        headers.insert("sec-websocket-protocol", "chat, superchat".parse().unwrap());
        let offered = validate_extended_connect_websocket_request("websocket", &headers)
            .unwrap()
            .unwrap();
        let response = http::Response::builder()
            .status(200)
            .header("sec-websocket-protocol", "chat")
            .body(())
            .unwrap();
        validate_extended_connect_websocket_response(
            response.status(),
            response.headers(),
            &offered,
        )
        .unwrap();
    }

    #[test]
    fn extended_connect_websocket_rejects_h1_fields_and_unoffered_protocol() {
        let mut headers = HeaderMap::new();
        headers.insert("sec-websocket-version", "13".parse().unwrap());
        headers.insert("sec-websocket-key", "key".parse().unwrap());
        assert!(validate_extended_connect_websocket_request("websocket", &headers).is_err());

        let response = http::Response::builder()
            .status(200)
            .header("sec-websocket-protocol", "other")
            .body(())
            .unwrap();
        assert!(
            validate_extended_connect_websocket_response(
                response.status(),
                response.headers(),
                &["chat".to_owned()],
            )
            .is_err()
        );
    }
    #[test]
    fn h1_websocket_requires_one_version_field_containing_13() {
        let invalid_versions: Vec<Vec<&str>> = vec![
            vec![],
            vec!["12"],
            vec!["13", "12"],
            vec!["12", "13"],
            vec!["13", "13"],
            vec!["13, 12"],
            vec!["13", ""],
        ];
        for values in &invalid_versions {
            let mut headers = valid_h1_websocket_headers();
            headers.remove("sec-websocket-version");
            for value in values {
                headers.append("sec-websocket-version", value.parse().unwrap());
            }
            assert!(
                is_websocket_upgrade(&http::Method::GET, &headers).is_err(),
                "accepted versions {values:?}"
            );
        }

        let mut headers = valid_h1_websocket_headers();
        headers.append(
            "sec-websocket-version",
            http::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        assert!(is_websocket_upgrade(&http::Method::GET, &headers).is_err());

        let mut headers = valid_h1_websocket_headers();
        headers.insert(
            "sec-websocket-version",
            http::HeaderValue::from_bytes(b" \t13\t ").unwrap(),
        );
        assert!(is_websocket_upgrade(&http::Method::GET, &headers).unwrap());
    }

    #[test]
    fn websocket_subprotocol_offers_are_unique_across_fields_and_lists() {
        let invalid_offers: Vec<Vec<&str>> = vec![
            vec!["chat, chat"],
            vec!["chat", "chat"],
            vec!["chat, superchat", "superchat"],
            vec![" chat\t,chat"],
        ];
        for values in &invalid_offers {
            let mut h1_headers = valid_h1_websocket_headers();
            for value in values {
                h1_headers.append("sec-websocket-protocol", value.parse().unwrap());
            }
            assert!(
                is_websocket_upgrade(&http::Method::GET, &h1_headers).is_err(),
                "accepted duplicate offers {values:?}"
            );
        }

        let mut h1_headers = valid_h1_websocket_headers();
        h1_headers.append("sec-websocket-protocol", "chat".parse().unwrap());
        h1_headers.append("sec-websocket-protocol", "superchat".parse().unwrap());
        assert!(is_websocket_upgrade(&http::Method::GET, &h1_headers).unwrap());

        let mut h1_headers = valid_h1_websocket_headers();
        h1_headers.insert("sec-websocket-protocol", "chat, Chat".parse().unwrap());
        assert!(is_websocket_upgrade(&http::Method::GET, &h1_headers).unwrap());
    }

    #[test]
    fn extended_connect_requires_one_version_and_unique_ordered_offers() {
        let mut duplicate_version = HeaderMap::new();
        duplicate_version.insert("sec-websocket-version", "13".parse().unwrap());
        duplicate_version.append("sec-websocket-version", "12".parse().unwrap());
        assert!(
            validate_extended_connect_websocket_request("websocket", &duplicate_version).is_err()
        );

        let invalid_offers = [
            vec!["chat, chat"],
            vec!["chat", "chat"],
            vec!["chat, superchat", "superchat"],
            vec![" chat\t,chat"],
        ];
        for values in &invalid_offers {
            let mut headers = HeaderMap::new();
            headers.insert("sec-websocket-version", "13".parse().unwrap());
            for value in values {
                headers.append("sec-websocket-protocol", value.parse().unwrap());
            }
            assert!(
                validate_extended_connect_websocket_request("websocket", &headers).is_err(),
                "accepted duplicate offers {values:?}"
            );
        }

        let mut headers = HeaderMap::new();
        headers.insert("sec-websocket-version", "13".parse().unwrap());
        headers.append("sec-websocket-protocol", "chat".parse().unwrap());
        headers.append("sec-websocket-protocol", "superchat".parse().unwrap());
        assert_eq!(
            validate_extended_connect_websocket_request("websocket", &headers)
                .unwrap()
                .unwrap(),
            ["chat", "superchat"]
        );

        let mut case_distinct = HeaderMap::new();
        case_distinct.insert("sec-websocket-version", "13".parse().unwrap());
        case_distinct.insert("sec-websocket-protocol", "chat, Chat".parse().unwrap());
        assert_eq!(
            validate_extended_connect_websocket_request("websocket", &case_distinct)
                .unwrap()
                .unwrap(),
            ["chat", "Chat"]
        );
    }
}
