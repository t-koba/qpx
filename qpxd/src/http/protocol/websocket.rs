use hyper_util::rt::TokioIo;
use qpx_http::body::Body;
use std::future::Future;
use std::time::Duration;
use tokio::time::timeout;

pub(crate) fn is_websocket_upgrade(
    method: &http::Method,
    headers: &http::HeaderMap,
) -> anyhow::Result<bool> {
    let websocket = header_values_contain_token(headers, http::header::UPGRADE, "websocket");
    let connection_upgrade =
        header_values_contain_token(headers, http::header::CONNECTION, "upgrade");
    if !websocket && !connection_upgrade {
        return Ok(false);
    }
    if !websocket || !connection_upgrade {
        return Err(anyhow::anyhow!("incomplete WebSocket upgrade handshake"));
    }
    if method != http::Method::GET {
        return Err(anyhow::anyhow!("WebSocket upgrade requires GET"));
    }
    if headers
        .get_all("sec-websocket-version")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|value| value.trim() == "13")
        .count()
        != 1
    {
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
    for value in headers.get_all("sec-websocket-protocol") {
        let value = value
            .to_str()
            .map_err(|_| anyhow::anyhow!("WebSocket subprotocol is not ASCII"))?;
        if value.split(',').any(|token| !is_http_token(token.trim())) {
            return Err(anyhow::anyhow!("WebSocket subprotocol token is invalid"));
        }
    }
    Ok(true)
}

fn is_http_token(value: &str) -> bool {
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
    let protocols = headers
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
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
        .map(|value| value.to_str().map(str::trim))
        .collect::<Result<Vec<_>, _>>()?;
    if versions.as_slice() != ["13"] {
        return Err(anyhow::anyhow!("WebSocket version must be exactly 13"));
    }
    let mut protocols = Vec::new();
    for value in headers.get_all("sec-websocket-protocol") {
        let value = value
            .to_str()
            .map_err(|_| anyhow::anyhow!("WebSocket subprotocol is not ASCII"))?;
        for token in value.split(',').map(str::trim) {
            if !is_http_token(token) {
                return Err(anyhow::anyhow!("WebSocket subprotocol token is invalid"));
            }
            protocols.push(token.to_owned());
        }
    }
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
    if !header_values_contain_token(response.headers(), http::header::UPGRADE, "websocket")
        || !header_values_contain_token(response.headers(), http::header::CONNECTION, "upgrade")
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

fn header_values_contain_token(
    headers: &http::HeaderMap,
    name: http::header::HeaderName,
    token: &str,
) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| raw.split(','))
        .any(|part| part.trim().eq_ignore_ascii_case(token))
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
        validate_extended_connect_websocket_response,
    };
    use http::HeaderMap;

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
}
