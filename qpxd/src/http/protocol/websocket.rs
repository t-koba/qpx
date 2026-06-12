use hyper_util::rt::TokioIo;
use qpx_http::body::Body;
use std::future::Future;
use std::time::Duration;
use tokio::time::timeout;

pub(crate) fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    header_values_contain_token(headers, http::header::UPGRADE, "websocket")
        && header_values_contain_token(headers, http::header::CONNECTION, "upgrade")
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
    use super::is_websocket_upgrade;
    use http::HeaderMap;

    #[test]
    fn websocket_upgrade_accepts_list_and_repeated_connection_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, "h2c, websocket".parse().unwrap());
        headers.append(http::header::CONNECTION, "keep-alive".parse().unwrap());
        headers.append(http::header::CONNECTION, "Upgrade".parse().unwrap());

        assert!(is_websocket_upgrade(&headers));
    }
}
