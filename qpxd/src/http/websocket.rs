use std::time::Duration;
use tokio::time::timeout;

pub fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    let upgrade = headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if !upgrade {
        return false;
    }

    headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false)
}

pub fn spawn_upgrade_tunnel(
    response: &mut hyper::Response<hyper::Body>,
    client_upgrade: hyper::upgrade::OnUpgrade,
    context: &'static str,
    upgrade_wait_timeout: Duration,
    idle_timeout: Duration,
) {
    if response.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
        return;
    }
    let server_upgrade = hyper::upgrade::on(response);
    tokio::spawn(async move {
        let client = timeout(upgrade_wait_timeout, client_upgrade).await;
        let server = timeout(upgrade_wait_timeout, server_upgrade).await;
        match (client, server) {
            (Ok(Ok(mut client)), Ok(Ok(mut server))) => {
                if let Err(err) = crate::io_copy::copy_bidirectional_with_export_and_idle(
                    &mut client,
                    &mut server,
                    None,
                    Some(idle_timeout),
                )
                .await
                {
                    tracing::warn!(error = ?err, %context, "websocket tunnel timed out");
                }
            }
            (Ok(Err(err)), _) | (_, Ok(Err(err))) => {
                tracing::warn!(error = ?err, %context, "websocket upgrade failed");
            }
            (Err(_), _) | (_, Err(_)) => {
                tracing::warn!(%context, "websocket upgrade timed out");
            }
        }
    });
}
