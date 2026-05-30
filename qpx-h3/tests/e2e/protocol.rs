use super::*;
use anyhow::anyhow;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_qpack_request_reaches_handler() -> Result<()> {
    let (seen_tx, seen_rx) = oneshot::channel();
    let handler = DynamicHeaderHandler {
        seen: Arc::new(Mutex::new(Some(seen_tx))),
    };
    let (addr, client_config, server_task) = start_server(handler).await?;
    let (_client_endpoint, connection) = connect_client(addr, client_config).await?;

    send_dynamic_qpack_request(&connection, &format!("localhost:{}", addr.port())).await?;

    let header = timeout(TEST_TIMEOUT, seen_rx)
        .await
        .map_err(|_| anyhow!("timed out waiting for dynamic QPACK request"))??;
    assert_eq!(header, "dynamic-value");

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn head_response_data_is_rejected_by_server_stream() -> Result<()> {
    let (addr, client_config, server_task) = start_server(HeadBodyAttemptHandler).await?;
    let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
    open_client_control_stream(&connection).await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    let headers = build_head_request_headers(&format!("localhost:{}", addr.port()));
    write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
    send.finish()?;

    let mut frame_buf = Vec::new();
    let (frame_type, _) =
        read_frame_raw_buffered(&mut recv, "HEAD response", &mut frame_buf).await?;
    assert_eq!(frame_type, FRAME_HEADERS);

    let next = loop {
        if !frame_buf.is_empty() {
            let (frame_type, _) =
                read_frame_raw_buffered(&mut recv, "HEAD response end", &mut frame_buf).await?;
            break Some(frame_type);
        }
        let next = timeout(TEST_TIMEOUT, recv.read_chunk(4096, true)).await;
        match next {
            Ok(Ok(Some(chunk))) if !chunk.bytes.is_empty() => {
                frame_buf.extend_from_slice(chunk.bytes.as_ref());
            }
            Ok(Ok(Some(_))) => continue,
            Ok(Ok(None)) => break None,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => return Err(anyhow!("timed out waiting for HEAD response end")),
        }
    };
    if let Some(frame_type) = next {
        assert_ne!(frame_type, FRAME_DATA, "HEAD response must not send DATA");
    }

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_request_stream_resets_with_h3_frame_unexpected() -> Result<()> {
    let (addr, client_config, server_task) = start_server(ExtendedEchoHandler).await?;
    let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    write_frame_raw(&mut send, FRAME_DATA, &[]).await?;
    send.finish()?;

    match recv.read_chunk(usize::MAX, true).await {
        Err(quinn::ReadError::Reset(code)) => {
            assert_eq!(u64::from(code), H3_FRAME_UNEXPECTED);
        }
        other => {
            return Err(anyhow!("expected H3_FRAME_UNEXPECTED reset, got {other:?}"));
        }
    }

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extended_connect_is_rejected_when_server_setting_disabled() -> Result<()> {
    let (addr, client_config, server_task) = start_server(ExtendedConnectDisabledHandler).await?;
    let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
    open_client_control_stream(&connection).await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    let headers = build_extended_connect_headers(&format!("localhost:{}", addr.port()));
    write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
    send.finish()?;

    match recv.read_chunk(usize::MAX, true).await {
        Err(quinn::ReadError::Reset(code)) => {
            assert_eq!(u64::from(code), H3_SETTINGS_ERROR);
        }
        other => {
            return Err(anyhow!("expected H3_SETTINGS_ERROR reset, got {other:?}"));
        }
    }

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extended_connect_rejects_malformed_content_length() -> Result<()> {
    let (addr, client_config, server_task) = start_server(ExtendedEchoHandler).await?;
    let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
    open_client_control_stream(&connection).await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    let headers =
        build_extended_connect_headers_with_content_lengths(&format!("localhost:{}", addr.port()));
    write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
    send.finish()?;

    match recv.read_chunk(usize::MAX, true).await {
        Err(quinn::ReadError::Reset(code)) => {
            assert_eq!(u64::from(code), H3_MESSAGE_ERROR);
        }
        other => {
            return Err(anyhow!("expected H3_MESSAGE_ERROR reset, got {other:?}"));
        }
    }

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}
