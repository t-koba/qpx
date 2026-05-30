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

    let bytes = loop {
        let first = timeout(TEST_TIMEOUT, recv.read_chunk(4096, true))
            .await
            .map_err(|_| anyhow!("timed out waiting for HEAD response"))??
            .ok_or_else(|| anyhow!("missing HEAD response"))?;
        if !first.bytes.is_empty() {
            break first.bytes;
        }
    };
    let (frame_type, used_type) = read_varint(bytes.as_ref())?;
    let (frame_len, used_len) = read_varint(&bytes[used_type..])?;
    assert_eq!(frame_type, FRAME_HEADERS);
    assert!(used_type + used_len + frame_len as usize <= bytes.len());

    let next = loop {
        let next = timeout(TEST_TIMEOUT, recv.read_chunk(4096, true))
            .await
            .map_err(|_| anyhow!("timed out waiting for HEAD response end"))??;
        if next.as_ref().is_none_or(|chunk| !chunk.bytes.is_empty()) {
            break next;
        }
    };
    if let Some(chunk) = next
        && !chunk.bytes.is_empty()
    {
        let (frame_type, _) = read_varint(chunk.bytes.as_ref())?;
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
