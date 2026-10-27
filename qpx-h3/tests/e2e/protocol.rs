use super::*;
use anyhow::anyhow;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mismatched_request_authority_is_reset_before_dispatch() -> Result<()> {
    let (seen_tx, mut seen_rx) = oneshot::channel();
    let handler = DynamicHeaderHandler {
        seen: Arc::new(Mutex::new(Some(seen_tx))),
    };
    let (addr, client_config, server_task) = start_server(handler).await?;
    let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
    open_client_control_stream(&connection).await?;
    open_client_qpack_streams(&connection).await?;

    // Send raw QPACK: a conforming client may refuse to encode this request.
    // The Host value is semantically equivalent by DNS case folding, but RFC
    // 9114 requires the two field values themselves to be the same.
    let authority = format!("localhost:{}", addr.port());
    let host = format!("LOCALHOST:{}", addr.port());
    let mut headers = build_head_request_headers(&authority);
    for (name, value) in [("host", host.as_str()), ("x-dynamic", "must-not-dispatch")] {
        encode_string(&mut headers, 4, 0b0010, name.as_bytes());
        encode_string(&mut headers, 8, 0, value.as_bytes());
    }
    let (mut send, mut recv) = connection.open_bi().await?;
    write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
    send.finish()?;

    match timeout(TEST_TIMEOUT, recv.read_chunk(usize::MAX, true)).await? {
        Err(quinn::ReadError::Reset(code)) => {
            assert_eq!(u64::from(code), H3_MESSAGE_ERROR);
        }
        other => return Err(anyhow!("expected H3_MESSAGE_ERROR reset, got {other:?}")),
    }
    assert!(matches!(
        seen_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_critical_streams_survive_request_read_timeout() -> Result<()> {
    let (addr, client_config, server_task) = start_server(IdleCriticalStreamsHandler).await?;
    let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
    open_client_control_stream(&connection).await?;
    open_client_qpack_streams(&connection).await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let (mut send, mut recv) = connection.open_bi().await?;
    let headers = build_head_request_headers(&format!("localhost:{}", addr.port()));
    write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
    send.finish()?;
    let (frame_type, _) = read_frame_raw(&mut recv, "idle critical stream response").await?;
    assert_eq!(frame_type, FRAME_HEADERS);

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_frame_before_request_headers_is_ignored() -> Result<()> {
    let (addr, client_config, server_task) = start_server(IdleCriticalStreamsHandler).await?;
    let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
    open_client_control_stream(&connection).await?;
    open_client_qpack_streams(&connection).await?;

    let (mut send, mut recv) = connection.open_bi().await?;
    write_frame_raw(&mut send, 0x21, b"grease").await?;
    let headers = build_head_request_headers(&format!("localhost:{}", addr.port()));
    write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
    send.finish()?;

    let (frame_type, _) = read_frame_raw(&mut recv, "response after unknown frame").await?;
    assert_eq!(frame_type, FRAME_HEADERS);

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

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

#[derive(Clone)]
struct OwnedIngressHandler {
    seen: Arc<Mutex<Option<oneshot::Sender<qpx_core::http_message::Request<()>>>>>,
}

impl RequestHandler for OwnedIngressHandler {
    fn settings(&self) -> Settings {
        Settings {
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        request: Request,
        _conn: ConnectionInfo,
        mut stream: RequestStream,
    ) -> H3Result<()> {
        if let Some(tx) = self.seen.lock().await.take() {
            let _ = tx.send(request.head);
        }
        stream
            .send_response_head(&http::Response::builder().status(204).body(())?)
            .await?;
        stream.finish().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decoded_qpack_fields_reach_owned_handler_without_coalescing() -> Result<()> {
    use qpx_core::http_message::OrdinaryHeaderName;

    // Exercise literal names, static name references, and both relative and
    // post-base dynamic name references, with per-occurrence never-index bits.
    for base in [0, 1] {
        let (seen_tx, seen_rx) = oneshot::channel();
        let handler = OwnedIngressHandler {
            seen: Arc::new(Mutex::new(Some(seen_tx))),
        };
        let (addr, client_config, server_task) = start_server(handler).await?;
        let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
        open_client_control_stream(&connection).await?;

        let mut encoder = connection.open_uni().await?;
        let mut instructions = vec![];
        push_varint(&mut instructions, STREAM_QPACK_ENCODER);
        instructions.extend_from_slice(&build_dynamic_encoder_instructions("table-value"));
        encoder.write_all(&instructions).await?;

        let authority = format!("localhost:{}", addr.port());
        let mut headers = vec![];
        encode_header_prefix(&mut headers, 1, base);
        // Reuse HEAD pseudo-fields, but replace its empty dynamic prefix.
        headers.extend_from_slice(&build_head_request_headers(&authority)[2..]);
        // Literal Cookie name with N=1, then both static name N values.
        encode_string(&mut headers, 4, 0b0011, b"cookie");
        encode_string(&mut headers, 8, 0, b"a=1");
        encode_prefixed_int(&mut headers, 4, if base == 0 { 0b0111 } else { 0b0101 }, 5);
        encode_string(&mut headers, 8, 0, b"b=2");
        // Duplicate Content-Length values must survive this boundary as fields.
        for value in [b"000".as_slice(), b"0".as_slice()] {
            encode_prefixed_int(&mut headers, 4, 0b0101, 4);
            encode_string(&mut headers, 8, 0, value);
        }
        for (value, sensitive) in [(b" first ".as_slice(), false), (b"second".as_slice(), true)] {
            if base == 0 {
                encode_prefixed_int(&mut headers, 3, u8::from(sensitive), 0);
            } else {
                encode_prefixed_int(&mut headers, 4, 0b0100 | (u8::from(sensitive) << 1), 0);
            }
            encode_string(&mut headers, 8, 0, value);
        }
        let (mut send, mut recv) = connection.open_bi().await?;
        write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
        send.finish()?;
        let head = timeout(TEST_TIMEOUT, seen_rx).await??;
        assert_eq!(head.version(), http::Version::HTTP_3);
        assert_eq!(head.method(), http::Method::HEAD);
        assert_eq!(head.uri().authority().unwrap().as_str(), authority);
        assert_eq!(head.uri().path(), "/");
        assert_eq!(head.headers().field_count(), 6);
        assert_eq!(head.headers().declared_content_length(), Ok(Some(0)));
        for (name, expected) in [
            (
                "cookie",
                vec![(b"a=1".as_slice(), true), (b"b=2".as_slice(), base == 0)],
            ),
            (
                "x-dynamic",
                vec![(b" first ".as_slice(), false), (b"second".as_slice(), true)],
            ),
        ] {
            let name = OrdinaryHeaderName::try_from(name)?;
            assert_eq!(
                head.headers()
                    .get_all(&name)
                    .map(|v| (v.as_bytes(), v.is_sensitive()))
                    .collect::<Vec<_>>(),
                expected
            );
        }
        assert_eq!(
            read_frame_raw(&mut recv, "owned ingress response").await?.0,
            FRAME_HEADERS
        );
        server_task.abort();
        let _ = server_task.await;
    }
    Ok(())
}
