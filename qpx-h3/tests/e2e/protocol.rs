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

type TrailerObservation = std::result::Result<(Vec<u8>, String), String>;

enum TrailerRecv<'a> {
    Combined(&'a mut RequestStream),
    Split(&'a mut qpx_h3::RequestRecvStream),
}

impl TrailerRecv<'_> {
    async fn recv_data(&mut self) -> H3Result<Option<Bytes>> {
        match self {
            Self::Combined(stream) => stream.recv_data().await,
            Self::Split(recv) => recv.recv_data().await,
        }
    }

    async fn recv_trailers(&mut self) -> H3Result<Option<http::HeaderMap>> {
        match self {
            Self::Combined(stream) => stream.recv_trailers().await,
            Self::Split(recv) => recv.recv_trailers().await,
        }
    }
}

#[derive(Clone)]
struct TrailerBodyHandler {
    split: bool,
    observed: Arc<Mutex<Option<oneshot::Sender<TrailerObservation>>>>,
}

async fn drain_body_and_read_trailers(
    mut recv: TrailerRecv<'_>,
    observed: &Arc<Mutex<Option<oneshot::Sender<TrailerObservation>>>>,
) -> H3Result<()> {
    let outcome: anyhow::Result<(Vec<u8>, String)> = async {
        let mut body = Vec::new();
        while body.len() < 3 {
            match recv
                .recv_data()
                .await
                .map_err(|err| anyhow!(err.to_string()))?
            {
                Some(chunk) => body.extend_from_slice(&chunk),
                None => break,
            }
        }
        let trailers = recv
            .recv_trailers()
            .await
            .map_err(|err| anyhow!(err.to_string()))?
            .ok_or_else(|| anyhow!("missing trailing HEADERS"))?;
        let value = trailers
            .get("x-end")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| anyhow!("missing x-end trailer"))?;
        if body.as_slice() != b"abc" {
            return Err(anyhow!("unexpected request body: {body:?}"));
        }
        if value != "ok" {
            return Err(anyhow!("unexpected x-end trailer: {value}"));
        }
        Ok((body, value.to_string()))
    }
    .await;

    if let Some(tx) = observed.lock().await.take() {
        let _ = tx.send(
            outcome
                .as_ref()
                .map(|(body, value)| (body.clone(), value.clone()))
                .map_err(|err| err.to_string()),
        );
    }
    outcome.map(|_| ()).map_err(Into::into)
}

impl RequestHandler for TrailerBodyHandler {
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
        assert_eq!(request.head.method(), http::Method::POST);
        assert_eq!(request.head.uri().path(), "/");
        let response = http::Response::builder().status(204).body(())?;
        if self.split {
            let (mut send, mut recv) = stream.split();
            drain_body_and_read_trailers(TrailerRecv::Split(&mut recv), &self.observed).await?;
            send.send_response_head(&response).await?;
            send.finish().await
        } else {
            drain_body_and_read_trailers(TrailerRecv::Combined(&mut stream), &self.observed)
                .await?;
            stream.send_response_head(&response).await?;
            stream.finish().await
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_frame_after_request_trailers_is_ignored() -> Result<()> {
    for split in [false, true] {
        let (observed_tx, observed_rx) = oneshot::channel();
        let handler = TrailerBodyHandler {
            split,
            observed: Arc::new(Mutex::new(Some(observed_tx))),
        };
        let (addr, client_config, server_task) = start_server(handler).await?;
        let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
        open_client_control_stream(&connection).await?;
        open_client_qpack_streams(&connection).await?;

        let authority = format!("localhost:{}", addr.port());
        let mut headers = Vec::new();
        encode_prefixed_int(&mut headers, 8, 0, 0);
        encode_prefixed_int(&mut headers, 7, 0, 0);
        encode_prefixed_int(&mut headers, 6, 0b11, 20); // Static :method POST.
        headers.extend_from_slice(&build_head_request_headers(&authority)[3..]);
        encode_prefixed_int(&mut headers, 4, 0b0101, 4); // Static content-length name.
        encode_string(&mut headers, 8, 0, b"3");

        let mut trailers = Vec::new();
        encode_prefixed_int(&mut trailers, 8, 0, 0);
        encode_prefixed_int(&mut trailers, 7, 0, 0);
        encode_string(&mut trailers, 4, 0b0010, b"x-end");
        encode_string(&mut trailers, 8, 0, b"ok");

        let (mut send, mut recv) = connection.open_bi().await?;
        write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
        write_frame_raw(&mut send, FRAME_DATA, b"abc").await?;
        write_frame_raw(&mut send, FRAME_HEADERS, &trailers).await?;
        write_frame_raw(&mut send, 0x21, b"grease").await?;
        send.finish()?;

        let (body, trailer) = timeout(TEST_TIMEOUT, observed_rx)
            .await
            .map_err(|_| anyhow!("timed out waiting for trailer handler (split={split})"))?
            .map_err(|_| anyhow!("trailer handler dropped its result (split={split})"))?
            .map_err(|err| anyhow!("trailer handler failed (split={split}): {err}"))?;
        assert_eq!(body.as_slice(), b"abc");
        assert_eq!(trailer, "ok");

        let (frame_type, _) = read_frame_raw(&mut recv, "response after request trailers").await?;
        assert_eq!(frame_type, FRAME_HEADERS);
        let end = timeout(TEST_TIMEOUT, recv.read_chunk(4096, true))
            .await
            .map_err(|_| anyhow!("timed out waiting for clean response end"))?;
        assert!(end?.is_none(), "unexpected response bytes after HEADERS");

        server_task.abort();
        let _ = server_task.await;
    }
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
async fn literal_empty_final_header_reaches_handler() -> Result<()> {
    use qpx_core::http_message::OrdinaryHeaderName;

    let (seen_tx, seen_rx) = oneshot::channel();
    let handler = OwnedIngressHandler {
        seen: Arc::new(Mutex::new(Some(seen_tx))),
    };
    let (addr, client_config, server_task) = start_server(handler).await?;
    let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
    open_client_control_stream(&connection).await?;
    open_client_qpack_streams(&connection).await?;

    let authority = format!("localhost:{}", addr.port());
    let mut headers = build_head_request_headers(&authority);
    encode_string(&mut headers, 4, 0b0010, b"x-empty");
    encode_string(&mut headers, 8, 0, b"");
    let (mut send, mut recv) = connection.open_bi().await?;
    write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
    send.finish()?;

    assert_eq!(
        read_frame_raw(&mut recv, "empty literal response").await?.0,
        FRAME_HEADERS
    );
    let head = timeout(TEST_TIMEOUT, seen_rx).await??;
    let name = OrdinaryHeaderName::try_from("x-empty")?;
    assert_eq!(
        head.headers()
            .get_all(&name)
            .map(|value| value.as_bytes())
            .collect::<Vec<_>>(),
        vec![b"".as_slice()]
    );

    server_task.abort();
    let _ = server_task.await;
    Ok(())
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

#[derive(Clone)]
struct WtStreamPlacementHandler {
    split: bool,
}

impl RequestHandler for WtStreamPlacementHandler {
    fn settings(&self) -> Settings {
        Settings {
            enable_extended_connect: true,
            enable_webtransport: true,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _request: Request,
        _conn: ConnectionInfo,
        mut stream: RequestStream,
    ) -> H3Result<()> {
        if self.split {
            let (_send, mut recv) = stream.split();
            recv.recv_data().await?;
        } else {
            stream.recv_data().await?;
        }
        Err(anyhow!("expected misplaced WT_STREAM to fail").into())
    }
}

async fn expect_wt_stream_connection_error(connection: &quinn::Connection) -> Result<()> {
    let closed = timeout(TEST_TIMEOUT, connection.closed()).await?;
    match closed {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(u64::from(close.error_code), H3_FRAME_UNEXPECTED);
        }
        other => {
            return Err(anyhow!(
                "expected H3_FRAME_UNEXPECTED connection error, got {other:?}"
            ));
        }
    }
    Ok(())
}

#[tokio::test]
async fn wt_stream_after_unknown_or_request_headers_closes_connection() -> Result<()> {
    // Cover the leading-frame parser and both combined/split message parsers.
    for (after_headers, split) in [(false, false), (true, false), (true, true)] {
        let (addr, config, server_task) = start_server(WtStreamPlacementHandler { split }).await?;
        let (_endpoint, connection) = connect_client(addr, config).await?;
        open_client_control_stream_with_webtransport(&connection).await?;
        open_client_qpack_streams(&connection).await?;
        let (mut send, _recv) = connection.open_bi().await?;
        if after_headers {
            let headers = build_head_request_headers(&format!("localhost:{}", addr.port()));
            write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
        } else {
            write_frame_raw(&mut send, 0x21, b"grease").await?;
        }
        let mut signal = Vec::new();
        push_varint(&mut signal, 0x41);
        send.write_all(&signal).await?;
        // No length, session id, or FIN: rejection must happen on type recognition.
        expect_wt_stream_connection_error(&connection).await?;
        server_task.abort();
        let _ = server_task.await;
    }
    Ok(())
}

#[tokio::test]
async fn wt_stream_on_control_stream_closes_connection() -> Result<()> {
    for after_settings in [false, true] {
        let (addr, config, server_task) = start_server(WebTransportEchoHandler).await?;
        let (_endpoint, connection) = connect_client(addr, config).await?;
        let mut control = connection.open_uni().await?;
        let mut bytes = vec![0]; // Control stream type.
        if after_settings {
            push_varint(&mut bytes, FRAME_SETTINGS);
            push_varint(&mut bytes, 0);
        }
        push_varint(&mut bytes, 0x41);
        control.write_all(&bytes).await?;
        expect_wt_stream_connection_error(&connection).await?;
        server_task.abort();
        let _ = server_task.await;
    }
    Ok(())
}
