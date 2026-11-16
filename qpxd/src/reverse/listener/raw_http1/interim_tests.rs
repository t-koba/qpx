use super::*;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;

const BOUND: Duration = Duration::from_secs(2);
const HINT: &[u8] = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\nContent-Length: invalid\r\nTransfer-Encoding: chunked\r\nTrailer: x-trailer\r\nConnection: x-private\r\nX-Private: secret\r\n\r\n";
const FINAL: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBODY";
const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: reverse.test\r\nConnection: close\r\n\r\n";

async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 8192);
        head.push(stream.read_u8().await.expect("complete response head"));
    }
    String::from_utf8(head).unwrap()
}

// The reverse runtime also opens TCP health probes. They carry no request and
// must not be mistaken for the retried HTTP exchange.
async fn accept_request(listener: &TcpListener) -> TcpStream {
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut buf = [0; 1024];
        crate::test_util::read_request_head(&mut stream, &mut head, &mut buf).await;
        if !head.is_empty() {
            assert!(head.ends_with(b"\r\n\r\n"));
            return stream;
        }
    }
}

async fn start_reverse(origin: &TcpListener) -> (TcpStream, tokio::task::JoinHandle<Result<()>>) {
    let reverse = super::super::tests::build_reloadable_reverse(origin.local_addr().unwrap());
    let conn = ReverseConnInfo::plain(([127, 0, 0, 1], 12345).into(), 80);
    // This regression must exercise Prepared, not the generic fallback codec.
    let mut cache = RawHttp1ConnectionCache::default();
    assert!(matches!(
        try_prepare_request(REQUEST, &reverse, &conn, &mut cache),
        FastParse::Prepared { .. }
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(serve_raw_or_fallback(
        server,
        Bytes::new(),
        reverse,
        conn,
        BOUND,
    ));
    (client, task)
}

#[derive(Clone, Copy)]
enum FinalHead {
    Immediate,
    Delayed,
    Closed,
}

async fn incremental_case(final_head: FinalHead) {
    timeout(BOUND, async {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut client, reverse) = start_reverse(&origin).await;
        let (observed, wait_observed) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let mut stream = accept_request(&origin).await;
            stream.write_all(HINT).await.unwrap();
            stream.flush().await.unwrap();
            if matches!(final_head, FinalHead::Closed) {
                // Close immediately: even heads still queued when parsing fails
                // must drain before the listener emits its final error response.
                return;
            }
            // No final response can be written (or parsed) before the CLIENT
            // sees 103. The timeout fails the old buffer-until-final design.
            wait_observed.await.unwrap();
            if matches!(final_head, FinalHead::Delayed) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            stream
                .write_all(b"HTTP/1.1 102 Processing\r\n\r\n")
                .await
                .unwrap();
            stream.write_all(FINAL).await.unwrap();
        });
        client.write_all(REQUEST).await.unwrap();
        let hint = timeout(Duration::from_secs(1), read_head(&mut client))
            .await
            .unwrap();
        assert!(hint.starts_with("HTTP/1.1 103 "), "{hint}");
        assert!(
            hint.contains("link: </style.css>; rel=preload\r\n"),
            "{hint}"
        );
        let lower = hint.to_ascii_lowercase();
        for removed in [
            "content-length:",
            "transfer-encoding:",
            "trailer:",
            "connection:",
            "x-private:",
        ] {
            assert!(!lower.contains(removed), "{hint}");
        }
        if matches!(final_head, FinalHead::Closed) {
            let error = read_head(&mut client).await;
            assert!(error.starts_with("HTTP/1.1 502 "), "{error}");
        } else {
            observed.send(()).unwrap();
            assert!(read_head(&mut client).await.starts_with("HTTP/1.1 102 "));
            assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200 "));
            let mut body = [0; 4];
            client.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"BODY");
        }
        upstream.await.unwrap();
        reverse.await.unwrap().unwrap();
    })
    .await
    .expect("incremental relay must finish without hanging");
}

#[tokio::test]
async fn early_hints_reach_downstream_before_origin_releases_final_head() {
    incremental_case(FinalHead::Immediate).await;
}

#[tokio::test]
async fn early_hints_precede_a_delayed_final_head() {
    incremental_case(FinalHead::Delayed).await;
}

#[tokio::test]
async fn early_hints_survive_final_head_failure_without_hanging() {
    incremental_case(FinalHead::Closed).await;
}

#[tokio::test]
async fn reused_connection_retry_does_not_duplicate_incremental_interim() {
    for first_has_interim in [true, false] {
        timeout(BOUND, async {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (mut client, reverse) = start_reverse(&origin).await;
            let (observed, wait_observed) = oneshot::channel();
            let upstream = tokio::spawn(async move {
                let mut stream = accept_request(&origin).await;
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
                // Accept a second request on the same stream, proving reuse.
                read_head(&mut stream).await;
                if first_has_interim {
                    stream.write_all(HINT).await.unwrap();
                    wait_observed.await.unwrap();
                }
                drop(stream);
                let mut retry = accept_request(&origin).await;
                retry.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </retry>\r\n\r\nHTTP/1.1 102 Processing\r\n\r\n").await.unwrap();
                retry.write_all(FINAL).await.unwrap();
            });
            client.write_all(b"GET / HTTP/1.1\r\nHost: reverse.test\r\n\r\n").await.unwrap();
            assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200 "));
            client.write_all(REQUEST).await.unwrap();
            let hint = read_head(&mut client).await;
            assert!(hint.starts_with("HTTP/1.1 103 "), "{hint}");
            if first_has_interim {
                assert!(hint.contains("</style.css>"));
                observed.send(()).unwrap();
            } else {
                assert!(hint.contains("</retry>"));
                assert!(read_head(&mut client).await.starts_with("HTTP/1.1 102 "));
            }
            // If a head from the retry were duplicated, this would be 103/102.
            let final_head = read_head(&mut client).await;
            assert!(final_head.starts_with("HTTP/1.1 200 "), "first_has_interim={first_has_interim}: {final_head}");
            let mut body = [0; 4];
            client.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"BODY");
            upstream.await.unwrap();
            reverse.await.unwrap().unwrap();
        }).await.expect("stale-connection retry must finish");
    }
}
