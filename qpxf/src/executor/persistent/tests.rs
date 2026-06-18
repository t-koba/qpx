use super::fastcgi_io::{
    FCGI_END_REQUEST, FCGI_OVERLOADED, FCGI_STDIN, FCGI_STDOUT, encode_fastcgi_params,
    validate_fastcgi_end_request,
};
use super::pool::FastCgiConnectionPool;
use super::*;
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{Duration, sleep, timeout};

#[test]
fn fastcgi_param_lengths_roundtrip_short_and_long() {
    let encoded = encode_fastcgi_params(vec![
        ("A".to_string(), "B".to_string()),
        ("X".repeat(130), "Y".repeat(140)),
    ])
    .expect("encode");
    let mut cursor = Cursor::new(encoded.as_ref());
    assert_eq!(read_len(&mut cursor), 1);
    assert_eq!(read_len(&mut cursor), 1);
    let mut name = vec![0; 1];
    let mut value = vec![0; 1];
    Read::read_exact(&mut cursor, &mut name).expect("name");
    Read::read_exact(&mut cursor, &mut value).expect("value");
    assert_eq!(&name, b"A");
    assert_eq!(&value, b"B");
    assert_eq!(read_len(&mut cursor), 130);
    assert_eq!(read_len(&mut cursor), 140);
}

fn read_len(cursor: &mut Cursor<&[u8]>) -> usize {
    let mut first = [0u8; 1];
    Read::read_exact(cursor, &mut first).expect("first");
    if first[0] & 0x80 == 0 {
        first[0] as usize
    } else {
        let mut rest = [0u8; 3];
        Read::read_exact(cursor, &mut rest).expect("rest");
        u32::from_be_bytes([first[0] & 0x7f, rest[0], rest[1], rest[2]]) as usize
    }
}

#[test]
fn gateway_env_does_not_duplicate_content_headers_as_http_vars() {
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    );
    headers.insert("content-length".to_string(), "99".to_string());
    let req = CgiRequest {
        script_name: "/cgi-bin/app".to_string(),
        path_info: String::new(),
        query_string: String::new(),
        request_method: "POST".to_string(),
        content_type: "text/plain".to_string(),
        content_length: 5,
        declared_content_length: Some(5),
        server_protocol: "HTTP/1.1".to_string(),
        server_name: "localhost".to_string(),
        server_port: 80,
        remote_addr: None,
        remote_port: None,
        http_headers: headers,
        matched_prefix: None,
    };

    let env = build_gateway_env(&req, Some(5));
    assert!(
        env.iter()
            .any(|(key, value)| key == "CONTENT_TYPE" && value == "text/plain")
    );
    assert!(
        env.iter()
            .any(|(key, value)| key == "CONTENT_LENGTH" && value == "5")
    );
    assert!(!env.iter().any(|(key, _)| key == "HTTP_CONTENT_TYPE"));
    assert!(!env.iter().any(|(key, _)| key == "HTTP_CONTENT_LENGTH"));
}

#[tokio::test]
async fn fastcgi_pool_reuses_idle_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_task = accepted.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        accepted_task.fetch_add(1, Ordering::SeqCst);
        for _ in 0..2 {
            read_fastcgi_request_from_tcp(&mut stream).await;
            write_fastcgi_record_to_tcp(&mut stream, FCGI_STDOUT, b"Status: 200 OK\r\n\r\nok")
                .await;
            write_fastcgi_record_to_tcp(&mut stream, FCGI_END_REQUEST, &[0; 8]).await;
        }
    });

    let pool = FastCgiConnectionPool::new(address, 1, 1).expect("pool");
    for _ in 0..2 {
        let (stdout, stderr) = pool
            .execute(Vec::new(), Bytes::new(), 1024, 1024)
            .await
            .expect("execute");
        assert!(stderr.is_empty());
        assert_eq!(stdout, Bytes::from_static(b"Status: 200 OK\r\n\r\nok"));
    }
    server.await.expect("server");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn fastcgi_pool_discards_broken_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_task = accepted.clone();
    let server = tokio::spawn(async move {
        let (mut broken, _) = listener.accept().await.expect("accept broken");
        accepted_task.fetch_add(1, Ordering::SeqCst);
        read_fastcgi_request_from_tcp(&mut broken).await;
        drop(broken);

        let (mut stream, _) = listener.accept().await.expect("accept replacement");
        accepted_task.fetch_add(1, Ordering::SeqCst);
        read_fastcgi_request_from_tcp(&mut stream).await;
        write_fastcgi_record_to_tcp(&mut stream, FCGI_STDOUT, b"Status: 200 OK\r\n\r\nok").await;
        write_fastcgi_record_to_tcp(&mut stream, FCGI_END_REQUEST, &[0; 8]).await;
    });

    let pool = FastCgiConnectionPool::new(address, 1, 1).expect("pool");
    let err = pool
        .execute(Vec::new(), Bytes::new(), 1024, 1024)
        .await
        .expect_err("broken connection should fail");
    assert!(err.to_string().contains("closed connection"));

    let (stdout, stderr) = pool
        .execute(Vec::new(), Bytes::new(), 1024, 1024)
        .await
        .expect("replacement connection");
    assert!(stderr.is_empty());
    assert_eq!(stdout, Bytes::from_static(b"Status: 200 OK\r\n\r\nok"));
    server.await.expect("server");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn fastcgi_pool_discards_missing_end_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_task = accepted.clone();
    let server = tokio::spawn(async move {
        let (mut broken, _) = listener.accept().await.expect("accept broken");
        accepted_task.fetch_add(1, Ordering::SeqCst);
        read_fastcgi_request_from_tcp(&mut broken).await;
        write_fastcgi_record_to_tcp(&mut broken, FCGI_STDOUT, b"Status: 200 OK\r\n\r\npartial")
            .await;
        drop(broken);

        let (mut stream, _) = listener.accept().await.expect("accept replacement");
        accepted_task.fetch_add(1, Ordering::SeqCst);
        read_fastcgi_request_from_tcp(&mut stream).await;
        write_fastcgi_record_to_tcp(&mut stream, FCGI_STDOUT, b"Status: 200 OK\r\n\r\nok").await;
        write_fastcgi_record_to_tcp(&mut stream, FCGI_END_REQUEST, &[0; 8]).await;
    });

    let pool = FastCgiConnectionPool::new(address, 1, 1).expect("pool");
    let err = pool
        .execute(Vec::new(), Bytes::new(), 1024, 1024)
        .await
        .expect_err("missing END_REQUEST should fail");
    assert!(err.to_string().contains("before end request"));

    let (stdout, stderr) = pool
        .execute(Vec::new(), Bytes::new(), 1024, 1024)
        .await
        .expect("replacement connection");
    assert!(stderr.is_empty());
    assert_eq!(stdout, Bytes::from_static(b"Status: 200 OK\r\n\r\nok"));
    server.await.expect("server");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn fastcgi_executor_times_out_slow_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_fastcgi_request_from_tcp(&mut stream).await;
        sleep(Duration::from_millis(200)).await;
    });

    let executor = FastCgiExecutor::new(&crate::config::FastCgiBackendConfig {
        address,
        timeout_ms: 25,
        script_name_prefixes: Vec::new(),
        pool: crate::config::FastCgiPoolConfig {
            max_concurrency: 1,
            max_idle: 1,
        },
        max_stdin_bytes: 1024,
        max_stdout_bytes: 1024,
        max_stderr_bytes: 1024,
    })
    .expect("executor");
    let mut execution = executor.start(test_cgi_request()).await.expect("start");
    drop(execution.stdin);
    while execution.stdout.recv().await.is_some() {}
    let err = execution
        .done
        .await
        .expect("join")
        .expect_err("slow backend should timeout");
    assert!(err.to_string().contains("timed out"));
    server.await.expect("server");
}

#[tokio::test]
async fn fastcgi_pool_respects_max_concurrency() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_fastcgi_request_from_tcp(&mut stream).await;
        release_rx.await.expect("release first request");
        write_fastcgi_record_to_tcp(&mut stream, FCGI_STDOUT, b"Status: 200 OK\r\n\r\none").await;
        write_fastcgi_record_to_tcp(&mut stream, FCGI_END_REQUEST, &[0; 8]).await;
        read_fastcgi_request_from_tcp(&mut stream).await;
        write_fastcgi_record_to_tcp(&mut stream, FCGI_STDOUT, b"Status: 200 OK\r\n\r\ntwo").await;
        write_fastcgi_record_to_tcp(&mut stream, FCGI_END_REQUEST, &[0; 8]).await;
    });

    let pool = Arc::new(FastCgiConnectionPool::new(address, 1, 1).expect("pool"));
    let first_pool = pool.clone();
    let first = tokio::spawn(async move {
        first_pool
            .execute(Vec::new(), Bytes::new(), 1024, 1024)
            .await
            .expect("first")
            .0
    });
    sleep(Duration::from_millis(50)).await;
    let second_pool = pool.clone();
    let mut second = tokio::spawn(async move {
        second_pool
            .execute(Vec::new(), Bytes::new(), 1024, 1024)
            .await
            .expect("second")
            .0
    });
    assert!(
        timeout(Duration::from_millis(50), &mut second)
            .await
            .is_err()
    );
    release_tx.send(()).expect("release");
    let first_stdout = first.await.expect("first join");
    assert_eq!(
        first_stdout,
        Bytes::from_static(b"Status: 200 OK\r\n\r\none")
    );
    let second_stdout = second.await.expect("second join");
    assert_eq!(
        second_stdout,
        Bytes::from_static(b"Status: 200 OK\r\n\r\ntwo")
    );
    server.await.expect("server");
}

#[tokio::test]
async fn scgi_executor_respects_max_concurrency() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let (checked_tx, checked_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("accept first");
        let first_task = tokio::spawn(async move {
            read_scgi_request_from_tcp(&mut first).await;
            release_rx.await.expect("release first scgi request");
            first
                .write_all(b"Status: 200 OK\r\n\r\none")
                .await
                .expect("first response");
        });
        assert!(
            timeout(Duration::from_millis(75), listener.accept())
                .await
                .is_err(),
            "second SCGI connection should wait for the concurrency permit"
        );
        checked_tx.send(()).expect("checked");
        first_task.await.expect("first task");
        let (mut second, _) = listener.accept().await.expect("accept second");
        read_scgi_request_from_tcp(&mut second).await;
        second
            .write_all(b"Status: 200 OK\r\n\r\ntwo")
            .await
            .expect("second response");
    });

    let executor = Arc::new(
        PersistentExecutor::new(address, 1000, 1, Vec::new(), 1024, 1024, 1024).expect("executor"),
    );
    let first = tokio::spawn(start_persistent_request(executor.clone()));
    sleep(Duration::from_millis(25)).await;
    let second = tokio::spawn(start_persistent_request(executor.clone()));
    checked_rx.await.expect("checked concurrency");
    release_tx.send(()).expect("release");
    let first_stdout = first.await.expect("first join");
    assert_eq!(
        first_stdout,
        Bytes::from_static(b"Status: 200 OK\r\n\r\none")
    );
    let second_stdout = second.await.expect("second join");
    assert_eq!(
        second_stdout,
        Bytes::from_static(b"Status: 200 OK\r\n\r\ntwo")
    );
    server.await.expect("server");
}

#[tokio::test]
async fn scgi_unknown_length_empty_stdin_is_sent_as_zero_length() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let request = read_scgi_request_from_tcp(&mut stream).await;
        assert_eq!(
            scgi_env_value(&request, "CONTENT_LENGTH"),
            Some(b"0".as_slice())
        );
        stream
            .write_all(b"Status: 200 OK\r\n\r\nempty")
            .await
            .expect("response");
    });
    let executor = Arc::new(
        PersistentExecutor::new(address, 1000, 1, Vec::new(), 1024, 1024, 1024).expect("executor"),
    );
    let mut req = test_cgi_request();
    req.declared_content_length = None;
    req.content_length = 0;
    let mut execution = executor.start(req).await.expect("start");
    drop(execution.stdin);
    let mut stdout = BytesMut::new();
    while let Some(chunk) = execution.stdout.recv().await {
        stdout.extend_from_slice(&chunk);
    }
    execution.done.await.expect("join").expect("done");
    assert_eq!(
        stdout.freeze(),
        Bytes::from_static(b"Status: 200 OK\r\n\r\nempty")
    );
    server.await.expect("server");
}

#[tokio::test]
async fn scgi_unknown_length_non_empty_stdin_is_rejected_without_collecting() {
    let executor = Arc::new(
        PersistentExecutor::new(
            "127.0.0.1:9".to_string(),
            1000,
            1,
            Vec::new(),
            1024,
            1024,
            1024,
        )
        .expect("executor"),
    );
    let mut req = test_cgi_request();
    req.declared_content_length = None;
    req.content_length = 0;
    let execution = executor.start(req).await.expect("start");
    execution
        .stdin
        .send(Bytes::from_static(b"x"))
        .await
        .expect("send stdin");
    drop(execution.stdin);
    let err = execution
        .done
        .await
        .expect("join")
        .expect_err("non-empty unknown stdin must fail");
    assert!(err.to_string().contains("requires Content-Length"));
}

#[tokio::test]
async fn scgi_cancel_cleans_up_worker_permit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("accept first");
        let _first = tokio::spawn(async move {
            let _ = read_scgi_request_from_tcp(&mut first).await;
            sleep(Duration::from_millis(200)).await;
        });
        let (mut second, _) = listener.accept().await.expect("accept second");
        read_scgi_request_from_tcp(&mut second).await;
        second
            .write_all(b"Status: 200 OK\r\n\r\nsecond")
            .await
            .expect("second response");
    });

    let executor = Arc::new(
        PersistentExecutor::new(address, 1000, 1, Vec::new(), 1024, 1024, 1024).expect("executor"),
    );
    let first = executor
        .start(test_cgi_request())
        .await
        .expect("first start");
    drop(first.stdin);
    sleep(Duration::from_millis(25)).await;
    let _ = first.abort.send(());
    first
        .done
        .await
        .expect("first join")
        .expect("first abort ok");

    let second_stdout = start_persistent_request(executor).await;
    assert_eq!(
        second_stdout,
        Bytes::from_static(b"Status: 200 OK\r\n\r\nsecond")
    );
    server.await.expect("server");
}

async fn start_persistent_request(executor: Arc<PersistentExecutor>) -> Bytes {
    let mut execution = executor
        .start(test_cgi_request())
        .await
        .expect("start request");
    drop(execution.stdin);
    let mut stdout = BytesMut::new();
    while let Some(chunk) = execution.stdout.recv().await {
        stdout.extend_from_slice(&chunk);
    }
    execution.done.await.expect("join").expect("done");
    stdout.freeze()
}

#[test]
fn fastcgi_end_request_rejects_protocol_error() {
    let mut body = [0u8; 8];
    body[4] = FCGI_OVERLOADED;
    assert!(validate_fastcgi_end_request(&body).is_err());
}

#[test]
fn fastcgi_end_request_accepts_request_complete() {
    assert!(validate_fastcgi_end_request(&[0u8; 8]).is_ok());
}

#[test]
fn persistent_script_prefixes_use_longest_configured_match() {
    let mut req = test_cgi_request_with_path("/cgi-bin/nested", "/app/foo");
    apply_script_name_prefixes(
        &mut req,
        &[
            "/cgi-bin/nested".to_string(),
            "/cgi-bin/nested/app".to_string(),
        ],
    );

    assert_eq!(req.script_name, "/cgi-bin/nested/app");
    assert_eq!(req.path_info, "/foo");
}

#[test]
fn persistent_script_prefixes_ignore_partial_segment_match() {
    let mut req = test_cgi_request_with_path("/cgi-bin/application", "/foo");
    apply_script_name_prefixes(&mut req, &["/cgi-bin/app".to_string()]);

    assert_eq!(req.script_name, "/cgi-bin/application");
    assert_eq!(req.path_info, "/foo");
}

#[test]
fn persistent_without_prefixes_preserves_ipc_split() {
    let mut req = test_cgi_request_with_path("/cgi-bin/nested", "/app/foo");
    apply_script_name_prefixes(&mut req, &[]);

    assert_eq!(req.script_name, "/cgi-bin/nested");
    assert_eq!(req.path_info, "/app/foo");
}

#[test]
fn persistent_default_split_keeps_exact_script_request() {
    let mut req = test_cgi_request_with_path("/cgi-bin/app", "");
    apply_script_name_prefixes(&mut req, &[]);

    assert_eq!(req.script_name, "/cgi-bin/app");
    assert_eq!(req.path_info, "");
}

fn test_cgi_request() -> CgiRequest {
    test_cgi_request_with_path("/index", "")
}

fn test_cgi_request_with_path(script_name: &str, path_info: &str) -> CgiRequest {
    CgiRequest {
        script_name: script_name.to_string(),
        path_info: path_info.to_string(),
        query_string: String::new(),
        request_method: "GET".to_string(),
        content_type: String::new(),
        content_length: 0,
        declared_content_length: Some(0),
        server_protocol: "HTTP/1.1".to_string(),
        server_name: "localhost".to_string(),
        server_port: 80,
        remote_addr: None,
        remote_port: None,
        http_headers: HashMap::new(),
        matched_prefix: None,
    }
}

async fn read_fastcgi_request_from_tcp(stream: &mut TcpStream) {
    loop {
        let Some((record_type, content)) = read_fastcgi_record_from_tcp(stream).await else {
            panic!("unexpected eof");
        };
        if record_type == FCGI_STDIN && content.is_empty() {
            break;
        }
    }
}

async fn read_fastcgi_record_from_tcp(stream: &mut TcpStream) -> Option<(u8, Bytes)> {
    let mut header = [0u8; 8];
    if stream.read_exact(&mut header).await.is_err() {
        return None;
    }
    let record_type = header[1];
    let content_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let padding_len = header[6] as usize;
    let mut content = vec![0u8; content_len];
    stream.read_exact(&mut content).await.expect("content");
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        stream.read_exact(&mut padding).await.expect("padding");
    }
    Some((record_type, Bytes::from(content)))
}

async fn write_fastcgi_record_to_tcp(stream: &mut TcpStream, record_type: u8, content: &[u8]) {
    let content_len = content.len() as u16;
    let padding_len = (8 - (content.len() % 8)) % 8;
    let header = [
        1,
        record_type,
        0,
        1,
        (content_len >> 8) as u8,
        content_len as u8,
        padding_len as u8,
        0,
    ];
    stream.write_all(&header).await.expect("header");
    stream.write_all(content).await.expect("content");
    if padding_len > 0 {
        stream
            .write_all(&[0u8; 8][..padding_len])
            .await
            .expect("padding");
    }
}

async fn read_scgi_request_from_tcp(stream: &mut TcpStream) -> Bytes {
    let mut len = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .expect("netstring length");
        if byte[0] == b':' {
            break;
        }
        len.push(byte[0]);
    }
    let len = std::str::from_utf8(&len)
        .expect("length utf8")
        .parse::<usize>()
        .expect("length");
    let mut headers = vec![0u8; len];
    stream.read_exact(&mut headers).await.expect("headers");
    let mut comma = [0u8; 1];
    stream.read_exact(&mut comma).await.expect("comma");
    assert_eq!(comma[0], b',');
    Bytes::from(headers)
}

fn scgi_env_value<'a>(payload: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let mut fields = payload.split(|byte| *byte == 0);
    while let Some(field_key) = fields.next() {
        if field_key.is_empty() {
            continue;
        }
        let field_value = fields.next().unwrap_or_default();
        if field_key == key.as_bytes() {
            return Some(field_value);
        }
    }
    None
}
