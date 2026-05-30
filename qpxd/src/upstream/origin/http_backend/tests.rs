use super::*;

use crate::http::body::to_bytes;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
#[cfg(feature = "tls-rustls")]
use hyper::Response as Http1Response;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
#[cfg(feature = "tls-rustls")]
use tokio::sync::Notify;
use tokio::task::yield_now;

async fn spawn_counting_http1_origin(scheme: &str) -> Result<(OriginEndpoint, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = accepts.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let service = service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from_static(b"OK")).boxed())
                        .expect("response"),
                )
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok((
        OriginEndpoint::direct(format!("{scheme}://127.0.0.1:{}", addr.port())),
        accepts,
    ))
}

#[tokio::test]
async fn proxy_plain_http_reuses_direct_origin_connection() -> Result<()> {
    let (origin, accepts) = spawn_counting_http1_origin("http").await?;

    let first = proxy_http_with_interim(
        Request::builder()
            .uri("http://reverse_edges.test/one")
            .body(Body::empty())?,
        &origin,
        "qpx-test",
        None,
    )
    .await?;
    assert_eq!(to_bytes(first.response.into_body()).await?, "OK");
    yield_now().await;

    let second = proxy_http_with_interim(
        Request::builder()
            .uri("http://reverse_edges.test/two")
            .body(Body::empty())?,
        &origin,
        "qpx-test",
        None,
    )
    .await?;
    assert_eq!(to_bytes(second.response.into_body()).await?, "OK");

    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    Ok(())
}

#[cfg(feature = "tls-rustls")]
async fn tls_trust_for_localhost(
    alpn: &[u8],
) -> Result<(tokio_rustls::TlsAcceptor, Arc<CompiledUpstreamTlsTrust>)> {
    use crate::tls::cert_info::extract_upstream_certificate_info;
    use qpx_core::config::UpstreamTlsTrustConfig;
    use qpx_core::tls::init_rustls_crypto_provider;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    init_rustls_crypto_provider();
    let certified =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("self-signed cert");
    let cert_der = certified.cert.der().clone();
    let fingerprint = extract_upstream_certificate_info(Some(cert_der.as_ref()))
        .fingerprint_sha256
        .expect("fingerprint");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let trust = CompiledUpstreamTlsTrust::from_config(Some(&UpstreamTlsTrustConfig {
        pin_sha256: vec![fingerprint],
        issuer: Vec::new(),
        san_dns: Vec::new(),
        san_uri: Vec::new(),
        client_cert: None,
        client_key: None,
    }))?
    .expect("trust");
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .expect("server config");
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok((tokio_rustls::TlsAcceptor::from(Arc::new(config)), trust))
}

#[cfg(feature = "tls-rustls")]
async fn spawn_counting_https_http1_origin() -> Result<(
    OriginEndpoint,
    Arc<CompiledUpstreamTlsTrust>,
    Arc<AtomicUsize>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (acceptor, trust) = tls_trust_for_localhost(b"http/1.1").await?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = accepts.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(stream).await.expect("tls");
                let service =
                    service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(b"OK")).boxed())
                                .expect("response"),
                        )
                    });
                let _ = hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Ok((
        OriginEndpoint::direct(format!("https://localhost:{}", addr.port())),
        trust,
        accepts,
    ))
}

#[cfg(feature = "tls-rustls")]
async fn spawn_counting_https_h2_origin() -> Result<(
    OriginEndpoint,
    Arc<CompiledUpstreamTlsTrust>,
    Arc<AtomicUsize>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (acceptor, trust) = tls_trust_for_localhost(b"h2").await?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = accepts.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(stream).await.expect("tls");
                let mut conn = h2::server::handshake(tls).await.expect("handshake");
                while let Some(result) = conn.accept().await {
                    let (_request, mut respond) = result.expect("request");
                    tokio::spawn(async move {
                        let response = Http1Response::builder()
                            .status(StatusCode::OK)
                            .body(())
                            .expect("response");
                        let mut send = respond.send_response(response, false).expect("send");
                        send.send_data(Bytes::from_static(b"OK"), true)
                            .expect("body");
                    });
                }
            });
        }
    });
    Ok((
        OriginEndpoint::direct(format!("https://localhost:{}", addr.port())),
        trust,
        accepts,
    ))
}

#[cfg(feature = "tls-rustls")]
async fn spawn_limited_https_h2_origin() -> Result<(
    OriginEndpoint,
    Arc<CompiledUpstreamTlsTrust>,
    Arc<AtomicUsize>,
    Arc<Notify>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (acceptor, trust) = tls_trust_for_localhost(b"h2").await?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let request_count = Arc::new(AtomicUsize::new(0));
    let release_first = Arc::new(Notify::new());
    let accepts_task = accepts.clone();
    let request_count_task = request_count.clone();
    let release_first_task = release_first.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let request_count = request_count_task.clone();
            let release_first = release_first_task.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(stream).await.expect("tls");
                let mut conn = h2::server::Builder::new()
                    .max_concurrent_streams(1)
                    .handshake(tls)
                    .await
                    .expect("handshake");
                while let Some(result) = conn.accept().await {
                    let request_idx = request_count.fetch_add(1, Ordering::SeqCst);
                    let (_request, mut respond) = result.expect("request");
                    let release_first = release_first.clone();
                    tokio::spawn(async move {
                        let response = Http1Response::builder()
                            .status(StatusCode::OK)
                            .body(())
                            .expect("response");
                        let mut send = respond.send_response(response, false).expect("send");
                        if request_idx == 0 {
                            release_first.notified().await;
                        }
                        send.send_data(Bytes::from_static(b"OK"), true)
                            .expect("body");
                    });
                }
            });
        }
    });
    Ok((
        OriginEndpoint::direct(format!("https://localhost:{}", addr.port())),
        trust,
        accepts,
        release_first,
    ))
}

#[cfg(feature = "tls-rustls")]
#[tokio::test]
async fn proxy_https_http1_reuses_direct_origin_connection() -> Result<()> {
    let (origin, trust, accepts) = spawn_counting_https_http1_origin().await?;

    let first = proxy_https_with_options(
        Request::builder()
            .uri("https://reverse_edges.test/one")
            .body(Body::empty())?,
        &origin,
        "qpx-test",
        Some(trust.as_ref()),
        false,
    )
    .await?;
    assert!(
        first
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false)
    );
    assert_eq!(to_bytes(first.response.into_body()).await?, "OK");
    yield_now().await;

    let second = proxy_https_with_options(
        Request::builder()
            .uri("https://reverse_edges.test/two")
            .body(Body::empty())?,
        &origin,
        "qpx-test",
        Some(trust.as_ref()),
        false,
    )
    .await?;
    assert!(
        second
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false)
    );
    assert_eq!(to_bytes(second.response.into_body()).await?, "OK");

    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    Ok(())
}

#[cfg(feature = "tls-rustls")]
#[tokio::test]
async fn proxy_https_h2_reuses_direct_origin_connection() -> Result<()> {
    let (origin, trust, accepts) = spawn_counting_https_h2_origin().await?;

    let first = proxy_https_with_options(
        Request::builder()
            .uri("https://reverse_edges.test/one")
            .body(Body::empty())?,
        &origin,
        "qpx-test",
        Some(trust.as_ref()),
        false,
    )
    .await?;
    assert!(
        first
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false)
    );
    assert_eq!(to_bytes(first.response.into_body()).await?, "OK");

    let second = proxy_https_with_options(
        Request::builder()
            .uri("https://reverse_edges.test/two")
            .body(Body::empty())?,
        &origin,
        "qpx-test",
        Some(trust.as_ref()),
        false,
    )
    .await?;
    assert!(
        second
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false)
    );
    assert_eq!(to_bytes(second.response.into_body()).await?, "OK");

    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    Ok(())
}

#[cfg(feature = "tls-rustls")]
#[tokio::test]
async fn proxy_https_h2_opens_additional_direct_origin_connections_under_stream_pressure()
-> Result<()> {
    let (origin, trust, accepts, release_first) = spawn_limited_https_h2_origin().await?;

    let first = proxy_https_with_options(
        Request::builder()
            .uri("https://reverse_edges.test/one")
            .body(Body::empty())?,
        &origin,
        "qpx-test",
        Some(trust.as_ref()),
        false,
    )
    .await?;
    assert!(
        first
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false)
    );

    let second = proxy_https_with_options(
        Request::builder()
            .uri("https://reverse_edges.test/two")
            .body(Body::empty())?,
        &origin,
        "qpx-test",
        Some(trust.as_ref()),
        false,
    )
    .await?;
    assert!(
        second
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false)
    );

    assert_eq!(accepts.load(Ordering::SeqCst), 2);
    release_first.notify_waiters();
    assert_eq!(to_bytes(first.response.into_body()).await?, "OK");
    assert_eq!(to_bytes(second.response.into_body()).await?, "OK");
    Ok(())
}
