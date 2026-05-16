use crate::http::body::Body;
use ::http::{Request as Http1Request, Response as Http1Response};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use hyper::header::{HOST, HeaderValue};
use hyper::{Request, Response, Uri};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::net::TcpStream;

use crate::http::common::request_with_shared_client;
use crate::http::h2_codec::{
    h1_headers_to_http, h2_response_to_hyper_with_inflight, http_headers_to_h1,
    parse_declared_content_length,
};
use crate::http::l7::prepare_request_with_headers_in_place;
use crate::tls::CompiledUpstreamTlsTrust;
use crate::upstream::raw_http1::{
    Http1ConnectionRecycler, Http1ResponseWithInterim, send_http1_request_with_interim_reusable,
};

use super::OriginEndpoint;
use super::dispatch::{OriginScheme, origin_scheme};
use super::ipc_backend::proxy_ipc_with_interim;

#[path = "http_backend_h2.rs"]
mod http_backend_h2;
#[path = "http_backend_shared.rs"]
mod http_backend_shared;
#[path = "http_pool.rs"]
mod http_pool;

use self::http_backend_h2::{
    prepare_internal_h2_request, prepare_proxy_h2_request, send_h2_request_with_sender,
};
pub(crate) use self::http_backend_shared::{
    shared_reverse_http_client, shared_reverse_https_client,
};
pub(crate) use self::http_pool::clear_direct_origin_connection_pools;
use self::http_pool::{
    HttpsConnectionAcquisition, acquire_https_connection, https_origin_pool_key, https_origin_slot,
    plain_http_origin_pool_key, plain_http_origin_slot,
};

pub(crate) async fn proxy_http(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Response<Body>> {
    let mut proxied = proxy_http_with_interim(req, origin, proxy_name, trust).await?;
    if !proxied.interim.is_empty() {
        proxied.response.extensions_mut().insert(proxied.interim);
    }
    Ok(proxied.response)
}

pub(crate) async fn proxy_http_with_interim(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Http1ResponseWithInterim> {
    match origin_scheme(origin)? {
        OriginScheme::Http | OriginScheme::Ws => proxy_plain_http(req, origin, proxy_name).await,
        OriginScheme::Https | OriginScheme::Wss => {
            proxy_https(req, origin, proxy_name, trust).await
        }
        OriginScheme::Ipc | OriginScheme::IpcUnix => {
            proxy_ipc_with_interim(req, origin, proxy_name).await
        }
    }
}

async fn open_plain_http_origin_stream(connect_authority: &str) -> Result<TcpStream> {
    let stream = TcpStream::connect(connect_authority).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn proxy_plain_http(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
) -> Result<Http1ResponseWithInterim> {
    let default_port = origin.default_port_hint();
    let connect_authority = origin.connect_authority(default_port)?;
    let host_authority = origin.host_header_authority(default_port)?;
    let slot = plain_http_origin_slot(plain_http_origin_pool_key(
        connect_authority.as_str(),
        host_authority.as_str(),
    ));
    let req = prepare_proxy_http1_request(req, host_authority.as_str(), proxy_name)?;
    let stream = match slot.idle.lock().await.pop() {
        Some(stream) => stream,
        None => open_plain_http_origin_stream(connect_authority.as_str()).await?,
    };
    send_http1_request_with_interim_reusable(
        stream,
        req,
        Http1ConnectionRecycler::from_idle(slot.idle.clone()),
    )
    .await
}

async fn proxy_https(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Http1ResponseWithInterim> {
    proxy_https_with_options(req, origin, proxy_name, trust, true).await
}

async fn proxy_https_with_options(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
    verify_upstream_cert: bool,
) -> Result<Http1ResponseWithInterim> {
    let default_port = origin.default_port_hint();
    let connect_authority = origin.connect_authority(default_port)?;
    let host_authority = origin.host_header_authority(default_port)?;
    let server_name = origin.tls_server_name()?;
    let pool_key = https_origin_pool_key(
        connect_authority.as_str(),
        host_authority.as_str(),
        server_name.as_str(),
        verify_upstream_cert,
        trust,
    );
    let slot = https_origin_slot(pool_key);

    match acquire_https_connection(
        &slot,
        connect_authority.as_str(),
        server_name.as_str(),
        verify_upstream_cert,
        trust,
    )
    .await?
    {
        HttpsConnectionAcquisition::H2Ready { shared, ready } => {
            let req = prepare_proxy_h2_request(req, "https", host_authority.as_str(), proxy_name)?;
            let proxied = send_h2_request_with_sender(
                req,
                ready,
                Some(shared.upstream_cert.clone()),
                Some(shared.inflight_streams.clone()),
            )
            .await;
            if proxied.is_err() {
                slot.remove_h2_connection(&shared);
            }
            proxied
        }
        HttpsConnectionAcquisition::H1(entry) => {
            let req = prepare_proxy_http1_request(req, host_authority.as_str(), proxy_name)?;
            http_backend_shared::send_tls_http1_with_recycle(slot, entry, req).await
        }
    }
}

fn prepare_proxy_http1_request(
    mut req: Request<Body>,
    host_authority: &str,
    proxy_name: &str,
) -> Result<Request<Body>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    prepare_request_with_headers_in_place(&mut req, proxy_name, None, false);
    *req.version_mut() = http::Version::HTTP_11;
    *req.uri_mut() = Uri::builder().path_and_query(path.as_str()).build()?;
    req.headers_mut()
        .insert(HOST, HeaderValue::from_str(host_authority)?);
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body::to_bytes;
    use bytes::Bytes;
    use http_body_util::{BodyExt as _, Full};
    use hyper::service::service_fn;
    use hyper::{Response, StatusCode};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    #[cfg(feature = "tls-rustls")]
    use tokio::sync::Notify;
    use tokio::task::yield_now;

    async fn spawn_counting_http1_origin(
        scheme: &str,
    ) -> Result<(OriginEndpoint, Arc<AtomicUsize>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = accepts.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept");
                accepts_task.fetch_add(1, Ordering::SeqCst);
                let service =
                    service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
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
}
