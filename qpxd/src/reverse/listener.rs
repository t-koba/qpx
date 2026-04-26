use super::transport::{handle_request_with_interim, ReverseConnInfo};
use super::{
    record_reverse_connection_filter_block, reverse_connection_filter_match, ReloadableReverse,
};
use crate::connection_filter::ConnectionFilterStage;
use crate::http::body::Body;
use crate::http::http1_codec::serve_http1_with_interim;
use crate::http::interim::{serve_h2_with_interim, sniff_h2_preface, H2_PREFACE};
use crate::xdp::remote::resolve_remote_addr_with_xdp;
use anyhow::Result;
use http::{Request, Response};
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
use qpx_observability::RequestHandler;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use tokio::net::TcpListener;
use tokio::sync::watch;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use tokio::time::timeout;
use tokio::time::Duration;
use tracing::warn;

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use crate::io_copy::copy_bidirectional_with_export_and_idle;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use crate::tls::{extract_client_hello_info, read_client_hello_with_timeout};
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use bytes::Bytes;
#[cfg(any(feature = "tls-rustls", feature = "tls-native", test))]
use std::sync::Arc;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use tokio::net::TcpStream;

#[derive(Clone)]
struct ReverseInterimService {
    reverse: ReloadableReverse,
    conn: ReverseConnInfo,
}

impl RequestHandler<Request<Body>> for ReverseInterimService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn call(&self, req: Request<Body>) -> Self::Future {
        let reverse = self.reverse.clone();
        let conn = self.conn.clone();
        Box::pin(async move {
            let (interim, mut response) = handle_request_with_interim(req, reverse, conn).await?;
            if !interim.is_empty() {
                response.extensions_mut().insert(interim);
            }
            Ok(response)
        })
    }
}

#[cfg(feature = "tls-rustls")]
struct ReverseTlsContext {
    reverse: ReloadableReverse,
}

#[cfg(feature = "tls-rustls")]
pub(super) async fn run_reverse_tls_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    reverse: ReloadableReverse,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let semaphore = reverse.runtime.state().connection_semaphore.clone();
    loop {
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            permit = semaphore.clone().acquire_owned() => Some(permit?),
        };
        if permit.is_none() {
            break;
        }
        let permit = permit.expect("checked permit");
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok(accepted) => Some(accepted),
                Err(err) => {
                    warn!(error = ?err, "reverse TLS accept failed");
                    continue;
                }
            }
        };
        if accepted.is_none() {
            break;
        }
        let (stream, remote_addr) = accepted.expect("checked accept");
        let _ = stream.set_nodelay(true);
        let local_port = match stream.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => {
                warn!(error = ?err, "failed to resolve reverse local addr");
                continue;
            }
        };
        let reverse = reverse.clone();
        let xdp_cfg = xdp_cfg.clone();
        let reverse_name = reverse.name.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let header_read_timeout = Duration::from_millis(
                reverse
                    .runtime
                    .state()
                    .config
                    .runtime
                    .http_header_read_timeout_ms,
            );
            let (stream, remote_addr) = match resolve_remote_addr_with_xdp(
                stream,
                remote_addr,
                xdp_cfg.as_ref(),
                header_read_timeout,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            if let Some(matched_rule) =
                reverse_connection_filter_match(&reverse, remote_addr, local_port, None)
            {
                record_reverse_connection_filter_block(
                    &reverse,
                    remote_addr,
                    local_port,
                    ConnectionFilterStage::Accept,
                    matched_rule.as_str(),
                    None,
                );
                return;
            }
            let reverse_name_for_log = reverse_name.clone();
            let ctx = ReverseTlsContext { reverse };
            if let Err(err) = handle_tls_connection(stream, remote_addr, local_port, ctx).await {
                warn!(error = ?err, "reverse tls connection failed");
                if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                    tracing::warn!(
                        target: "audit_log",
                        event = "tls_error",
                        reverse = %reverse_name_for_log,
                        remote = %remote_addr,
                        error = ?err,
                    );
                }
            }
        });
    }
    Ok(())
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
struct ReverseTlsContext {
    reverse: ReloadableReverse,
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
pub(super) async fn run_reverse_tls_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    reverse: ReloadableReverse,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let semaphore = reverse.runtime.state().connection_semaphore.clone();
    loop {
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            permit = semaphore.clone().acquire_owned() => Some(permit?),
        };
        if permit.is_none() {
            break;
        }
        let permit = permit.expect("checked permit");
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok(accepted) => Some(accepted),
                Err(err) => {
                    warn!(error = ?err, "reverse TLS accept failed");
                    continue;
                }
            }
        };
        if accepted.is_none() {
            break;
        }
        let (stream, remote_addr) = accepted.expect("checked accept");
        let _ = stream.set_nodelay(true);
        let local_port = match stream.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => {
                warn!(error = ?err, "failed to resolve reverse local addr");
                continue;
            }
        };
        let reverse = reverse.clone();
        let xdp_cfg = xdp_cfg.clone();
        let reverse_name = reverse.name.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let header_read_timeout = Duration::from_millis(
                reverse
                    .runtime
                    .state()
                    .config
                    .runtime
                    .http_header_read_timeout_ms,
            );
            let (stream, remote_addr) = match resolve_remote_addr_with_xdp(
                stream,
                remote_addr,
                xdp_cfg.as_ref(),
                header_read_timeout,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            if let Some(matched_rule) =
                reverse_connection_filter_match(&reverse, remote_addr, local_port, None)
            {
                record_reverse_connection_filter_block(
                    &reverse,
                    remote_addr,
                    local_port,
                    ConnectionFilterStage::Accept,
                    matched_rule.as_str(),
                    None,
                );
                return;
            }
            let reverse_name_for_log = reverse_name.clone();
            let ctx = ReverseTlsContext { reverse };
            if let Err(err) = handle_tls_connection(stream, remote_addr, local_port, ctx).await {
                warn!(error = ?err, "reverse tls connection failed");
                if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                    tracing::warn!(
                        target: "audit_log",
                        event = "tls_error",
                        reverse = %reverse_name_for_log,
                        remote = %remote_addr,
                        error = ?err,
                    );
                }
            }
        });
    }
    Ok(())
}

pub(super) async fn run_reverse_http_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    reverse: ReloadableReverse,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let semaphore = reverse.runtime.state().connection_semaphore.clone();
    loop {
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            permit = semaphore.clone().acquire_owned() => Some(permit?),
        };
        if permit.is_none() {
            break;
        }
        let permit = permit.expect("checked permit");
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok(accepted) => Some(accepted),
                Err(err) => {
                    warn!(error = ?err, "reverse accept failed");
                    continue;
                }
            }
        };
        if accepted.is_none() {
            break;
        }
        let (stream, remote_addr) = accepted.expect("checked accept");
        let _ = stream.set_nodelay(true);
        let local_port = match stream.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => {
                warn!(error = ?err, "failed to resolve reverse local addr");
                continue;
            }
        };
        let xdp_cfg = xdp_cfg.clone();
        let reverse = reverse.clone();
        let reverse_name = reverse.name.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let header_read_timeout = Duration::from_millis(
                reverse
                    .runtime
                    .state()
                    .config
                    .runtime
                    .http_header_read_timeout_ms,
            );
            let (stream, remote_addr) = match resolve_remote_addr_with_xdp(
                stream,
                remote_addr,
                xdp_cfg.as_ref(),
                header_read_timeout,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            if let Some(matched_rule) =
                reverse_connection_filter_match(&reverse, remote_addr, local_port, None)
            {
                record_reverse_connection_filter_block(
                    &reverse,
                    remote_addr,
                    local_port,
                    ConnectionFilterStage::Accept,
                    matched_rule.as_str(),
                    None,
                );
                return;
            }
            let mut stream = stream;
            let preface = match sniff_h2_preface(&mut stream, header_read_timeout).await {
                Ok(preface) => preface,
                Err(err) => {
                    warn!(error = ?err, "reverse protocol sniff failed");
                    return;
                }
            };
            let stream = crate::io_prefix::PrefixedIo::new(stream, preface.clone());
            let conn = ReverseConnInfo::plain(remote_addr, local_port);
            if preface.as_ref() == H2_PREFACE {
                let access_cfg = reverse.runtime.state().config.access_log.clone();
                let service = AccessLogService::new(
                    ReverseInterimService {
                        reverse: reverse.clone(),
                        conn,
                    },
                    remote_addr,
                    AccessLogContext {
                        kind: "reverse",
                        name: reverse_name,
                    },
                    &access_cfg,
                );
                if let Err(err) =
                    serve_h2_with_interim(stream, service, false, header_read_timeout).await
                {
                    warn!(error = ?err, "reverse HTTP/2 connection failed");
                }
            } else {
                let access_cfg = reverse.runtime.state().config.access_log.clone();
                let service = AccessLogService::new(
                    ReverseInterimService {
                        reverse: reverse.clone(),
                        conn,
                    },
                    remote_addr,
                    AccessLogContext {
                        kind: "reverse",
                        name: reverse_name,
                    },
                    &access_cfg,
                );
                if let Err(err) =
                    serve_http1_with_interim(stream, service, header_read_timeout).await
                {
                    warn!(error = ?err, "reverse connection failed");
                }
            }
        });
    }
    Ok(())
}

#[cfg(feature = "tls-rustls")]
async fn handle_tls_connection(
    stream: crate::io_prefix::PrefixedIo<TcpStream>,
    remote_addr: std::net::SocketAddr,
    local_port: u16,
    ctx: ReverseTlsContext,
) -> Result<()> {
    let ReverseTlsContext { reverse } = ctx;
    let mut stream = stream;
    let peek_timeout =
        Duration::from_millis(reverse.runtime.state().config.runtime.tls_peek_timeout_ms);
    let peek = read_client_hello_with_timeout(&mut stream, peek_timeout).await?;
    let client_hello = extract_client_hello_info(&peek);
    let sni = client_hello
        .as_ref()
        .and_then(|hello| hello.sni.clone())
        .map(Arc::<str>::from);
    if let Some(matched_rule) =
        reverse_connection_filter_match(&reverse, remote_addr, local_port, client_hello.as_ref())
    {
        record_reverse_connection_filter_block(
            &reverse,
            remote_addr,
            local_port,
            ConnectionFilterStage::ClientHello,
            matched_rule.as_str(),
            client_hello.as_ref().and_then(|hello| hello.sni.as_deref()),
        );
        return Ok(());
    }
    let stream = crate::io_prefix::PrefixedIo::new(stream, Bytes::from(peek));

    let compiled = reverse.compiled().await;
    if let Some(upstream) = compiled.router.select_tls_passthrough_upstream(
        remote_addr.ip(),
        local_port,
        sni.as_deref(),
    ) {
        let addr = upstream.origin.connect_authority(443)?;
        let upstream_timeout = Duration::from_millis(
            reverse
                .runtime
                .state()
                .config
                .runtime
                .upstream_http_timeout_ms,
        );
        let upstream_stream =
            tokio::time::timeout(upstream_timeout, TcpStream::connect(&addr)).await??;
        let _ = upstream_stream.set_nodelay(true);
        let export = upstream_stream.peer_addr().ok().and_then(|server_addr| {
            reverse
                .runtime
                .state()
                .export_session(remote_addr, server_addr)
        });
        let idle_timeout = Duration::from_millis(
            reverse
                .runtime
                .state()
                .config
                .runtime
                .tunnel_idle_timeout_ms,
        );
        copy_bidirectional_with_export_and_idle(
            stream,
            upstream_stream,
            export,
            Some(idle_timeout),
            None,
        )
        .await?;
        return Ok(());
    }

    let tls_accept_timeout = Duration::from_millis(
        reverse
            .runtime
            .state()
            .config
            .runtime
            .upstream_http_timeout_ms,
    );
    let acceptor = compiled
        .tls_acceptor
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("reverse tls acceptor missing"))?
        .clone();
    let tls_stream = timeout(tls_accept_timeout, acceptor.accept(stream)).await??;
    let negotiated_h2 = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|alpn| alpn == b"h2")
        .unwrap_or(false);
    let peer_certificates = tls_stream.get_ref().1.peer_certificates().map(|certs| {
        Arc::new(
            certs
                .iter()
                .map(|cert| cert.as_ref().to_vec())
                .collect::<Vec<_>>(),
        )
    });
    let header_read_timeout = Duration::from_millis(
        reverse
            .runtime
            .state()
            .config
            .runtime
            .http_header_read_timeout_ms,
    );
    let conn = ReverseConnInfo::terminated(remote_addr, local_port, sni.clone(), peer_certificates);
    let access_cfg = reverse.runtime.state().config.access_log.clone();
    let reverse_name = reverse.name.clone();
    if negotiated_h2 {
        let service = AccessLogService::new(
            ReverseInterimService {
                reverse: reverse.clone(),
                conn,
            },
            remote_addr,
            AccessLogContext {
                kind: "reverse",
                name: reverse_name.clone(),
            },
            &access_cfg,
        );
        serve_h2_with_interim(tls_stream, service, false, header_read_timeout).await?;
    } else {
        let service = AccessLogService::new(
            ReverseInterimService {
                reverse: reverse.clone(),
                conn,
            },
            remote_addr,
            AccessLogContext {
                kind: "reverse",
                name: reverse_name.clone(),
            },
            &access_cfg,
        );
        serve_http1_with_interim(tls_stream, service, header_read_timeout).await?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::runtime::Runtime;
    use crate::tls::TlsClientHelloInfo;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CacheConfig, Config,
        IdentityConfig, MatchConfig, MessagesConfig, ReverseConfig, ReverseRouteConfig, RuleConfig,
        RuntimeConfig, SystemLogConfig, TlsFingerprintMatchConfig, UpstreamConfig,
    };
    use std::future::poll_fn;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn build_reloadable_reverse(upstream_addr: SocketAddr) -> ReloadableReverse {
        build_reloadable_reverse_with_filter(upstream_addr, Vec::new())
    }

    fn build_reloadable_reverse_with_filter(
        upstream_addr: SocketAddr,
        connection_filter: Vec<RuleConfig>,
    ) -> ReloadableReverse {
        let reverse_cfg = ReverseConfig {
            name: "test".to_string(),
            listen: "127.0.0.1:0".to_string(),
            tls: None,
            http3: None,
            xdp: None,
            enforce_sni_host_match: false,
            sni_host_exceptions: Vec::new(),
            policy_context: None,
            connection_filter,
            destination_resolution: None,
            routes: vec![ReverseRouteConfig {
                name: Some("route".to_string()),
                r#match: MatchConfig::default(),
                upstreams: vec!["upstream".to_string()],
                backends: Vec::new(),
                mirrors: Vec::new(),
                local_response: None,
                headers: None,
                lb: "round_robin".to_string(),
                timeout_ms: None,
                health_check: None,
                cache: None,
                rate_limit: None,
                path_rewrite: None,
                upstream_trust_profile: None,
                upstream_trust: None,
                lifecycle: None,
                ipc: None,
                affinity: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
            }],
            tls_passthrough_routes: Vec::new(),
        };
        let upstream_cfg = UpstreamConfig {
            name: "upstream".to_string(),
            url: format!("http://{upstream_addr}"),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        };
        let config = Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            acme: None,
            exporter: None,
            auth: AuthConfig::default(),
            identity_sources: Vec::new(),
            ext_authz: Vec::new(),
            destination_resolution: Default::default(),
            listeners: Vec::new(),
            named_sets: Vec::new(),
            http_guard_profiles: Vec::new(),
            rate_limit_profiles: Vec::new(),
            upstream_trust_profiles: Vec::new(),
            reverse: vec![reverse_cfg.clone()],
            upstreams: vec![upstream_cfg],
            cache: CacheConfig::default(),
        };
        let runtime = Runtime::new(config).expect("runtime");
        ReloadableReverse::new(
            reverse_cfg,
            runtime,
            Arc::<str>::from("reverse_upstreams_unhealthy"),
        )
        .expect("reloadable reverse")
    }

    #[tokio::test]
    async fn reverse_connection_filter_blocks_accept_stage_before_upstream() {
        let _upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = _upstream_listener.local_addr().expect("upstream addr");
        let reverse = build_reloadable_reverse_with_filter(
            upstream_addr,
            vec![RuleConfig {
                name: "block-local".to_string(),
                r#match: Some(MatchConfig::default()),
                auth: None,
                action: Some(ActionConfig {
                    kind: ActionKind::Block,
                    upstream: None,
                    local_response: None,
                }),
                headers: None,
                rate_limit: None,
            }],
        );
        let reverse_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind reverse");
        let reverse_addr = reverse_listener.local_addr().expect("reverse addr");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let acceptor = tokio::spawn(async move {
            run_reverse_http_acceptor(reverse_listener, None, reverse, shutdown_rx)
                .await
                .expect("acceptor");
        });

        let mut client = TcpStream::connect(reverse_addr)
            .await
            .expect("connect reverse");
        client
            .write_all(b"GET /asset HTTP/1.1\r\nHost: reverse.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
            .await
            .expect("read timeout");
        match read {
            Ok(0) => {}
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(n) => panic!("blocked connection returned unexpected {n} bytes"),
            Err(err) => panic!("unexpected read error: {err}"),
        }
        let _ = shutdown_tx.send(true);
        acceptor.await.expect("join");
    }

    #[tokio::test]
    async fn reverse_connection_filter_matches_client_hello_metadata() {
        let reverse = build_reloadable_reverse_with_filter(
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            vec![RuleConfig {
                name: "block-client-hello".to_string(),
                r#match: Some(MatchConfig {
                    sni: vec!["blocked.example".to_string()],
                    alpn: vec!["h2".to_string()],
                    tls_version: vec!["tls1.3".to_string()],
                    tls_fingerprint: Some(TlsFingerprintMatchConfig {
                        ja3: vec!["ja3-hash".to_string()],
                        ja4: vec!["ja4-hash".to_string()],
                    }),
                    ..Default::default()
                }),
                auth: None,
                action: Some(ActionConfig {
                    kind: ActionKind::Block,
                    upstream: None,
                    local_response: None,
                }),
                headers: None,
                rate_limit: None,
            }],
        );

        let matched = reverse_connection_filter_match(
            &reverse,
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            443,
            Some(&TlsClientHelloInfo {
                sni: Some("blocked.example".to_string()),
                alpn: Some("h2".to_string()),
                tls_version: Some("tls1.3".to_string()),
                ja3: Some("ja3-hash".to_string()),
                ja4: Some("ja4-hash".to_string()),
            }),
        );

        assert_eq!(matched.as_deref(), Some("block-client-hello"));
    }

    #[tokio::test]
    async fn reverse_h2_service_emits_early_hints() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
                let mut raw = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = stream.read(&mut buf).await.expect("read request");
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                if !raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    continue;
                }
                stream
                    .write_all(
                        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
                    )
                    .await
                    .expect("write response");
                tokio::time::sleep(Duration::from_millis(50)).await;
                stream.shutdown().await.expect("shutdown");
                break;
            }
        });

        let reverse = build_reloadable_reverse(upstream_addr);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind reverse");
        let addr = listener.local_addr().expect("reverse addr");
        let access_cfg = reverse.runtime.state().config.access_log.clone();
        let service = AccessLogService::new(
            ReverseInterimService {
                reverse,
                conn: ReverseConnInfo::plain(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                    80,
                ),
            },
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            AccessLogContext {
                kind: "reverse",
                name: Arc::<str>::from("test"),
            },
            &access_cfg,
        );
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept reverse");
            serve_h2_with_interim(socket, service, false, Duration::from_secs(5))
                .await
                .expect("serve h2");
        });

        let socket = TcpStream::connect(addr).await.expect("connect reverse");
        let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("client connection");
        });

        let mut client = client.ready().await.expect("ready");
        let request = ::http::Request::builder()
            .method("GET")
            .uri("/asset")
            .header("host", "reverse.test")
            .body(())
            .expect("request");
        let (mut response_future, _) = client.send_request(request, true).expect("send");

        let interim = poll_fn(|cx| response_future.poll_informational(cx)).await;
        let response = response_future.await;
        assert!(
            interim.is_some(),
            "missing interim: response={:?}",
            response.as_ref().map(|resp| resp.status())
        );
        let interim = interim
            .expect("informational state")
            .expect("informational ok");
        assert_eq!(interim.status(), ::http::StatusCode::EARLY_HINTS);
        assert_eq!(
            interim
                .headers()
                .get(::http::header::LINK)
                .and_then(|value| value.to_str().ok()),
            Some("</style.css>; rel=preload; as=style")
        );

        let response = response.expect("final response");
        assert_eq!(response.status(), ::http::StatusCode::OK);
        let mut body = response.into_body();
        assert_eq!(
            body.data().await.expect("body frame").expect("body bytes"),
            bytes::Bytes::from_static(b"OK")
        );

        drop(client);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn reverse_h1_listener_emits_early_hints() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
                let mut raw = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = stream.read(&mut buf).await.expect("read request");
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                if !raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    continue;
                }
                stream
                    .write_all(
                        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
                    )
                    .await
                    .expect("write response");
                tokio::time::sleep(Duration::from_millis(50)).await;
                stream.shutdown().await.expect("shutdown");
                break;
            }
        });

        let reverse = build_reloadable_reverse(upstream_addr);
        let reverse_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind reverse");
        let reverse_addr = reverse_listener.local_addr().expect("reverse addr");
        let acceptor = tokio::spawn(async move {
            let (_shutdown_tx, shutdown_rx) = watch::channel(false);
            run_reverse_http_acceptor(reverse_listener, None, reverse, shutdown_rx)
                .await
                .expect("acceptor");
        });

        let mut client = TcpStream::connect(reverse_addr)
            .await
            .expect("connect reverse");
        client
            .write_all(b"GET /asset HTTP/1.1\r\nHost: reverse.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let mut raw = Vec::new();
        client.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8(raw).expect("utf8");
        assert!(text.contains("HTTP/1.1 103"), "response: {text}");
        assert!(text.contains("</style.css>; rel=preload; as=style"));
        assert!(text.contains("HTTP/1.1 200"));
        assert!(text.ends_with("OK"));

        acceptor.abort();
        let _ = acceptor.await;
    }

    #[tokio::test]
    async fn sniff_h2_preface_reads_full_client_preface() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let extra = b"extra";
        tokio::spawn(async move {
            client.write_all(H2_PREFACE).await.expect("write preface");
            client.write_all(extra).await.expect("write extra");
        });

        let preface = sniff_h2_preface(&mut server, Duration::from_secs(1))
            .await
            .expect("sniff preface");
        assert_eq!(preface.as_ref(), H2_PREFACE);

        let mut rest = [0u8; 5];
        server.read_exact(&mut rest).await.expect("read rest");
        assert_eq!(&rest, extra);
    }
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
async fn handle_tls_connection(
    stream: crate::io_prefix::PrefixedIo<TcpStream>,
    remote_addr: std::net::SocketAddr,
    local_port: u16,
    ctx: ReverseTlsContext,
) -> Result<()> {
    let ReverseTlsContext { reverse } = ctx;
    let mut stream = stream;
    let peek_timeout =
        Duration::from_millis(reverse.runtime.state().config.runtime.tls_peek_timeout_ms);
    let peek = read_client_hello_with_timeout(&mut stream, peek_timeout).await?;
    let client_hello = extract_client_hello_info(&peek);
    let sni = client_hello
        .as_ref()
        .and_then(|hello| hello.sni.clone())
        .map(Arc::<str>::from);
    if let Some(matched_rule) =
        reverse_connection_filter_match(&reverse, remote_addr, local_port, client_hello.as_ref())
    {
        record_reverse_connection_filter_block(
            &reverse,
            remote_addr,
            local_port,
            ConnectionFilterStage::ClientHello,
            matched_rule.as_str(),
            client_hello.as_ref().and_then(|hello| hello.sni.as_deref()),
        );
        return Ok(());
    }
    let stream = crate::io_prefix::PrefixedIo::new(stream, Bytes::from(peek));

    let compiled = reverse.compiled().await;
    if let Some(upstream) = compiled.router.select_tls_passthrough_upstream(
        remote_addr.ip(),
        local_port,
        sni.as_deref(),
    ) {
        let addr = upstream.origin.connect_authority(443)?;
        let upstream_timeout = Duration::from_millis(
            reverse
                .runtime
                .state()
                .config
                .runtime
                .upstream_http_timeout_ms,
        );
        let upstream_stream =
            tokio::time::timeout(upstream_timeout, TcpStream::connect(&addr)).await??;
        let _ = upstream_stream.set_nodelay(true);
        let export = upstream_stream.peer_addr().ok().and_then(|server_addr| {
            reverse
                .runtime
                .state()
                .export_session(remote_addr, server_addr)
        });
        let idle_timeout = Duration::from_millis(
            reverse
                .runtime
                .state()
                .config
                .runtime
                .tunnel_idle_timeout_ms,
        );
        copy_bidirectional_with_export_and_idle(
            stream,
            upstream_stream,
            export,
            Some(idle_timeout),
            None,
        )
        .await?;
        return Ok(());
    }

    let tls_accept_timeout = Duration::from_millis(
        reverse
            .runtime
            .state()
            .config
            .runtime
            .upstream_http_timeout_ms,
    );
    let acceptor = compiled
        .tls_acceptor
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("reverse tls acceptor missing"))?
        .clone();
    let tls_stream = timeout(tls_accept_timeout, acceptor.accept(stream, sni.as_deref())).await??;
    let negotiated_h2 = tls_stream
        .get_ref()
        .negotiated_alpn()
        .ok()
        .flatten()
        .map(|alpn| alpn == b"h2")
        .unwrap_or(false);
    let header_read_timeout = Duration::from_millis(
        reverse
            .runtime
            .state()
            .config
            .runtime
            .http_header_read_timeout_ms,
    );
    let conn = ReverseConnInfo::terminated(remote_addr, local_port, sni.clone(), None);
    let access_cfg = reverse.runtime.state().config.access_log.clone();
    let reverse_name = reverse.name.clone();
    if negotiated_h2 {
        let service = AccessLogService::new(
            ReverseInterimService {
                reverse: reverse.clone(),
                conn,
            },
            remote_addr,
            AccessLogContext {
                kind: "reverse",
                name: reverse_name.clone(),
            },
            &access_cfg,
        );
        serve_h2_with_interim(tls_stream, service, false, header_read_timeout).await?;
    } else {
        let service = AccessLogService::new(
            ReverseInterimService {
                reverse: reverse.clone(),
                conn,
            },
            remote_addr,
            AccessLogContext {
                kind: "reverse",
                name: reverse_name.clone(),
            },
            &access_cfg,
        );
        serve_http1_with_interim(tls_stream, service, header_read_timeout).await?;
    }
    Ok(())
}
