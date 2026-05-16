use super::*;

pub(crate) struct SharedReverseHttpClient;

pub(crate) fn shared_reverse_http_client() -> &'static SharedReverseHttpClient {
    static CLIENT: SharedReverseHttpClient = SharedReverseHttpClient;
    &CLIENT
}

impl SharedReverseHttpClient {
    pub(crate) async fn request(&self, req: Request<Body>) -> Result<Response<Body>> {
        Ok(request_with_shared_client(req).await?)
    }
}

pub(crate) struct SharedReverseHttpsClient;

pub(crate) fn shared_reverse_https_client() -> &'static SharedReverseHttpsClient {
    static CLIENT: OnceLock<SharedReverseHttpsClient> = OnceLock::new();
    CLIENT.get_or_init(|| SharedReverseHttpsClient)
}

impl SharedReverseHttpsClient {
    pub(crate) async fn request(&self, req: Request<Body>) -> Result<Response<Body>> {
        let target = absolute_request_target(req.uri())?;
        let authority =
            crate::http::address::format_authority_host_port(target.host.as_str(), target.port);
        let slot = https_origin_slot(https_origin_pool_key(
            authority.as_str(),
            authority.as_str(),
            target.host.as_str(),
            true,
            None,
        ));

        match acquire_https_connection(&slot, authority.as_str(), target.host.as_str(), true, None)
            .await?
        {
            HttpsConnectionAcquisition::H2Ready { shared, ready } => {
                let req =
                    prepare_internal_h2_request(req, target.scheme.as_str(), authority.as_str())?;
                let mut proxied = send_h2_request_with_sender(
                    req,
                    ready,
                    Some(shared.upstream_cert.clone()),
                    Some(shared.inflight_streams.clone()),
                )
                .await?;
                if !proxied.interim.is_empty() {
                    proxied.response.extensions_mut().insert(proxied.interim);
                }
                Ok(proxied.response)
            }
            HttpsConnectionAcquisition::H1(entry) => {
                let req = prepare_internal_http1_request(req, authority.as_str())?;
                let mut proxied = send_tls_http1_with_recycle(slot, entry, req).await?;
                if !proxied.interim.is_empty() {
                    proxied.response.extensions_mut().insert(proxied.interim);
                }
                Ok(proxied.response)
            }
        }
    }
}

pub(super) async fn send_tls_http1_with_recycle(
    slot: Arc<self::http_pool::HttpsOriginSlot>,
    entry: self::http_pool::TlsHttp1OriginConnection,
    req: Request<Body>,
) -> Result<Http1ResponseWithInterim> {
    let upstream_cert = entry.upstream_cert.clone();
    let mut proxied = send_http1_request_with_interim_reusable(
        entry.stream,
        req,
        Http1ConnectionRecycler::new({
            let idle = slot.http1_idle.clone();
            move |stream| {
                let idle = idle.clone();
                let upstream_cert = upstream_cert.clone();
                async move {
                    idle.lock()
                        .await
                        .push(self::http_pool::TlsHttp1OriginConnection {
                            stream,
                            upstream_cert,
                        });
                }
            }
        }),
    )
    .await?;
    proxied.upstream_cert = Some(entry.upstream_cert);
    Ok(proxied)
}

struct AbsoluteRequestTarget {
    scheme: String,
    host: String,
    port: u16,
}

fn prepare_internal_http1_request(
    mut req: Request<Body>,
    authority: &str,
) -> Result<Request<Body>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    *req.version_mut() = http::Version::HTTP_11;
    *req.uri_mut() = Uri::builder().path_and_query(path.as_str()).build()?;
    if !req.headers().contains_key(HOST) {
        req.headers_mut()
            .insert(HOST, HeaderValue::from_str(authority)?);
    }
    Ok(req)
}

fn absolute_request_target(uri: &Uri) -> Result<AbsoluteRequestTarget> {
    let parsed = url::Url::parse(uri.to_string().as_str())?;
    let scheme = parsed.scheme().to_string();
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("absolute request URI missing host"))?
        .to_string();
    let port = parsed
        .port()
        .unwrap_or_else(|| super::super::dispatch::default_port_for_scheme(scheme.as_str()));
    Ok(AbsoluteRequestTarget { scheme, host, port })
}
