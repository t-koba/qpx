use crate::http::body::Body;
use anyhow::Result;
use hyper::Request;
use url::Url;

use crate::upstream::raw_http1::Http1ResponseWithInterim;

use super::OriginEndpoint;

pub(super) fn parse_ipc_url(origin: &OriginEndpoint) -> Result<Url> {
    Ok(Url::parse(origin.upstream.as_str())?)
}

pub(super) async fn proxy_ipc_with_interim(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
) -> Result<Http1ResponseWithInterim> {
    let url = parse_ipc_url(origin)?;
    let response = crate::ipc_client::proxy_ipc(req, &url, proxy_name).await?;
    Ok(Http1ResponseWithInterim {
        interim: Vec::new(),
        response,
        upstream_cert: None,
    })
}
