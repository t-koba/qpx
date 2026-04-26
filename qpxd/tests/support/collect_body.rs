use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::BodyExt as _;

pub async fn collect_body<B>(body: B) -> Result<Bytes>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    Ok(body
        .collect()
        .await
        .map_err(|err| anyhow!(err.to_string()))?
        .to_bytes())
}
