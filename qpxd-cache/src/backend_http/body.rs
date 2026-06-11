use anyhow::{Result, anyhow};
use bytes::BytesMut;
use qpx_http::body::Body;

pub async fn collect_body_limited(mut body: Body, max_bytes: usize) -> Result<bytes::Bytes> {
    let mut out = BytesMut::new();
    while let Some(frame) = body.data().await {
        let chunk = frame?;
        let next = out
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("http cache get body length overflow"))?;
        if next > max_bytes {
            return Err(anyhow!(
                "http cache get payload too large: {} > {}",
                next,
                max_bytes
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}
