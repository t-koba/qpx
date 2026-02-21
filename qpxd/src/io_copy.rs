use crate::exporter::ExportSession;
use crate::rate_limit::RateLimiter;
use anyhow::Result;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep, timeout, Duration};

#[derive(Clone)]
pub struct BandwidthThrottle {
    src_ip: IpAddr,
    limiters: Arc<Vec<Arc<RateLimiter>>>,
}

impl BandwidthThrottle {
    pub fn new(src_ip: IpAddr, limiters: Vec<Arc<RateLimiter>>) -> Option<Self> {
        if limiters.is_empty() {
            return None;
        }
        Some(Self {
            src_ip,
            limiters: Arc::new(limiters),
        })
    }

    fn reserve_delay(&self, bytes: usize) -> Duration {
        let mut delay = Duration::ZERO;
        for limiter in self.limiters.iter() {
            delay = delay.max(limiter.reserve_delay(self.src_ip, bytes as u64));
        }
        delay
    }
}

async fn copy_one_way<R, W>(
    mut reader: R,
    mut writer: W,
    session: Option<ExportSession>,
    client_to_server: bool,
    idle_timeout: Option<Duration>,
    throttle: Option<BandwidthThrottle>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match idle_timeout {
            Some(dur) => timeout(dur, reader.read(&mut buf)).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel read timed out")
            })??,
            None => reader.read(&mut buf).await?,
        };
        if n == 0 {
            match idle_timeout {
                Some(dur) => timeout(dur, writer.shutdown()).await.map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel shutdown timed out")
                })??,
                None => writer.shutdown().await?,
            }
            return Ok(total);
        }
        if let Some(throttle) = throttle.as_ref() {
            let delay = throttle.reserve_delay(n);
            if !delay.is_zero() {
                sleep(delay).await;
            }
        }
        match idle_timeout {
            Some(dur) => timeout(dur, writer.write_all(&buf[..n]))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel write timed out")
                })??,
            None => writer.write_all(&buf[..n]).await?,
        }
        if let Some(session) = &session {
            session.emit_encrypted_pair(client_to_server, &buf[..n]);
        }
        total = total.saturating_add(n as u64);
    }
}

pub async fn copy_bidirectional_with_export_and_idle<A, B>(
    a: A,
    b: B,
    session: Option<ExportSession>,
    idle_timeout: Option<Duration>,
    throttle: Option<BandwidthThrottle>,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if session.is_none() && idle_timeout.is_none() && throttle.is_none() {
        let mut a = a;
        let mut b = b;
        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await?;
        return Ok(());
    }

    let (a_reader, a_writer) = tokio::io::split(a);
    let (b_reader, b_writer) = tokio::io::split(b);

    let a_to_b_session = session.clone();
    let b_to_a_session = session;
    let a_to_b_throttle = throttle.clone();
    let b_to_a_throttle = throttle;

    let _ = tokio::try_join!(
        copy_one_way(
            a_reader,
            b_writer,
            a_to_b_session,
            true,
            idle_timeout,
            a_to_b_throttle
        ),
        copy_one_way(
            b_reader,
            a_writer,
            b_to_a_session,
            false,
            idle_timeout,
            b_to_a_throttle
        ),
    )?;
    Ok(())
}
