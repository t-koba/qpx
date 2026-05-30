#[cfg(test)]
use super::fastcgi_io::run_fastcgi_on_stream;
use super::fastcgi_io::{FastCgiStreamingStdin, run_fastcgi_on_stream_streaming_stdin};
use anyhow::{Context, Result, anyhow};
#[cfg(test)]
use bytes::Bytes;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{Mutex, Semaphore};

pub(super) trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub(super) type BoxedIo = Pin<Box<dyn AsyncIo>>;

pub(super) struct FastCgiConnectionPool {
    address: String,
    idle: Mutex<Vec<BoxedIo>>,
    semaphore: Arc<Semaphore>,
    max_idle: usize,
}

impl FastCgiConnectionPool {
    pub(super) fn new(address: String, max_concurrency: usize, max_idle: usize) -> Result<Self> {
        if address.trim().is_empty() {
            return Err(anyhow!("fastcgi backend address must not be empty"));
        }
        Ok(Self {
            address,
            idle: Mutex::new(Vec::new()),
            semaphore: Arc::new(Semaphore::new(max_concurrency)),
            max_idle,
        })
    }

    #[cfg(test)]
    pub(super) async fn execute(
        &self,
        env: Vec<(String, String)>,
        body: Bytes,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<(Bytes, Bytes)> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| anyhow!("fastcgi backend semaphore closed"))?;
        let mut stream = self.take().await?;
        let result =
            run_fastcgi_on_stream(&mut stream, env, body, max_stdout_bytes, max_stderr_bytes).await;
        if result.is_ok() {
            self.put(stream).await;
        }
        result
    }

    pub(super) async fn execute_streaming_stdin(
        &self,
        request: FastCgiStreamingStdin,
    ) -> Result<()> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| anyhow!("fastcgi backend semaphore closed"))?;
        let mut stream = self.take().await?;
        let result = run_fastcgi_on_stream_streaming_stdin(&mut stream, request).await;
        if result.is_ok() {
            self.put(stream).await;
        }
        result
    }

    async fn take(&self) -> Result<BoxedIo> {
        if let Some(stream) = self.idle.lock().await.pop() {
            return Ok(stream);
        }
        connect_backend(self.address.as_str()).await
    }

    async fn put(&self, stream: BoxedIo) {
        let mut idle = self.idle.lock().await;
        if idle.len() < self.max_idle {
            idle.push(stream);
        }
    }
}
pub(super) async fn connect_backend(address: &str) -> Result<BoxedIo> {
    if let Some(path) = address.strip_prefix("unix://") {
        #[cfg(unix)]
        {
            let stream = UnixStream::connect(path)
                .await
                .with_context(|| format!("failed to connect unix backend {path}"))?;
            Ok(Box::pin(stream))
        }
        #[cfg(not(unix))]
        {
            Err(anyhow!(
                "unix backend addresses are not supported on this platform: {path}"
            ))
        }
    } else {
        let stream = TcpStream::connect(address)
            .await
            .with_context(|| format!("failed to connect tcp backend {address}"))?;
        Ok(Box::pin(stream))
    }
}
