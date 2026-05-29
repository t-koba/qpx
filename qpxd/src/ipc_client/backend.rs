use anyhow::{Result, anyhow};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

#[derive(Debug, Clone)]
pub(super) enum IpcBackend {
    Tcp {
        host: String,
        port: u16,
    },
    #[cfg(unix)]
    Unix {
        path: PathBuf,
    },
}

impl IpcBackend {
    pub(super) fn pool_key(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("tcp://{}:{}", host, port),
            #[cfg(unix)]
            Self::Unix { path } => format!("unix://{}", path.display()),
        }
    }
}

pub(super) enum IpcStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl IpcStream {
    pub(super) async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.write_all(buf).await,
            #[cfg(unix)]
            Self::Unix(s) => s.write_all(buf).await,
        }
    }
}

pub(super) fn parse_ipc_address(raw: &str) -> Result<IpcBackend> {
    if let Some(path) = raw.strip_prefix("unix://") {
        #[cfg(unix)]
        {
            return Ok(IpcBackend::Unix {
                path: PathBuf::from(path),
            });
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(anyhow!("unix IPC backends are not supported"));
        }
    }
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(anyhow!(
            "invalid IPC address (expected host:port or unix://path): {}",
            raw
        ));
    };
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow!("invalid IPC port in address: {}", raw))?;
    Ok(IpcBackend::Tcp {
        host: host.to_string(),
        port,
    })
}

impl tokio::io::AsyncRead for IpcStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            Self::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for IpcStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            Self::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}
