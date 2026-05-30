mod protocol;

use self::protocol::{
    ShmRequestContext, TcpRequestContext, handle_one_request_shm, handle_one_request_tcp,
    is_unexpected_eof, meta_uses_shm,
};
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};

use crate::router::Router;

use qpx_core::ipc::meta::IpcRequestMeta;
use qpx_core::ipc::protocol::read_frame;

#[derive(Clone)]
pub struct ConnectionContext {
    pub router: Arc<Router>,
    pub semaphore: Arc<Semaphore>,
    pub allow_shm_reuse: bool,
    pub input_idle: Duration,
    pub conn_idle: Duration,
    pub max_requests_per_connection: usize,
    pub max_params_bytes: usize,
    pub max_stdin_bytes: usize,
}

pub async fn handle_connection<S>(mut stream: S, ctx: ConnectionContext) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ConnectionContext {
        router,
        semaphore,
        allow_shm_reuse,
        input_idle,
        conn_idle,
        max_requests_per_connection,
        max_params_bytes,
        max_stdin_bytes,
    } = ctx;
    let mut handled_requests: usize = 0;
    loop {
        // 1) Read the metadata frame from qpxd.
        let meta: IpcRequestMeta = match timeout(conn_idle, read_frame(&mut stream)).await {
            Ok(Ok(meta)) => meta,
            Ok(Err(err)) => {
                if is_unexpected_eof(&err) {
                    return Ok(());
                }
                return Err(err);
            }
            Err(_) => return Ok(()), // idle
        };

        let uses_shm = meta_uses_shm(&meta);
        if uses_shm {
            handle_one_request_shm(
                &mut stream,
                meta,
                ShmRequestContext {
                    router: &router,
                    semaphore: &semaphore,
                    input_idle,
                    max_params_bytes,
                    max_stdin_bytes,
                    allow_shm_reuse,
                },
            )
            .await?;
            handled_requests = handled_requests.saturating_add(1);
            if handled_requests >= max_requests_per_connection {
                return Ok(());
            }
            continue;
        }
        // TCP-streaming mode uses connection-close (EOF) semantics, so keep-alive isn't possible.
        return handle_one_request_tcp(
            stream,
            meta,
            TcpRequestContext {
                router,
                semaphore,
                input_idle,
                output_idle: conn_idle,
                max_params_bytes,
                max_stdin_bytes,
            },
        )
        .await;
    }
}
