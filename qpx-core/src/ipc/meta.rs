use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequestMeta {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub params: HashMap<String, String>,

    /// Shared Memory Ring Buffer identifier for reading request body.
    ///
    /// Security note: the receiver (qpxf) MUST NOT treat this as an arbitrary filesystem path
    /// supplied by the client. It is expected to be a safe file name token under a sandboxed
    /// directory (e.g. `ShmRingBuffer::default_shm_dir()/ipc/<token>`).
    /// If None, body is streamed over the network socket following this meta frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_body_shm_path: Option<String>,

    /// Size of the request body SHM ring buffer in bytes.
    /// Must be set when `req_body_shm_path` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_body_shm_size_bytes: Option<usize>,

    /// Shared Memory Ring Buffer identifier for writing response body.
    ///
    /// See the security note on `req_body_shm_path`.
    /// If None, body is streamed over the network socket following the response meta frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub res_body_shm_path: Option<String>,

    /// Size of the response body SHM ring buffer in bytes.
    /// Must be set when `res_body_shm_path` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub res_body_shm_size_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponseMeta {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}
