mod session;
mod shared;

pub(super) use crate::http3::quic_packet::QuicConnectionId;
#[cfg(test)]
pub(super) use session::should_queue_touch_at;
pub(super) use session::{PassthroughSession, SessionTouch};

pub(super) use shared::SharedSessionIndex;
