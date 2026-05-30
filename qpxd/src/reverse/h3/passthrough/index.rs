mod quic;
mod session;
mod shared;

#[cfg(test)]
mod legacy;

pub(super) use quic::QuicConnectionId;
#[cfg(test)]
pub(super) use quic::{parse_quic_long_header, parse_quic_short_dcid};
#[cfg(test)]
pub(super) use session::should_queue_touch_at;
pub(super) use session::{PassthroughSession, SessionTouch};

#[cfg(test)]
pub(super) use legacy::SessionIndex;
pub(super) use shared::SharedSessionIndex;
