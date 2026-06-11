#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) mod passthrough;
#[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
pub(crate) mod passthrough;
#[cfg(all(
    feature = "http3",
    not(any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        feature = "http3-backend-qpx"
    ))
))]
mod passthrough_invalid;
#[cfg(all(
    feature = "http3",
    not(any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        feature = "http3-backend-qpx"
    ))
))]
pub(crate) mod passthrough {
    pub(crate) use super::passthrough_invalid::*;
}

#[cfg(feature = "http3")]
mod streaming;

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) mod terminate;
#[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
mod terminate_qpx;
#[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
pub(crate) mod terminate {
    pub(crate) use super::terminate_qpx::*;
}
#[cfg(all(
    feature = "http3",
    not(any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        feature = "http3-backend-qpx"
    ))
))]
mod terminate_invalid;
#[cfg(all(
    feature = "http3",
    not(any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        feature = "http3-backend-qpx"
    ))
))]
pub(crate) mod terminate {
    pub(crate) use super::terminate_invalid::*;
}
