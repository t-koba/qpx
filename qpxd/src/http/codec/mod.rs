pub mod h1;
pub mod h1_common;
pub mod h1_request_body;
pub mod h2;
pub(crate) mod header_pool;
pub mod interim;
pub(crate) mod lazy_timeout;

pub(crate) fn is_expected_peer_disconnect(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::is_expected_peer_disconnect;
    use anyhow::Context as _;

    #[test]
    fn classifies_wrapped_peer_disconnects() {
        let error = Err::<(), _>(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "peer closed",
        ))
        .context("response write failed")
        .expect_err("wrapped error");

        assert!(is_expected_peer_disconnect(&error));
    }

    #[test]
    fn does_not_hide_unrelated_io_failures() {
        let error = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));

        assert!(!is_expected_peer_disconnect(&error));
    }
}
