use crate::protocol::QPACK_DECOMPRESSION_FAILED;

#[derive(Debug)]
pub(super) enum FieldDecodeError {
    MissingRefs(usize),
    DecompressionFailed(String),
}

impl FieldDecodeError {
    pub(super) fn decompression_failed(message: impl Into<String>) -> Self {
        Self::DecompressionFailed(message.into())
    }
}

impl From<anyhow::Error> for FieldDecodeError {
    fn from(error: anyhow::Error) -> Self {
        Self::DecompressionFailed(error.to_string())
    }
}

#[derive(Debug)]
pub(crate) enum HeaderDecodeError {
    Qpack(String),
    Message(String),
}

impl HeaderDecodeError {
    pub(super) fn qpack(message: impl Into<String>) -> Self {
        Self::Qpack(message.into())
    }

    pub(crate) fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub(crate) fn code(&self) -> u64 {
        match self {
            Self::Qpack(_) => QPACK_DECOMPRESSION_FAILED,
            Self::Message(_) => crate::protocol::H3_MESSAGE_ERROR,
        }
    }
}

impl std::fmt::Display for HeaderDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Qpack(message) | Self::Message(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for HeaderDecodeError {}
