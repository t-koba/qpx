use super::InterimResponseHead;
use anyhow::{Result, anyhow};
use tokio::sync::mpsc::Sender;

/// Incremental mode transfers heads to the listener, never to the relay's Vec.
/// The bounded channel applies backpressure without introducing another writer.
pub(crate) struct InterimResponseSink {
    sender: Sender<InterimResponseHead>,
    sent: bool,
    discard: bool,
}

impl InterimResponseSink {
    pub(crate) fn new(sender: Sender<InterimResponseHead>) -> Self {
        Self {
            sender,
            sent: false,
            discard: false,
        }
    }

    pub(crate) async fn send(&mut self, head: InterimResponseHead) -> Result<()> {
        if !self.discard {
            self.sender
                .send(head)
                .await
                .map_err(|_| anyhow!("HTTP/1 interim receiver closed"))?;
            self.sent = true;
        }
        Ok(())
    }

    /// Preserve the stale-connection retry for the final response. If the first
    /// attempt published any informational heads, suppress ALL retry interim so
    /// they cannot duplicate or reorder the already published sequence.
    pub(crate) fn retry(&mut self) {
        self.discard = self.sent;
    }
}
