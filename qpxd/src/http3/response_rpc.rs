use crate::http::rpc::{FramedBodySummary, streaming::StreamingRpcObserver};
use anyhow::{Result, anyhow};
use http::HeaderMap;

pub(crate) struct H3ResponseRpcObserver<'a> {
    observer: Option<StreamingRpcObserver>,
    listener_name: Option<&'a str>,
}

impl<'a> H3ResponseRpcObserver<'a> {
    pub(crate) fn new(
        headers: &HeaderMap,
        fallback_protocol: Option<&str>,
        max_message_bytes: Option<u64>,
        max_trailer_bytes: Option<u64>,
        observe_metrics: bool,
        listener_name: Option<&'a str>,
    ) -> Self {
        let observer = if observe_metrics {
            crate::http::rpc::streaming_rpc_observer(
                headers,
                fallback_protocol,
                max_message_bytes,
                max_trailer_bytes,
            )
        } else {
            None
        };
        Self {
            observer,
            listener_name,
        }
    }

    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Result<()> {
        if let Some(observer) = self.observer.as_mut() {
            observer.feed(chunk).map_err(|err| anyhow!(err))?;
        }
        Ok(())
    }

    pub(crate) fn emit_status_without_body(&self, headers: &HeaderMap) {
        if let (Some(listener), Some(observer)) = (self.listener_name, self.observer.as_ref()) {
            crate::http::rpc::emit_grpc_status_metric(listener, observer.protocol(), headers, None);
        }
    }

    pub(crate) fn finish(
        self,
        headers: &HeaderMap,
        trailers_for_status: &mut Option<HeaderMap>,
    ) -> Result<Option<FramedBodySummary>> {
        let Some(observer) = self.observer else {
            return Ok(None);
        };
        let protocol = observer.protocol().to_string();
        let summary = observer.finish().map_err(|err| anyhow!(err))?;
        if trailers_for_status.is_none() {
            *trailers_for_status = summary.trailers().cloned();
        }
        if let Some(listener) = self.listener_name {
            crate::http::rpc::emit_grpc_body_metrics(
                "response",
                listener,
                protocol.as_str(),
                &summary,
            );
            crate::http::rpc::emit_grpc_status_metric(
                listener,
                protocol.as_str(),
                headers,
                trailers_for_status.as_ref(),
            );
        }
        Ok(Some(summary))
    }
}
