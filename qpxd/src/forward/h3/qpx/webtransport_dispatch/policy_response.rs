use super::super::response::{QpxPolicyResponseContext, send_qpx_policy_response};
use anyhow::Result;
use hyper::Response;
use qpx_observability::access_log::RequestLogContext;

pub(super) struct WebTransportPolicyResponder<'a> {
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) listener_name: &'a str,
    pub(super) conn: &'a qpx_h3::ConnectionInfo,
    pub(super) host: &'a str,
    pub(super) path: Option<&'a str>,
}

impl WebTransportPolicyResponder<'_> {
    pub(super) async fn send(
        &self,
        req_stream: &mut qpx_h3::RequestStream,
        response: Response<qpx_http::body::Body>,
        outcome: crate::http::dispatch::DispatchOutcome,
        matched_rule: Option<&str>,
        ext_authz_policy_id: Option<&str>,
        log_context: &RequestLogContext,
    ) -> Result<()> {
        send_qpx_policy_response(
            req_stream,
            response,
            QpxPolicyResponseContext {
                state: self.state,
                listener_name: self.listener_name,
                conn: self.conn,
                host: self.host,
                path: self.path,
                outcome,
                matched_rule,
                ext_authz_policy_id,
                log_context,
            },
        )
        .await
    }
}
