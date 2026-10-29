use super::*;
use crate::http::dispatch::{DispatchOutcome, ProxyKind};
use crate::http::local_response::build_local_response;
use crate::http::modules::HttpModuleExecution;
use bytes::Bytes;
use http::{HeaderValue, StatusCode, Version};
use http_body_util::BodyExt as _;
use qpx_core::config::{HeaderControl, LocalResponseConfig};
use qpx_core::http_message::OrdinaryHeaderName;

#[tokio::test]
async fn local_response_policy_output_is_owned_and_preserves_finalization_and_streams() {
    let headers = Arc::new(
        CompiledHeaderControl::compile(&HeaderControl {
            response_set: [("x-policy".into(), "applied".into())].into(),
            ..Default::default()
        })
        .unwrap(),
    );
    for (method, status, abort) in [
        (Method::GET, 202, false),
        (Method::GET, 202, true),
        (Method::HEAD, 202, false),
        (Method::GET, 204, false),
    ] {
        let mut response = build_local_response(&LocalResponseConfig {
            status,
            body: "payload".into(),
            content_type: Some("text/plain".into()),
            headers: [("content-length".into(), "0007".into())].into(),
            rpc: None,
        })
        .unwrap();
        response.extensions_mut().insert(42_usize);
        response
            .headers_mut()
            .append("x-duplicate", HeaderValue::from_static("first"));
        let mut sensitive = HeaderValue::from_bytes(b"\x80last").unwrap();
        sensitive.set_sensitive(true);
        response.headers_mut().append("x-duplicate", sensitive);
        // Finalization must still remove Connection-nominated fields.
        response
            .headers_mut()
            .insert("connection", HeaderValue::from_static("x-hop"));
        response
            .headers_mut()
            .insert("x-hop", HeaderValue::from_static("remove"));
        *response.body_mut() = if abort {
            let (mut sender, body) = Body::channel();
            sender.abort();
            body
        } else {
            let mut trailers = http::HeaderMap::new();
            trailers.append("x-trailer", HeaderValue::from_static("one"));
            trailers.append("x-trailer", HeaderValue::from_static("two"));
            trailers.insert("connection", HeaderValue::from_static("remove"));
            Body::replay_chunks(vec![Bytes::from_static(b"payload")], Some(trailers))
        };
        let audit = DispatchAuditContext::new(
            None,
            ProxyKind::Forward,
            None,
            "127.0.0.1:1234".parse().unwrap(),
            method.clone(),
            None,
            Default::default(),
        );
        let mut modules = HttpModuleExecution::Empty;
        let outcome = ListenerResponsePolicyDecision::LocalResponse {
            response,
            headers: Some(headers.clone()),
            policy_tags: vec!["local".into()],
        }
        .apply_dispatch_transform(DispatchResponseTransformContext {
            http_modules: &mut modules,
            audit: &audit,
            local_response_outcome: DispatchOutcome::ResponseLocalResponse,
            request_method: &method,
            request_version: Version::HTTP_11,
            proxy_name: "qpx-test",
        })
        .await
        .unwrap();
        let DispatchResponsePolicyOutcome::Response(mut response) = outcome else {
            panic!("expected owned local response");
        };
        // This type assertion also guards against moving the import back to callers.
        let _: &OwnerResponse<Body> = &response;
        assert_eq!(response.status(), StatusCode::from_u16(status).unwrap());
        assert_eq!(response.extensions().get::<usize>(), Some(&42));
        assert_eq!(
            response
                .headers()
                .get(&OrdinaryHeaderName::try_from("x-policy").unwrap())
                .unwrap(),
            "applied"
        );
        assert_eq!(
            response
                .headers()
                .get(&OrdinaryHeaderName::try_from("via").unwrap())
                .unwrap(),
            "1.1 qpx-test"
        );
        assert!(
            response
                .headers()
                .get(&OrdinaryHeaderName::try_from("date").unwrap())
                .is_some()
        );
        assert!(
            !response
                .headers()
                .contains_key(&OrdinaryHeaderName::try_from("x-hop").unwrap())
        );
        let duplicates = response
            .headers()
            .get_all(&OrdinaryHeaderName::try_from("x-duplicate").unwrap())
            .collect::<Vec<_>>();
        assert_eq!(duplicates.len(), 2);
        assert_eq!(duplicates[0], "first");
        assert_eq!(duplicates[1].as_bytes(), b"\x80last");
        assert!(duplicates[1].is_sensitive());
        if method == Method::HEAD || status == 204 {
            assert!(response.body_mut().frame().await.is_none());
            assert_eq!(
                response.headers().declared_content_length().unwrap(),
                if method == Method::HEAD {
                    Some(7)
                } else {
                    None
                }
            );
        } else if abort {
            assert_eq!(
                response
                    .body_mut()
                    .frame()
                    .await
                    .unwrap()
                    .unwrap_err()
                    .to_string(),
                "body aborted"
            );
        } else {
            assert_eq!(
                response
                    .body_mut()
                    .frame()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_data()
                    .unwrap(),
                "payload"
            );
            let trailers = response
                .body_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap();
            assert_eq!(
                trailers
                    .get_all("x-trailer")
                    .iter()
                    .map(|v| v.as_bytes())
                    .collect::<Vec<_>>(),
                [b"one", b"two"]
            );
            assert!(!trailers.contains_key("connection"));
            assert!(response.body_mut().frame().await.is_none());
        }
    }
}
