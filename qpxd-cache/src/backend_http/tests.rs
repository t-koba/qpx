use super::body::collect_body_limited;
use super::*;

#[tokio::test]
async fn collect_body_limited_rejects_large_payload() {
    let err = collect_body_limited(Body::from(vec![0_u8; 5]), 4)
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("payload too large"));
}
