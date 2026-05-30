use crate::http::body::{Body, Sender};
use bytes::Bytes;
use metrics::counter;
#[cfg(test)]
use tokio::time::{Duration, timeout};

#[cfg(test)]
const MIRROR_BACKPRESSURE_TIMEOUT: Duration = Duration::from_millis(25);

#[cfg(test)]
pub(crate) fn tee_body(
    source: Body,
    mirror_limits: Vec<Option<usize>>,
    capacity: usize,
) -> (Body, Vec<Body>) {
    tee_body_with_backpressure(source, mirror_limits, capacity, MIRROR_BACKPRESSURE_TIMEOUT)
}

#[cfg(test)]
pub(crate) fn tee_body_with_backpressure(
    mut source: Body,
    mirror_limits: Vec<Option<usize>>,
    capacity: usize,
    mirror_backpressure_timeout: Duration,
) -> (Body, Vec<Body>) {
    tee_body_inner(
        &mut source,
        mirror_limits,
        capacity,
        MirrorBackpressure::Timeout(mirror_backpressure_timeout),
        None,
    )
}

#[cfg(test)]
pub(crate) fn tee_body_lossy(
    source: Body,
    mirror_limits: Vec<Option<usize>>,
    capacity: usize,
) -> (Body, Vec<Body>) {
    tee_body_lossy_with_metrics(source, mirror_limits, capacity, None)
}

pub(crate) fn tee_body_lossy_with_metrics(
    mut source: Body,
    mirror_limits: Vec<Option<usize>>,
    capacity: usize,
    drop_metric_label: Option<&'static str>,
) -> (Body, Vec<Body>) {
    tee_body_inner(
        &mut source,
        mirror_limits,
        capacity,
        MirrorBackpressure::DropOnFull,
        drop_metric_label,
    )
}

fn tee_body_inner(
    source: &mut Body,
    mirror_limits: Vec<Option<usize>>,
    capacity: usize,
    backpressure: MirrorBackpressure,
    drop_metric_label: Option<&'static str>,
) -> (Body, Vec<Body>) {
    let mirror_count = mirror_limits.len();
    if mirror_count == 0 {
        return (std::mem::take(source), Vec::new());
    }

    let (primary_sender, primary_body) = Body::channel_with_capacity(capacity.max(1));
    let mut mirror_senders = Vec::with_capacity(mirror_count);
    let mut mirror_bodies = Vec::with_capacity(mirror_count);
    for limit in mirror_limits {
        let (sender, body) = Body::channel_with_capacity(capacity.max(1));
        mirror_senders.push(MirrorSender {
            sender,
            bytes_sent: 0,
            max_body_bytes: limit,
            active: true,
        });
        mirror_bodies.push(body);
    }

    let mut source = std::mem::take(source);
    tokio::spawn(async move {
        copy_tee_body(
            &mut source,
            primary_sender,
            mirror_senders,
            backpressure,
            drop_metric_label,
        )
        .await;
    });
    (primary_body, mirror_bodies)
}

#[derive(Clone, Copy)]
enum MirrorBackpressure {
    #[cfg(test)]
    Timeout(Duration),
    DropOnFull,
}

struct MirrorSender {
    sender: Sender,
    bytes_sent: usize,
    max_body_bytes: Option<usize>,
    active: bool,
}

async fn copy_tee_body(
    source: &mut Body,
    mut primary_sender: Sender,
    mut mirror_senders: Vec<MirrorSender>,
    backpressure: MirrorBackpressure,
    drop_metric_label: Option<&'static str>,
) {
    while let Some(chunk) = source.data().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => {
                primary_sender.abort();
                abort_mirrors(&mut mirror_senders, drop_metric_label, "source_error");
                return;
            }
        };
        if primary_sender.send_data(chunk.clone()).await.is_err() {
            abort_mirrors(&mut mirror_senders, drop_metric_label, "primary_closed");
            return;
        }
        send_to_mirrors(&mut mirror_senders, &chunk, backpressure, drop_metric_label).await;
    }

    match source.trailers().await {
        Ok(Some(trailers)) => {
            for mirror in &mut mirror_senders {
                if !mirror.active {
                    continue;
                }
                let sent = match backpressure {
                    #[cfg(test)]
                    MirrorBackpressure::Timeout(duration) => {
                        matches!(
                            timeout(duration, mirror.sender.send_trailers(trailers.clone())).await,
                            Ok(Ok(()))
                        )
                    }
                    MirrorBackpressure::DropOnFull => {
                        mirror.sender.try_send_trailers(trailers.clone()).is_ok()
                    }
                };
                if !sent {
                    deactivate_mirror(mirror, drop_metric_label, "trailers_backpressure");
                }
            }
            let _ = primary_sender.send_trailers(trailers).await;
        }
        Ok(None) => {}
        Err(_) => {
            primary_sender.abort();
            abort_mirrors(&mut mirror_senders, drop_metric_label, "trailers_error");
        }
    }
}

async fn send_to_mirrors(
    mirror_senders: &mut [MirrorSender],
    chunk: &Bytes,
    backpressure: MirrorBackpressure,
    drop_metric_label: Option<&'static str>,
) {
    for mirror in mirror_senders {
        if !mirror.active {
            continue;
        }
        let next = mirror.bytes_sent.saturating_add(chunk.len());
        if mirror.max_body_bytes.is_some_and(|limit| next > limit) {
            deactivate_mirror(mirror, drop_metric_label, "limit");
            continue;
        }
        let sent = match backpressure {
            #[cfg(test)]
            MirrorBackpressure::Timeout(duration) => {
                matches!(
                    timeout(duration, mirror.sender.send_data(chunk.clone())).await,
                    Ok(Ok(()))
                )
            }
            MirrorBackpressure::DropOnFull => mirror.sender.try_send_data(chunk.clone()).is_ok(),
        };
        if !sent {
            deactivate_mirror(mirror, drop_metric_label, "backpressure");
            continue;
        }
        mirror.bytes_sent = next;
    }
}

fn deactivate_mirror(
    mirror: &mut MirrorSender,
    drop_metric_label: Option<&'static str>,
    reason: &'static str,
) {
    if let Some(label) = drop_metric_label {
        counter!(
            "qpx_body_mirror_drops_total",
            "mirror" => label,
            "reason" => reason,
        )
        .increment(1);
    }
    mirror.sender.abort();
    mirror.active = false;
}

fn abort_mirrors(
    mirror_senders: &mut [MirrorSender],
    drop_metric_label: Option<&'static str>,
    reason: &'static str,
) {
    for mirror in mirror_senders {
        if mirror.active {
            deactivate_mirror(mirror, drop_metric_label, reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::http::body::tee::*;
    use crate::http::body::to_bytes;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn mirror_streaming_tee_body_replays_source_to_primary_and_mirror() {
        let (mut primary, mut mirrors) = tee_body(Body::from("abcdef"), vec![None], 4);
        let mirror = mirrors.pop().expect("mirror");

        let primary_bytes = to_bytes(&mut primary).await.expect("primary");
        let mirror_bytes = to_bytes(mirror).await.expect("mirror");

        assert_eq!(primary_bytes.as_ref(), b"abcdef");
        assert_eq!(mirror_bytes.as_ref(), b"abcdef");
    }

    #[tokio::test]
    async fn mirror_limit_drops_mirror_without_blocking_primary() {
        let (mut primary, mut mirrors) = tee_body(Body::from("abcdef"), vec![Some(3)], 1);
        let mut mirror = mirrors.pop().expect("mirror");

        let primary_bytes = timeout(Duration::from_secs(1), to_bytes(&mut primary))
            .await
            .expect("primary timeout")
            .expect("primary");
        assert_eq!(primary_bytes.as_ref(), b"abcdef");
        assert!(to_bytes(&mut mirror).await.is_err());
    }

    #[tokio::test]
    async fn lossy_mirror_drops_full_mirror_without_blocking_primary() {
        let source = Body::replay_chunks(
            vec![
                Bytes::from_static(b"ab"),
                Bytes::from_static(b"cd"),
                Bytes::from_static(b"ef"),
            ],
            None,
        );
        let (mut primary, mut mirrors) = tee_body_lossy(source, vec![None], 1);
        let mut mirror = mirrors.pop().expect("mirror");

        let primary_bytes = timeout(Duration::from_secs(1), to_bytes(&mut primary))
            .await
            .expect("primary timeout")
            .expect("primary");
        assert_eq!(primary_bytes.as_ref(), b"abcdef");
        assert!(to_bytes(&mut mirror).await.is_err());
    }

    #[tokio::test]
    async fn backpressure_mirror_waits_for_reader_instead_of_dropping() {
        let source = Body::replay_chunks(
            vec![
                Bytes::from_static(b"ab"),
                Bytes::from_static(b"cd"),
                Bytes::from_static(b"ef"),
            ],
            None,
        );
        let (mut primary, mut mirrors) =
            tee_body_with_backpressure(source, vec![None], 1, Duration::from_secs(1));
        let mut mirror = mirrors.pop().expect("mirror");
        let mirror_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            to_bytes(&mut mirror).await
        });

        let primary_bytes = timeout(Duration::from_secs(1), to_bytes(&mut primary))
            .await
            .expect("primary timeout")
            .expect("primary");
        let mirror_bytes = mirror_task
            .await
            .expect("mirror task")
            .expect("mirror should stay active");

        assert_eq!(primary_bytes.as_ref(), b"abcdef");
        assert_eq!(mirror_bytes.as_ref(), b"abcdef");
    }
}
