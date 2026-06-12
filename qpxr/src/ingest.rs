use crate::hub::{ExporterHub, SequenceKey, SequenceState};
use crate::pcap::{Endpoint, encode_enhanced_packet, endpoints_for_event, interface_id};
use anyhow::Result;
use bytes::Bytes;
use etherparse::PacketBuilder;
use qpx_core::exporter::CaptureEvent;
use qpx_core::shm_ring::ShmRingBuffer;
use tokio::sync::mpsc;
use tracing::warn;

pub(crate) async fn run_event_ingest_loop(mut ring: ShmRingBuffer, hub: ExporterHub) -> Result<()> {
    use std::collections::BTreeMap;

    const MAX_ENCODE_WORKERS: usize = 32;
    const WORKER_QUEUE_DEPTH: usize = 256;
    const RESULT_QUEUE_DEPTH: usize = 4096;

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, MAX_ENCODE_WORKERS);

    #[derive(Clone, Copy)]
    struct EncodeJob {
        index: u64,
        interface_id: u32,
        timestamp_unix_nanos: u64,
        src: Endpoint,
        dst: Endpoint,
        sequence_number: u32,
    }

    struct EncodeResult {
        index: u64,
        timestamp_unix_nanos: u64,
        encoded: Option<Bytes>,
    }

    let (res_tx, mut res_rx) = mpsc::channel::<EncodeResult>(RESULT_QUEUE_DEPTH);
    let mut job_txs = Vec::with_capacity(workers);

    for _ in 0..workers {
        let (job_tx, mut job_rx) = mpsc::channel::<(EncodeJob, Bytes)>(WORKER_QUEUE_DEPTH);
        job_txs.push(job_tx);
        let res_tx = res_tx.clone();
        tokio::spawn(async move {
            while let Some((job, payload)) = job_rx.recv().await {
                let builder = PacketBuilder::ipv4(job.src.ip.octets(), job.dst.ip.octets(), 64)
                    .tcp(job.src.port, job.dst.port, job.sequence_number, 1024);
                let mut packet = Vec::with_capacity(payload.len() + 96);
                if builder.write(&mut packet, payload.as_ref()).is_err() {
                    let _ = res_tx
                        .send(EncodeResult {
                            index: job.index,
                            timestamp_unix_nanos: job.timestamp_unix_nanos,
                            encoded: None,
                        })
                        .await;
                    continue;
                }
                let encoded = match encode_enhanced_packet(
                    job.interface_id,
                    job.timestamp_unix_nanos,
                    packet,
                ) {
                    Ok(bytes) => Some(Bytes::from(bytes)),
                    Err(err) => {
                        warn!(error = ?err, "failed to encode enhanced packet");
                        None
                    }
                };
                let _ = res_tx
                    .send(EncodeResult {
                        index: job.index,
                        timestamp_unix_nanos: job.timestamp_unix_nanos,
                        encoded,
                    })
                    .await;
            }
        });
    }
    drop(res_tx);

    let publish_hub = hub.clone();
    let publish_task = tokio::spawn(async move {
        let mut pending: BTreeMap<u64, EncodeResult> = BTreeMap::new();
        let mut next = 0u64;
        while let Some(res) = res_rx.recv().await {
            pending.insert(res.index, res);
            while let Some(res) = pending.remove(&next) {
                if let Some(encoded) = res.encoded {
                    publish_hub
                        .publish_encoded_block(res.timestamp_unix_nanos, encoded)
                        .await;
                }
                next = next.saturating_add(1);
            }
        }
    });

    let mut index = 0u64;
    loop {
        match ring.try_pop() {
            Ok(Some(frame)) => {
                if frame.is_empty() {
                    continue;
                }
                let event = match CaptureEvent::decode_wire(Bytes::from(frame)) {
                    Ok(event) => event,
                    Err(err) => {
                        warn!(error = ?err, "failed to decode capture event frame");
                        continue;
                    }
                };
                if event.payload.len() > hub.max_payload_bytes {
                    warn!(
                        payload_len = event.payload.len(),
                        max_payload_bytes = hub.max_payload_bytes,
                        "payload too large; dropped"
                    );
                    continue;
                }

                let sequence_number = {
                    let seq_key = SequenceKey {
                        session_id: event.session_id.clone(),
                        plane: event.plane.clone(),
                        direction: event.direction.clone(),
                    };
                    let mut state = hub.sequences.lock().await;
                    let seq = state.sequences.entry(seq_key).or_insert(SequenceState {
                        next: 1,
                        last_seen_unix_nanos: event.timestamp_unix_nanos,
                    });
                    let sequence_number = seq.next;
                    seq.next = seq.next.wrapping_add(event.payload.len() as u32);
                    seq.last_seen_unix_nanos = event.timestamp_unix_nanos;
                    hub.gc_sequences_locked(&mut state, event.timestamp_unix_nanos);
                    sequence_number
                };

                let (src, dst) = endpoints_for_event(&event);
                let job = EncodeJob {
                    index,
                    interface_id: interface_id(event.plane.clone()),
                    timestamp_unix_nanos: event.timestamp_unix_nanos,
                    src,
                    dst,
                    sequence_number,
                };
                if job_txs[(index as usize) % job_txs.len()]
                    .send((job, event.payload.clone()))
                    .await
                    .is_err()
                {
                    break;
                }
                index = index.saturating_add(1);
            }
            Ok(None) => {
                ring.wait_for_data().await?;
            }
            Err(e) => {
                warn!(error = ?e, "fatal error reading from shared memory ring buffer");
                break;
            }
        }
    }

    drop(job_txs);
    let _ = publish_task.await;
    Ok(())
}
