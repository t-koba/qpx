use bytes::Bytes;
use metrics::{counter, histogram};
use std::time::Duration;

pub(super) fn record_slot_wait(duration: Duration) {
    histogram!("qpx_response_compression_slot_wait_seconds").record(duration.as_secs_f64());
}

pub(super) fn record_compression_job(kind: &'static str, chunks: usize, input_bytes: usize) {
    counter!("qpx_response_compression_jobs_total", "kind" => kind).increment(1);
    histogram!("qpx_response_compression_job_chunks", "kind" => kind).record(chunks as f64);
    histogram!("qpx_response_compression_input_bytes", "kind" => kind).record(input_bytes as f64);
}

pub(super) fn record_compression_output(kind: &'static str, chunks: &[Bytes]) {
    for chunk in chunks {
        record_compression_output_bytes(kind, chunk.len());
    }
}

pub(super) fn record_compression_output_bytes(kind: &'static str, bytes: usize) {
    counter!("qpx_response_compression_output_bytes_total", "kind" => kind).increment(bytes as u64);
    histogram!("qpx_response_compression_output_chunk_bytes", "kind" => kind).record(bytes as f64);
}

pub(super) fn record_compression_error(kind: &'static str) {
    counter!("qpx_response_compression_errors_total", "kind" => kind).increment(1);
}
