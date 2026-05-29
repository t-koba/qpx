use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use qpxd::module_api::Body;
use std::io::Write;
use tokio::runtime::Runtime;

fn bench_h3_streaming_throughput(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("h3_streaming_throughput");
    for chunk_size in [1024usize, 64 * 1024, 1024 * 1024] {
        let chunks = (16 * 1024 * 1024 / chunk_size).max(1);
        group.throughput(Throughput::Bytes((chunk_size * chunks) as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_size),
            &chunk_size,
            |bench, &chunk_size| {
                bench.to_async(&runtime).iter(|| async move {
                    relay_body_chunks(chunk_size, chunks, 16).await;
                });
            },
        );
    }
    group.finish();
}

fn bench_body_channel_backpressure(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("body_channel_backpressure");
    for capacity in [4usize, 16, 64, 256] {
        group.throughput(Throughput::Bytes(4 * 1024 * 1024));
        group.bench_with_input(
            BenchmarkId::new("capacity", capacity),
            &capacity,
            |bench, &capacity| {
                bench.to_async(&runtime).iter(|| async move {
                    relay_body_chunks(1024, 4096, capacity).await;
                });
            },
        );
    }
    group.finish();
}

fn bench_grpc_frame_observer_overhead(c: &mut Criterion) {
    let payload = build_grpc_frame(&vec![b'x'; 1024]);
    c.bench_function("grpc_frame_observer_overhead", |bench| {
        bench.iter(|| {
            feed_grpc_frame_observer(&payload, 128).expect("grpc observer");
        });
    });
}

fn bench_compression_streaming_throughput(c: &mut Criterion) {
    let payload = vec![b'a'; 1024 * 1024];
    let mut group = c.benchmark_group("compression_streaming_throughput");
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function("gzip", |bench| {
        bench.iter(|| {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(&payload).expect("gzip write");
            encoder.finish().expect("gzip finish");
        });
    });
    group.bench_function("brotli", |bench| {
        bench.iter(|| {
            let mut out = Vec::new();
            {
                let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 3, 22);
                writer.write_all(&payload).expect("brotli write");
            }
            out
        });
    });
    group.bench_function("zstd", |bench| {
        bench.iter(|| {
            zstd::stream::encode_all(payload.as_slice(), 1).expect("zstd encode");
        });
    });
    group.finish();
}

fn bench_sse_event_observer_overhead(c: &mut Criterion) {
    let payload = b"id: 1\ndata: hello\n\nid: 2\ndata: world\n\n";
    c.bench_function("sse_event_observer_overhead", |bench| {
        bench.iter(|| {
            feed_sse_event_observer(payload, 256);
        });
    });
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
fn feed_grpc_frame_observer(payload: &[u8], iterations: usize) -> anyhow::Result<usize> {
    qpxd::bench_support::feed_grpc_frame_observer(payload, iterations)
}

#[cfg(not(any(feature = "http3-backend-h3", feature = "http3-backend-qpx")))]
fn feed_grpc_frame_observer(_payload: &[u8], _iterations: usize) -> anyhow::Result<usize> {
    Ok(0)
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
fn feed_sse_event_observer(payload: &[u8], iterations: usize) -> u64 {
    qpxd::bench_support::feed_sse_event_observer(payload, iterations)
}

#[cfg(not(any(feature = "http3-backend-h3", feature = "http3-backend-qpx")))]
fn feed_sse_event_observer(_payload: &[u8], _iterations: usize) -> u64 {
    0
}

fn bench_notify_latency(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    c.bench_function("notify_latency", |bench| {
        bench.to_async(&runtime).iter(|| async {
            let (sender, mut body) = Body::channel_with_capacity(1);
            drop(sender);
            let _ = body.data().await;
        });
    });
}

async fn relay_body_chunks(chunk_size: usize, chunks: usize, capacity: usize) {
    let (mut sender, mut body) = Body::channel_with_capacity(capacity);
    let payload = Bytes::from(vec![0u8; chunk_size]);
    let producer = tokio::spawn(async move {
        for _ in 0..chunks {
            sender.send_data(payload.clone()).await.expect("send");
        }
    });
    while let Some(chunk) = body.data().await {
        let _ = chunk.expect("chunk");
    }
    producer.await.expect("producer");
}

fn build_grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

criterion_group!(
    streaming,
    bench_h3_streaming_throughput,
    bench_body_channel_backpressure,
    bench_grpc_frame_observer_overhead,
    bench_compression_streaming_throughput,
    bench_sse_event_observer_overhead,
    bench_notify_latency
);
criterion_main!(streaming);
