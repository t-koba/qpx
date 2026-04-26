#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use qpx_core::shm_ring::ShmRingBuffer;
use std::collections::VecDeque;
use tempfile::NamedTempFile;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    extra_capacity: u16,
    ops: Vec<FuzzOp>,
}

#[derive(Arbitrary, Debug)]
enum FuzzOp {
    Push(Vec<u8>),
    Pop,
    Reopen,
}

fuzz_target!(|input: FuzzInput| {
    let temp = match NamedTempFile::new() {
        Ok(file) => file,
        Err(_) => return,
    };
    let size = 256usize + usize::from(input.extra_capacity % 4096);
    let path = temp.path().to_path_buf();
    let mut ring = match ShmRingBuffer::create_or_open(&path, size) {
        Ok(ring) => ring,
        Err(_) => return,
    };
    let mut model = VecDeque::new();

    for op in input.ops.into_iter().take(256) {
        match op {
            FuzzOp::Push(mut data) => {
                if data.len() > 1024 {
                    data.truncate(1024);
                }
                match ring.try_push(&data) {
                    Ok(true) => model.push_back(data),
                    Ok(false) | Err(_) => {}
                }
            }
            FuzzOp::Pop => match ring.try_pop() {
                Ok(Some(actual)) => {
                    if let Some(expected) = model.pop_front() {
                        assert_eq!(actual, expected);
                    }
                }
                Ok(None) => {
                    assert!(model.is_empty());
                }
                Err(_) => {}
            },
            FuzzOp::Reopen => {
                drop(ring);
                ring = match ShmRingBuffer::create_or_open(&path, size) {
                    Ok(ring) => ring,
                    Err(_) => return,
                };
            }
        }
    }
});
