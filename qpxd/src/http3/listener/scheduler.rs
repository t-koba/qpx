use std::collections::VecDeque;
use std::sync::Arc;

use tokio::sync::{Semaphore, mpsc};

use super::{
    H3ConnInfo, H3Limits, H3RequestHandler, H3ServerRequestStream, H3StreamDatagrams, handle_stream,
};
use crate::http3::datagram::DatagramRegistration;

pub(super) struct ScheduledH3Stream {
    pub(super) req_head: ::http::Request<()>,
    pub(super) req_stream: H3ServerRequestStream,
    pub(super) datagrams: Option<H3StreamDatagrams>,
    pub(super) disabled_datagram_registration: Option<DatagramRegistration>,
    pub(super) priority: crate::http3::priority::StreamPriority,
}

pub(super) async fn run_priority_scheduler<H: H3RequestHandler>(
    mut rx: mpsc::Receiver<ScheduledH3Stream>,
    stream_semaphore: Arc<Semaphore>,
    handler: H,
    conn_info: H3ConnInfo,
    limits: H3Limits,
) {
    let mut scheduler = PriorityScheduler::new();
    let mut closed = false;
    loop {
        while let Ok(task) = rx.try_recv() {
            let priority = task.priority;
            scheduler.enqueue(task, priority);
        }
        if let Some(task) = scheduler.next_task() {
            let permit = match stream_semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => break,
            };
            let handler = handler.clone();
            let conn_info = conn_info.clone();
            let limits = limits.clone();
            tokio::spawn(async move {
                let _permit = permit;
                handle_stream(
                    task.req_head,
                    task.req_stream,
                    conn_info,
                    handler,
                    limits,
                    task.datagrams,
                    task.disabled_datagram_registration,
                )
                .await;
            });
            continue;
        }
        if closed {
            break;
        }
        match rx.recv().await {
            Some(task) => {
                let priority = task.priority;
                scheduler.enqueue(task, priority);
            }
            None => closed = true,
        }
    }
}

pub(super) struct PriorityScheduler<T> {
    queues: [PriorityQueues<T>; 8],
}

struct PriorityQueues<T> {
    non_incremental: VecDeque<T>,
    incremental: VecDeque<T>,
}

impl<T> PriorityQueues<T> {
    pub(super) fn new() -> Self {
        Self {
            non_incremental: VecDeque::new(),
            incremental: VecDeque::new(),
        }
    }
}

impl<T> PriorityScheduler<T> {
    pub(super) fn new() -> Self {
        Self {
            queues: std::array::from_fn(|_| PriorityQueues::new()),
        }
    }

    pub(super) fn enqueue(&mut self, task: T, priority: crate::http3::priority::StreamPriority) {
        let queue = &mut self.queues[priority.urgency as usize];
        if priority.incremental {
            queue.incremental.push_back(task);
        } else {
            queue.non_incremental.push_back(task);
        }
    }

    pub(super) fn next_task(&mut self) -> Option<T> {
        for queue in &mut self.queues {
            if let Some(task) = queue.non_incremental.pop_front() {
                return Some(task);
            }
            if let Some(task) = queue.incremental.pop_front() {
                return Some(task);
            }
        }
        None
    }
}

pub(super) fn request_priority(
    headers: &::http::HeaderMap,
) -> crate::http3::priority::StreamPriority {
    headers
        .get("priority")
        .and_then(|value| value.to_str().ok())
        .map(crate::http3::priority::parse_priority)
        .unwrap_or_default()
}
