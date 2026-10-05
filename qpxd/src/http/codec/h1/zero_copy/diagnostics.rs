use std::io;
use std::os::fd::RawFd;

pub(super) struct SpliceTransferCounters {
    planned_bytes: u64,
    socket_batch_limit: usize,
    pipe_capacity: usize,
    source_batches: u64,
    destination_batches: u64,
    source_bytes: u64,
    destination_bytes: u64,
    source_max_batch: usize,
    destination_max_batch: usize,
    source_batches_over_socket_limit: u64,
    destination_short_batches: u64,
    source_would_block: u64,
    destination_would_block: u64,
}

impl SpliceTransferCounters {
    pub(super) fn begin(
        read_fd: RawFd,
        planned_bytes: u64,
        socket_batch_limit: usize,
    ) -> io::Result<Option<Box<Self>>> {
        if !tracing::enabled!(target: "qpx_perf_splice", tracing::Level::DEBUG) {
            return Ok(None);
        }
        // SAFETY: read_fd is the owned live pipe endpoint used by this transfer.
        let capacity = unsafe { libc::fcntl(read_fd, libc::F_GETPIPE_SZ) };
        if capacity < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Box::new(Self {
            planned_bytes,
            socket_batch_limit,
            pipe_capacity: capacity as usize,
            source_batches: 0,
            destination_batches: 0,
            source_bytes: 0,
            destination_bytes: 0,
            source_max_batch: 0,
            destination_max_batch: 0,
            source_batches_over_socket_limit: 0,
            destination_short_batches: 0,
            source_would_block: 0,
            destination_would_block: 0,
        })))
    }

    pub(super) fn read(&mut self, bytes: usize) {
        self.source_batches += 1;
        self.source_bytes += bytes as u64;
        self.source_max_batch = self.source_max_batch.max(bytes);
        self.source_batches_over_socket_limit += u64::from(bytes > self.socket_batch_limit);
    }

    pub(super) fn write(&mut self, bytes: usize) {
        self.destination_batches += 1;
        self.destination_bytes += bytes as u64;
        self.destination_max_batch = self.destination_max_batch.max(bytes);
        self.destination_short_batches += u64::from(bytes < self.socket_batch_limit);
    }

    pub(super) fn source_pending(&mut self) {
        self.source_would_block += 1;
    }

    pub(super) fn destination_pending(&mut self) {
        self.destination_would_block += 1;
    }
}

impl Drop for SpliceTransferCounters {
    fn drop(&mut self) {
        tracing::debug!(target: "qpx_perf_splice",
            planned_bytes = self.planned_bytes,
            completed = self.source_bytes == self.planned_bytes
                && self.destination_bytes == self.planned_bytes,
            pipe_capacity = self.pipe_capacity,
            socket_batch_limit = self.socket_batch_limit,
            source_batches = self.source_batches,
            destination_batches = self.destination_batches,
            source_bytes = self.source_bytes,
            destination_bytes = self.destination_bytes,
            source_max_batch = self.source_max_batch,
            destination_max_batch = self.destination_max_batch,
            source_batches_over_socket_limit = self.source_batches_over_socket_limit,
            destination_short_batches = self.destination_short_batches,
            source_would_block = self.source_would_block,
            destination_would_block = self.destination_would_block,
            "splice transfer counters completed");
    }
}
