//! Temporary spool files that remove themselves when released.

use crate::body::metrics;
use std::path::{Path, PathBuf};

/// A temporary spool file that is removed when the guard is released.
///
/// The guard owns the path from the moment the file is created, so every
/// failure path - an over-limit chunk, a read or trailer timeout, a write or
/// flush error, cancellation - removes the file. A caller that keeps the file
/// for later use keeps this guard instead of the bare path, and the file is
/// removed when that guard is released.
#[derive(Debug)]
pub struct SpoolFile<H> {
    handle: Option<H>,
    path: PathBuf,
    direction: &'static str,
    site: &'static str,
}

impl<H> SpoolFile<H> {
    /// Takes ownership of a spool file and of the handle that writes it.
    ///
    /// `direction` and `site` label the cleanup-failure metric, so a removal
    /// that fails is attributable both to the side of the exchange the spooled
    /// body came from and to the spool it belongs to.
    pub fn new(handle: H, path: PathBuf, direction: &'static str, site: &'static str) -> Self {
        Self {
            handle: Some(handle),
            path,
            direction,
            site,
        }
    }

    /// The path of the spool file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The handle that writes the spool file.
    pub fn handle(&self) -> &H {
        self.handle.as_ref().expect("the spool file handle is open")
    }

    /// The handle that writes the spool file, mutably.
    pub fn handle_mut(&mut self) -> &mut H {
        self.handle.as_mut().expect("the spool file handle is open")
    }

    /// Closes the handle and keeps the path, so the file stays available for
    /// later use while the guard still removes it when it is released.
    pub fn close(&mut self) {
        self.handle = None;
    }
}

impl<H> Drop for SpoolFile<H> {
    fn drop(&mut self) {
        // The handle is closed before the path is removed, so the removal
        // also works on platforms that refuse to unlink an open file.
        drop(self.handle.take());
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => metrics::spool_cleanup_error(self.direction, self.site),
        }
    }
}

#[cfg(test)]
mod tests;
