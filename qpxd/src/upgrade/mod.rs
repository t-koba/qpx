#[cfg(unix)]
mod unix;
#[cfg(not(any(unix, windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(crate) use unix::*;
#[cfg(not(any(unix, windows)))]
pub(crate) use unsupported::*;
#[cfg(windows)]
pub(crate) use windows::*;
