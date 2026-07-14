#[cfg(windows)]
mod imp;
#[cfg(not(windows))]
mod unsupported;

#[cfg(windows)]
pub(crate) use imp::*;
#[cfg(not(windows))]
pub(crate) use unsupported::*;
