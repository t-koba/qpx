#[cfg(windows)]
mod imp;
#[cfg(not(windows))]
mod stub;

#[cfg(windows)]
pub(crate) use imp::*;
#[cfg(not(windows))]
pub(crate) use stub::*;
