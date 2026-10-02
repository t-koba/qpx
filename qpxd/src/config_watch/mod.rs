#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::ConfigFileWatcher;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod platform;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) use platform::ConfigFileWatcher;
