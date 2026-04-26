#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SidecarControl {
    #[default]
    Running,
    Stop,
    ExportForUpgrade,
}

impl SidecarControl {
    pub(crate) fn should_stop(self) -> bool {
        !matches!(self, Self::Running)
    }

    #[cfg(feature = "http3")]
    pub(crate) fn should_export(self) -> bool {
        matches!(self, Self::ExportForUpgrade)
    }
}
