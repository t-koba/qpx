use std::sync::Mutex;

use tokio::task::JoinHandle;

#[derive(Default)]
pub(crate) struct RelayTask(Mutex<Option<JoinHandle<()>>>);

impl RelayTask {
    pub(crate) fn attach(&self, task: JoinHandle<()>) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
    }

    pub(crate) fn take(&self) -> Option<JoinHandle<()>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}
