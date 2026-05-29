use std::process::Child;

pub struct QpxdHandle {
    child: Child,
}

impl QpxdHandle {
    pub fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for QpxdHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
