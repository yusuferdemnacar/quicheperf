use std::time::Duration;

pub struct ProxyUI {}

impl ProxyUI {
    pub fn timeout(&self) -> Duration {
        Duration::MAX
    }
}
