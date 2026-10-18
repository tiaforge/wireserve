//! Stand-ins where there are no abstract sockets: every claim succeeds
//! and nobody else ever holds one, which is what a single agent per host
//! amounts to.

use crate::lock::Holder;

#[derive(Debug)]
pub struct IfnameClaim {
    ifname: String,
}

impl IfnameClaim {
    pub fn take(ifname: &str) -> std::io::Result<Result<Self, Holder>> {
        Ok(Ok(Self {
            ifname: ifname.to_string(),
        }))
    }
    #[must_use]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }
    pub fn hold(self) {}
}

#[must_use]
pub fn holder(_ifname: &str) -> Holder {
    Holder::Nobody
}
