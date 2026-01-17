use std::net::SocketAddr;

use super::{LookupError, UidLookup};

#[derive(Debug, Default)]
pub struct BsdLookup;

impl BsdLookup {
    pub fn new() -> Self {
        Self
    }
}

impl UidLookup for BsdLookup {
    fn lookup_uid(&self, _local: SocketAddr, _remote: SocketAddr) -> Result<Option<u32>, LookupError> {
        Err(LookupError::Unsupported)
    }
}
