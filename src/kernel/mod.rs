use std::net::SocketAddr;

pub mod bsd;
pub mod linux;

#[derive(Debug)]
pub enum LookupError {
    Io(std::io::Error),
    Unsupported,
}

pub trait UidLookup {
    fn lookup_uid(&self, local: SocketAddr, remote: SocketAddr) -> Result<Option<u32>, LookupError>;
}

pub struct UnsupportedLookup;

impl UidLookup for UnsupportedLookup {
    fn lookup_uid(&self, _local: SocketAddr, _remote: SocketAddr) -> Result<Option<u32>, LookupError> {
        Err(LookupError::Unsupported)
    }
}
