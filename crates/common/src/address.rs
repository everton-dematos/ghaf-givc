//use std::net::SocketAddr;
use tokio_vsock::VsockAddr;

#[derive(Clone, Debug, PartialEq)]
pub enum EndpointAddress {
    Tcp {
        // IP + port (FIXME: should be SocketAddres)
        addr: String,
        port: u16,
    },
    Unix(String),     // "/path/to/sock"  (same host only)
    Abstract(String), // "@abstract-socket-name" (same host only)
    Vsock(VsockAddr), // cid+port. FIXME: cid have two magic numbers for host and local
}
