use std::net::SocketAddr;

pub use self::tcp::IpStackTcpStream;
pub use self::udp::IpStackUdpStream;

mod tcb;
mod tcp;
mod udp;

pub enum IpStackStream {
    Tcp(IpStackTcpStream),
    Udp(IpStackUdpStream),
}

impl IpStackStream {
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            IpStackStream::Tcp(tcp) => tcp.local_addr(),
            IpStackStream::Udp(udp) => udp.local_addr(),
        }
    }
    pub fn peer_addr(&self) -> SocketAddr {
        match self {
            IpStackStream::Tcp(tcp) => tcp.peer_addr(),
            IpStackStream::Udp(udp) => udp.peer_addr(),
        }
    }
}
