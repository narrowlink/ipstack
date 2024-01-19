use std::net::{IpAddr, SocketAddr};

pub use self::raw::RawPacket;
pub use self::tcp::IpStackTcpStream;
pub use self::udp::IpStackUdpStream;

mod raw;
mod tcb;
mod tcp;
mod udp;

pub enum IpStackStream {
    Tcp(IpStackTcpStream),
    Udp(IpStackUdpStream),
    RawPacket(RawPacket),
}

impl IpStackStream {
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            IpStackStream::Tcp(tcp) => tcp.local_addr(),
            IpStackStream::Udp(udp) => udp.local_addr(),
            IpStackStream::RawPacket(_) => unreachable!(),
        }
    }
    pub fn local_ip(&self) -> IpAddr {
        match self {
            IpStackStream::Tcp(tcp) => tcp.local_addr().ip(),
            IpStackStream::Udp(udp) => udp.local_addr().ip(),
            IpStackStream::RawPacket(_) => unreachable!(),
        }
    }
    pub fn peer_addr(&self) -> SocketAddr {
        match self {
            IpStackStream::Tcp(tcp) => tcp.peer_addr(),
            IpStackStream::Udp(udp) => udp.peer_addr(),
            IpStackStream::RawPacket(_) => unreachable!(),
        }
    }
    pub fn peer_ip(&self) -> IpAddr {
        match self {
            IpStackStream::Tcp(tcp) => tcp.peer_addr().ip(),
            IpStackStream::Udp(udp) => udp.peer_addr().ip(),
            IpStackStream::RawPacket(_) => unreachable!(),
        }
    }
}
