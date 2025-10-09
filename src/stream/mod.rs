use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub use self::tcp::IpStackTcpStream;
pub use self::tcp::{TcpConfig, TcpOptions};
pub use self::udp::IpStackUdpStream;
pub use self::unknown::IpStackUnknownTransport;

mod seqnum;
mod tcb;
mod tcp;
mod udp;
mod unknown;

pub enum IpStackStream {
    Tcp(IpStackTcpStream),
    Udp(IpStackUdpStream),
    UnknownTransport(IpStackUnknownTransport),
    UnknownNetwork(Vec<u8>),
}

impl IpStackStream {
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            IpStackStream::Tcp(tcp) => tcp.local_addr(),
            IpStackStream::Udp(udp) => udp.local_addr(),
            IpStackStream::UnknownNetwork(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            IpStackStream::UnknownTransport(unknown) => match unknown.src_addr() {
                IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, 0)),
                IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0)),
            },
        }
    }
    pub fn peer_addr(&self) -> SocketAddr {
        match self {
            IpStackStream::Tcp(tcp) => tcp.peer_addr(),
            IpStackStream::Udp(udp) => udp.peer_addr(),
            IpStackStream::UnknownNetwork(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            IpStackStream::UnknownTransport(unknown) => match unknown.dst_addr() {
                IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, 0)),
                IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0)),
            },
        }
    }

    pub fn stream_sender(&self) -> Result<crate::PacketSender, std::io::Error> {
        match self {
            IpStackStream::Tcp(tcp) => Ok(tcp.stream_sender()),
            IpStackStream::Udp(udp) => Ok(udp.stream_sender()),
            _ => Err(std::io::Error::other("Unknown transport stream does not have a sender")),
        }
    }
}
