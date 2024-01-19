use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use etherparse::{IpHeader, PacketHeaders, TcpHeader, TransportHeader};

use crate::error::IpStackError;

#[derive(Eq, Hash, PartialEq, Debug)]
pub struct NetworkTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub tcp: bool,
}
pub mod tcp_flags {
    pub const CWR: u8 = 0b10000000;
    pub const ECE: u8 = 0b01000000;
    pub const URG: u8 = 0b00100000;
    pub const ACK: u8 = 0b00010000;
    pub const PSH: u8 = 0b00001000;
    pub const RST: u8 = 0b00000100;
    pub const SYN: u8 = 0b00000010;
    pub const FIN: u8 = 0b00000001;
}

pub(crate) enum IpStackPacketProtocol {
    Tcp(TcpPacket),
    Udp,
}
#[derive(Debug)]
pub struct NetworkPacket {
    pub ip: IpHeader,
    pub transport: TransportHeader,
    pub payload: Vec<u8>,
}

pub enum TunPacket {
    NetworkPacket(Box<NetworkPacket>),
    RawPacket,
}

pub(crate) fn parse_packet(buf: &[u8]) -> Result<TunPacket, IpStackError> {
    let p = PacketHeaders::from_ip_slice(buf).map_err(|_| IpStackError::InvalidPacket)?;
    let ip = p.ip.ok_or(IpStackError::InvalidPacket)?;
    let transport = p
        .transport
        .ok_or(IpStackError::UnsupportedTransportProtocol)?;
    match transport {
        TransportHeader::Tcp(_) | TransportHeader::Udp(_) => {
            Ok(TunPacket::NetworkPacket(Box::new(NetworkPacket {
                ip,
                transport,
                payload: p.payload.to_vec(),
            })))
        }
        TransportHeader::Icmpv4(_) | TransportHeader::Icmpv6(_) => Ok(TunPacket::RawPacket),
    }
}

impl NetworkPacket {
    pub fn parse_from(buf: &[u8]) -> Result<Self, IpStackError> {
        let p = PacketHeaders::from_ip_slice(buf).map_err(|_| IpStackError::InvalidPacket)?;
        let ip = p.ip.ok_or(IpStackError::InvalidPacket)?;
        let transport = p
            .transport
            .filter(|t| {
                (matches!(t, TransportHeader::Tcp(_))
                    || matches!(t, TransportHeader::Udp(_))
                    || matches!(t, TransportHeader::Icmpv4(_))
                    || matches!(t, TransportHeader::Icmpv6(_)))
            })
            .ok_or(IpStackError::UnsupportedTransportProtocol)?;
        let payload = p.payload.to_vec();
        Ok(NetworkPacket {
            ip,
            transport,
            payload,
        })
    }
    pub(crate) fn transport_protocol(&self) -> IpStackPacketProtocol {
        match self.transport {
            TransportHeader::Udp(_) => IpStackPacketProtocol::Udp,
            TransportHeader::Tcp(ref h) => IpStackPacketProtocol::Tcp(h.into()),
            _ => unreachable!(),
        }
    }
    pub fn src_addr(&self) -> SocketAddr {
        let port = match &self.transport {
            TransportHeader::Udp(udp) => udp.source_port,
            TransportHeader::Tcp(tcp) => tcp.source_port,
            _ => unreachable!(),
        };
        SocketAddr::new(self.src_ip(), port)
    }
    pub fn src_ip(&self) -> IpAddr {
        match &self.ip {
            IpHeader::Version4(ip, _) => IpAddr::V4(Ipv4Addr::from(ip.source)),
            IpHeader::Version6(ip, _) => IpAddr::V6(Ipv6Addr::from(ip.source)),
        }
    }
    pub fn dst_addr(&self) -> SocketAddr {
        let port = match &self.transport {
            TransportHeader::Udp(udp) => udp.destination_port,
            TransportHeader::Tcp(tcp) => tcp.destination_port,
            _ => unreachable!(),
        };
        SocketAddr::new(self.dst_ip(), port)
    }
    pub fn dst_ip(&self) -> IpAddr {
        match &self.ip {
            IpHeader::Version4(ip, _) => IpAddr::V4(Ipv4Addr::from(ip.destination)),
            IpHeader::Version6(ip, _) => IpAddr::V6(Ipv6Addr::from(ip.destination)),
        }
    }
    pub fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple {
            src: self.src_addr(),
            dst: self.dst_addr(),
            tcp: matches!(self.transport, TransportHeader::Tcp(_)),
        }
    }
    pub fn reverse_network_tuple(&self) -> NetworkTuple {
        NetworkTuple {
            src: self.dst_addr(),
            dst: self.src_addr(),
            tcp: matches!(self.transport, TransportHeader::Tcp(_)),
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, IpStackError> {
        let mut buf = Vec::new();
        self.ip
            .write(&mut buf)
            .map_err(IpStackError::PacketWriteError)?;
        self.transport
            .write(&mut buf)
            .map_err(IpStackError::PacketWriteError)?;
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }
    pub fn ttl(&self) -> u8 {
        match &self.ip {
            IpHeader::Version4(ip, _) => ip.time_to_live,
            IpHeader::Version6(ip, _) => ip.hop_limit,
        }
    }
}

pub(super) struct TcpPacket {
    header: TcpHeader,
}

impl TcpPacket {
    pub fn inner(&self) -> &TcpHeader {
        &self.header
    }
    pub fn flags(&self) -> u8 {
        let inner = self.inner();
        let mut flags = 0;
        if inner.cwr {
            flags |= tcp_flags::CWR;
        }
        if inner.ece {
            flags |= tcp_flags::ECE;
        }
        if inner.urg {
            flags |= tcp_flags::URG;
        }
        if inner.ack {
            flags |= tcp_flags::ACK;
        }
        if inner.psh {
            flags |= tcp_flags::PSH;
        }
        if inner.rst {
            flags |= tcp_flags::RST;
        }
        if inner.syn {
            flags |= tcp_flags::SYN;
        }
        if inner.fin {
            flags |= tcp_flags::FIN;
        }

        flags
    }
}

impl From<&TcpHeader> for TcpPacket {
    fn from(header: &TcpHeader) -> Self {
        TcpPacket {
            header: header.clone(),
        }
    }
}

// pub struct UdpPacket {
//     header: UdpHeader,
// }

// impl UdpPacket {
//     pub fn inner(&self) -> &UdpHeader {
//         &self.header
//     }
// }

// impl From<&UdpHeader> for UdpPacket {
//     fn from(header: &UdpHeader) -> Self {
//         UdpPacket {
//             header: header.clone(),
//         }
//     }
// }
