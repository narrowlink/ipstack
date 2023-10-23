use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use etherparse::{IpHeader, PacketHeaders, TcpHeader, TransportHeader};

use crate::error::IpStackError;

#[derive(Eq, Hash, PartialEq)]
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
pub struct NetworkPacket {
    pub ip: IpHeader,
    pub transport: TransportHeader,
    pub payload: Vec<u8>,
}

impl NetworkPacket {
    pub fn parse(buf: &[u8]) -> Result<Self, IpStackError> {
        let p = PacketHeaders::from_ip_slice(buf).map_err(|_| IpStackError::InvalidPacket)?;
        let ip = p.ip.ok_or(IpStackError::InvalidPacket)?;
        let transport = p
            .transport
            .filter(|t| {
                (matches!(t, TransportHeader::Tcp(_)) || matches!(t, TransportHeader::Udp(_)))
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
        match &self.ip {
            IpHeader::Version4(ip, _) => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip.source)), port)
            }
            IpHeader::Version6(ip, _) => {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip.source)), port)
            }
        }
    }
    pub fn dst_addr(&self) -> SocketAddr {
        let port = match &self.transport {
            TransportHeader::Udp(udp) => udp.destination_port,
            TransportHeader::Tcp(tcp) => tcp.destination_port,
            _ => unreachable!(),
        };
        match &self.ip {
            IpHeader::Version4(ip, _) => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip.destination)), port)
            }
            IpHeader::Version6(ip, _) => {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip.destination)), port)
            }
        }
    }
    pub fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple {
            src: self.src_addr(),
            dst: self.dst_addr(),
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
