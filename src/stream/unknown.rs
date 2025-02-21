use crate::{
    packet::{IpHeader, NetworkPacket, TransportHeader},
    IpStackError, PacketSender, TTL,
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header};
use std::net::IpAddr;

pub struct IpStackUnknownTransport {
    src_addr: IpAddr,
    dst_addr: IpAddr,
    payload: Vec<u8>,
    protocol: IpNumber,
    mtu: u16,
    packet_sender: PacketSender,
}

impl IpStackUnknownTransport {
    pub(crate) fn new(src_addr: IpAddr, dst_addr: IpAddr, payload: Vec<u8>, ip: &IpHeader, mtu: u16, packet_sender: PacketSender) -> Self {
        let protocol = match ip {
            IpHeader::Ipv4(ip) => ip.protocol,
            IpHeader::Ipv6(ip) => ip.next_header,
        };
        IpStackUnknownTransport {
            src_addr,
            dst_addr,
            payload,
            protocol,
            mtu,
            packet_sender,
        }
    }
    pub fn src_addr(&self) -> IpAddr {
        self.src_addr
    }
    pub fn dst_addr(&self) -> IpAddr {
        self.dst_addr
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn ip_protocol(&self) -> IpNumber {
        self.protocol
    }
    pub fn send(&self, mut payload: Vec<u8>) -> std::io::Result<()> {
        loop {
            let packet = self.create_rev_packet(&mut payload)?;
            self.packet_sender
                .send(packet)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("send error: {}", e)))?;
            if payload.is_empty() {
                return Ok(());
            }
        }
    }

    pub fn create_rev_packet(&self, payload: &mut Vec<u8>) -> std::io::Result<NetworkPacket> {
        match (self.dst_addr, self.src_addr) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, TTL, self.protocol, dst.octets(), src.octets()).map_err(IpStackError::from)?;
                let line_buffer = self.mtu.saturating_sub(ip_h.header_len() as u16);

                let p = if payload.len() > line_buffer as usize {
                    payload.drain(0..line_buffer as usize).collect::<Vec<u8>>()
                } else {
                    std::mem::take(payload)
                };
                ip_h.set_payload_len(p.len()).map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv4(ip_h),
                    transport: TransportHeader::Unknown,
                    payload: p,
                })
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: IpNumber::UDP,
                    hop_limit: TTL,
                    source: dst.octets(),
                    destination: src.octets(),
                };
                let line_buffer = self.mtu.saturating_sub(ip_h.header_len() as u16);
                let p = if payload.len() > line_buffer as usize {
                    payload.drain(0..line_buffer as usize).collect::<Vec<u8>>()
                } else {
                    std::mem::take(payload)
                };
                ip_h.set_payload_length(p.len()).map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv6(ip_h),
                    transport: TransportHeader::Unknown,
                    payload: p,
                })
            }
            _ => unreachable!(),
        }
    }
}
