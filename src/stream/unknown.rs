use std::net::IpAddr;

use etherparse::IpHeader;
use tokio::sync::mpsc::UnboundedSender;

use crate::packet::NetworkPacket;

pub struct IpStackUnknownTransport {
    src_addr: IpAddr,
    dst_addr: IpAddr,
    payload: Vec<u8>,
    ip: IpHeader,
    // packet_sender: UnboundedSender<NetworkPacket>,
}

impl IpStackUnknownTransport {
    pub fn new(
        src_addr: IpAddr,
        dst_addr: IpAddr,
        payload: Vec<u8>,
        ip: IpHeader,
        _packet_sender: UnboundedSender<NetworkPacket>,
    ) -> Self {
        IpStackUnknownTransport {
            src_addr,
            dst_addr,
            payload,
            ip,
            // packet_sender,
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
    pub fn ip_protocol(&self) -> u8 {
        match &self.ip {
            IpHeader::Version4(ip, _) => ip.protocol,
            IpHeader::Version6(ip, _) => ip.next_header,
        }
    }
    // pub fn send(&self, payload: Vec<u8>) {
    //     let packet = NetworkPacket::new(self.ip.clone(), payload);
    //     self.packet_sender.send(packet).unwrap();
    // // }
    // pub fn create_rev_packet(&self, mut payload: Vec<u8>)-> Result<NetworkPacket, Error>{

    // }
}
