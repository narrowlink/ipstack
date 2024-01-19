use crate::IpStackError;
use etherparse::WriteError;
use tokio::sync::mpsc::UnboundedSender;

use crate::packet::NetworkPacket;

#[derive(Debug)]
pub struct RawPacket {
    packet: Vec<u8>,
    pkt_sender: UnboundedSender<NetworkPacket>,
    mtu: u16,
}
impl RawPacket {
    pub fn new(packet: Vec<u8>, pkt_sender: UnboundedSender<NetworkPacket>, mtu: u16) -> Self {
        Self {
            packet,
            pkt_sender,
            mtu,
        }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.packet
    }
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
    pub async fn send(self, pkt: &[u8]) -> Result<(), IpStackError> {
        self.pkt_sender
            .send(NetworkPacket::parse_from(pkt)?)
            .map_err(|_| {
                IpStackError::PacketWriteError(WriteError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "",
                )))
            })?;
        Ok(())
    }
}
