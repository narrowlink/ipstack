use etherparse::WriteError;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum IpStackError {
    #[error("The transport protocol is not supported")]
    UnsupportedTransportProtocol,
    #[error("The packet is invalid")]
    InvalidPacket,
    #[error("Write error: {0}")]
    PacketWriteError(WriteError),
    #[error("Invalid Tcp packet")]
    InvalidTcpPacket,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Accept Error")]
    AcceptError,
}
