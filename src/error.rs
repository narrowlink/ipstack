#[derive(thiserror::Error, Debug)]
pub enum IpStackError {
    #[error("The transport protocol is not supported")]
    UnsupportedTransportProtocol,

    #[error("The packet is invalid")]
    InvalidPacket,

    #[error("ValueTooBigError<u16> {0}")]
    ValueTooBigErrorU16(#[from] etherparse::err::ValueTooBigError<u16>),

    #[error("ValueTooBigError<usize> {0}")]
    ValueTooBigErrorUsize(#[from] etherparse::err::ValueTooBigError<usize>),

    #[error("Invalid Tcp packet")]
    InvalidTcpPacket,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Accept Error")]
    AcceptError,

    #[error("Send Error {0}")]
    SendError(#[from] Box<tokio::sync::mpsc::error::SendError<crate::stream::IpStackStream>>),
}

impl From<tokio::sync::mpsc::error::SendError<crate::stream::IpStackStream>> for IpStackError {
    fn from(e: tokio::sync::mpsc::error::SendError<crate::stream::IpStackStream>) -> Self {
        IpStackError::SendError(Box::new(e))
    }
}

// Safety: All variants of IpStackError either contain no data or wrap types that are `Send`.
// This ensures that IpStackError as a whole is safe to send between threads.
unsafe impl Send for IpStackError {}

// Safety: All variants of IpStackError either contain no data or wrap types that are `Sync`.
// This ensures that IpStackError as a whole is safe to share between threads.
unsafe impl Sync for IpStackError {}

impl From<IpStackError> for std::io::Error {
    fn from(e: IpStackError) -> Self {
        match e {
            IpStackError::IoError(e) => e,
            _ => std::io::Error::other(e),
        }
    }
}

pub type Result<T, E = IpStackError> = std::result::Result<T, E>;
