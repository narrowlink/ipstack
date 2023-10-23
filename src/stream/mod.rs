pub use self::tcp::IpStackTcpStream;
pub use self::udp::IpStackUdpStream;

mod tcb;
mod tcp;
mod udp;

pub enum IpStackStream {
    Tcp(IpStackTcpStream),
    Udp(IpStackUdpStream),
}
