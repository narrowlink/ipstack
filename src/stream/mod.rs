pub use self::tcp::TunTcpStream;

mod tcb;
mod tcp;
mod udp;

pub enum TunStream {
    Tcp(TunTcpStream),
    // Udp(TunUdpStream),
}
