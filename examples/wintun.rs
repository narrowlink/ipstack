use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipstack::stream::IpStackStream;
use tokio::{join, net::TcpStream};
use udp_stream::UdpStream;

// const MTU: u16 = 1500;
const MTU: u16 = u16::MAX;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
    #[cfg(not(target_os = "windows"))]
    let mut config = tun::Configuration::default();
    #[cfg(not(target_os = "windows"))]
    config
        .address(ipv4)
        .netmask((255, 255, 255, 0))
        .mtu(MTU as i32)
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    #[cfg(not(target_os = "windows"))]
    let mut ip_stack = ipstack::IpStack::new(tun::create_as_async(&config).unwrap(), MTU, true);

    #[cfg(target_os = "windows")]
    let mut ip_stack = ipstack::IpStack::new(
        wintun::WinTunDevice::new(ipv4, Ipv4Addr::new(255, 255, 255, 0)),
        MTU,
        false,
    );

    loop {
        match ip_stack.accept().await.unwrap() {
            IpStackStream::Tcp(tcp) => {
                let s = TcpStream::connect("1.1.1.1:80").await.unwrap();
                let (mut t_rx, mut t_tx) = tokio::io::split(tcp);
                let (mut s_rx, mut s_tx) = tokio::io::split(s);
                tokio::spawn(async move {
                    join! {
                         tokio::io::copy(&mut t_rx, &mut s_tx) ,
                         tokio::io::copy(&mut s_rx, &mut t_tx),
                    }
                });
            }
            IpStackStream::Udp(udp) => {
                let s =
                    UdpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53))
                        .await
                        .unwrap();
                let (mut t_rx, mut t_tx) = tokio::io::split(udp);
                let (mut s_rx, mut s_tx) = tokio::io::split(s);
                tokio::spawn(async move {
                    join! {
                         tokio::io::copy(&mut t_rx, &mut s_tx) ,
                         tokio::io::copy(&mut s_rx, &mut t_tx),
                    }
                });
            }
        };
    }
}

#[cfg(target_os = "windows")]
mod wintun {
    use std::{net::Ipv4Addr, sync::Arc, task::ready, thread};

    use tokio::io::{AsyncRead, AsyncWrite};

    pub struct WinTunDevice {
        session: Arc<wintun::Session>,
        receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        _task: thread::JoinHandle<()>,
    }

    impl WinTunDevice {
        pub fn new(ip: Ipv4Addr, netmask: Ipv4Addr) -> WinTunDevice {
            let wintun = unsafe { wintun::load() }.unwrap();
            let adapter = wintun::Adapter::create(&wintun, "IpStack", "Tunnel", None).unwrap();
            adapter.set_address(ip).unwrap();
            adapter.set_netmask(netmask).unwrap();
            let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
            let (receiver_tx, receiver_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            let session_reader = session.clone();
            let task = thread::spawn(move || {
                loop {
                    let packet = session_reader.receive_blocking().unwrap();
                    let bytes = packet.bytes().to_vec();
                    // dbg!(&bytes);
                    receiver_tx.send(bytes).unwrap();
                }
            });
            WinTunDevice {
                session,
                receiver: receiver_rx,
                _task: task,
            }
        }
    }

    impl AsyncRead for WinTunDevice {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match ready!(self.receiver.poll_recv(cx)) {
                Some(bytes) => {
                    buf.put_slice(&bytes);
                    std::task::Poll::Ready(Ok(()))
                }
                None => std::task::Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for WinTunDevice {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            let mut write_pack = self.session.allocate_send_packet(buf.len() as u16)?;
            write_pack.bytes_mut().copy_from_slice(buf.as_ref());
            self.session.send_packet(write_pack);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
}
