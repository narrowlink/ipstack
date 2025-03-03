use std::net::{Ipv4Addr, SocketAddr};

use clap::Parser;
use etherparse::Icmpv4Header;
use ipstack::{stream::IpStackStream, IpNumber};
use tokio::net::TcpStream;
use udp_stream::UdpStream;

// const MTU: u16 = 1500;
const MTU: u16 = u16::MAX;

#[derive(Parser)]
#[command(author, version, about = "Testing app for tun.", long_about = None)]
struct Args {
    /// echo server address, likes `127.0.0.1:8080`
    #[arg(short, long, value_name = "IP:port")]
    server_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let args = Args::parse();

    env_logger::init();

    let ipv4 = Ipv4Addr::new(10, 0, 0, 33);
    let _netmask = Ipv4Addr::new(255, 255, 255, 0);
    let _gateway = Ipv4Addr::new(10, 0, 0, 1);
    #[cfg(not(target_os = "windows"))]
    let mut config = tun::Configuration::default();
    #[cfg(not(target_os = "windows"))]
    config.address(ipv4).netmask(_netmask).mtu(MTU).up();
    #[cfg(not(target_os = "windows"))]
    config.destination(_gateway);

    // #[cfg(target_os = "linux")]
    // config.platform_config(|config| {
    //     config.ensure_root_privileges(true);
    // });

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(MTU);
    // ipstack_config.packet_information(cfg!(target_family = "unix"));

    #[cfg(not(target_os = "windows"))]
    let mut ip_stack = ipstack::IpStack::new(ipstack_config, tun::create_as_async(&config)?);

    #[cfg(target_os = "windows")]
    let mut ip_stack = ipstack::IpStack::new(ipstack_config, wintun::WinTunDevice::new(ipv4, Ipv4Addr::new(255, 255, 255, 0)));

    let server_addr = args.server_addr;

    loop {
        match ip_stack.accept().await? {
            IpStackStream::Tcp(mut tcp) => {
                let mut s = match TcpStream::connect(server_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        println!("connect TCP server failed \"{}\"", e);
                        continue;
                    }
                };
                println!("==== New TCP connection ====");
                tokio::spawn(async move {
                    _ = tokio::io::copy_bidirectional(&mut tcp, &mut s).await;
                    println!("====== end tcp connection ======");
                });
            }
            IpStackStream::Udp(mut udp) => {
                let mut s = match UdpStream::connect(server_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        println!("connect UDP server failed \"{}\"", e);
                        continue;
                    }
                };
                println!("==== New UDP connection ====");
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut udp, &mut s).await;
                    println!("==== end UDP connection ====");
                });
            }
            IpStackStream::UnknownTransport(u) => {
                if u.src_addr().is_ipv4() && u.ip_protocol() == IpNumber::ICMP {
                    let (icmp_header, req_payload) = Icmpv4Header::from_slice(u.payload())?;
                    if let etherparse::Icmpv4Type::EchoRequest(echo) = icmp_header.icmp_type {
                        println!("ICMPv4 echo");
                        let mut resp = Icmpv4Header::new(etherparse::Icmpv4Type::EchoReply(echo));
                        resp.update_checksum(req_payload);
                        let mut payload = resp.to_bytes().to_vec();
                        payload.extend_from_slice(req_payload);
                        u.send(payload)?;
                    } else {
                        println!("ICMPv4");
                    }
                    continue;
                }
                println!("unknown transport - Ip Protocol {:?}", u.ip_protocol());
                continue;
            }
            IpStackStream::UnknownNetwork(pkt) => {
                println!("unknown transport - {} bytes", pkt.len());
                continue;
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

        fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
}
