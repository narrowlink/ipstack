//!
//! Build: `cargo build --examples`
//!
//! Usage:
//!
//! This example must be run as root or administrator privileges.
//! ```
//! sudo target/debug/examples/tun --server-addr 127.0.0.1:8080 # Linux or macOS
//! ```
//! Then please run the `echo` example server, which listens on TCP & UDP ports 127.0.0.1:8080.
//! ```
//! target/debug/examples/echo 127.0.0.1:8080
//! ```
//! To route traffic to the tun interface, run the following command with root or administrator privileges:
//! ```
//! sudo ip route add 1.2.3.4/32 dev tun0    # Linux
//! route add 1.2.3.4 mask 255.255.255.255 10.0.0.1 metric 100  # Windows
//! sudo route add 1.2.3.4/32 10.0.0.1  # macOS
//! ```
//! Now you can test it with `nc 1.2.3.4 any_port` or `nc -u 1.2.3.4 any_port`.
//! You can watch the echo information in the `nc` console.
//! ```
//! nc 1.2.3.4 2323 # TCP
//! nc -u 1.2.3.4 2323 # UDP
//! ```
//!

use clap::Parser;
use etherparse::{IcmpEchoHeader, Icmpv4Header};
use ipstack::stream::IpStackStream;
use std::net::{Ipv4Addr, SocketAddr};
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
    let args = Args::parse();

    let ipv4 = Ipv4Addr::new(10, 0, 0, 33);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let gateway = Ipv4Addr::new(10, 0, 0, 1);

    let mut config = tun2::Configuration::default();
    config.address(ipv4).netmask(netmask).mtu(MTU as usize).up();
    config.destination(gateway);

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    #[cfg(target_os = "windows")]
    config.platform_config(|config| {
        config.device_guid(Some(12324323423423434234_u128));
    });

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(MTU);

    let mut ip_stack = ipstack::IpStack::new(ipstack_config, tun2::create_as_async(&config)?);

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
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut s).await;
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
                if u.src_addr().is_ipv4() && u.ip_protocol() == 1 {
                    let (icmp_header, req_payload) = Icmpv4Header::from_slice(u.payload())?;
                    if let etherparse::Icmpv4Type::EchoRequest(req) = icmp_header.icmp_type {
                        println!("ICMPv4 echo");
                        let echo = IcmpEchoHeader {
                            id: req.id,
                            seq: req.seq,
                        };
                        let mut resp = Icmpv4Header::new(etherparse::Icmpv4Type::EchoReply(echo));
                        resp.update_checksum(req_payload);
                        let mut payload = resp.to_bytes().to_vec();
                        payload.extend_from_slice(req_payload);
                        u.send(payload).await?;
                    } else {
                        println!("ICMPv4");
                    }
                    continue;
                }
                println!("unknown transport - Ip Protocol {}", u.ip_protocol());
                continue;
            }
            IpStackStream::UnknownNetwork(pkt) => {
                println!("unknown transport - {} bytes", pkt.len());
                continue;
            }
        };
    }
}
