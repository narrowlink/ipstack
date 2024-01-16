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
//! sudo ip route add 1.2.3.4/32 dev utun3    # Linux
//! route add 1.2.3.4 mask 255.255.255.255 10.0.0.1 metric 100  # Windows
//! sudo route add 1.2.3.4/32 10.0.0.1  # Apple macOS
//! ```
//! Now you can test it with `nc 1.2.3.4 any_port` or `nc -u 1.2.3.4 any_port`.
//! You can watch the echo information in the `nc` console.
//! ```
//! nc 1.2.3.4 2323 # TCP
//! nc -u 1.2.3.4 2323 # UDP
//! ```
//!

use clap::Parser;
use ipstack::stream::IpStackStream;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::{join, net::TcpStream};
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
    config.address(ipv4).netmask(netmask).mtu(MTU as i32).up();
    config.destination(gateway).name("utun3");

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    #[cfg(target_os = "windows")]
    config.platform(|config| {
        config.initialize(Some(12324323423423434234_u128));
    });

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(MTU);
    ipstack_config.packet_info(cfg!(target_family = "unix"));

    let mut ip_stack = ipstack::IpStack::new(ipstack_config, tun2::create_as_async(&config)?);

    let server_addr = args.server_addr;

    loop {
        match ip_stack.accept().await? {
            IpStackStream::Tcp(tcp) => {
                let s = TcpStream::connect(server_addr).await;
                if let Err(ref err) = s {
                    println!("connect TCP server failed \"{}\"", err);
                    continue;
                }
                println!("==== New TCP connection ====");
                let (mut t_rx, mut t_tx) = tokio::io::split(tcp);
                let (mut s_rx, mut s_tx) = tokio::io::split(s?);
                tokio::spawn(async move {
                    let _r = join! {
                         tokio::io::copy(&mut t_rx, &mut s_tx) ,
                         tokio::io::copy(&mut s_rx, &mut t_tx),
                    };
                    println!("====== end tcp connection ======");
                });
            }
            IpStackStream::Udp(udp) => {
                let s = UdpStream::connect(server_addr).await;
                if let Err(ref err) = s {
                    println!("connect UDP server failed \"{}\"", err);
                    continue;
                }
                println!("==== New UDP connection ====");
                let (mut t_rx, mut t_tx) = tokio::io::split(udp);
                let (mut s_rx, mut s_tx) = tokio::io::split(s?);
                tokio::spawn(async move {
                    let _r = join! {
                         tokio::io::copy(&mut t_rx, &mut s_tx) ,
                         tokio::io::copy(&mut s_rx, &mut t_tx),
                    };
                    println!("==== end UDP connection ====");
                });
            }
        };
    }
}
