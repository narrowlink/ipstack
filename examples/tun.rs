use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipstack::stream::IpStackStream;
use tokio::{join, net::TcpStream};
use udp_stream::UdpStream;

const MTU: u16 = 1500;
// const MTU: u16 = 1u16 << 16 - 1;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
    let mut config = tun::Configuration::default();
    config
        .address(ipv4)
        .netmask((255, 255, 255, 0))
        .mtu(MTU as i32)
        .up();
    let mut ip_stack = ipstack::IpStack::new(tun::create_as_async(&config).unwrap(), MTU, true);

    loop {
        match ip_stack.accept().await {
            IpStackStream::Tcp(tcp) => {
                let s = TcpStream::connect("1.1.1.1:80").await.unwrap();
                let (mut t_rx, mut t_tx) = tokio::io::split(tcp);
                let (mut s_rx, mut s_tx) = tokio::io::split(s);
                tokio::spawn(async move {
                    // loop {
                    join! {
                         tokio::io::copy(&mut t_rx, &mut s_tx) ,
                         tokio::io::copy(&mut s_rx, &mut t_tx),
                    }
                    // }
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
                    // loop {
                    join! {
                         tokio::io::copy(&mut t_rx, &mut s_tx) ,
                         tokio::io::copy(&mut s_rx, &mut t_tx),
                    }
                    // }
                });
            }
        };
    }
}
