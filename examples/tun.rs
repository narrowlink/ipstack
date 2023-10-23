use std::net::Ipv4Addr;

use ipstack::stream::IpStackStream;
use tokio::{join, net::TcpStream};

const MTU: u16 = 1500;
// const MTU: u16 = 1u16 << 16 - 1;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let ipv4 = Ipv4Addr::new(10, 10, 10, 10);
    let mut config = tun::Configuration::default();
    config
        .address(ipv4)
        .netmask((255, 255, 255, 0))
        .mtu(MTU as i32)
        .up();
    let mut ip_stack = ipstack::IpStack::new(tun::create_as_async(&config).unwrap(), MTU, true);

    loop {
        match ip_stack.accept().await {
            IpStackStream::Tcp(t) => {
                let s = TcpStream::connect("127.0.0.1:8000").await.unwrap();
                let (mut t_rx, mut t_tx) = tokio::io::split(t);
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
                dbg!(udp.get_dst_addr());
                dbg!(udp.get_src_addr());
            }
        };
    }
}
