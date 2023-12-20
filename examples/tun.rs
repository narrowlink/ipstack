use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipstack::stream::IpStackStream;
use tokio::{join, net::TcpStream};
use udp_stream::UdpStream;

// const MTU: u16 = 1500;
const MTU: u16 = u16::MAX;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let ipv4 = Ipv4Addr::new(10, 0, 0, 1);

    let mut config = tun::Configuration::default();
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
    let mut ipstack_config = ipstack::IpStackConfig::default();

    #[cfg(target_os = "windows")]
    let ipstack_config = ipstack::IpStackConfig::default();

    #[cfg(not(target_os = "windows"))]
    ipstack_config.packet_info(true);

    let mut ip_stack =
        ipstack::IpStack::new(ipstack_config, tun::create_as_async(&config).unwrap());

    #[cfg(target_os = "macos")]
    {
        let s = format!("sudo route -n add -net 10.0.0.0/24 {}", ipv4);
        let command = std::process::Command::new("sh")
            .arg("-c")
            .arg(s)
            .output()
            .unwrap();
        if !command.status.success() {
            panic!("cannot establish route to tun device");
        }
    };

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
