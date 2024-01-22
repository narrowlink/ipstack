An asynchronous lightweight implementation of TCP/IP stack for Tun device.
Unstable, under development.

### Usage

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use udp_stream::UdpStream;
use tokio::io{AsyncRead, AsyncWrite};
use etherparse::{IcmpEchoHeader, Icmpv4Header};

#[tokio::main]
async fn main(){
    const MTU: u16 = 1500;
    let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let mut config = tun2::Configuration::default();
    config.address(ipv4).netmask(netmask).mtu(MTU as i32).up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.packet_information(true);
		config.apply_settings(true);
    });

    #[cfg(target_os = "windows")]
    config.platform_config(|config| {
        config.device_guid(Some(12324323423423434234_u128));
    });

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(MTU);
    let packet_information = cfg!(all(target_family = "unix", not(target_os = "android")));
    ipstack_config.packet_information(packet_information);
    let mut ip_stack = ipstack::IpStack::new(ipstack_config, tun2::create_as_async(&config).unwrap());

    while let Ok(stream) = ip_stack.accept().await {
        match stream {
            IpStackStream::Tcp(mut tcp) => {
                let mut rhs = TcpStream::connect("1.1.1.1:80").await.unwrap();
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(& mut tcp, & mut rhs).await;
                });
            }
            IpStackStream::Udp(mut udp) => {
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
                let mut rhs = UdpStream::connect(addr).await.unwrap();
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(& mut udp, & mut rhs).await;
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
        }
    }
}
```

We also suggest that you take a look at the complete [examples](examples).
