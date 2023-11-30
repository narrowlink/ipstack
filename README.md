An asynchronous lightweight implementation of TCP/IP stack for Tun device.
Unstable, under development.

### Usage
````rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use udp_stream::UdpStream;
use tokio::io{AsyncRead, AsyncWrite};
async fn copy_from_lhs_to_rhs(lhs:impl AsyncRead + AsyncWrite, rhs:impl AsyncRead + AsyncWrite){
	let (lhs_reader,lhs_writer) = tokio::io::split(lhs);
	let (rhs_reader, rhs_writer) = tokio::io::split(rhs);
    tokio::join! {
		tokio::io::copy(&mut lhs_reader, &mut rhs_writer) ,
		tokio::io::copy(&mut rhs_reader, &mut lhs_writer),
    }
}
#[tokio::main]
async fn main(){
	const MTU: u16 = 1500;
	let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
	let mut config = tun::Configuration::default();
    config
        .address(ipv4)
        .netmask((255, 255, 255, 0))
        .mtu(MTU as i32)
        .up();
	let mut ip_stack = ipstack::IpStack::new(tun::create_as_async(&config).unwrap(), MTU, true);
	while let Ok(stream) = ip_stack.accept().await{
		match stream{
			IpStackStream::Tcp(tcp) => {
				let rhs = TcpStream::connect("1.1.1.1:80").await.unwrap();
				tokio::spawn(async move {
					copy_from_lhs_to_rhs(tcp,rhs).await;
                });
			}
			IpStackStream::Udp(udp) => {
                let rhs = UdpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53))
				        .await
                        .unwrap();
				tokio::spawn(async move {
					copy_from_lhs_to_rhs(udp,rhs).await;
                });	
			}
		}
	}
}
````