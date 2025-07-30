//!
//! Build: `cargo build --examples`
//!
//! Usage:
//!
//! This example must be run as root or administrator privileges.
//! ```
//! sudo target/debug/examples/tun --server-addr 127.0.0.1:5201
//! ```
//! Then run the `iperf3` as a server, which listens on TCP port 127.0.0.1:5201.
//! ```
//! iperf3 -s -p 5201
//! ```
//! Now you can connect `10.3.0.1:any_port`, and the traffic will be routed to the tun interface then to the server `127.0.0.1:5201`.
//! You can test it with `iperf3` as a client
//! ```
//! iperf3 -c 10.3.0.1       # TCP test
//! iperf3 -c 10.3.0.1 -R    # TCP reverse test
//! iperf3 -c 10.3.0.1 -u    # UDP test
//! iperf3 -c 10.3.0.1 -u -R # UDP reverse test
//! ```
//!

use clap::Parser;
use etherparse::Icmpv4Header;
use ipstack::{IpNumber, IpStackStream};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use udp_stream::UdpStream;

// const MTU: u16 = 1500;
const MTU: u16 = u16::MAX;

#[repr(C)]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum ArgVerbosity {
    Off = 0,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Parser)]
#[command(author, version, about = "Testing app for tun.", long_about = None)]
struct Args {
    /// echo server address, likes `127.0.0.1:8080`
    #[arg(short, long, value_name = "IP:port")]
    server_addr: SocketAddr,

    /// tcp timeout
    #[arg(long, value_name = "seconds", default_value = "60")]
    tcp_timeout: u64,

    /// udp timeout
    #[arg(long, value_name = "seconds", default_value = "10")]
    udp_timeout: u64,

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    pub verbosity: ArgVerbosity,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let args = Args::parse();

    let default = format!("{:?}", args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let ipv4 = Ipv4Addr::new(10, 3, 0, 33);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    #[cfg(not(target_os = "windows"))]
    let gateway = Ipv4Addr::new(10, 3, 0, 1);

    let mut tun_config = tun::Configuration::default();
    tun_config.address(ipv4).netmask(netmask).mtu(MTU).up();
    #[cfg(not(target_os = "windows"))]
    tun_config.destination(gateway); // avoid routing all traffic to tun on Windows platform

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|p_cfg| {
        p_cfg.ensure_root_privileges(true);
    });

    #[cfg(target_os = "windows")]
    tun_config.platform_config(|p_cfg| {
        p_cfg.device_guid(12324323423423434234_u128);
    });

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(MTU);
    ipstack_config.tcp_timeout(std::time::Duration::from_secs(args.tcp_timeout));
    ipstack_config.udp_timeout(std::time::Duration::from_secs(args.udp_timeout));

    let mut ip_stack = ipstack::IpStack::new(ipstack_config, tun::create_as_async(&tun_config)?);

    let server_addr = args.server_addr;

    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let serial_number = std::sync::atomic::AtomicUsize::new(0);

    loop {
        let count = count.clone();
        let number = serial_number.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match ip_stack.accept().await? {
            IpStackStream::Tcp(mut tcp) => {
                let mut s = match TcpStream::connect(server_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        log::info!("connect TCP server failed \"{e}\"");
                        continue;
                    }
                };
                let c = count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let number1 = number;
                log::info!("#{number1} TCP connecting, session count {c}");
                tokio::spawn(async move {
                    if let Err(err) = tokio::io::copy_bidirectional(&mut tcp, &mut s).await {
                        log::info!("#{number1} TCP error: {err}");
                    }
                    if let Err(e) = s.shutdown().await {
                        log::info!("#{number1} TCP upstream shutdown error: {e}");
                    }
                    if let Err(e) = tcp.shutdown().await {
                        log::info!("#{number1} TCP stack stream shutdown error: {e}");
                    }
                    let c = count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed) - 1;
                    log::info!("#{number1} TCP closed, session count {c}");
                });
            }
            IpStackStream::Udp(mut udp) => {
                let mut s = match UdpStream::connect(server_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        log::info!("connect UDP server failed \"{e}\"");
                        continue;
                    }
                };
                let c = count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let number2 = number;
                log::info!("#{number2} UDP connecting, session count {c}");
                tokio::spawn(async move {
                    if let Err(err) = tokio::io::copy_bidirectional(&mut udp, &mut s).await {
                        log::info!("#{number2} UDP error: {err}");
                    }
                    s.shutdown();
                    if let Err(e) = udp.shutdown().await {
                        log::info!("#{number2} UDP stack stream shutdown error: {e}");
                    }
                    let c = count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed) - 1;
                    log::info!("#{number2} UDP closed, session count {c}");
                });
            }
            IpStackStream::UnknownTransport(u) => {
                let n = number;
                if u.src_addr().is_ipv4() && u.ip_protocol() == IpNumber::ICMP {
                    let (icmp_header, req_payload) = Icmpv4Header::from_slice(u.payload())?;
                    if let etherparse::Icmpv4Type::EchoRequest(echo) = icmp_header.icmp_type {
                        log::info!("#{n} ICMPv4 echo");
                        let mut resp = Icmpv4Header::new(etherparse::Icmpv4Type::EchoReply(echo));
                        resp.update_checksum(req_payload);
                        let mut payload = resp.to_bytes().to_vec();
                        payload.extend_from_slice(req_payload);
                        u.send(payload)?;
                    } else {
                        log::info!("#{n} ICMPv4");
                    }
                    continue;
                }
                log::info!("#{n} unknown transport - Ip Protocol {:?}", u.ip_protocol());
                continue;
            }
            IpStackStream::UnknownNetwork(pkt) => {
                log::info!("#{number} unknown network - {} bytes", pkt.len());
                continue;
            }
        };
    }
}
