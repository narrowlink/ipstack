#![cfg(target_os = "linux")]
// Run only inside an isolated network namespace. See scripts/qualify-linux-tcp.sh.
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

struct LossyTun {
    device: tun::AsyncDevice,
    lose_fin: Arc<AtomicBool>,
    dropped_fin: Arc<AtomicBool>,
    client_port: Arc<AtomicU16>,
}
impl AsyncRead for LossyTun {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_read(cx, buf)
    }
}
impl AsyncWrite for LossyTun {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        // TUN supplies complete IPv4 packets without a packet-information prefix.
        if bytes.len() >= 20 && bytes[0] >> 4 == 4 && bytes[9] == 6 {
            let tcp = ((bytes[0] & 15) as usize) * 4;
            if bytes.len() >= tcp + 20
                && bytes[tcp + 13] & 1 != 0
                && u16::from_be_bytes([bytes[tcp + 2], bytes[tcp + 3]]) == self.client_port.load(Ordering::SeqCst)
                && self.lose_fin.swap(false, Ordering::SeqCst)
            {
                self.dropped_fin.store(true, Ordering::SeqCst);
                return Poll::Ready(Ok(bytes.len()));
            }
        }
        Pin::new(&mut self.device).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_shutdown(cx)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TUN and an isolated Linux network namespace"]
async fn linux_kernel_tcp_close_matrix() {
    assert_eq!(
        std::env::var("IPSTACK_TEST_NETNS").as_deref(),
        Ok("1"),
        "use scripts/qualify-linux-tcp.sh"
    );
    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name("ipstack-test")
        .address((198, 18, 0, 1))
        .destination((198, 18, 0, 2))
        .netmask((255, 255, 255, 0))
        .mtu(1500)
        .up();
    let lose_fin = Arc::new(AtomicBool::new(false));
    let dropped_fin = Arc::new(AtomicBool::new(false));
    let client_port = Arc::new(AtomicU16::new(0));
    let device = LossyTun {
        device: tun::create_as_async(&tun_config).unwrap(),
        lose_fin: lose_fin.clone(),
        dropped_fin: dropped_fin.clone(),
        client_port: client_port.clone(),
    };
    let mut config = IpStackConfig::default();
    config.mtu(1500).unwrap();
    let mut stack = IpStack::new(config, device);
    if std::env::var_os("IPSTACK_TEST_NETEM").is_some() {
        let status = std::process::Command::new("tc")
            .args([
                "qdisc",
                "add",
                "dev",
                "ipstack-test",
                "root",
                "netem",
                "delay",
                "10ms",
                "loss",
                "1%",
            ])
            .status()
            .unwrap();
        assert!(status.success(), "netem setup failed");
    }
    for size in [5usize, 131_072] {
        for mode in ["client-first", "server-first", "simultaneous", "drop"] {
            for loss in [false, true] {
                // Bind before arming loss: a late FIN from an earlier connection must
                // not consume this scenario's deterministic loss injection.
                let socket = tokio::net::TcpSocket::new_v4().unwrap();
                socket.bind("198.18.0.1:0".parse().unwrap()).unwrap();
                client_port.store(socket.local_addr().unwrap().port(), Ordering::SeqCst);
                lose_fin.store(loss, Ordering::SeqCst);
                dropped_fin.store(false, Ordering::SeqCst);
                let request = vec![0x51; size];
                let response = vec![0x72; size];
                let client_request = request.clone();
                let client_response = response.clone();
                let client = tokio::spawn(async move {
                    let mut socket = socket.connect("198.18.0.2:18089".parse().unwrap()).await.unwrap();
                    socket.set_nodelay(true).unwrap();
                    let mut result = Vec::new();
                    if mode == "server-first" {
                        socket.read_to_end(&mut result).await.unwrap();
                        socket.write_all(&client_request).await.unwrap();
                        socket.shutdown().await.unwrap();
                    } else {
                        socket.write_all(&client_request).await.unwrap();
                        socket.shutdown().await.unwrap();
                        socket.read_to_end(&mut result).await.unwrap();
                    }
                    assert_eq!(result, client_response);
                });
                tokio::time::timeout(Duration::from_secs(45), async {
                    let mut stream = loop {
                        match stack.accept().await.unwrap() {
                            IpStackStream::Tcp(stream) => break stream,
                            // Linux may solicit an IPv6 router when the TUN comes up.
                            // This IPv4 TCP matrix does not consume that control traffic.
                            IpStackStream::UnknownTransport(other)
                                if other.ip_protocol().0 == 58
                                    && other.src_addr().is_ipv6()
                                    && other.dst_addr() == "ff02::2".parse::<std::net::IpAddr>().unwrap()
                                    && other.payload().starts_with(&[133, 0]) =>
                            {
                                eprintln!("CONTROL ipv6_router_solicitation src={}", other.src_addr());
                            }
                            IpStackStream::UnknownTransport(other) => panic!(
                                "expected TCP: protocol={:?} src={} dst={} payload={:02x?}",
                                other.ip_protocol(),
                                other.src_addr(),
                                other.dst_addr(),
                                other.payload()
                            ),
                            IpStackStream::UnknownNetwork(bytes) => panic!("expected TCP: unknown network={bytes:02x?}"),
                            IpStackStream::Udp(_) => panic!("expected TCP: got UDP"),
                        }
                    };
                    let mut received = Vec::new();
                    if mode == "server-first" {
                        stream.write_all(&response).await.unwrap();
                        let (mut reader, mut writer) = tokio::io::split(stream);
                        tokio::try_join!(writer.shutdown(), reader.read_to_end(&mut received)).unwrap();
                    } else if mode == "simultaneous" {
                        // Read the known request length, then close without first waiting for EOF.
                        received.resize(size, 0);
                        stream.read_exact(&mut received).await.unwrap();
                        stream.write_all(&response).await.unwrap();
                        stream.shutdown().await.unwrap();
                    } else {
                        stream.read_to_end(&mut received).await.unwrap();
                        stream.write_all(&response).await.unwrap();
                        if mode == "drop" {
                            drop(stream);
                        } else {
                            stream.shutdown().await.unwrap();
                        }
                    }
                    assert_eq!(received, request);
                    client.await.unwrap();
                })
                .await
                .unwrap_or_else(|_| panic!("timeout for {mode}, bytes={size}, loss={loss}"));
                assert_eq!(dropped_fin.load(Ordering::SeqCst), loss);
                eprintln!("PASS mode={mode} bytes={size} dropped_first_stack_fin={loss}");
            }
        }
    }
    if std::env::var_os("IPSTACK_TEST_NETEM").is_some() {
        let status = std::process::Command::new("tc")
            .args(["-s", "qdisc", "show", "dev", "ipstack-test"])
            .status()
            .unwrap();
        assert!(status.success(), "netem statistics collection failed");
    }
}
