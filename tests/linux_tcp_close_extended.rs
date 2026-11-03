#![cfg(target_os = "linux")]
//! Deterministic close-handshake faults against real IPv4 and IPv6 Linux sockets.
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    None,
    Fins(usize),
    AckToStack,
    AckToKernel,
    ReorderData,
    CrossFins,
}

#[derive(Clone, Copy)]
struct Packet {
    version: u8,
    src: u16,
    dst: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    len: usize,
}
impl Packet {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let version = *bytes.first()? >> 4;
        let offset = match version {
            4 if bytes.len() >= 20 && bytes[9] == 6 => usize::from(bytes[0] & 15) * 4,
            6 if bytes.len() >= 40 && bytes[6] == 6 => 40,
            _ => return None,
        };
        let tcp = bytes.get(offset..)?;
        let header = usize::from(*tcp.get(12)? >> 4) * 4;
        if header < 20 || tcp.len() < header {
            return None;
        }
        Some(Self {
            version,
            src: u16::from_be_bytes(tcp[0..2].try_into().ok()?),
            dst: u16::from_be_bytes(tcp[2..4].try_into().ok()?),
            seq: u32::from_be_bytes(tcp[4..8].try_into().ok()?),
            ack: u32::from_be_bytes(tcp[8..12].try_into().ok()?),
            flags: tcp[13],
            len: tcp.len() - header,
        })
    }
    fn fin(self) -> bool {
        self.flags & 1 != 0
    }
    fn pure_ack(self) -> bool {
        self.flags == 0x10 && self.len == 0
    }
}

struct Trace {
    version: u8,
    port: u16,
    fault: Fault,
    stack_fins: Vec<u32>,
    kernel_fins: Vec<u32>,
    dropped_fins: usize,
    dropped_ack: usize,
    stack_ack_passed: usize,
    kernel_ack_passed: usize,
    reordered_pairs: usize,
    resets: usize,
    late_resets: usize,
    peer_fin_reply_attempts: usize,
    crossed_peer_fin: bool,
    released_cross_fin: bool,
}
impl Trace {
    fn new(version: u8, port: u16, fault: Fault) -> Self {
        Self {
            version,
            port,
            fault,
            stack_fins: vec![],
            kernel_fins: vec![],
            dropped_fins: 0,
            dropped_ack: 0,
            stack_ack_passed: 0,
            kernel_ack_passed: 0,
            reordered_pairs: 0,
            resets: 0,
            late_resets: 0,
            peer_fin_reply_attempts: 0,
            crossed_peer_fin: false,
            released_cross_fin: false,
        }
    }
    fn matches(&self, p: Packet, outgoing: bool) -> bool {
        p.version == self.version
            && if outgoing {
                p.src == 18089 && p.dst == self.port
            } else {
                p.src == self.port && p.dst == 18089
            }
    }
    fn fin_ack(&self, p: Packet, outgoing: bool) -> bool {
        let fins = if outgoing { &self.kernel_fins } else { &self.stack_fins };
        p.flags & 0x10 != 0 && fins.first().is_some_and(|seq| p.ack == seq.wrapping_add(1))
    }
    fn should_drop(&self, p: Packet, outgoing: bool) -> bool {
        if !self.matches(p, outgoing) {
            return false;
        }
        match self.fault {
            Fault::Fins(count) => outgoing && p.fin() && self.dropped_fins < count,
            Fault::AckToStack => !outgoing && p.pure_ack() && self.dropped_ack == 0 && self.fin_ack(p, outgoing),
            Fault::AckToKernel => outgoing && p.pure_ack() && self.dropped_ack == 0 && self.fin_ack(p, outgoing),
            _ => false,
        }
    }
    fn record(&mut self, p: Packet, outgoing: bool, dropped: bool) {
        if !self.matches(p, outgoing) {
            return;
        }
        if p.flags & 4 != 0 {
            // A delayed duplicate FIN can arrive after Linux has consumed our
            // final ACK and closed. Its RST in reply to the required duplicate
            // FIN ACK is distinct from an unsolicited extra window ACK.
            let late = !outgoing
                && p.flags == 4
                && p.ack == 0
                && p.len == 0
                && self.kernel_fins.len() > 1
                && self.kernel_fins.first().is_some_and(|fin| p.seq == fin.wrapping_add(1))
                && !self.stack_fins.is_empty()
                && self.stack_ack_passed > 0
                && self.kernel_ack_passed > 0
                && self.peer_fin_reply_attempts == self.kernel_fins.len();
            if late {
                self.late_resets += 1;
            } else {
                self.resets += 1;
            }
            let label = if late { "LATE_CLOSED_PEER_RST" } else { "WIRE_RESET" };
            eprintln!(
                "{label} outgoing={outgoing} v={} src={} dst={} seq={} ack={} flags={} len={} stack_fins={:?} kernel_fins={:?}",
                p.version, p.src, p.dst, p.seq, p.ack, p.flags, p.len, self.stack_fins, self.kernel_fins
            );
        }
        if p.fin() {
            if !outgoing && self.fault == Fault::CrossFins && !self.stack_fins.is_empty() && !self.released_cross_fin {
                // The kernel sent its FIN before it could have seen ours.
                self.crossed_peer_fin = true;
            }
            let seq = p.seq.wrapping_add(p.len as u32);
            let fins = if outgoing { &mut self.stack_fins } else { &mut self.kernel_fins };
            if let Some(first) = fins.first() {
                assert_eq!(*first, seq, "FIN retransmission changed sequence");
            }
            fins.push(seq);
            if dropped {
                self.dropped_fins += 1;
            }
        }
        if self.fin_ack(p, outgoing) {
            if outgoing && p.pure_ack() {
                self.peer_fin_reply_attempts += 1;
            }
            if dropped && !p.fin() {
                self.dropped_ack += 1;
            } else if !dropped && outgoing {
                self.stack_ack_passed += 1;
            } else if !dropped {
                self.kernel_ack_passed += 1;
            }
        }
    }
    fn fault_recovered(&self) -> bool {
        // EOF alone is insufficient, including in cases without injected loss.
        if self.stack_fins.is_empty() || self.kernel_fins.is_empty() || self.stack_ack_passed == 0 || self.kernel_ack_passed == 0 {
            return false;
        }
        match self.fault {
            Fault::None => true,
            Fault::Fins(n) => self.dropped_fins == n && self.stack_fins.len() > n && self.kernel_ack_passed > 0,
            Fault::AckToStack => self.dropped_ack == 1 && self.stack_fins.len() >= 2 && self.kernel_ack_passed > 0,
            Fault::AckToKernel => self.dropped_ack == 1 && self.kernel_fins.len() >= 2 && self.stack_ack_passed > 0,
            Fault::ReorderData => self.reordered_pairs == 1,
            Fault::CrossFins => self.crossed_peer_fin && self.released_cross_fin && self.kernel_ack_passed > 0,
        }
    }
}

struct FaultTun {
    device: tun::AsyncDevice,
    trace: Arc<Mutex<Trace>>,
    buffer: Vec<u8>,
    held: Option<Vec<u8>>,
    release_held: bool,
    held_fin: Option<Vec<u8>>,
}
impl AsyncRead for FaultTun {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.release_held {
            let bytes = this.held.take().unwrap();
            this.release_held = false;
            output.put_slice(&bytes);
            return Poll::Ready(Ok(()));
        }
        loop {
            let mut buffer = ReadBuf::new(&mut this.buffer);
            match Pin::new(&mut this.device).poll_read(cx, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            let bytes = buffer.filled();
            if let Some(packet) = Packet::parse(bytes) {
                let mut trace = this.trace.lock().unwrap();
                let dropped = trace.should_drop(packet, false);
                trace.record(packet, false, dropped);
                if dropped {
                    continue;
                }
                if trace.fault == Fault::ReorderData
                    && trace.matches(packet, false)
                    && packet.len > 0
                    && !packet.fin()
                    && trace.reordered_pairs == 0
                {
                    if this.held.is_none() {
                        this.held = Some(bytes.to_vec());
                        continue;
                    }
                    trace.reordered_pairs += 1;
                    this.release_held = true;
                    cx.waker().wake_by_ref();
                }
            }
            output.put_slice(bytes);
            return Poll::Ready(Ok(()));
        }
    }
}
impl AsyncWrite for FaultTun {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let packet = Packet::parse(bytes);
        if let Some(packet) = packet {
            let hold = {
                let trace = self.trace.lock().unwrap();
                trace.matches(packet, true) && trace.fault == Fault::CrossFins && packet.fin() && !trace.released_cross_fin
            };
            if hold {
                self.trace.lock().unwrap().record(packet, true, false);
                self.held_fin = Some(bytes.to_vec());
                return Poll::Ready(Ok(bytes.len()));
            }
            let release = {
                let trace = self.trace.lock().unwrap();
                self.held_fin.is_some() && trace.matches(packet, true) && trace.fin_ack(packet, true) && !packet.fin()
            };
            if release {
                let this = self.as_mut().get_mut();
                let held = this.held_fin.as_ref().unwrap();
                match Pin::new(&mut this.device).poll_write(cx, held) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(size)) => {
                        assert_eq!(size, held.len());
                        this.held_fin = None;
                        this.trace.lock().unwrap().released_cross_fin = true;
                    }
                }
            }
        }
        if let Some(packet) = packet {
            let mut trace = self.trace.lock().unwrap();
            if trace.should_drop(packet, true) {
                trace.record(packet, true, true);
                return Poll::Ready(Ok(bytes.len()));
            }
        }
        let result = Pin::new(&mut self.device).poll_write(cx, bytes);
        if matches!(&result, Poll::Ready(Ok(n)) if *n == bytes.len())
            && let Some(packet) = packet
        {
            self.trace.lock().unwrap().record(packet, true, false);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_shutdown(cx)
    }
}

fn command(program: &str, args: &[&str]) {
    assert!(
        std::process::Command::new(program).args(args).status().unwrap().success(),
        "{program} {args:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TUN and an isolated Linux network namespace"]
async fn linux_kernel_extended_close_matrix() {
    assert_eq!(std::env::var("IPSTACK_TEST_NETNS").as_deref(), Ok("1"));
    let _ = env_logger::try_init();
    let profile = std::env::var("IPSTACK_EXT_PROFILE").unwrap_or_else(|_| "clean".into());
    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name("ipstack-ext")
        .address((198, 18, 1, 1))
        .destination((198, 18, 1, 2))
        .netmask((255, 255, 255, 0))
        .mtu(1500)
        .up();
    let trace = Arc::new(Mutex::new(Trace::new(4, 0, Fault::None)));
    let device = FaultTun {
        device: tun::create_as_async(&tun_config).unwrap(),
        trace: trace.clone(),
        buffer: vec![0; 65536],
        held: None,
        release_held: false,
        held_fin: None,
    };
    command("ip", &["-6", "addr", "add", "fd42:89:112::1/64", "dev", "ipstack-ext", "nodad"]);
    let mut config = IpStackConfig::default();
    config.mtu(1500).unwrap();
    let mut stack = IpStack::new(config, device);
    match profile.as_str() {
        "clean" => {}
        "netem" => command(
            "tc",
            &["qdisc", "add", "dev", "ipstack-ext", "root", "netem", "delay", "10ms", "loss", "1%"],
        ),
        "reorder" => command(
            "tc",
            &[
                "qdisc",
                "add",
                "dev",
                "ipstack-ext",
                "root",
                "netem",
                "delay",
                "10ms",
                "reorder",
                "25%",
                "50%",
            ],
        ),
        _ => panic!("unknown profile {profile}"),
    }
    for version in [4, 6] {
        for size in [5usize, 131_072] {
            for mode in ["client-first", "server-first", "simultaneous", "drop", "crossed"] {
                let mut faults = vec![Fault::None, Fault::Fins(1), Fault::Fins(2), Fault::Fins(3)];
                if matches!(mode, "client-first" | "drop") {
                    faults.push(Fault::AckToStack);
                }
                if mode == "server-first" {
                    faults.push(Fault::AckToKernel);
                }
                if size > 5 {
                    faults.push(Fault::ReorderData);
                }
                if mode == "crossed" {
                    faults = vec![Fault::CrossFins];
                }
                for fault in faults {
                    let case = format!("v{version}/{mode}/{size}/{fault:?}");
                    if let Ok(filter) = std::env::var("IPSTACK_EXT_CASE")
                        && !filter.is_empty()
                        && case != filter
                    {
                        continue;
                    }
                    let socket = if version == 4 {
                        tokio::net::TcpSocket::new_v4()
                    } else {
                        tokio::net::TcpSocket::new_v6()
                    }
                    .unwrap();
                    let (local, remote) = if version == 4 {
                        ("198.18.1.1:0", "198.18.1.2:18089")
                    } else {
                        ("[fd42:89:112::1]:0", "[fd42:89:112::2]:18089")
                    };
                    socket.bind(local.parse().unwrap()).unwrap();
                    *trace.lock().unwrap() = Trace::new(version, socket.local_addr().unwrap().port(), fault);
                    let request: Vec<u8> = (0..size).map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8).collect();
                    let response: Vec<u8> = (0..size).map(|i| (i.wrapping_mul(67) ^ (i >> 9) ^ 0xa5) as u8).collect();
                    let client_request = request.clone();
                    let client_response = response.clone();
                    let client_trace = trace.clone();
                    let client = tokio::spawn(async move {
                        let mut socket = socket.connect(remote.parse().unwrap()).await.unwrap();
                        socket.set_nodelay(true).unwrap();
                        let mut received = Vec::new();
                        if mode == "server-first" {
                            socket.read_to_end(&mut received).await.unwrap();
                            socket.write_all(&client_request).await.unwrap();
                            socket.shutdown().await.unwrap();
                        } else if mode == "crossed" {
                            socket.write_all(&client_request).await.unwrap();
                            received.resize(size, 0);
                            socket.read_exact(&mut received).await.unwrap();
                            while client_trace.lock().unwrap().stack_fins.is_empty() {
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                            socket.shutdown().await.unwrap();
                            socket.read_to_end(&mut received).await.unwrap();
                        } else {
                            socket.write_all(&client_request).await.unwrap();
                            socket.shutdown().await.unwrap();
                            socket.read_to_end(&mut received).await.unwrap();
                        }
                        assert_eq!(received, client_response);
                    });
                    let result = tokio::time::timeout(Duration::from_secs(45), async {
                        let mut stream = loop {
                            match stack.accept().await.unwrap() {
                                IpStackStream::Tcp(stream) => break stream,
                                IpStackStream::UnknownTransport(other)
                                    if other.ip_protocol().0 == 58 && other.dst_addr().is_multicast() =>
                                {
                                    eprintln!("CONTROL icmpv6 dst={} type={:?}", other.dst_addr(), other.payload().first());
                                }
                                _ => panic!("unexpected non-TCP stream"),
                            }
                        };
                        let mut received = Vec::new();
                        if mode == "server-first" {
                            stream.write_all(&response).await.unwrap();
                            let (mut reader, mut writer) = tokio::io::split(stream);
                            tokio::try_join!(writer.shutdown(), reader.read_to_end(&mut received)).unwrap();
                        } else if matches!(mode, "simultaneous" | "crossed") {
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
                        while !trace.lock().unwrap().fault_recovered() {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    })
                    .await;
                    let state = trace.lock().unwrap();
                    assert!(
                        result.is_ok(),
                        "timeout profile={profile} v={version} mode={mode} bytes={size} fault={fault:?} stack_fin={} kernel_fin={} drop_fin={} drop_ack={} stack_ack={} kernel_ack={}",
                        state.stack_fins.len(),
                        state.kernel_fins.len(),
                        state.dropped_fins,
                        state.dropped_ack,
                        state.stack_ack_passed,
                        state.kernel_ack_passed
                    );
                    assert_eq!(state.resets, 0, "unexpected RST in {case}");
                    eprintln!(
                        "PASS_EXT profile={profile} v={version} mode={mode} bytes={size} fault={fault:?} stack_fin={} kernel_fin={} drop_fin={} drop_ack={} reorder={} crossed={} stack_ack={} kernel_ack={} late_rst={}",
                        state.stack_fins.len(),
                        state.kernel_fins.len(),
                        state.dropped_fins,
                        state.dropped_ack,
                        state.reordered_pairs,
                        state.crossed_peer_fin && state.released_cross_fin,
                        state.stack_ack_passed,
                        state.kernel_ack_passed,
                        state.late_resets
                    );
                }
            }
        }
    }
    command("tc", &["-s", "qdisc", "show", "dev", "ipstack-ext"]);
}
