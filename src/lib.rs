#![doc = include_str!("../README.md")]

use ahash::AHashMap;
use packet::{NetworkPacket, NetworkTuple, TransportHeader};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

pub(crate) type PacketSender = UnboundedSender<NetworkPacket>;
pub(crate) type PacketReceiver = UnboundedReceiver<NetworkPacket>;
pub(crate) type SessionCollection = AHashMap<NetworkTuple, PacketSender>;

mod error;
mod packet;
mod stream;

pub use self::error::{IpStackError, Result};
pub use self::stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport};
pub use self::stream::{TcpConfig, TcpOptions};
pub use etherparse::IpNumber;

#[cfg(unix)]
const TTL: u8 = 64;

#[cfg(windows)]
const TTL: u8 = 128;

#[cfg(unix)]
const TUN_FLAGS: [u8; 2] = [0x00, 0x00];

#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "espidf"))]
const TUN_PROTO_IP6: [u8; 2] = [0x86, 0xdd];
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "espidf"))]
const TUN_PROTO_IP4: [u8; 2] = [0x08, 0x00];

#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP6: [u8; 2] = [0x00, 0x0A];
#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP4: [u8; 2] = [0x00, 0x02];

/// Minimum MTU required for IPv6 (per RFC 8200 §5: MTU ≥ 1280).
/// Also satisfies IPv4 minimum MTU (RFC 791 §3.1: 68 bytes).
const MIN_MTU: u16 = 1280;

/// Configuration for the IP stack.
///
/// This structure holds configuration parameters that control the behavior of the IP stack,
/// including network settings and protocol-specific timeouts.
///
/// # Examples
///
/// ```
/// use ipstack::IpStackConfig;
/// use std::time::Duration;
///
/// let mut config = IpStackConfig::default();
/// config.mtu(1500).expect("Failed to set MTU")
///       .udp_timeout(Duration::from_secs(60))
///       .packet_information(false);
/// ```
#[non_exhaustive]
pub struct IpStackConfig {
    /// Maximum Transmission Unit (MTU) size in bytes.
    /// Default is `MIN_MTU` (1280).
    pub mtu: u16,
    /// Whether to include packet information headers (Unix platforms only).
    /// Default is `false`.
    pub packet_information: bool,
    /// TCP-specific configuration parameters.
    pub tcp_config: Arc<TcpConfig>,
    /// Timeout for UDP connections.
    /// Default is 30 seconds.
    pub udp_timeout: Duration,
}

impl Default for IpStackConfig {
    fn default() -> Self {
        IpStackConfig {
            mtu: MIN_MTU,
            packet_information: false,
            tcp_config: Arc::new(TcpConfig::default()),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

impl IpStackConfig {
    /// Set custom TCP configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The TCP configuration to use
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::{IpStackConfig, TcpConfig};
    ///
    /// let mut config = IpStackConfig::default();
    /// config.with_tcp_config(TcpConfig::default());
    /// ```
    pub fn with_tcp_config(&mut self, config: TcpConfig) -> &mut Self {
        self.tcp_config = Arc::new(config);
        self
    }

    /// Set the UDP connection timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout duration for UDP connections
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::IpStackConfig;
    /// use std::time::Duration;
    ///
    /// let mut config = IpStackConfig::default();
    /// config.udp_timeout(Duration::from_secs(60));
    /// ```
    pub fn udp_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.udp_timeout = timeout;
        self
    }

    /// Set the Maximum Transmission Unit (MTU) size.
    ///
    /// # Arguments
    ///
    /// * `mtu` - The MTU size in bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::IpStackConfig;
    ///
    /// let mut config = IpStackConfig::default();
    /// config.mtu(1500).expect("Failed to set MTU");
    /// ```
    pub fn mtu(&mut self, mtu: u16) -> Result<&mut Self, IpStackError> {
        if mtu < MIN_MTU {
            return Err(IpStackError::InvalidMtuSize(mtu));
        }
        self.mtu = mtu;
        Ok(self)
    }

    /// Set the Maximum Transmission Unit (MTU) size without validation.
    pub fn mtu_unchecked(&mut self, mtu: u16) -> &mut Self {
        self.mtu = mtu;
        self
    }

    /// Enable or disable packet information headers (Unix platforms only).
    ///
    /// When enabled on Unix platforms, the TUN device will include 4-byte packet
    /// information headers.
    ///
    /// # Arguments
    ///
    /// * `packet_information` - Whether to include packet information headers
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::IpStackConfig;
    ///
    /// let mut config = IpStackConfig::default();
    /// config.packet_information(true);
    /// ```
    pub fn packet_information(&mut self, packet_information: bool) -> &mut Self {
        self.packet_information = packet_information;
        self
    }
}

/// The main IP stack instance.
///
/// `IpStack` provides a userspace TCP/IP stack implementation for TUN devices.
/// It processes network packets and creates stream abstractions for TCP, UDP, and
/// unknown transport protocols.
///
/// # Examples
///
/// ```no_run
/// use ipstack::{IpStack, IpStackConfig, IpStackStream};
/// use std::net::Ipv4Addr;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Configure TUN device
///     let mut config = tun::Configuration::default();
///     config
///         .address(Ipv4Addr::new(10, 0, 0, 1))
///         .netmask(Ipv4Addr::new(255, 255, 255, 0))
///         .up();
///
///     // Create IP stack
///     let ipstack_config = IpStackConfig::default();
///     let mut ip_stack = IpStack::new(ipstack_config, tun::create_as_async(&config)?);
///
///     // Accept incoming streams
///     while let Ok(stream) = ip_stack.accept().await {
///         match stream {
///             IpStackStream::Tcp(tcp) => {
///                 // Handle TCP connection
///             }
///             IpStackStream::Udp(udp) => {
///                 // Handle UDP connection
///             }
///             _ => {}
///         }
///     }
///     Ok(())
/// }
/// ```
pub struct IpStack {
    accept_receiver: UnboundedReceiver<IpStackStream>,
    handle: JoinHandle<Result<()>>,
}

impl IpStack {
    /// Create a new IP stack instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the IP stack
    /// * `device` - An async TUN device implementing `AsyncRead` + `AsyncWrite`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ipstack::{IpStack, IpStackConfig};
    /// use std::net::Ipv4Addr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut tun_config = tun::Configuration::default();
    /// tun_config.address(Ipv4Addr::new(10, 0, 0, 1))
    ///           .netmask(Ipv4Addr::new(255, 255, 255, 0))
    ///           .up();
    ///
    /// let ipstack_config = IpStackConfig::default();
    /// let ip_stack = IpStack::new(ipstack_config, tun::create_as_async(&tun_config)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<Device>(config: IpStackConfig, device: Device) -> IpStack
    where
        Device: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (accept_sender, accept_receiver) = mpsc::unbounded_channel::<IpStackStream>();
        IpStack {
            accept_receiver,
            handle: run(config, device, accept_sender),
        }
    }

    /// Accept an incoming network stream.
    ///
    /// This method waits for and returns the next incoming network connection or packet.
    /// The returned `IpStackStream` enum indicates the type of stream (TCP, UDP, or unknown).
    ///
    /// # Returns
    ///
    /// * `Ok(IpStackStream)` - The next incoming stream
    /// * `Err(IpStackError::AcceptError)` - If the IP stack has been shut down
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ipstack::{IpStack, IpStackConfig, IpStackStream};
    ///
    /// # async fn example(mut ip_stack: IpStack) -> Result<(), Box<dyn std::error::Error>> {
    /// match ip_stack.accept().await? {
    ///     IpStackStream::Tcp(tcp) => {
    ///         println!("New TCP connection from {}", tcp.peer_addr());
    ///     }
    ///     IpStackStream::Udp(udp) => {
    ///         println!("New UDP stream from {}", udp.peer_addr());
    ///     }
    ///     IpStackStream::UnknownTransport(unknown) => {
    ///         println!("Unknown transport protocol: {:?}", unknown.ip_protocol());
    ///     }
    ///     IpStackStream::UnknownNetwork(data) => {
    ///         println!("Unknown network packet: {} bytes", data.len());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn accept(&mut self) -> Result<IpStackStream, IpStackError> {
        self.accept_receiver.recv().await.ok_or(IpStackError::AcceptError)
    }
}

impl Drop for IpStack {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn run<Device: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    config: IpStackConfig,
    mut device: Device,
    accept_sender: UnboundedSender<IpStackStream>,
) -> JoinHandle<Result<()>> {
    let mut sessions: SessionCollection = AHashMap::new();
    let (session_remove_tx, mut session_remove_rx) = mpsc::unbounded_channel::<NetworkTuple>();
    let pi = config.packet_information;
    let offset = if pi && cfg!(unix) { 4 } else { 0 };
    let mut buffer = vec![0_u8; config.mtu as usize + offset];
    let mut outgoing_buffer = Vec::with_capacity(config.mtu as usize + offset);
    let (up_pkt_sender, mut up_pkt_receiver) = mpsc::unbounded_channel::<NetworkPacket>();

    tokio::spawn(async move {
        loop {
            select! {
                read_result = device.read(&mut buffer) => {
                    let n = match read_result {
                        Ok(0) => {
                            log::info!("Device EOF, stopping IP stack");
                            return Ok(());
                        }
                        Ok(n) if n <= offset => {
                            log::warn!("Discarding packet smaller than header offset: received {n} bytes, expected > {offset} bytes");
                            continue;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            log::error!("Device read error: {e}");
                            return Err(e.into());
                        }
                    };
                    if let Err(e) = process_device_read(&buffer[offset..n], &mut sessions, &session_remove_tx, &up_pkt_sender, &config, &accept_sender).await {
                        let io_err: std::io::Error = e.into();
                        if io_err.kind() == std::io::ErrorKind::ConnectionRefused {
                            log::trace!("Received junk data: {io_err}");
                        } else {
                            log::warn!("process_device_read error: {io_err}");
                        }
                    }
                }
                Some(network_tuple) = session_remove_rx.recv() => {
                    remove_closed_session(&mut sessions, network_tuple);
                }
                Some(packet) = up_pkt_receiver.recv() => {
                    process_upstream_recv(packet, &mut device, &mut outgoing_buffer, #[cfg(unix)]pi).await?;
                }
            }
        }
    })
}

fn remove_closed_session(sessions: &mut SessionCollection, network_tuple: NetworkTuple) {
    // A dead stream may already have been replaced while its destroy notification
    // was queued. Never remove a live replacement on behalf of the old stream.
    if sessions.get(&network_tuple).is_some_and(PacketSender::is_closed) {
        sessions.remove(&network_tuple);
        log::debug!("session destroyed: {network_tuple}");
    }
}

async fn process_device_read(
    data: &[u8],
    sessions: &mut SessionCollection,
    session_remove_tx: &UnboundedSender<NetworkTuple>,
    up_pkt_sender: &PacketSender,
    config: &IpStackConfig,
    accept_sender: &UnboundedSender<IpStackStream>,
) -> Result<()> {
    let Ok(packet) = NetworkPacket::parse(data) else {
        let stream = IpStackStream::UnknownNetwork(data.to_owned());
        accept_sender.send(stream)?;
        return Ok(());
    };

    if let TransportHeader::Unknown = packet.transport_header() {
        let stream = IpStackStream::UnknownTransport(IpStackUnknownTransport::new(
            packet.src_addr().ip(),
            packet.dst_addr().ip(),
            packet.payload.unwrap_or_default(),
            &packet.ip,
            config.mtu,
            up_pkt_sender.clone(),
        ));
        accept_sender.send(stream)?;
        return Ok(());
    }

    let network_tuple = packet.network_tuple();
    match sessions.entry(network_tuple) {
        std::collections::hash_map::Entry::Occupied(entry) => {
            let len = packet.payload.as_ref().map(|p| p.len()).unwrap_or(0);
            log::trace!("packet sent to stream: {network_tuple} len {len}");
            if let Err(send_error) = entry.get().send(packet) {
                // The receiver is gone, but its removal notification has not yet been
                // processed (issue #81). Keep this packet as the new stream's first packet.
                let packet = send_error.0;
                entry.remove();
                create_and_register_stream(
                    packet,
                    network_tuple,
                    sessions,
                    session_remove_tx,
                    up_pkt_sender,
                    config,
                    accept_sender,
                )?;
            }
        }
        std::collections::hash_map::Entry::Vacant(_) => {
            create_and_register_stream(
                packet,
                network_tuple,
                sessions,
                session_remove_tx,
                up_pkt_sender,
                config,
                accept_sender,
            )?;
        }
    }
    Ok(())
}

fn create_and_register_stream(
    packet: NetworkPacket,
    network_tuple: NetworkTuple,
    sessions: &mut SessionCollection,
    session_remove_tx: &UnboundedSender<NetworkTuple>,
    up_pkt_sender: &PacketSender,
    config: &IpStackConfig,
    accept_sender: &UnboundedSender<IpStackStream>,
) -> Result<()> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let ip_stack_stream = create_stream(packet, config, up_pkt_sender.clone(), Some(tx))?;
    let session_remove_tx = session_remove_tx.clone();
    tokio::spawn(async move {
        rx.await.ok();
        if let Err(e) = session_remove_tx.send(network_tuple) {
            log::error!("Failed to send session removal for {network_tuple}: {e}");
        }
    });
    let packet_sender = ip_stack_stream.stream_sender()?;
    accept_sender.send(ip_stack_stream)?;
    sessions.insert(network_tuple, packet_sender);
    log::debug!("session created: {network_tuple}");
    Ok(())
}

fn create_stream(
    packet: NetworkPacket,
    cfg: &IpStackConfig,
    up_pkt_sender: PacketSender,
    msgr: Option<::tokio::sync::oneshot::Sender<()>>,
) -> Result<IpStackStream> {
    let src_addr = packet.src_addr();
    let dst_addr = packet.dst_addr();
    match packet.transport_header() {
        TransportHeader::Tcp(h) => {
            let stream = IpStackTcpStream::new(src_addr, dst_addr, h.clone(), up_pkt_sender, cfg.mtu, msgr, cfg.tcp_config.clone())?;
            Ok(IpStackStream::Tcp(stream))
        }
        TransportHeader::Udp(_) => {
            let payload = packet.payload.unwrap_or_default();
            let stream = IpStackUdpStream::new(src_addr, dst_addr, payload, up_pkt_sender, cfg.mtu, cfg.udp_timeout, msgr);
            Ok(IpStackStream::Udp(stream))
        }
        TransportHeader::Unknown => Err(IpStackError::UnsupportedTransportProtocol),
    }
}

async fn process_upstream_recv<Device: AsyncWrite + Unpin + 'static>(
    up_packet: NetworkPacket,
    device: &mut Device,
    packet_bytes: &mut Vec<u8>,
    #[cfg(unix)] packet_information: bool,
) -> Result<()> {
    #[cfg(unix)]
    let metadata_len = if packet_information {
        TUN_FLAGS.len() + TUN_PROTO_IP4.len()
    } else {
        0
    };
    #[cfg(not(unix))]
    let metadata_len = 0;
    packet_bytes.clear();
    packet_bytes.reserve(metadata_len + up_packet.serialized_len());
    #[cfg(unix)]
    if packet_information {
        packet_bytes.extend_from_slice(&TUN_FLAGS);
        if up_packet.src_addr().is_ipv4() {
            packet_bytes.extend_from_slice(&TUN_PROTO_IP4);
        } else {
            packet_bytes.extend_from_slice(&TUN_PROTO_IP6);
        }
    }
    if up_packet.write_to(packet_bytes).is_err() {
        log::warn!("to_bytes error");
        return Ok(());
    }
    device.write_all(packet_bytes).await?;
    // device.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };

    use std::time::Duration;
    use tokio::{io::duplex, time::timeout};

    #[cfg(unix)]
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    fn udp_packet(payload: &[u8]) -> Vec<u8> {
        use etherparse::{IpNumber, Ipv4Header, UdpHeader};
        let mut ip = Ipv4Header::new(0, 64, IpNumber::UDP, [192, 0, 2, 1], [192, 0, 2, 2]).unwrap();
        ip.set_payload_len(payload.len() + 8).unwrap();
        let udp = UdpHeader::with_ipv4_checksum(53000, 53, &ip, payload).unwrap();
        NetworkPacket {
            ip: packet::IpHeader::Ipv4(ip),
            transport: TransportHeader::Udp(udp),
            payload: Some(payload.to_vec()),
        }
        .to_bytes()
        .unwrap()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn upstream_packet_information_precedes_serialized_ipv4_and_ipv6_packets() {
        use tokio::io::AsyncReadExt;

        let mut buffer = Vec::new();
        for ipv6 in [false, true] {
            let mut raw = Vec::new();
            if ipv6 {
                etherparse::PacketBuilder::ipv6([0; 16], [1; 16], 64)
                    .udp(1234, 5678)
                    .write(&mut raw, b"payload")
                    .unwrap();
            } else {
                raw = udp_packet(b"payload");
            }
            for packet_information in [false, true] {
                let packet = NetworkPacket::parse(&raw).unwrap();
                let mut expected = Vec::new();
                if packet_information {
                    expected.extend_from_slice(&TUN_FLAGS);
                    expected.extend_from_slice(if ipv6 { &TUN_PROTO_IP6 } else { &TUN_PROTO_IP4 });
                }
                expected.extend_from_slice(&packet.to_bytes().unwrap());
                let (mut device, mut peer) = duplex(256);
                process_upstream_recv(packet, &mut device, &mut buffer, packet_information)
                    .await
                    .unwrap();
                let mut actual = vec![0; expected.len()];
                peer.read_exact(&mut actual).await.unwrap();
                assert_eq!(actual, expected);
            }
        }
    }

    /// Exercise dispatch before the old removal notification is consumed, then pass that
    /// notification through the same handler used by the event loop.
    #[tokio::test]
    async fn dead_udp_session_preserves_payload_and_survives_stale_removal() {
        let mut sessions = SessionCollection::new();
        let (remove_tx, mut remove_rx) = mpsc::unbounded_channel();
        let (up_tx, _up_rx) = mpsc::unbounded_channel();
        let (accept_tx, mut accept_rx) = mpsc::unbounded_channel();
        let config = IpStackConfig::default();
        process_device_read(&udp_packet(b"first"), &mut sessions, &remove_tx, &up_tx, &config, &accept_tx)
            .await
            .unwrap();
        let first = accept_rx.recv().await.unwrap();
        let tuple = NetworkTuple::new(first.local_addr(), first.peer_addr(), false);
        drop(first);
        // Waiting for the notification does not remove the stale table entry.
        let old_notification = remove_rx.recv().await.unwrap();
        assert_eq!(old_notification, tuple);

        process_device_read(&udp_packet(b"replacement"), &mut sessions, &remove_tx, &up_tx, &config, &accept_tx)
            .await
            .expect("the first datagram after closure must recreate the session");
        let IpStackStream::Udp(mut replacement) = accept_rx.recv().await.unwrap() else {
            panic!("expected replacement UDP stream");
        };
        let mut buffer = [0; 64];
        let n = replacement.read(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..n], b"replacement");

        remove_closed_session(&mut sessions, old_notification);
        assert!(sessions.contains_key(&tuple), "old notification removed the replacement");
        process_device_read(&udp_packet(b"next"), &mut sessions, &remove_tx, &up_tx, &config, &accept_tx)
            .await
            .unwrap();
        let n = replacement.read(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..n], b"next");
        assert!(accept_rx.try_recv().is_err(), "a live replacement must be reused");

        drop(replacement);
        remove_closed_session(&mut sessions, remove_rx.recv().await.unwrap());
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn stale_udp_removal_does_not_remove_a_live_session() {
        let mut sessions = SessionCollection::new();
        let (sender, _receiver) = mpsc::unbounded_channel();
        let tuple = NetworkTuple::new("192.0.2.1:53000".parse().unwrap(), "192.0.2.2:53".parse().unwrap(), false);
        sessions.insert(tuple, sender);
        remove_closed_session(&mut sessions, tuple);
        assert!(sessions.contains_key(&tuple));
    }

    /// Run the real event loop, send no more packets after drop/expiration, and observe
    /// that it releases its sender. The retained probe is the only remaining strong sender.
    async fn udp_session_is_cleaned_without_more_traffic(expire: bool) {
        let (device, mut peer) = duplex(4096);
        let mut config = IpStackConfig::default();
        config.udp_timeout(Duration::from_secs(1));
        let mut stack = IpStack::new(config, device);
        peer.write_all(&udp_packet(b"first")).await.unwrap();
        let IpStackStream::Udp(mut stream) = stack.accept().await.unwrap() else {
            panic!("expected a UDP stream");
        };
        let probe = stream.stream_sender();
        let mut buffer = [0; 64];
        assert_eq!(stream.read(&mut buffer).await.unwrap(), 5);
        assert_eq!(probe.strong_count(), 3); // stream, table, and probe
        if expire {
            tokio::time::advance(Duration::from_secs(2)).await;
            assert_eq!(stream.read(&mut buffer).await.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        }
        drop(stream);
        // No device input or manual table manipulation: only the production event loop runs.
        for _ in 0..100 {
            if probe.strong_count() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(probe.strong_count(), 1, "closed UDP session remains in the table");
        assert!(!stack.handle.is_finished(), "cleanup must not stop the IP stack");
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_udp_session_is_cleaned_without_more_traffic() {
        udp_session_is_cleaned_without_more_traffic(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn expired_udp_session_is_cleaned_without_more_traffic() {
        udp_session_is_cleaned_without_more_traffic(true).await;
    }

    #[cfg(unix)]
    struct ChunkedDevice {
        chunks: VecDeque<Vec<u8>>,
    }

    #[cfg(unix)]
    impl ChunkedDevice {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self { chunks: chunks.into() }
        }
    }

    #[cfg(unix)]
    impl AsyncRead for ChunkedDevice {
        fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            if let Some(mut chunk) = self.chunks.pop_front() {
                let to_copy = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..to_copy]);
                chunk.drain(..to_copy);
                if !chunk.is_empty() {
                    self.chunks.push_front(chunk);
                }
            }

            Poll::Ready(Ok(()))
        }
    }

    #[cfg(unix)]
    impl AsyncWrite for ChunkedDevice {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn device_eof_closes_accept_channel() {
        let (device, peer) = duplex(64);
        let mut ip_stack = IpStack::new(IpStackConfig::default(), device);

        drop(peer);

        let accept_result = timeout(Duration::from_secs(1), ip_stack.accept())
            .await
            .expect("accept should not hang after device EOF");
        assert!(matches!(accept_result, Err(IpStackError::AcceptError)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn packet_smaller_than_header_offset_is_discarded_without_panic() {
        let mut config = IpStackConfig::default();
        config.packet_information(true);
        let mut packet_data = vec![0u8; 4];
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(1234, 5678);
        builder.write(&mut packet_data, &[1, 2, 3, 4]).unwrap();

        let device = ChunkedDevice::new(vec![vec![0x00, 0x01], packet_data]);
        let mut ip_stack = IpStack::new(config, device);

        let accepted = timeout(Duration::from_secs(1), ip_stack.accept())
            .await
            .expect("accept timed out")
            .expect("accept returned error");
        assert!(matches!(accepted, IpStackStream::Udp(_)));
    }
}
