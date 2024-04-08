use crate::{
    packet::IpStackPacketProtocol,
    stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport},
};
use ahash::AHashMap;
use log::{error, trace};
use packet::{NetworkPacket, NetworkTuple};
use std::{
    collections::hash_map::Entry::{Occupied, Vacant},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

mod error;
mod packet;
pub mod stream;

pub use self::error::{IpStackError, Result};

const DROP_TTL: u8 = 0;

#[cfg(unix)]
const TTL: u8 = 64;

#[cfg(windows)]
const TTL: u8 = 128;

#[cfg(unix)]
const TUN_FLAGS: [u8; 2] = [0x00, 0x00];

#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
const TUN_PROTO_IP6: [u8; 2] = [0x86, 0xdd];
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
const TUN_PROTO_IP4: [u8; 2] = [0x08, 0x00];

#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP6: [u8; 2] = [0x00, 0x0A];
#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP4: [u8; 2] = [0x00, 0x02];

pub struct IpStackConfig {
    pub mtu: u16,
    pub packet_information: bool,
    pub tcp_timeout: Duration,
    pub udp_timeout: Duration,
}

impl Default for IpStackConfig {
    fn default() -> Self {
        IpStackConfig {
            mtu: u16::MAX,
            packet_information: false,
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

impl IpStackConfig {
    pub fn tcp_timeout(&mut self, timeout: Duration) {
        self.tcp_timeout = timeout;
    }
    pub fn udp_timeout(&mut self, timeout: Duration) {
        self.udp_timeout = timeout;
    }
    pub fn mtu(&mut self, mtu: u16) {
        self.mtu = mtu;
    }
    pub fn packet_information(&mut self, packet_information: bool) {
        self.packet_information = packet_information;
    }
}

pub struct IpStack {
    accept_receiver: UnboundedReceiver<IpStackStream>,
    pub handle: JoinHandle<Result<()>>,
}

impl IpStack {
    pub fn new<D>(config: IpStackConfig, device: D) -> IpStack
    where
        D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (accept_sender, accept_receiver) = mpsc::unbounded_channel::<IpStackStream>();
        let handle = run(config, device, accept_sender);

        IpStack {
            accept_receiver,
            handle,
        }
    }

    pub async fn accept(&mut self) -> Result<IpStackStream, IpStackError> {
        self.accept_receiver
            .recv()
            .await
            .ok_or(IpStackError::AcceptError)
    }
}

fn run<D>(
    config: IpStackConfig,
    mut device: D,
    accept_sender: UnboundedSender<IpStackStream>,
) -> JoinHandle<Result<()>>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut streams: AHashMap<NetworkTuple, UnboundedSender<NetworkPacket>> = AHashMap::new();
    let offset = if config.packet_information && cfg!(unix) {
        4
    } else {
        0
    };
    let mut buffer = [0_u8; u16::MAX as usize + 4];
    let (pkt_sender, mut pkt_receiver) = mpsc::unbounded_channel::<NetworkPacket>();

    tokio::spawn(async move {
        loop {
            select! {
                Ok(n) = device.read(&mut buffer) => {
                    if let Some(stream) = process_read(
                        &buffer[offset..n],
                        &mut streams,
                        &pkt_sender,
                        &config,
                    )? {
                        accept_sender.send(stream)?;
                    }
                }
                Some(packet) = pkt_receiver.recv() => {
                    process_recv(
                        packet,
                        &mut streams,
                        &mut device,
                        #[cfg(unix)]
                        config.packet_information,
                    )
                    .await?;
                }
            }
        }
    })
}

fn process_read(
    data: &[u8],
    streams: &mut AHashMap<NetworkTuple, UnboundedSender<NetworkPacket>>,
    pkt_sender: &UnboundedSender<NetworkPacket>,
    config: &IpStackConfig,
) -> Result<Option<IpStackStream>> {
    let Ok(packet) = NetworkPacket::parse(data) else {
        return Ok(Some(IpStackStream::UnknownNetwork(data.to_owned())));
    };

    if let IpStackPacketProtocol::Unknown = packet.transport_protocol() {
        return Ok(Some(IpStackStream::UnknownTransport(
            IpStackUnknownTransport::new(
                packet.src_addr().ip(),
                packet.dst_addr().ip(),
                packet.payload,
                &packet.ip,
                config.mtu,
                pkt_sender.clone(),
            ),
        )));
    }

    Ok(match streams.entry(packet.network_tuple()) {
        Occupied(mut entry) => {
            if let Err(e) = entry.get().send(packet) {
                trace!("New stream because: {}", e);
                create_stream(e.0, config, pkt_sender)?.map(|s| {
                    entry.insert(s.0);
                    s.1
                })
            } else {
                None
            }
        }
        Vacant(entry) => create_stream(packet, config, pkt_sender)?.map(|s| {
            entry.insert(s.0);
            s.1
        }),
    })
}

fn create_stream(
    packet: NetworkPacket,
    config: &IpStackConfig,
    pkt_sender: &UnboundedSender<NetworkPacket>,
) -> Result<Option<(UnboundedSender<NetworkPacket>, IpStackStream)>> {
    match packet.transport_protocol() {
        IpStackPacketProtocol::Tcp(h) => {
            match IpStackTcpStream::new(
                packet.src_addr(),
                packet.dst_addr(),
                h,
                pkt_sender.clone(),
                config.mtu,
                config.tcp_timeout,
            ) {
                Ok(stream) => Ok(Some((stream.stream_sender(), IpStackStream::Tcp(stream)))),
                Err(e) => {
                    if matches!(e, IpStackError::InvalidTcpPacket) {
                        trace!("Invalid TCP packet");
                    } else {
                        error!("IpStackTcpStream::new failed \"{}\"", e);
                    }
                    Ok(None)
                }
            }
        }
        IpStackPacketProtocol::Udp => {
            let stream = IpStackUdpStream::new(
                packet.src_addr(),
                packet.dst_addr(),
                packet.payload,
                pkt_sender.clone(),
                config.mtu,
                config.udp_timeout,
            );
            Ok(Some((stream.stream_sender(), IpStackStream::Udp(stream))))
        }
        IpStackPacketProtocol::Unknown => {
            unreachable!()
        }
    }
}

async fn process_recv<D>(
    packet: NetworkPacket,
    streams: &mut AHashMap<NetworkTuple, UnboundedSender<NetworkPacket>>,
    device: &mut D,
    #[cfg(unix)] packet_information: bool,
) -> Result<()>
where
    D: AsyncWrite + Unpin + 'static,
{
    if packet.ttl() == 0 {
        streams.remove(&packet.reverse_network_tuple());
        return Ok(());
    }
    #[allow(unused_mut)]
    let Ok(mut packet_byte) = packet.to_bytes() else {
        trace!("to_bytes error");
        return Ok(());
    };
    #[cfg(unix)]
    if packet_information {
        if packet.src_addr().is_ipv4() {
            packet_byte.splice(0..0, [TUN_FLAGS, TUN_PROTO_IP4].concat());
        } else {
            packet_byte.splice(0..0, [TUN_FLAGS, TUN_PROTO_IP6].concat());
        }
    }
    device.write_all(&packet_byte).await?;
    // device.flush().await.unwrap();

    Ok(())
}
