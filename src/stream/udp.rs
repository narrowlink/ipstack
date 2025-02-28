use crate::{
    packet::{IpHeader, NetworkPacket, TransportHeader},
    IpStackError, PacketReceiver, PacketSender, TTL,
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, UdpHeader};
use std::{future::Future, net::SocketAddr, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
    time::Sleep,
};

#[derive(Debug)]
pub struct IpStackUdpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: PacketReceiver,
    up_pkt_sender: PacketSender,
    first_payload: Option<Vec<u8>>,
    timeout: Pin<Box<Sleep>>,
    timeout_interval: Duration,
    mtu: u16,
    destroy_messenger: Option<oneshot::Sender<()>>,
}

impl IpStackUdpStream {
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: Vec<u8>,
        up_pkt_sender: PacketSender,
        mtu: u16,
        timeout_interval: Duration,
    ) -> Self {
        let (stream_sender, stream_receiver) = mpsc::unbounded_channel::<NetworkPacket>();
        let deadline = tokio::time::Instant::now() + timeout_interval;
        IpStackUdpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver,
            up_pkt_sender,
            first_payload: Some(payload),
            timeout: Box::pin(tokio::time::sleep_until(deadline)),
            timeout_interval,
            mtu,
            destroy_messenger: None,
        }
    }

    pub(crate) fn set_destroy_messenger(&mut self, messenger: oneshot::Sender<()>) {
        self.destroy_messenger = Some(messenger);
    }

    pub(crate) fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    fn create_rev_packet(&self, ttl: u8, mut payload: Vec<u8>) -> std::io::Result<NetworkPacket> {
        const UHS: usize = 8; // udp header size is 8
        match (self.dst_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::UDP, dst.octets(), src.octets()).map_err(IpStackError::from)?;
                let line_buffer = self.mtu.saturating_sub((ip_h.header_len() + UHS) as u16);
                payload.truncate(line_buffer as usize);
                ip_h.set_payload_len(payload.len() + UHS).map_err(IpStackError::from)?;
                let udp_header = UdpHeader::with_ipv4_checksum(self.dst_addr.port(), self.src_addr.port(), &ip_h, &payload)
                    .map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv4(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload,
                })
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: IpNumber::UDP,
                    hop_limit: ttl,
                    source: dst.octets(),
                    destination: src.octets(),
                };
                let line_buffer = self.mtu.saturating_sub((ip_h.header_len() + UHS) as u16);

                payload.truncate(line_buffer as usize);

                ip_h.payload_length = (payload.len() + UHS) as u16;
                let udp_header = UdpHeader::with_ipv6_checksum(self.dst_addr.port(), self.src_addr.port(), &ip_h, &payload)
                    .map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv6(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload,
                })
            }
            _ => unreachable!(),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    fn reset_timeout(&mut self) {
        let deadline = tokio::time::Instant::now() + self.timeout_interval;
        self.timeout.as_mut().reset(deadline);
    }
}

impl AsyncRead for IpStackUdpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(p) = self.first_payload.take() {
            buf.put_slice(&p);
            return std::task::Poll::Ready(Ok(()));
        }
        if matches!(self.timeout.as_mut().poll(cx), std::task::Poll::Ready(_)) {
            return std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        }

        self.reset_timeout();

        match self.stream_receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(p)) => {
                buf.put_slice(&p.payload);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for IpStackUdpStream {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        self.reset_timeout();
        let packet = self.create_rev_packet(TTL, buf.to_vec())?;
        let payload_len = packet.payload.len();
        self.up_pkt_sender.send(packet).or(Err(std::io::ErrorKind::UnexpectedEof))?;
        std::task::Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for IpStackUdpStream {
    fn drop(&mut self) {
        if let Some(messenger) = self.destroy_messenger.take() {
            let _ = messenger.send(());
        }
    }
}
