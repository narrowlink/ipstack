use crate::{
    error::IpStackError,
    packet::{tcp_flags, IpStackPacketProtocol, TcpPacket, TransportHeader},
    stream::tcb::{Tcb, TcpState},
    DROP_TTL, TTL,
};
use etherparse::{IpNumber, Ipv4Extensions, Ipv4Header, Ipv6Extensions, Ipv6FlowLabel};
use std::{
    cmp,
    future::Future,
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    task::Waker,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};
#[cfg(feature = "log")]
use tracing::{trace, warn};

use crate::packet::NetworkPacket;

use super::tcb::PacketStatus;

#[derive(Debug, Default)]
enum Shutdown {
    Ready,
    Pending(Waker),
    #[default]
    None,
}

impl Shutdown {
    fn pending(&mut self, w: Waker) {
        *self = Shutdown::Pending(w);
    }
    fn ready(&mut self) {
        if let Shutdown::Pending(w) = self {
            w.wake_by_ref();
        }
        *self = Shutdown::Ready;
    }
}

#[derive(Debug)]
pub struct IpStackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: UnboundedSender<NetworkPacket>,
    stream_receiver: UnboundedReceiver<NetworkPacket>,
    packet_sender: UnboundedSender<NetworkPacket>,
    packet_to_send: Option<NetworkPacket>,
    tcb: Tcb,
    mtu: u16,
    shutdown: Shutdown,
    write_notify: Option<Waker>,
}

impl IpStackTcpStream {
    pub(crate) async fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp: TcpPacket,
        pkt_sender: UnboundedSender<NetworkPacket>,
        mtu: u16,
        tcp_timeout: Duration,
    ) -> Result<IpStackTcpStream, IpStackError> {
        let (stream_sender, stream_receiver) = mpsc::unbounded_channel::<NetworkPacket>();

        let mut stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver,
            packet_sender: pkt_sender.clone(),
            packet_to_send: None,
            tcb: Tcb::new(tcp.inner().sequence_number + 1, tcp_timeout),
            mtu,
            shutdown: Shutdown::default(),
            write_notify: None,
        };
        if !tcp.inner().syn {
            let flags = tcp_flags::RST | tcp_flags::ACK;
            pkt_sender
                .send(stream.create_rev_packet(flags, TTL, None, Vec::new())?)
                .map_err(|_| IpStackError::InvalidTcpPacket)?;
            stream.tcb.change_state(TcpState::Closed);
        }
        Ok(stream)
    }

    pub(crate) fn stream_sender(&self) -> UnboundedSender<NetworkPacket> {
        self.stream_sender.clone()
    }

    fn calculate_payload_len(&self, ip_header_size: u16, tcp_header_size: u16) -> u16 {
        cmp::min(
            self.tcb.get_send_window(),
            self.mtu.saturating_sub(ip_header_size + tcp_header_size),
        )
    }

    fn create_rev_packet(
        &self,
        flags: u8,
        ttl: u8,
        seq: impl Into<Option<u32>>,
        mut payload: Vec<u8>,
    ) -> Result<NetworkPacket, Error> {
        let mut tcp_header = etherparse::TcpHeader::new(
            self.dst_addr.port(),
            self.src_addr.port(),
            seq.into().unwrap_or(self.tcb.get_seq()),
            self.tcb.get_recv_window(),
        );

        tcp_header.acknowledgment_number = self.tcb.get_ack();
        if flags & tcp_flags::SYN != 0 {
            tcp_header.syn = true;
        }
        if flags & tcp_flags::ACK != 0 {
            tcp_header.ack = true;
        }
        if flags & tcp_flags::RST != 0 {
            tcp_header.rst = true;
        }
        if flags & tcp_flags::FIN != 0 {
            tcp_header.fin = true;
        }
        if flags & tcp_flags::PSH != 0 {
            tcp_header.psh = true;
        }

        let ip_header = match (self.dst_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::TCP, dst.octets(), src.octets())
                    .map_err(IpStackError::from)?;
                let payload_len = self.calculate_payload_len(
                    ip_h.header_len() as u16,
                    tcp_header.header_len() as u16,
                );
                payload.truncate(payload_len as usize);
                ip_h.set_payload_len(payload.len() + tcp_header.header_len())
                    .map_err(IpStackError::from)?;
                ip_h.dont_fragment = true;
                etherparse::NetHeaders::Ipv4(ip_h, Ipv4Extensions::default())
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = etherparse::Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: IpNumber::TCP,
                    hop_limit: ttl,
                    source: dst.octets(),
                    destination: src.octets(),
                };
                let payload_len = self.calculate_payload_len(
                    ip_h.header_len() as u16,
                    tcp_header.header_len() as u16,
                );
                payload.truncate(payload_len as usize);
                ip_h.payload_length = (payload.len() + tcp_header.header_len()) as u16;

                etherparse::NetHeaders::Ipv6(ip_h, Ipv6Extensions::default())
            }
            _ => unreachable!(),
        };

        match ip_header {
            etherparse::NetHeaders::Ipv4(ref ip_header, _) => {
                tcp_header.checksum = tcp_header
                    .calc_checksum_ipv4(ip_header, &payload)
                    .map_err(|_e| Error::from(ErrorKind::InvalidInput))?;
            }
            etherparse::NetHeaders::Ipv6(ref ip_header, _) => {
                tcp_header.checksum = tcp_header
                    .calc_checksum_ipv6(ip_header, &payload)
                    .map_err(|_e| Error::from(ErrorKind::InvalidInput))?;
            }
        }
        Ok(NetworkPacket {
            ip: ip_header,
            transport: TransportHeader::Tcp(tcp_header),
            payload,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if matches!(self.tcb.get_state(), TcpState::FinWait2(false)) {
                self.packet_to_send =
                    Some(self.create_rev_packet(0, DROP_TTL, None, Vec::new())?);
                self.tcb.change_state(TcpState::Closed);
                self.shutdown.ready();
                return std::task::Poll::Ready(Ok(()));
            }
            let min = cmp::min(self.tcb.get_available_read_buffer_size() as u16, u16::MAX);
            self.tcb.change_recv_window(min);
            if matches!(
                Pin::new(&mut self.tcb.timeout).poll(cx),
                std::task::Poll::Ready(_)
            ) {
                #[cfg(feature = "log")]
                trace!("timeout reached for {:?}", self.dst_addr);
                let flags = tcp_flags::RST | tcp_flags::ACK;
                self.packet_sender
                    .send(self.create_rev_packet(flags, TTL, None, Vec::new())?)
                    .map_err(|_| ErrorKind::UnexpectedEof)?;
                return std::task::Poll::Ready(Err(Error::from(ErrorKind::TimedOut)));
            }

            self.tcb.reset_timeout();

            if matches!(self.tcb.get_state(), TcpState::SynReceived(false)) {
                let flags = tcp_flags::SYN | tcp_flags::ACK;
                self.packet_to_send = Some(self.create_rev_packet(flags, TTL, None, Vec::new())?);
                self.tcb.add_seq_one();
                self.tcb.change_state(TcpState::SynReceived(true));
            }

            if let Some(packet) = self.packet_to_send.take() {
                self.packet_sender
                    .send(packet)
                    .map_err(|_| Error::from(ErrorKind::UnexpectedEof))?;
                if matches!(self.tcb.get_state(), TcpState::Closed) {
                    self.shutdown.ready();
                    return std::task::Poll::Ready(Ok(()));
                }
            }
            if let Some(b) = self.tcb.get_unordered_packets() {
                self.tcb.add_ack(b.len() as u32);
                buf.put_slice(&b);
                self.packet_sender
                    .send(self.create_rev_packet(tcp_flags::ACK, TTL, None, Vec::new())?)
                    .map_err(|_| Error::from(ErrorKind::UnexpectedEof))?;
                return std::task::Poll::Ready(Ok(()));
            }

            match self.stream_receiver.poll_recv(cx) {
                std::task::Poll::Ready(Some(p)) => {
                    let IpStackPacketProtocol::Tcp(t) = p.transport_protocol() else {
                        unreachable!()
                    };
                    if t.flags() & tcp_flags::RST != 0 {
                        self.packet_to_send =
                            Some(self.create_rev_packet(0, DROP_TTL, None, Vec::new())?);
                        self.tcb.change_state(TcpState::Closed);
                        return std::task::Poll::Ready(Err(Error::from(
                            ErrorKind::ConnectionReset,
                        )));
                    }
                    if matches!(
                        self.tcb.check_pkt_type(&t, &p.payload),
                        PacketStatus::Invalid
                    ) {
                        continue;
                    }

                    if matches!(self.tcb.get_state(), TcpState::SynReceived(true)) {
                        if t.flags() == tcp_flags::ACK {
                            self.tcb.change_last_ack(t.inner().acknowledgment_number);
                            self.tcb.change_send_window(t.inner().window_size);
                            self.tcb.change_state(TcpState::Established);
                        }
                    } else if matches!(self.tcb.get_state(), TcpState::Established) {
                        if t.flags() == tcp_flags::ACK {
                            match self.tcb.check_pkt_type(&t, &p.payload) {
                                PacketStatus::WindowUpdate => {
                                    self.tcb.change_send_window(t.inner().window_size);
                                    if let Some(ref n) = self.write_notify {
                                        n.wake_by_ref();
                                        self.write_notify = None;
                                    };
                                    continue;
                                }
                                PacketStatus::Invalid => continue,
                                PacketStatus::KeepAlive => {
                                    self.tcb.change_last_ack(t.inner().acknowledgment_number);
                                    self.tcb.change_send_window(t.inner().window_size);
                                    self.packet_to_send = Some(self.create_rev_packet(
                                        tcp_flags::ACK,
                                        TTL,
                                        None,
                                        Vec::new(),
                                    )?);
                                    continue;
                                }
                                PacketStatus::RetransmissionRequest => {
                                    self.tcb.change_send_window(t.inner().window_size);
                                    self.tcb.retransmission = Some(t.inner().acknowledgment_number);
                                    if matches!(
                                        self.as_mut().poll_flush(cx),
                                        std::task::Poll::Pending
                                    ) {
                                        return std::task::Poll::Pending;
                                    }
                                    continue;
                                }
                                PacketStatus::NewPacket => {
                                    // if t.inner().sequence_number != self.tcb.get_ack() {
                                    //     dbg!(t.inner().sequence_number);
                                    //     self.packet_to_send = Some(self.create_rev_packet(
                                    //         tcp_flags::ACK,
                                    //         TTL,
                                    //         None,
                                    //         Vec::new(),
                                    //     )?);
                                    //     continue;
                                    // }

                                    self.tcb.change_last_ack(t.inner().acknowledgment_number);
                                    self.tcb.add_unordered_packet(
                                        t.inner().sequence_number,
                                        &p.payload,
                                    );
                                    // buf.put_slice(&p.payload);
                                    // self.tcb.add_ack(p.payload.len() as u32);
                                    // self.packet_to_send = Some(self.create_rev_packet(
                                    //     tcp_flags::ACK,
                                    //     TTL,
                                    //     None,
                                    //     Vec::new(),
                                    // )?);
                                    self.tcb.change_send_window(t.inner().window_size);
                                    if let Some(ref n) = self.write_notify {
                                        n.wake_by_ref();
                                        self.write_notify = None;
                                    };
                                    continue;
                                    // return std::task::Poll::Ready(Ok(()));
                                }
                                PacketStatus::Ack => {
                                    self.tcb.change_last_ack(t.inner().acknowledgment_number);
                                    self.tcb.change_send_window(t.inner().window_size);
                                    if let Some(ref n) = self.write_notify {
                                        n.wake_by_ref();
                                        self.write_notify = None;
                                    };
                                    continue;
                                }
                            };
                        }
                        if t.flags() == (tcp_flags::FIN | tcp_flags::ACK) {
                            self.tcb.add_ack(1);
                            let flags = tcp_flags::ACK;
                            self.packet_to_send =
                                Some(self.create_rev_packet(flags, TTL, None, Vec::new())?);
                            // self.tcb.add_seq_one();
                            self.tcb.change_state(TcpState::FinWait1(true));
                            continue;
                        }
                        if t.flags() == (tcp_flags::PSH | tcp_flags::ACK) {
                            if !matches!(
                                self.tcb.check_pkt_type(&t, &p.payload),
                                PacketStatus::NewPacket
                            ) {
                                continue;
                            }
                            self.tcb.change_last_ack(t.inner().acknowledgment_number);

                            if p.payload.is_empty()
                                || self.tcb.get_ack() != t.inner().sequence_number
                            {
                                continue;
                            }

                            // self.tcb.add_ack(p.payload.len() as u32);
                            self.tcb.change_send_window(t.inner().window_size);
                            // buf.put_slice(&p.payload);
                            // self.packet_to_send = Some(self.create_rev_packet(
                            //     tcp_flags::ACK,
                            //     TTL,
                            //     None,
                            //     Vec::new(),
                            // )?);
                            // return std::task::Poll::Ready(Ok(()));
                            self.tcb
                                .add_unordered_packet(t.inner().sequence_number, &p.payload);
                            continue;
                        }
                    } else if matches!(self.tcb.get_state(), TcpState::FinWait1(false)) {
                        if t.flags() == (tcp_flags::FIN | tcp_flags::ACK) {
                            let flags = tcp_flags::ACK;
                            self.packet_to_send =
                                Some(self.create_rev_packet(flags, TTL, None, Vec::new())?);
                            self.tcb.change_send_window(t.inner().window_size);
                            // self.tcb.add_seq_one();
                            self.tcb.change_state(TcpState::FinWait2(false));
                            continue;
                        }
                    } else if matches!(self.tcb.get_state(), TcpState::FinWait2(true))
                        && t.flags() == tcp_flags::ACK
                    {
                        self.tcb.change_state(TcpState::FinWait2(false));
                    }
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(())),
                std::task::Poll::Pending => {
                    if matches!(self.tcb.get_state(), TcpState::FinWait1(true)) {
                        let flags = tcp_flags::FIN | tcp_flags::ACK;
                        self.packet_to_send =
                            Some(self.create_rev_packet(flags, TTL, None, Vec::new())?);

                        self.tcb.change_state(TcpState::FinWait2(false));
                        continue;
                    } else if matches!(self.shutdown, Shutdown::Pending(_))
                        && matches!(self.tcb.get_state(), TcpState::Established)
                    {
                        let flags = tcp_flags::FIN | tcp_flags::ACK;
                        self.packet_to_send =
                            Some(self.create_rev_packet(flags, TTL, None, Vec::new())?);
                        self.tcb.change_state(TcpState::FinWait1(false));

                        continue;
                    }
                    return std::task::Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.tcb.reset_timeout();

        if (self.tcb.send_window as u64) < self.tcb.avg_send_window.0 / 2
            || self.tcb.is_send_buffer_full()
        {
            self.write_notify = Some(cx.waker().clone());
            return std::task::Poll::Pending;
        }

        if self.tcb.retransmission.is_some() {
            self.write_notify = Some(cx.waker().clone());
            if matches!(self.as_mut().poll_flush(cx), std::task::Poll::Pending) {
                return std::task::Poll::Pending;
            }
        }

        let flags = tcp_flags::PSH | tcp_flags::ACK;
        let packet = self.create_rev_packet(flags, TTL, None, buf.to_vec())?;
        let seq = self.tcb.seq;
        let payload_len = packet.payload.len();
        let payload = packet.payload.clone();

        self.packet_sender
            .send(packet)
            .map_err(|_| Error::from(ErrorKind::UnexpectedEof))?;
        self.tcb.add_inflight_packet(seq, &payload);

        std::task::Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if let Some(i) = self
            .tcb
            .retransmission
            .and_then(|s| self.tcb.inflight_packets.iter().position(|p| p.seq == s))
            .and_then(|p| self.tcb.inflight_packets.get(p))
        {
            let flags = tcp_flags::PSH | tcp_flags::ACK;
            let packet = self.create_rev_packet(flags, TTL, i.seq, i.payload.to_vec())?;

            self.packet_sender
                .send(packet)
                .map_err(|_| Error::from(ErrorKind::UnexpectedEof))?;
            self.tcb.retransmission = None;
        } else if let Some(_i) = self.tcb.retransmission {
            #[cfg(feature = "log")]
            {
                warn!(_i);
                warn!(self.tcb.seq);
                warn!(self.tcb.last_ack);
                warn!(self.tcb.ack);
                for p in self.tcb.inflight_packets.iter() {
                    warn!(p.seq);
                    warn!("{}", p.payload.len());
                }
            }
            panic!("Please report these values at: https://github.com/narrowlink/ipstack/");
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match &self.shutdown {
            Shutdown::Ready => std::task::Poll::Ready(Ok(())),
            Shutdown::Pending(_) | Shutdown::None => {
                self.shutdown.pending(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        if let Ok(p) = self.create_rev_packet(0, DROP_TTL, None, Vec::new()) {
            _ = self.packet_sender.send(p);
        }
    }
}
