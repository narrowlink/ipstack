use super::seqnum::SeqNum;
use crate::{
    error::IpStackError,
    packet::{
        tcp_flags::{ACK, FIN, PSH, RST, SYN},
        tcp_header_flags, tcp_header_fmt, IpHeader, NetworkPacket, NetworkTuple, TransportHeader,
    },
    stream::tcb::{PacketStatus, Tcb, TcpState},
    PacketReceiver, PacketSender, TTL,
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, TcpHeader};
use std::{
    future::Future,
    io::ErrorKind::{ConnectionRefused, InvalidData, InvalidInput, UnexpectedEof},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug)]
enum Shutdown {
    None,
    Pending(Waker),
    Ready,
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

impl std::fmt::Display for Shutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shutdown::None => write!(f, "None"),
            Shutdown::Pending(_) => write!(f, "Pending"),
            Shutdown::Ready => write!(f, "Ready"),
        }
    }
}

#[derive(Debug)]
pub struct IpStackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: PacketReceiver,
    up_packet_sender: PacketSender,
    tcb: Tcb,
    mtu: u16,
    shutdown: Shutdown,
    read_notify_for_shutdown: Option<Waker>,
    write_notify: Option<Waker>,
    destroy_messenger: Option<tokio::sync::oneshot::Sender<()>>,
    timeout: Pin<Box<tokio::time::Sleep>>,
    timeout_interval: Duration,
}

impl IpStackTcpStream {
    pub(crate) fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp: TcpHeader,
        up_packet_sender: PacketSender,
        mtu: u16,
        timeout_interval: Duration,
    ) -> Result<IpStackTcpStream, IpStackError> {
        let (stream_sender, stream_receiver) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let deadline = tokio::time::Instant::now() + timeout_interval;
        let stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver,
            up_packet_sender,
            tcb: Tcb::new(SeqNum(tcp.sequence_number) + 1),
            mtu,
            shutdown: Shutdown::None,
            read_notify_for_shutdown: None,
            write_notify: None,
            destroy_messenger: None,
            timeout: Box::pin(tokio::time::sleep_until(deadline)),
            timeout_interval,
        };
        if tcp.syn {
            return Ok(stream);
        }
        if !tcp.rst {
            let (seq, ack, window_size) = (stream.tcb.get_seq().0, stream.tcb.get_ack().0, stream.tcb.get_recv_window());
            let pkt = stream.create_rev_packet(RST | ACK, TTL, seq, ack, window_size, Vec::new())?;
            if let Err(err) = stream.up_packet_sender.send(pkt) {
                log::warn!("Error sending RST/ACK packet: {:?}", err);
            }
        }
        let info = format!("Invalid TCP packet: {} {}", stream.network_tuple(), tcp_header_fmt(&tcp));
        Err(IpStackError::IoError(std::io::Error::new(ConnectionRefused, info)))
    }

    fn reset_timeout(&mut self, final_reset: bool) {
        let two_msl = Duration::from_secs(2);
        let deadline = tokio::time::Instant::now() + if final_reset { two_msl } else { self.timeout_interval };
        self.timeout.as_mut().reset(deadline);
    }

    pub(crate) fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple::new(self.src_addr, self.dst_addr, true)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }
    pub fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    pub(crate) fn set_destroy_messenger(&mut self, messenger: tokio::sync::oneshot::Sender<()>) {
        self.destroy_messenger = Some(messenger);
    }

    fn calculate_payload_max_len(&self, ip_header_size: usize, tcp_header_size: usize) -> usize {
        std::cmp::min(
            self.tcb.get_send_window() as usize,
            (self.mtu as usize).saturating_sub(ip_header_size + tcp_header_size),
        )
    }

    fn create_rev_packet(&self, flags: u8, ttl: u8, seq: u32, ack: u32, win: u16, mut payload: Vec<u8>) -> std::io::Result<NetworkPacket> {
        let mut tcp_header = etherparse::TcpHeader::new(self.dst_addr.port(), self.src_addr.port(), seq, win);
        tcp_header.acknowledgment_number = ack;
        tcp_header.syn = flags & SYN != 0;
        tcp_header.ack = flags & ACK != 0;
        tcp_header.rst = flags & RST != 0;
        tcp_header.fin = flags & FIN != 0;
        tcp_header.psh = flags & PSH != 0;

        let ip_header = match (self.dst_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h =
                    Ipv4Header::new(0, ttl, IpNumber::TCP, dst.octets(), src.octets()).map_err(|e| std::io::Error::new(InvalidInput, e))?;
                let payload_len = self.calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
                payload.truncate(payload_len);
                ip_h.set_payload_len(payload.len() + tcp_header.header_len())
                    .map_err(|e| std::io::Error::new(InvalidInput, e))?;
                ip_h.dont_fragment = true;
                IpHeader::Ipv4(ip_h)
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
                let payload_len = self.calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
                payload.truncate(payload_len);
                let len = payload.len() + tcp_header.header_len();
                ip_h.set_payload_length(len).map_err(|e| std::io::Error::new(InvalidInput, e))?;

                IpHeader::Ipv6(ip_h)
            }
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "IP version mismatch")),
        };

        match ip_header {
            IpHeader::Ipv4(ref ip_header) => {
                tcp_header.checksum = tcp_header
                    .calc_checksum_ipv4(ip_header, &payload)
                    .map_err(|e| std::io::Error::new(InvalidInput, e))?;
            }
            IpHeader::Ipv6(ref ip_header) => {
                tcp_header.checksum = tcp_header
                    .calc_checksum_ipv6(ip_header, &payload)
                    .map_err(|e| std::io::Error::new(InvalidInput, e))?;
            }
        }
        Ok(NetworkPacket {
            ip: ip_header,
            transport: TransportHeader::Tcp(tcp_header),
            payload,
        })
    }
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        // update the waker for shutdown every time to keep it up-to-date
        self.read_notify_for_shutdown = Some(cx.waker().clone());
        loop {
            if self.tcb.get_state() == TcpState::Closed {
                self.shutdown.ready();
                return Poll::Ready(Ok(()));
            }

            use std::io::Error;
            let final_reset = self.tcb.get_state() == TcpState::TimeWait;
            if matches!(Pin::new(&mut self.timeout).poll(cx), Poll::Ready(_)) {
                if !final_reset {
                    log::warn!("timeout reached for {}", self.network_tuple());
                }
                let (seq, ack, window_size) = (self.tcb.get_seq().0, self.tcb.get_ack().0, self.tcb.get_recv_window());
                let packet = self.create_rev_packet(RST | ACK, TTL, seq, ack, window_size, Vec::new())?;
                self.up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
                self.tcb.change_state(TcpState::Closed);
                self.shutdown.ready();
                return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
            }
            self.reset_timeout(final_reset);

            if self.tcb.get_state() == TcpState::Listen {
                let (seq, ack, window_size) = (self.tcb.get_seq().0, self.tcb.get_ack().0, self.tcb.get_recv_window());
                let packet = self.create_rev_packet(SYN | ACK, TTL, seq, ack, window_size, Vec::new())?;
                self.up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
                self.tcb.increase_seq();
                self.tcb.change_state(TcpState::SynReceived);
                continue;
            }

            if let Some(data) = self.tcb.get_unordered_packets().filter(|_| matches!(self.shutdown, Shutdown::None)) {
                buf.put_slice(&data);
                let (seq, ack, window_size) = (self.tcb.get_seq().0, self.tcb.get_ack().0, self.tcb.get_recv_window());
                let packet = self.create_rev_packet(ACK, TTL, seq, ack, window_size, Vec::new())?;
                self.up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
                return Poll::Ready(Ok(()));
            }
            if self.tcb.get_state() == TcpState::CloseWait {
                let (seq, ack, window_size) = (self.tcb.get_seq().0, self.tcb.get_ack().0, self.tcb.get_recv_window());
                let packet = self.create_rev_packet(FIN | ACK, TTL, seq, ack, window_size, Vec::new())?;
                self.tcb.increase_seq();
                self.tcb.increase_ack();
                self.tcb.change_state(TcpState::LastAck);
                self.up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
                continue;
            }
            if matches!(self.shutdown, Shutdown::Pending(_))
                && self.tcb.get_state() == TcpState::Established
                && self.tcb.get_last_received_ack() == self.tcb.get_seq()
            {
                // Act as a client, actively send a farewell packet to the other side.
                let (seq, ack, window_size) = (self.tcb.get_seq().0, self.tcb.get_ack().0, self.tcb.get_recv_window());
                let packet = self.create_rev_packet(FIN | ACK, TTL, seq, ack, window_size, Vec::new())?;
                self.tcb.increase_seq();
                self.tcb.change_state(TcpState::FinWait1);
                self.up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
                continue;
            }
            match self.stream_receiver.poll_recv(cx) {
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(network_packet)) => {
                    let TransportHeader::Tcp(tcp_header) = network_packet.transport_header() else {
                        return Poll::Ready(Err(std::io::Error::new(InvalidData, "Invalid TCP packet")));
                    };
                    let payload = &network_packet.payload;
                    let flags = tcp_header_flags(tcp_header);
                    let incoming_ack: SeqNum = tcp_header.acknowledgment_number.into();
                    let incoming_seq: SeqNum = tcp_header.sequence_number.into();
                    let window_size = tcp_header.window_size;
                    if flags & RST != 0 {
                        self.tcb.change_state(TcpState::Closed);
                        self.shutdown.ready();
                        return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset)));
                    }
                    let pkt_type = self.tcb.check_pkt_type(tcp_header, payload);
                    if pkt_type == PacketStatus::Invalid {
                        continue;
                    }

                    if self.tcb.get_state() == TcpState::SynReceived {
                        if flags == ACK {
                            assert_eq!(incoming_ack, self.tcb.get_seq());
                            assert_eq!(incoming_seq, self.tcb.get_ack());
                            self.tcb.update_last_received_ack(incoming_ack);
                            self.tcb.change_send_window(window_size);
                            self.tcb.change_state(TcpState::Established);
                        }
                    } else if self.tcb.get_state() == TcpState::Established {
                        if flags == ACK {
                            match pkt_type {
                                PacketStatus::WindowUpdate => {
                                    self.tcb.change_send_window(window_size);
                                    if let Some(waker) = self.write_notify.take() {
                                        waker.wake_by_ref();
                                    }
                                    continue;
                                }
                                PacketStatus::KeepAlive => {
                                    self.tcb.update_last_received_ack(incoming_ack);
                                    self.tcb.change_send_window(window_size);
                                    let (seq, ack, window_size) = (self.tcb.get_seq().0, self.tcb.get_ack().0, self.tcb.get_recv_window());
                                    let packet = self.create_rev_packet(ACK, TTL, seq, ack, window_size, Vec::new())?;
                                    self.up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
                                    continue;
                                }
                                PacketStatus::RetransmissionRequest => {
                                    log::debug!("Retransmission request {} {}", self.network_tuple(), tcp_header_fmt(tcp_header));
                                    self.tcb.change_send_window(window_size);
                                    if let Some(packet) = self.tcb.find_inflight_packet(incoming_ack) {
                                        let (s, a, w) = (packet.seq.0, self.tcb.get_ack().0, self.tcb.get_recv_window());
                                        let rev_packet = self.create_rev_packet(PSH | ACK, TTL, s, a, w, packet.payload.clone())?;
                                        self.up_packet_sender.send(rev_packet).map_err(|e| Error::new(UnexpectedEof, e))?;
                                    } else {
                                        log::error!("Packet {} not found in inflight_packets", incoming_ack);
                                        log::error!("seq: {}", self.tcb.get_seq());
                                        log::error!("last_received_ack: {}", self.tcb.get_last_received_ack());
                                        log::error!("ack: {}", self.tcb.get_ack());
                                        log::error!("inflight_packets:");
                                        for p in self.tcb.get_all_inflight_packets().iter() {
                                            log::error!("seq: {}", p.seq);
                                            log::error!("payload len: {}", p.payload.len());
                                        }
                                        panic!("Please report these values at: https://github.com/narrowlink/ipstack/");
                                    }
                                    continue;
                                }
                                PacketStatus::NewPacket => {
                                    // if incoming_seq != self.tcb.get_ack() {
                                    //     dbg!(incoming_seq);
                                    //     let packet = self.create_rev_packet(ACK, TTL, None, Vec::new())?;
                                    //     self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
                                    //     continue;
                                    // }

                                    self.tcb.update_last_received_ack(incoming_ack);
                                    self.tcb.add_unordered_packet(incoming_seq, payload.clone());

                                    self.tcb.change_send_window(window_size);
                                    if let Some(waker) = self.write_notify.take() {
                                        waker.wake_by_ref();
                                    }
                                    continue;
                                }
                                PacketStatus::Ack => {
                                    self.tcb.update_last_received_ack(incoming_ack);
                                    self.tcb.change_send_window(window_size);
                                    if let Some(waker) = self.write_notify.take() {
                                        waker.wake_by_ref();
                                    }
                                    continue;
                                }
                                PacketStatus::Invalid => continue,
                            };
                        }
                        if flags == (FIN | ACK) {
                            self.tcb.increase_ack();
                            let (seq, ack, window_size) = (self.tcb.get_seq().0, self.tcb.get_ack().0, self.tcb.get_recv_window());
                            let packet = self.create_rev_packet(ACK, TTL, seq, ack, window_size, Vec::new())?;
                            self.tcb.change_state(TcpState::CloseWait);
                            self.up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
                            continue;
                        }
                        if flags == (PSH | ACK) {
                            if pkt_type != PacketStatus::NewPacket {
                                continue;
                            }
                            self.tcb.update_last_received_ack(incoming_ack);

                            if payload.is_empty() || self.tcb.get_ack() != incoming_seq {
                                continue;
                            }

                            self.tcb.change_send_window(window_size);

                            self.tcb.add_unordered_packet(incoming_seq, payload.clone());
                            continue;
                        }
                    } else if self.tcb.get_state() == TcpState::FinWait1 {
                        if flags == ACK {
                            self.tcb.update_last_received_ack(incoming_ack);
                            self.tcb.increase_ack();
                            self.tcb.change_state(TcpState::FinWait2);
                            continue;
                        }
                    } else if self.tcb.get_state() == TcpState::FinWait2 {
                        if flags == (FIN | ACK) {
                            self.tcb.increase_ack();
                            let (seq, ack, window_size) = (self.tcb.get_seq().0, self.tcb.get_ack().0, self.tcb.get_recv_window());
                            let packet = self.create_rev_packet(ACK, TTL, seq, ack, window_size, Vec::new())?;
                            self.tcb.change_send_window(window_size);
                            self.tcb.change_state(TcpState::TimeWait);
                            self.up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
                            continue;
                        }
                    } else if self.tcb.get_state() == TcpState::LastAck {
                        if flags == ACK {
                            self.tcb.change_state(TcpState::Closed);
                        }
                    } else if self.tcb.get_state() == TcpState::TimeWait && flags == (FIN | ACK) {
                        let (seq, ack, window_size) = (self.tcb.get_seq().0, self.tcb.get_ack().0, self.tcb.get_recv_window());
                        let packet = self.create_rev_packet(ACK, TTL, seq, ack, window_size, Vec::new())?;
                        // wait to timeout, can't change state here
                        // self.tcb.change_state(TcpState::Closed);
                        self.up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
                        // now we need to wait for the timeout to reach...
                    }
                }
            }
        }
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if self.tcb.get_state() != TcpState::Established {
            return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)));
        }
        self.reset_timeout(false);

        if (self.tcb.get_send_window() as u64) < self.tcb.get_avg_send_window() / 2 || self.tcb.is_send_buffer_full() {
            self.write_notify = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let (seq, ack, window_size) = (self.tcb.get_seq().0, self.tcb.get_ack().0, self.tcb.get_recv_window());
        let pkt = self.create_rev_packet(PSH | ACK, TTL, seq, ack, window_size, buf.to_vec())?;
        let payload_len = pkt.payload.len();
        use std::io::{Error, ErrorKind::UnexpectedEof};
        self.up_packet_sender.send(pkt.clone()).map_err(|e| Error::new(UnexpectedEof, e))?;
        self.tcb.add_inflight_packet(pkt.payload)?;

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.tcb.get_state() != TcpState::Established {
            return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let (nt, ts, sd) = (self.network_tuple(), self.tcb.get_state(), &self.shutdown);
        log::trace!("poll_shutdown {nt}, TCP state {ts:?}, shutdown status {sd}");
        match self.shutdown {
            Shutdown::None => {
                self.shutdown.pending(cx.waker().clone());
                self.read_notify_for_shutdown.take().map(|w| w.wake_by_ref()).unwrap_or(());
                Poll::Pending
            }
            Shutdown::Pending(_) => {
                self.read_notify_for_shutdown.take().map(|w| w.wake_by_ref()).unwrap_or(());
                Poll::Pending
            }
            Shutdown::Ready => Poll::Ready(Ok(())),
        }
    }
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        if let Some(messenger) = self.destroy_messenger.take() {
            let _ = messenger.send(());
        }
    }
}
