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
    cmp,
    future::Future,
    io::{Error, ErrorKind},
    mem::MaybeUninit,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug)]
enum Shutdown {
    Ready,
    Pending(Waker),
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
    stream_sender: PacketSender,
    stream_receiver: PacketReceiver,
    up_packet_sender: PacketSender,
    tcb: Tcb,
    mtu: u16,
    shutdown: Shutdown,
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
            write_notify: None,
            destroy_messenger: None,
            timeout: Box::pin(tokio::time::sleep_until(deadline)),
            timeout_interval,
        };
        if tcp.syn {
            return Ok(stream);
        }
        if !tcp.rst {
            let pkt = stream.create_rev_packet(RST | ACK, TTL, None, Vec::new())?;
            if let Err(err) = stream.up_packet_sender.send(pkt) {
                log::warn!("Error sending RST/ACK packet: {:?}", err);
            }
        }
        let info = format!("Invalid TCP packet: {}", tcp_header_fmt(stream.network_tuple(), &tcp));
        Err(IpStackError::IoError(Error::new(ErrorKind::ConnectionRefused, info)))
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

    fn calculate_payload_max_len(&self, ip_header_size: u16, tcp_header_size: u16) -> u16 {
        cmp::min(
            self.tcb.get_send_window(),
            self.mtu.saturating_sub(ip_header_size + tcp_header_size),
        )
    }

    fn create_rev_packet(&self, flags: u8, ttl: u8, seq: impl Into<Option<SeqNum>>, mut payload: Vec<u8>) -> Result<NetworkPacket, Error> {
        let mut tcp_header = etherparse::TcpHeader::new(
            self.dst_addr.port(),
            self.src_addr.port(),
            seq.into().unwrap_or(self.tcb.get_seq()).0,
            self.tcb.get_recv_window(),
        );

        tcp_header.acknowledgment_number = self.tcb.get_ack().0;
        tcp_header.syn = flags & SYN != 0;
        tcp_header.ack = flags & ACK != 0;
        tcp_header.rst = flags & RST != 0;
        tcp_header.fin = flags & FIN != 0;
        tcp_header.psh = flags & PSH != 0;

        let ip_header = match (self.dst_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::TCP, dst.octets(), src.octets())
                    .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
                let payload_len = self.calculate_payload_max_len(ip_h.header_len() as u16, tcp_header.header_len() as u16);
                payload.truncate(payload_len as usize);
                ip_h.set_payload_len(payload.len() + tcp_header.header_len())
                    .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
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
                let payload_len = self.calculate_payload_max_len(ip_h.header_len() as u16, tcp_header.header_len() as u16);
                payload.truncate(payload_len as usize);
                let len = payload.len() + tcp_header.header_len();
                ip_h.set_payload_length(len).map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;

                IpHeader::Ipv6(ip_h)
            }
            _ => unreachable!(),
        };

        match ip_header {
            IpHeader::Ipv4(ref ip_header) => {
                tcp_header.checksum = tcp_header
                    .calc_checksum_ipv4(ip_header, &payload)
                    .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
            }
            IpHeader::Ipv6(ref ip_header) => {
                tcp_header.checksum = tcp_header
                    .calc_checksum_ipv6(ip_header, &payload)
                    .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
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
        loop {
            if self.tcb.get_state() == TcpState::Closed {
                self.shutdown.ready();
                return Poll::Ready(Ok(()));
            }

            let min = self.tcb.get_available_read_buffer_size() as u16;
            self.tcb.change_recv_window(min);

            let final_reset = self.tcb.get_state() == TcpState::TimeWait;
            if matches!(Pin::new(&mut self.timeout).poll(cx), Poll::Ready(_)) {
                if !final_reset {
                    log::trace!("timeout reached for {}", self.network_tuple());
                }
                let packet = self.create_rev_packet(RST | ACK, TTL, None, Vec::new())?;
                self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
                self.tcb.change_state(TcpState::Closed);
                self.shutdown.ready();
                return Poll::Ready(Err(Error::from(ErrorKind::TimedOut)));
            }
            self.reset_timeout(final_reset);

            if self.tcb.get_state() == TcpState::Listen {
                let packet = self.create_rev_packet(SYN | ACK, TTL, None, Vec::new())?;
                self.tcb.add_seq_one();
                self.tcb.change_state(TcpState::SynReceived);
                self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
                continue;
            }

            if let Some(b) = self.tcb.get_unordered_packets().filter(|_| matches!(self.shutdown, Shutdown::None)) {
                self.tcb.add_ack(b.len().try_into()?);
                buf.put_slice(&b);
                let packet = self.create_rev_packet(ACK, TTL, None, Vec::new())?;
                self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
                return Poll::Ready(Ok(()));
            }
            if self.tcb.get_state() == TcpState::CloseWait {
                let packet = self.create_rev_packet(FIN | ACK, TTL, None, Vec::new())?;
                self.tcb.add_seq_one();
                self.tcb.add_ack(1.into());
                self.tcb.change_state(TcpState::LastAck);
                self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
                continue;
            } else if matches!(self.shutdown, Shutdown::Pending(_))
                && self.tcb.get_state() == TcpState::Established
                && self.tcb.get_last_ack() == self.tcb.get_seq()
            {
                // Act as a client, actively send a farewell packet to the other side.
                let packet = self.create_rev_packet(FIN | ACK, TTL, None, Vec::new())?;
                self.tcb.add_seq_one();
                self.tcb.change_state(TcpState::FinWait1);
                self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
                continue;
            }
            match self.stream_receiver.poll_recv(cx) {
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(network_packet)) => {
                    let TransportHeader::Tcp(tcp_header) = network_packet.transport_header() else {
                        unreachable!()
                    };
                    let payload = &network_packet.payload;
                    let flags = tcp_header_flags(tcp_header);
                    let incoming_ack: SeqNum = tcp_header.acknowledgment_number.into();
                    let incoming_seq: SeqNum = tcp_header.sequence_number.into();
                    let window_size = tcp_header.window_size;
                    if flags & RST != 0 {
                        self.tcb.change_state(TcpState::Closed);
                        self.shutdown.ready();
                        return Poll::Ready(Err(Error::from(ErrorKind::ConnectionReset)));
                    }
                    if self.tcb.check_pkt_type(tcp_header, payload) == PacketStatus::Invalid {
                        continue;
                    }

                    if self.tcb.get_state() == TcpState::SynReceived {
                        if flags == ACK {
                            self.tcb.change_last_ack(incoming_ack);
                            self.tcb.change_send_window(window_size);
                            self.tcb.change_state(TcpState::Established);
                        }
                    } else if self.tcb.get_state() == TcpState::Established {
                        if flags == ACK {
                            match self.tcb.check_pkt_type(tcp_header, payload) {
                                PacketStatus::WindowUpdate => {
                                    self.tcb.change_send_window(window_size);
                                    if let Some(waker) = self.write_notify.take() {
                                        waker.wake_by_ref();
                                    }
                                    continue;
                                }
                                PacketStatus::Invalid => continue,
                                PacketStatus::KeepAlive => {
                                    self.tcb.change_last_ack(incoming_ack);
                                    self.tcb.change_send_window(window_size);
                                    let packet = self.create_rev_packet(ACK, TTL, None, Vec::new())?;
                                    self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
                                    continue;
                                }
                                PacketStatus::RetransmissionRequest => {
                                    log::trace!("Retransmission request {}", tcp_header_fmt(self.network_tuple(), tcp_header));
                                    self.tcb.change_send_window(window_size);
                                    if let Some(packet) = self.tcb.find_inflight_packet(incoming_ack) {
                                        let rev_packet = self.create_rev_packet(PSH | ACK, TTL, packet.seq, packet.payload.clone())?;
                                        self.up_packet_sender.send(rev_packet).or(Err(ErrorKind::UnexpectedEof))?;
                                    } else {
                                        log::error!("Packet {} not found in inflight_packets", incoming_ack);
                                        log::error!("seq: {}", self.tcb.get_seq());
                                        log::error!("last_ack: {}", self.tcb.get_last_ack());
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
                                    //     self.packet_to_send = Some(self.create_rev_packet(
                                    //         ACK,
                                    //         TTL,
                                    //         None,
                                    //         Vec::new(),
                                    //     )?);
                                    //     continue;
                                    // }

                                    self.tcb.change_last_ack(incoming_ack);
                                    self.tcb.add_unordered_packet(incoming_seq, payload.clone());

                                    self.tcb.change_send_window(window_size);
                                    if let Some(waker) = self.write_notify.take() {
                                        waker.wake_by_ref();
                                    }
                                    continue;
                                }
                                PacketStatus::Ack => {
                                    self.tcb.change_last_ack(incoming_ack);
                                    self.tcb.change_send_window(window_size);
                                    if let Some(waker) = self.write_notify.take() {
                                        waker.wake_by_ref();
                                    }
                                    continue;
                                }
                            };
                        }
                        if flags == (FIN | ACK) {
                            self.tcb.add_ack(1.into());
                            let packet = self.create_rev_packet(ACK, TTL, None, Vec::new())?;
                            self.tcb.change_state(TcpState::CloseWait);
                            self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
                            continue;
                        }
                        if flags == (PSH | ACK) {
                            if !matches!(self.tcb.check_pkt_type(tcp_header, payload), PacketStatus::NewPacket) {
                                continue;
                            }
                            self.tcb.change_last_ack(incoming_ack);

                            if payload.is_empty() || self.tcb.get_ack() != incoming_seq {
                                continue;
                            }

                            self.tcb.change_send_window(window_size);

                            self.tcb.add_unordered_packet(incoming_seq, payload.clone());
                            continue;
                        }
                    } else if self.tcb.get_state() == TcpState::FinWait1 {
                        if flags == ACK {
                            self.tcb.change_last_ack(incoming_ack);
                            self.tcb.add_ack(1.into());
                            self.tcb.change_state(TcpState::FinWait2);
                            continue;
                        }
                    } else if self.tcb.get_state() == TcpState::FinWait2 {
                        if flags == (FIN | ACK) {
                            self.tcb.add_ack(1.into());
                            let packet = self.create_rev_packet(ACK, TTL, None, Vec::new())?;
                            self.tcb.change_send_window(window_size);
                            self.tcb.change_state(TcpState::TimeWait);
                            self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
                            continue;
                        }
                    } else if self.tcb.get_state() == TcpState::LastAck {
                        if flags == ACK {
                            self.tcb.change_state(TcpState::Closed);
                        }
                    } else if self.tcb.get_state() == TcpState::TimeWait && flags == (FIN | ACK) {
                        let packet = self.create_rev_packet(ACK, TTL, None, Vec::new())?;
                        // wait to timeout, can't change state here
                        // self.tcb.change_state(TcpState::Closed);
                        self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
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
            return Poll::Ready(Err(Error::from(ErrorKind::NotConnected)));
        }
        self.reset_timeout(false);

        if (self.tcb.get_send_window() as u64) < self.tcb.get_avg_send_window() / 2 || self.tcb.is_send_buffer_full() {
            self.write_notify = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let packet = self.create_rev_packet(PSH | ACK, TTL, None, buf.to_vec())?;
        let seq = self.tcb.get_seq();
        let payload_len = packet.payload.len();
        let payload = packet.payload.clone();
        self.up_packet_sender.send(packet).or(Err(ErrorKind::UnexpectedEof))?;
        self.tcb.add_inflight_packet(seq, payload);

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.tcb.get_state() != TcpState::Established {
            return Poll::Ready(Err(Error::from(ErrorKind::NotConnected)));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if matches!(self.shutdown, Shutdown::Ready) {
            return Poll::Ready(Ok(()));
        } else if matches!(self.shutdown, Shutdown::None) {
            self.shutdown.pending(cx.waker().clone());
        }
        self.poll_read(cx, &mut tokio::io::ReadBuf::uninit(&mut [MaybeUninit::<u8>::uninit()]))
    }
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        if let Some(messenger) = self.destroy_messenger.take() {
            let _ = messenger.send(());
        }
    }
}
