use crate::{
    error::IpStackError,
    packet::{tcp_flags, IpStackPacketProtocol, TcpPacket},
    stream::tcb::{Tcb, TcpState},
};
use etherparse::{Ipv4Extensions, Ipv4Header, Ipv6Extensions, TransportHeader};
use std::{
    cmp,
    future::Future,
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    task::Waker,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        Notify,
    },
};

use crate::packet::NetworkPacket;

use super::tcb::PacketStatus;

pub struct IpStackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: UnboundedSender<NetworkPacket>,
    stream_receiver: UnboundedReceiver<NetworkPacket>,
    packet_sender: UnboundedSender<NetworkPacket>,
    packet_to_send: Option<NetworkPacket>,
    tcb: Tcb,
    mtu: u16,
    shutdown: Option<Notify>,
    flush_notify: Option<Waker>,
    write_notify: Option<Waker>,
}

impl IpStackTcpStream {
    pub(crate) async fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp: TcpPacket,
        pkt_sender: UnboundedSender<NetworkPacket>,
        mtu: u16,
    ) -> Result<IpStackTcpStream, IpStackError> {
        let (stream_sender, stream_receiver) = mpsc::unbounded_channel::<NetworkPacket>();

        let stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver,
            packet_sender: pkt_sender.clone(),
            packet_to_send: None,
            tcb: Tcb::new(tcp.inner().sequence_number + 1),
            mtu,
            shutdown: None,
            flush_notify: None,
            write_notify: None,
        };
        if !tcp.inner().syn {
            pkt_sender
                .send(stream.create_rev_packet(
                    tcp_flags::RST | tcp_flags::ACK,
                    64,
                    None,
                    Vec::new(),
                )?)
                .map_err(|_| IpStackError::InvalidTcpPacket)?;
        }
        Ok(stream)
    }
    pub(crate) fn stream_sender(&self) -> UnboundedSender<NetworkPacket> {
        self.stream_sender.clone()
    }
    fn calculate_payload_len(
        &self,
        ip_header_size: u16,
        tcp_header_size: u16,
        payload_len: u16,
        skip_buffer: bool,
    ) -> u16 {
        let line_buffer = cmp::min(
            self.tcb.get_send_window(),
            self.mtu.saturating_sub(ip_header_size + tcp_header_size),
        );
        if skip_buffer {
            line_buffer
        } else {
            cmp::min(self.tcb.buffer_size(payload_len), line_buffer)
        }
    }
    fn create_rev_packet(
        &self,
        flags: u8,
        ttl: u8,
        seq: Option<u32>,
        mut payload: Vec<u8>,
    ) -> Result<NetworkPacket, Error> {
        let mut tcp_header = etherparse::TcpHeader::new(
            self.dst_addr.port(),
            self.src_addr.port(),
            seq.unwrap_or(self.tcb.get_seq()),
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
                let mut ip_h = Ipv4Header::new(0, ttl, 6, dst.octets(), src.octets());
                let payload_len = self.calculate_payload_len(
                    ip_h.header_len() as u16,
                    tcp_header.header_len(),
                    payload.len() as u16,
                    seq.is_some(),
                );
                ip_h.payload_len = payload_len + tcp_header.header_len();
                payload.truncate(payload_len as usize);
                ip_h.dont_fragment = true;
                etherparse::IpHeader::Version4(ip_h, Ipv4Extensions::default())
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = etherparse::Ipv6Header {
                    traffic_class: 0,
                    flow_label: 0,
                    payload_length: 0,
                    next_header: 6,
                    hop_limit: ttl,
                    source: dst.octets(),
                    destination: src.octets(),
                };
                let payload_len = self.calculate_payload_len(
                    ip_h.header_len() as u16,
                    tcp_header.header_len(),
                    payload.len() as u16,
                    seq.is_some(),
                );
                ip_h.payload_length = payload_len + tcp_header.header_len();
                payload.truncate(payload_len as usize);

                etherparse::IpHeader::Version6(ip_h, Ipv6Extensions::default())
            }
            _ => unreachable!(),
        };

        match ip_header {
            etherparse::IpHeader::Version4(ref ip_header, _) => {
                tcp_header.checksum = tcp_header
                    .calc_checksum_ipv4(ip_header, &payload)
                    .map_err(|_e| Error::from(ErrorKind::InvalidInput))?;
            }
            etherparse::IpHeader::Version6(ref ip_header, _) => {
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
            self.tcb
                .change_recv_window(buf.initialize_unfilled().len() as u16);

            if matches!(self.tcb.get_state(), TcpState::SynReceived(false)) {
                self.packet_to_send = Some(self.create_rev_packet(
                    tcp_flags::SYN | tcp_flags::ACK,
                    64,
                    None,
                    Vec::new(),
                )?);
                self.tcb.add_seq_one();
                self.tcb.change_state(TcpState::SynReceived(true));
            }

            if let Some(packet) = self.packet_to_send.take() {
                self.packet_sender
                    .send(packet)
                    .map_err(|_| Error::from(ErrorKind::UnexpectedEof))?;
                if matches!(self.tcb.get_state(), TcpState::Closed) {
                    if let Some(shutdown) = self.shutdown.take() {
                        shutdown.notify_one();
                    }
                    return std::task::Poll::Ready(Ok(()));
                }
            }
            if self.shutdown.is_some() && matches!(self.tcb.get_state(), TcpState::Established) {
                self.tcb.change_state(TcpState::FinWait1);
                self.packet_to_send = Some(self.create_rev_packet(
                    tcp_flags::FIN | tcp_flags::ACK,
                    64,
                    None,
                    Vec::new(),
                )?);
                continue;
            }
            match self.stream_receiver.poll_recv(cx) {
                std::task::Poll::Ready(Some(p)) => {
                    let IpStackPacketProtocol::Tcp(t) = p.transport_protocol() else {
                        unreachable!()
                    };

                    if t.flags() & tcp_flags::RST != 0 {
                        self.packet_to_send =
                            Some(self.create_rev_packet(0, 0, None, Vec::new())?);
                        self.tcb.change_state(TcpState::Closed);
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
                                    self.tcb.change_last_ack(t.inner().acknowledgment_number);
                                    buf.put_slice(&p.payload);
                                    self.tcb.add_ack(p.payload.len() as u32);
                                    self.packet_to_send = Some(self.create_rev_packet(
                                        tcp_flags::ACK,
                                        64,
                                        None,
                                        Vec::new(),
                                    )?);
                                    self.tcb.change_send_window(t.inner().window_size);
                                    if let Some(ref n) = self.flush_notify {
                                        n.wake_by_ref();
                                        self.flush_notify = None;
                                    };
                                    return std::task::Poll::Ready(Ok(()));
                                }
                                PacketStatus::Ack => {
                                    self.tcb.change_last_ack(t.inner().acknowledgment_number);
                                    self.tcb.change_send_window(t.inner().window_size);
                                    if let Some(ref n) = self.flush_notify {
                                        n.wake_by_ref();
                                        self.flush_notify = None;
                                    };
                                    continue;
                                }
                            };
                        }
                        if t.flags() == (tcp_flags::FIN | tcp_flags::ACK) {
                            self.tcb.add_ack(1);
                            // self.ack = self.ack.wrapping_add(1);
                            self.packet_to_send = Some(self.create_rev_packet(
                                tcp_flags::FIN | tcp_flags::ACK,
                                64,
                                None,
                                Vec::new(),
                            )?);
                            self.tcb.change_state(TcpState::FinWait2);
                            continue;
                        }
                        if t.flags() == (tcp_flags::PSH | tcp_flags::ACK) {
                            self.tcb.change_last_ack(t.inner().acknowledgment_number);

                            if p.payload.is_empty()
                                || self.tcb.get_ack() != t.inner().sequence_number
                            {
                                continue;
                            }
                            self.tcb.add_ack(p.payload.len() as u32);
                            self.tcb.change_send_window(t.inner().window_size);
                            buf.put_slice(&p.payload);
                            self.packet_to_send = Some(self.create_rev_packet(
                                tcp_flags::ACK,
                                64,
                                None,
                                Vec::new(),
                            )?);
                            return std::task::Poll::Ready(Ok(()));
                        }
                    } else if matches!(self.tcb.get_state(), TcpState::FinWait1) {
                        if t.flags() == (tcp_flags::FIN | tcp_flags::ACK) {
                            self.packet_to_send = Some(self.create_rev_packet(
                                tcp_flags::ACK,
                                64,
                                None,
                                Vec::new(),
                            )?);
                            self.tcb.change_send_window(t.inner().window_size);
                            self.tcb.add_seq_one();
                            self.tcb.change_state(TcpState::FinWait2);
                            continue;
                        }
                    } else if matches!(self.tcb.get_state(), TcpState::FinWait2) {
                        self.packet_to_send =
                            Some(self.create_rev_packet(0, 0, None, Vec::new())?);
                        self.tcb.change_state(TcpState::Closed);
                        continue;
                    }
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(())),
                std::task::Poll::Pending => return std::task::Poll::Pending,
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
        loop {
            if matches!(self.tcb.get_state(), TcpState::Closed) {
                return std::task::Poll::Pending;
            }
            if self.tcb.get_send_window() == 0 {
                self.write_notify = Some(cx.waker().clone());
                return std::task::Poll::Pending;
            }

            if self.tcb.is_send_buffer_full() || self.tcb.retransmission.is_some() {
                self.write_notify = Some(cx.waker().clone());
                if matches!(self.as_mut().poll_flush(cx), std::task::Poll::Pending) {
                    return std::task::Poll::Pending;
                }
            }

            let packet =
                self.create_rev_packet(tcp_flags::PSH | tcp_flags::ACK, 64, None, buf.to_vec())?;
            let payload_len = packet.payload.len();
            let payload = packet.payload.clone();
            if payload_len == 0 {
                continue; // require end condition
            }

            self.packet_sender
                .send(packet)
                .map_err(|_| Error::from(ErrorKind::UnexpectedEof))?;
            self.tcb.add_send_buffer(&payload);

            return std::task::Poll::Ready(Ok(payload_len));
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let mut retransmission_full = false;
        loop {
            if self.tcb.seq == self.tcb.last_ack && self.tcb.retransmission.is_none() {
                return std::task::Poll::Ready(Ok(()));
            }
            let (from_seq, offset) = if let Some(s) = self.tcb.retransmission {
                if s == self.tcb.seq {
                    self.tcb.retransmission = None;
                    return std::task::Poll::Ready(Ok(()));
                } else {
                    (s, s.wrapping_sub(self.tcb.last_ack) as usize)
                }
            } else {
                match self.tcb.timeout.as_mut().poll(cx) {
                    std::task::Poll::Ready(_) => {
                        // dbg!("timeout");
                        retransmission_full = true;
                        self.tcb.retransmission = Some(self.tcb.last_ack);
                        (self.tcb.last_ack, 0)
                    }
                    std::task::Poll::Pending => {
                        self.flush_notify = Some(cx.waker().clone());
                        return std::task::Poll::Pending;
                    }
                }
            };

            let buf = if self.tcb.send_buffer.is_empty() {
                return std::task::Poll::Ready(Ok(()));
            } else {
                self.tcb.send_buffer[offset..].to_vec()
            };

            let packet =
                self.create_rev_packet(tcp_flags::PSH | tcp_flags::ACK, 64, Some(from_seq), buf)?;
            let buf_len = packet.payload.len();
            self.packet_sender
                .send(packet)
                .map_err(|_| Error::from(ErrorKind::UnexpectedEof))?;

            if let Some(s) = self.tcb.retransmission.take() {
                if retransmission_full {
                    self.tcb.retransmission = Some(s + buf_len as u32);
                } else {
                    self.tcb.retransmission = None;
                    return std::task::Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let notified = self.shutdown.get_or_insert(Notify::new()).notified();
        match Pin::new(&mut Box::pin(notified)).poll(cx) {
            std::task::Poll::Ready(_) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
