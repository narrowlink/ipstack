use super::seqnum::SeqNum;
use crate::{
    error::IpStackError,
    packet::{
        tcp_flags::{ACK, FIN, PSH, RST, SYN},
        tcp_header_flags, tcp_header_fmt, IpHeader, NetworkPacket, NetworkTuple, TransportHeader,
    },
    stream::tcb::{PacketType, Tcb, TcpState},
    PacketReceiver, PacketSender, TTL,
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, TcpHeader};
use std::{
    future::Future,
    io::ErrorKind::{BrokenPipe, ConnectionRefused, InvalidInput, UnexpectedEof},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// 2 * MSL (Maximum Segment Lifetime) is the maximum time a TCP connection can be in the TIME_WAIT state.
const TWO_MSL: Duration = Duration::from_secs(2);

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
    stream_receiver: Option<PacketReceiver>,
    up_packet_sender: PacketSender,
    tcb: std::sync::Arc<std::sync::Mutex<Tcb>>,
    mtu: u16,
    shutdown: std::sync::Arc<std::sync::Mutex<Shutdown>>,
    write_notify: std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
    destroy_messenger: Option<tokio::sync::oneshot::Sender<()>>,
    timeout: Pin<Box<tokio::time::Sleep>>,
    timeout_interval: Duration,
    data_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    data_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    read_notify: std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
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
        let (data_tx, data_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let tcb = std::sync::Arc::new(std::sync::Mutex::new(Tcb::new(SeqNum(tcp.sequence_number))));
        let deadline = tokio::time::Instant::now() + timeout_interval;
        let mut stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver: Some(stream_receiver),
            up_packet_sender,
            tcb,
            mtu,
            shutdown: std::sync::Arc::new(std::sync::Mutex::new(Shutdown::None)),
            write_notify: std::sync::Arc::new(std::sync::Mutex::new(None)),
            destroy_messenger: None,
            timeout: Box::pin(tokio::time::sleep_until(deadline)),
            timeout_interval,
            data_tx,
            data_rx,
            read_notify: std::sync::Arc::new(std::sync::Mutex::new(None)),
        };
        if tcp.syn {
            stream.spawn_tasks()?;
            return Ok(stream);
        }
        let tuple = stream.network_tuple();
        if !tcp.rst {
            let tcb = stream.tcb.lock().unwrap();
            if let Err(err) = Self::write_packet_to_device(&stream.up_packet_sender, tuple, mtu, &tcb, ACK | RST, None, None) {
                log::warn!("Error sending RST/ACK packet: {:?}", err);
            }
        }
        let info = format!("Invalid TCP packet: {} {}", tuple, tcp_header_fmt(&tcp));
        Err(IpStackError::IoError(std::io::Error::new(ConnectionRefused, info)))
    }

    fn reset_timeout(&mut self) {
        let deadline = tokio::time::Instant::now() + self.timeout_interval;
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

    fn calculate_payload_max_len(tcb: &Tcb, mtu: u16, ip_header_size: usize, tcp_header_size: usize) -> usize {
        std::cmp::min(
            tcb.get_send_window() as usize,
            (mtu as usize).saturating_sub(ip_header_size + tcp_header_size),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_rev_packet(
        tuple: NetworkTuple,
        tcb: &Tcb,
        mtu: u16,
        flags: u8,
        ttl: u8,
        seq: u32,
        ack: u32,
        win: u16,
        mut payload: Vec<u8>,
    ) -> std::io::Result<NetworkPacket> {
        let mut tcp_header = etherparse::TcpHeader::new(tuple.dst.port(), tuple.src.port(), seq, win);
        tcp_header.acknowledgment_number = ack;
        tcp_header.syn = flags & SYN != 0;
        tcp_header.ack = flags & ACK != 0;
        tcp_header.rst = flags & RST != 0;
        tcp_header.fin = flags & FIN != 0;
        tcp_header.psh = flags & PSH != 0;

        let ip_header = match (tuple.dst.ip(), tuple.src.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h =
                    Ipv4Header::new(0, ttl, IpNumber::TCP, dst.octets(), src.octets()).map_err(|e| std::io::Error::new(InvalidInput, e))?;
                let payload_len = Self::calculate_payload_max_len(tcb, mtu, ip_h.header_len(), tcp_header.header_len());
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
                let payload_len = Self::calculate_payload_max_len(tcb, mtu, ip_h.header_len(), tcp_header.header_len());
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

    /// Send a TCP packet to the downstream device, with the specified flags, sequence number, and payload.
    /// The returned value is the length of the `payload` sent, it may be shorter than the length of the incoming parameter `payload`.
    pub(crate) fn write_packet_to_device(
        up_packet_sender: &PacketSender,
        tuple: NetworkTuple,
        mtu: u16,
        tcb: &Tcb,
        flags: u8,
        seq: Option<SeqNum>,
        payload: Option<Vec<u8>>,
    ) -> std::io::Result<usize> {
        use std::io::Error;
        let seq = seq.unwrap_or(tcb.get_seq()).0;
        let (ack, window_size) = (tcb.get_ack().0, tcb.get_recv_window().max(mtu));
        let packet = Self::create_rev_packet(tuple, tcb, mtu, flags, TTL, seq, ack, window_size, payload.unwrap_or_default())?;
        let len = packet.payload.len();
        up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
        Ok(len)
    }
}

static SESSION_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl AsyncRead for IpStackTcpStream {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let network_tuple = self.network_tuple();

        let state = self.tcb.lock().unwrap().get_state();
        if state == TcpState::Closed {
            self.shutdown.lock().unwrap().ready();
            return Poll::Ready(Ok(()));
        }

        // handle timeout
        if matches!(Pin::new(&mut self.timeout).poll(cx), Poll::Ready(_)) {
            {
                let mut tcb = self.tcb.lock().unwrap();
                let (seq, ack) = (tcb.get_seq().0, tcb.get_ack().0);
                let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
                log::warn!("{network_tuple} {state:?}: {l_info}, session timeout reached, closing forcefully...");
                let sender = &self.up_packet_sender;
                Self::write_packet_to_device(sender, network_tuple, self.mtu, &tcb, ACK | RST, None, None)?;
                tcb.change_state(TcpState::Closed);
            }
            self.shutdown.lock().unwrap().ready();
            return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        }
        self.reset_timeout();

        // read data from channel
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => {
                self.read_notify.lock().unwrap().replace(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let nt = self.network_tuple();
        self.reset_timeout();

        let (state, send_window, avg_send_window, is_send_buffer_full) = {
            let tcb = self.tcb.lock().unwrap();
            let state = tcb.get_state();
            (state, tcb.get_send_window(), tcb.get_avg_send_window(), tcb.is_send_buffer_full())
        };

        if (send_window as u64) < avg_send_window / 2 || is_send_buffer_full {
            self.write_notify.lock().unwrap().replace(cx.waker().clone());
            log::debug!("{nt} {state:?}: send buffer is full, waiting for the other side to send ACK...");
            return Poll::Pending;
        }

        let mut tcb = self.tcb.lock().unwrap();
        let sender = &self.up_packet_sender;
        let payload_len = Self::write_packet_to_device(sender, nt, self.mtu, &tcb, ACK | PSH, None, Some(buf.to_vec()))?;
        tcb.add_inflight_packet(buf[..payload_len].to_vec())?;

        let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::trace!("{nt} {state:?}: {l_info} upstream data written to device, len = {payload_len}");

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match *self.shutdown.lock().unwrap() {
            Shutdown::None => {
                self.shutdown.lock().unwrap().pending(cx.waker().clone());
                Poll::Pending
            }
            Shutdown::Pending(_) => Poll::Pending,
            Shutdown::Ready => {
                let (nt, state) = (self.network_tuple(), self.tcb.lock().unwrap().get_state());
                let sessions = SESSION_COUNTER.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) - 1;
                log::trace!("{nt} {state:?}: session closed, total sessions: {sessions}");
                Poll::Ready(Ok(()))
            }
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

impl IpStackTcpStream {
    fn spawn_tasks(&mut self) -> std::io::Result<()> {
        let network_tuple = self.network_tuple();
        let data_notify = std::sync::Arc::new(tokio::sync::Notify::new());
        let exit_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        // task 1: data receiving and processing
        let data_notify_clone = data_notify.clone();
        let tcb = self.tcb.clone();
        let mut stream_receiver = self.stream_receiver.take().unwrap();
        let up_packet_sender = self.up_packet_sender.clone();
        let mtu = self.mtu;
        let shutdown = self.shutdown.clone();
        let write_notify = self.write_notify.clone();
        let exit_flag_clone = exit_flag.clone();
        tokio::spawn(async move {
            {
                let mut tcb = tcb.lock().unwrap();

                let state = tcb.get_state();
                if state != TcpState::Listen {
                    log::warn!("{network_tuple} {state:?}: Invalid TCP state, not in Listen state");
                    return Ok::<(), std::io::Error>(());
                }

                tcb.increase_ack();
                let sessions = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                let (seq, ack) = (tcb.get_seq().0, tcb.get_ack().0);
                let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
                log::trace!("{network_tuple} {state:?}: {l_info} session begins, total sessions: {sessions}");
                Self::write_packet_to_device(&up_packet_sender, network_tuple, mtu, &tcb, ACK | SYN, None, None)?;
                tcb.increase_seq();
                tcb.change_state(TcpState::SynReceived);
            }

            let tcb_clone = tcb.clone();
            type ExitNotifier = tokio::sync::mpsc::Sender<()>;
            let (exit_notifier, mut exit_receiver) = tokio::sync::mpsc::channel::<()>(u16::MAX as usize);

            async fn task_wait_to_close(tcb: std::sync::Arc<std::sync::Mutex<Tcb>>, notifier: ExitNotifier) {
                tokio::time::sleep(TWO_MSL).await;
                tcb.lock().unwrap().change_state(TcpState::Closed);
                notifier.send(()).await.unwrap_or(());
            }

            loop {
                let network_packet = tokio::select! {
                    Some(network_packet) = stream_receiver.recv() => {
                        network_packet
                    }
                    Some(_) = exit_receiver.recv() => {
                        let state = tcb.lock().unwrap().get_state();
                        let hint =  if state == TcpState::Closed { "gracefully" } else { "unexpectedly" };
                        let ending = "exit \"data receiving and processing task\"";
                        log::debug!("{network_tuple} {state:?}: session closed {hint}, {ending}");
                        shutdown.lock().unwrap().ready();
                        exit_flag_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                        break;
                    }
                    else => {
                        let state = tcb.lock().unwrap().get_state();
                        let ending = "exit \"data receiving and processing task\"";
                        log::debug!("{network_tuple} {state:?}: session closed unexpectedly, {ending}");
                        break;
                    }
                };

                let TransportHeader::Tcp(tcp_header) = network_packet.transport_header() else {
                    log::warn!("{network_tuple} Invalid TCP packet");
                    continue;
                };
                let payload = &network_packet.payload;
                let flags = tcp_header_flags(tcp_header);
                let incoming_ack: SeqNum = tcp_header.acknowledgment_number.into();
                let incoming_seq: SeqNum = tcp_header.sequence_number.into();
                let window_size = tcp_header.window_size;

                let mut tcb = tcb.lock().unwrap();

                if flags & RST == RST {
                    tcb.change_state(TcpState::Closed);
                    let exit_notifier = exit_notifier.clone();
                    tokio::spawn(async move { exit_notifier.send(()).await.unwrap_or(()) });
                    continue;
                }

                tcb.update_inflight_packet_queue(incoming_ack);
                let pkt_type = tcb.check_pkt_type(tcp_header, payload);
                if pkt_type == PacketType::Invalid {
                    continue;
                }

                let (state, seq, ack) = { (tcb.get_state(), tcb.get_seq().0, tcb.get_ack().0) };
                let (info, len) = (tcp_header_fmt(tcp_header), payload.len());
                let l_info = format!("local {{ seq: {}, ack: {} }}", seq, ack);
                log::trace!("{network_tuple} {state:?}: {l_info} {info}, {pkt_type:?}, len = {len}");

                match state {
                    TcpState::SynReceived => {
                        if flags & ACK == ACK {
                            tcb.update_last_received_ack(incoming_ack);
                            tcb.update_send_window(window_size);
                            if len > 0 {
                                tcb.add_unordered_packet(incoming_seq, payload.to_vec());
                                data_notify_clone.notify_one();
                            }
                            tcb.change_state(TcpState::Established);
                        }
                    }
                    TcpState::Established => {
                        if flags == ACK {
                            match pkt_type {
                                PacketType::WindowUpdate => {
                                    tcb.update_send_window(window_size);
                                    write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                                    continue;
                                }
                                PacketType::KeepAlive => {
                                    tcb.update_last_received_ack(incoming_ack);
                                    tcb.update_send_window(window_size);
                                    Self::write_packet_to_device(&up_packet_sender, network_tuple, mtu, &tcb, ACK, None, None)?;
                                    continue;
                                }
                                PacketType::RetransmissionRequest => {
                                    tcb.update_send_window(window_size);
                                    if let Some(packet) = tcb.find_inflight_packet(incoming_ack) {
                                        let s = Some(packet.seq);
                                        let p = Some(packet.payload.clone());
                                        Self::write_packet_to_device(&up_packet_sender, network_tuple, mtu, &tcb, ACK | PSH, s, p)?;
                                    }
                                    continue;
                                }
                                PacketType::NewPacket => {
                                    tcb.update_last_received_ack(incoming_ack);
                                    tcb.add_unordered_packet(incoming_seq, payload.clone());
                                    data_notify_clone.notify_one();
                                    tcb.update_send_window(window_size);
                                    write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                                    continue;
                                }
                                PacketType::Ack => {
                                    tcb.update_last_received_ack(incoming_ack);
                                    tcb.update_send_window(window_size);
                                    write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                                    continue;
                                }
                                PacketType::Invalid => {}
                            }

                            if matches!(*shutdown.lock().unwrap(), Shutdown::Pending(_)) && tcb.get_last_received_ack() == tcb.get_seq() {
                                let nt = network_tuple;
                                log::trace!("{nt} {state:?}: Shutting down, actively send a farewell packet to the other side...");
                                Self::write_packet_to_device(&up_packet_sender, network_tuple, mtu, &tcb, ACK | FIN, None, None)?;
                                tcb.increase_seq();
                                tcb.change_state(TcpState::FinWait1);
                            }
                        }
                        if flags == (ACK | FIN) {
                            // The other side is closing the connection, we need to send an ACK and change state to CloseWait
                            log::trace!("{network_tuple} {state:?}: {l_info}, {pkt_type:?}, closed by the other side...");
                            tcb.increase_ack();
                            Self::write_packet_to_device(&up_packet_sender, network_tuple, mtu, &tcb, ACK, None, None)?;
                            tcb.change_state(TcpState::CloseWait);
                            continue;
                        }
                        if flags == (ACK | PSH) && pkt_type == PacketType::NewPacket {
                            tcb.update_last_received_ack(incoming_ack);
                            if !payload.is_empty() && tcb.get_ack() == incoming_seq {
                                tcb.update_send_window(window_size);
                                tcb.add_unordered_packet(incoming_seq, payload.clone());
                                data_notify_clone.notify_one();
                            }
                            continue;
                        }
                    }
                    TcpState::CloseWait => {
                        if flags == ACK {
                            Self::write_packet_to_device(&up_packet_sender, network_tuple, mtu, &tcb, ACK | FIN, None, None)?;
                            tcb.increase_seq();
                            tcb.change_state(TcpState::LastAck);
                        }
                    }
                    TcpState::LastAck => {
                        if flags == ACK {
                            tcb.change_state(TcpState::Closed);
                            let exit_notifier = exit_notifier.clone();
                            tokio::spawn(async move { exit_notifier.send(()).await.unwrap_or(()) });
                        }
                    }
                    TcpState::FinWait1 => {
                        if flags & (ACK | FIN) == (ACK | FIN) && len == 0 {
                            // If the received packet is an ACK with FIN, we need to send an ACK and change state to TimeWait directly, not to FinWait2
                            tcb.increase_ack();
                            Self::write_packet_to_device(&up_packet_sender, network_tuple, mtu, &tcb, ACK, None, None)?;
                            tcb.update_send_window(window_size);
                            tcb.change_state(TcpState::TimeWait);
                            tokio::spawn(task_wait_to_close(tcb_clone.clone(), exit_notifier.clone()));
                            continue;
                        }
                        if flags & ACK == ACK && len == 0 {
                            tcb.update_last_received_ack(incoming_ack);
                            tcb.change_state(TcpState::FinWait2);
                            continue;
                        }
                        if flags & (ACK | PSH) == (ACK | PSH) && len > 0 {
                            // if the other side is still sending data, we need to deal with it like PacketStatus::NewPacket
                            tcb.update_last_received_ack(incoming_ack);
                            tcb.add_unordered_packet(incoming_seq, payload.clone());
                            data_notify_clone.notify_one();
                            tcb.update_send_window(window_size);
                            tcb.change_state(TcpState::FinWait2);
                            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                            continue;
                        }
                    }
                    TcpState::FinWait2 => {
                        if flags & (ACK | FIN) == (ACK | FIN) && len == 0 {
                            tcb.increase_ack();
                            Self::write_packet_to_device(&up_packet_sender, network_tuple, mtu, &tcb, ACK, None, None)?;
                            tcb.update_send_window(window_size);
                            tcb.change_state(TcpState::TimeWait);
                            tokio::spawn(task_wait_to_close(tcb_clone.clone(), exit_notifier.clone()));
                            continue;
                        }
                        if flags & ACK == ACK && len == 0 {
                            // unnormal case, we do nothing here
                            tcb.update_send_window(window_size);
                            let l_ack = tcb.get_ack();
                            if incoming_seq < l_ack {
                                log::trace!("{network_tuple} {state:?}: Ignoring duplicate ACK, seq {incoming_seq}, expected {l_ack}");
                            }
                            continue;
                        }
                        if flags & (ACK | PSH) == (ACK | PSH) && len > 0 {
                            // if the other side is still sending data, we need to deal with it like PacketStatus::NewPacket
                            tcb.update_last_received_ack(incoming_ack);
                            tcb.add_unordered_packet(incoming_seq, payload.clone());
                            data_notify_clone.notify_one();
                            tcb.update_send_window(window_size);
                            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                            if flags & FIN == FIN {
                                tcb.change_state(TcpState::TimeWait);
                                tokio::spawn(task_wait_to_close(tcb_clone.clone(), exit_notifier.clone()));
                            }
                            continue;
                        }
                    }
                    TcpState::TimeWait => {
                        if flags & (ACK | FIN) == (ACK | FIN) {
                            Self::write_packet_to_device(&up_packet_sender, network_tuple, mtu, &tcb, ACK, None, None)?;
                            // wait to timeout, can't call `tcb.change_state(TcpState::Closed);` to change state here
                            // now we need to wait for the timeout to reach...
                        }
                    }
                    _ => {}
                }
            }
            Ok::<(), std::io::Error>(())
        });

        // task 2: Data extraction and ACK sending
        let tcb = self.tcb.clone();
        let up_packet_sender = self.up_packet_sender.clone();
        let data_tx = self.data_tx.clone();
        let read_notify = self.read_notify.clone();
        let data_notify_clone = data_notify.clone();
        let exit_flag_clone = exit_flag.clone();
        tokio::spawn(async move {
            loop {
                let duration = Duration::from_millis(1000);
                tokio::time::timeout(duration, data_notify_clone.notified()).await.ok();
                let mut tcb = tcb.lock().unwrap();
                let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
                let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
                if exit_flag_clone.load(std::sync::atomic::Ordering::SeqCst) {
                    log::debug!("{network_tuple} {state:?}: {l_info} session closed, exiting \"data extraction task\"...");
                    break;
                }

                if let Some(data) = tcb.get_unordered_packets(4096) {
                    let hint = if state == TcpState::Established { "normally" } else { "still" };
                    log::trace!("{network_tuple} {state:?}: {l_info} {hint} receiving data, len = {}", data.len());
                    data_tx.send(data).map_err(|e| std::io::Error::new(BrokenPipe, e))?;
                    read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                    Self::write_packet_to_device(&up_packet_sender, network_tuple, mtu, &tcb, ACK, None, None)?;
                }
            }
            Ok::<(), std::io::Error>(())
        });
        Ok(())
    }
}
