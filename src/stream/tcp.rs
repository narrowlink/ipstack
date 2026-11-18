use super::seqnum::SeqNum;
use crate::{
    PacketReceiver, PacketSender, TTL,
    error::IpStackError,
    packet::{IpHeader, NetworkPacket, NetworkTuple, TcpFlags, TransportHeader, tcp_header_flags, tcp_header_fmt},
    stream::tcb::{MAX_COUNT_FOR_DUP_ACK, MAX_RETRANSMIT_COUNT, MAX_UNACK, PacketType, READ_BUFFER_SIZE, READ_CHUNK, RTO, Tcb, TcpState},
};
use atomic_waker::AtomicWaker;
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, TcpHeader, TcpOptionElement};
use std::{
    future::Future,
    io::ErrorKind::{BrokenPipe, ConnectionRefused, InvalidInput, UnexpectedEof},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// 2 * MSL (Maximum Segment Lifetime) is the maximum time a TCP connection can be in the TIME_WAIT state.
const TWO_MSL: Duration = Duration::from_secs(2);

const TIMEOUT: Duration = Duration::from_secs(60);

const ACK: TcpFlags = TcpFlags::ACK;
const FIN: TcpFlags = TcpFlags::FIN;
const PSH: TcpFlags = TcpFlags::PSH;
const RST: TcpFlags = TcpFlags::RST;
const SYN: TcpFlags = TcpFlags::SYN;

#[non_exhaustive]
#[derive(Debug, Clone)]
/// TCP configuration
pub struct TcpConfig {
    /// Unused; retained for API compatibility. `LAST_ACK` uses `rto` and `max_retransmit_count`.
    pub last_ack_max_retries: usize,
    /// Unused; retained for API compatibility. `LAST_ACK` uses `rto` and `max_retransmit_count`.
    pub last_ack_timeout: Duration,
    /// Unused; retained for API compatibility. `CLOSE_WAIT` remains open until shutdown or drop.
    pub close_wait_timeout: Duration,
    /// Timeout for TCP connections. Default is 60 seconds.
    pub timeout: Duration,
    /// Timeout for the TIME_WAIT state. Default is 2 seconds.
    pub two_msl: Duration,
    /// Maximum number of unacknowledged bytes allowed in the send buffer.
    pub max_unacked_bytes: u32,
    /// Size of the read buffer for incoming data.
    pub read_buffer_size: usize,
    /// Maximum number of duplicate ACKs before triggering fast retransmission.
    pub max_count_for_dup_ack: usize,
    /// Retransmission timeout duration.
    pub rto: std::time::Duration,
    /// R2, the transmission count of one segment at which the connection closes.
    pub max_retransmit_count: usize,
    /// TCP options
    pub options: Option<Vec<TcpOptions>>,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum TcpOptions {
    /// Maximum segment size (MSS) for TCP connections.
    MaximumSegmentSize(u16),
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig {
            last_ack_max_retries: 3,
            last_ack_timeout: Duration::from_millis(500),
            close_wait_timeout: TIMEOUT,
            timeout: TIMEOUT,
            two_msl: TWO_MSL,
            max_unacked_bytes: MAX_UNACK,
            read_buffer_size: READ_BUFFER_SIZE,
            max_count_for_dup_ack: MAX_COUNT_FOR_DUP_ACK,
            rto: RTO,
            max_retransmit_count: MAX_RETRANSMIT_COUNT,
            options: Default::default(),
        }
    }
}

/// Remembers shutdown completion and wakes the latest task polling for it.
#[derive(Debug, Default)]
struct ShutdownSignal {
    initiated: AtomicBool,
    completed: AtomicBool,
    drop_requested: AtomicBool,
    waker: AtomicWaker,
}

impl ShutdownSignal {
    fn initiate(&self) -> bool {
        !self.initiated.swap(true, Ordering::AcqRel)
    }

    fn is_initiated(&self) -> bool {
        self.initiated.load(Ordering::Acquire)
    }

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        // Register first: completion either wakes this task or is observed below.
        self.waker.register(cx.waker());
        if self.completed.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Re-poll a deferred shutdown without completing it.
    fn wake(&self) {
        self.waker.wake();
    }

    fn complete(&self) {
        self.completed.store(true, Ordering::Release);
        self.wake();
    }
}

static SESSION_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

type TcbPtr = std::sync::Arc<std::sync::Mutex<Tcb>>;

/// A TCP stream in the IP stack.
///
/// This type represents a TCP connection and implements `AsyncRead` and `AsyncWrite`
/// for bidirectional data transfer. It handles TCP state management, flow control,
/// and retransmission automatically.
///
/// # Examples
///
/// ```no_run
/// use ipstack::{IpStack, IpStackConfig, IpStackStream};
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # async fn example(mut ip_stack: IpStack) -> Result<(), Box<dyn std::error::Error>> {
/// if let IpStackStream::Tcp(mut tcp_stream) = ip_stack.accept().await? {
///     println!("New TCP connection from {}", tcp_stream.peer_addr());
///     
///     // Read data
///     let mut buffer = [0u8; 1024];
///     let n = tcp_stream.read(&mut buffer).await?;
///     
///     // Write data
///     tcp_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
///     
///     // Shutdown the stream
///     tcp_stream.shutdown().await?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct IpStackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: Option<PacketReceiver>,
    up_packet_sender: PacketSender,
    tcb: TcbPtr,
    shutdown: Arc<ShutdownSignal>,
    write_notify: Arc<AtomicWaker>,
    destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
    timeout: Pin<Box<tokio::time::Sleep>>,
    data_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    data_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    read_notify: Arc<AtomicWaker>,
    drain_notify: Arc<tokio::sync::Notify>,
    arm_notify: Arc<tokio::sync::Notify>,
    task_handle: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    exit_notifier: Option<tokio::sync::mpsc::Sender<()>>,
    temp_read_buffer: Vec<u8>,
    config: Arc<TcpConfig>,
}

impl IpStackTcpStream {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp: TcpHeader,
        payload_len: usize,
        up_packet_sender: PacketSender,
        mtu: u16,
        destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
        config: Arc<TcpConfig>,
    ) -> Result<IpStackTcpStream, IpStackError> {
        let tuple = NetworkTuple::new(src_addr, dst_addr, true);
        // RFC 9293 §3.10.7.2: in LISTEN, ignore RST segments and reset any ACK-bearing or non-SYN segment.
        if tcp.rst {
            let info = format!("Invalid TCP packet: {tuple} {}", tcp_header_fmt(&tcp));
            return Err(IpStackError::IoError(std::io::Error::new(ConnectionRefused, info)));
        }
        if tcp.ack || !tcp.syn {
            let (flags, seq, ack) = if tcp.ack {
                // RFC 9293 §3.10.7.2: any ACK-bearing segment in LISTEN triggers <SEQ=SEG.ACK><CTL=RST>.
                (RST, tcp.acknowledgment_number, 0)
            } else {
                // RFC 9293 §3.10.7.1: a non-ACK segment triggers <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>.
                let seg_len = (payload_len as u32)
                    .wrapping_add(u32::from(tcp.syn))
                    .wrapping_add(u32::from(tcp.fin));
                (ACK | RST, 0, tcp.sequence_number.wrapping_add(seg_len))
            };
            let rst = create_raw_packet(tuple.dst, tuple.src, |_, _| 0, flags, TTL, seq, ack, 0, Vec::new(), &[])
                .and_then(|pkt| up_packet_sender.send(pkt).map_err(|e| std::io::Error::new(UnexpectedEof, e)));
            if let Err(err) = rst {
                log::warn!("Error sending RST packet: {err}");
            }
            let info = format!("Invalid TCP packet: {tuple} {}", tcp_header_fmt(&tcp));
            return Err(IpStackError::IoError(std::io::Error::new(ConnectionRefused, info)));
        }

        // RFC 7323 §2.2: a window scale option is read only from a segment carrying SYN.
        let peer_window_shift = tcp.options_iterator().flatten().find_map(|option| match option {
            TcpOptionElement::WindowScale(shift) => Some(shift),
            _ => None,
        });
        let mut tcb = Tcb::new(
            SeqNum(tcp.sequence_number),
            tcp.window_size,
            peer_window_shift,
            mtu,
            config.max_unacked_bytes,
            config.read_buffer_size,
            config.max_count_for_dup_ack,
            config.rto,
            config.max_retransmit_count,
        );
        // Like the window scale, the MSS option is read only from a segment carrying SYN.
        if let Some(mss) = tcp.options_iterator().flatten().find_map(|option| match option {
            TcpOptionElement::MaximumSegmentSize(mss) => Some(mss),
            _ => None,
        }) {
            tcb.set_peer_mss(mss);
        }

        let (stream_sender, stream_receiver) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let data_channel_len = config.read_buffer_size.div_ceil(READ_CHUNK).max(1);
        let (data_tx, data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(data_channel_len);
        let deadline = tokio::time::Instant::now() + config.timeout;

        let mut stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver: Some(stream_receiver),
            up_packet_sender,
            tcb: std::sync::Arc::new(std::sync::Mutex::new(tcb.clone())),
            shutdown: Arc::new(ShutdownSignal::default()),
            write_notify: Arc::new(AtomicWaker::new()),
            destroy_messenger,
            timeout: Box::pin(tokio::time::sleep_until(deadline)),
            data_tx,
            data_rx,
            read_notify: Arc::new(AtomicWaker::new()),
            drain_notify: Arc::new(tokio::sync::Notify::new()),
            arm_notify: Arc::new(tokio::sync::Notify::new()),
            task_handle: None,
            exit_notifier: None,
            temp_read_buffer: Vec::new(),
            config,
        };

        let sessions = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst).saturating_add(1);
        let (seq, ack, state) = { (tcb.get_seq().0, tcb.get_ack().0, tcb.get_state()) };
        let l_info = LocalInfo(seq, ack);
        log::debug!("{tuple} {state:?}: {l_info} session begins, total TCP sessions: {sessions}");

        stream.spawn_tasks()?;
        Ok(stream)
    }

    fn reset_timeout(&mut self) {
        let deadline = tokio::time::Instant::now() + self.config.timeout;
        self.timeout.as_mut().reset(deadline);
    }

    pub(crate) fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple::new(self.src_addr, self.dst_addr, true)
    }

    /// Returns the local socket address of the TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackTcpStream;
    /// # fn example(tcp_stream: &IpStackTcpStream) {
    /// let local_addr = tcp_stream.local_addr();
    /// println!("Local address: {}", local_addr);
    /// # }
    /// ```
    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// Returns the remote socket address of the TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackTcpStream;
    /// # fn example(tcp_stream: &IpStackTcpStream) {
    /// let peer_addr = tcp_stream.peer_addr();
    /// println!("Peer address: {}", peer_addr);
    /// # }
    /// ```
    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    pub fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        // if there is data in the temp buffer, read it first
        if !self.temp_read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.temp_read_buffer.len());
            buf.put_slice(&self.temp_read_buffer[..len]);
            self.temp_read_buffer.drain(..len); // remove the read data from the temp buffer
            return Poll::Ready(Ok(()));
        }

        let network_tuple = self.network_tuple();

        // Register before checking state so a concurrent close cannot miss this reader.
        self.read_notify.register(cx.waker());
        let state = self.tcb.lock().unwrap().get_state();
        #[cfg(test)]
        tests::run_after_state_snapshot();
        if matches!(
            state,
            TcpState::CloseWait | TcpState::LastAck | TcpState::Closing | TcpState::TimeWait | TcpState::Closed
        ) {
            // Data on hand reaches the reader before end-of-stream.
            let data = {
                let this = self.as_mut().get_mut();
                let mut tcb = this.tcb.lock().unwrap();
                this.data_rx.try_recv().ok().or_else(|| tcb.take_received(usize::MAX))
            };
            if let Some(data) = data {
                let len = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..len]);
                self.temp_read_buffer.extend_from_slice(&data[len..]);
                return Poll::Ready(Ok(()));
            }
            if state == TcpState::Closed {
                self.shutdown.complete();
                self.write_notify.wake();
            }
            return Poll::Ready(Ok(()));
        }

        // handle timeout
        if matches!(Pin::new(&mut self.timeout).poll(cx), Poll::Ready(_)) {
            {
                let mut tcb = self.tcb.lock().unwrap();
                let (seq, ack) = (tcb.get_seq().0, tcb.get_ack().0);
                let l_info = LocalInfo(seq, ack);
                log::debug!("{network_tuple} {state:?}: [poll_read] {l_info}, session timeout reached, closing forcefully...");
                let sender = &self.up_packet_sender;
                write_packet_to_device(sender, network_tuple, &tcb, None, ACK | RST, None, None)?;
                tcb.change_state(TcpState::Closed);
                let state = tcb.get_state();
                log::debug!("{network_tuple} {state:?}: [poll_read] {l_info}, session notified to close");
            }
            self.shutdown.complete();

            return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        }
        self.reset_timeout();

        // read data from channel
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let capacity = buf.remaining();
                if capacity >= data.len() {
                    buf.put_slice(&data);
                } else {
                    // if `buf` is not enough, put the remaining data into the temp buffer
                    buf.put_slice(&data[..capacity]);
                    self.temp_read_buffer.extend_from_slice(&data[capacity..]);
                }
                // A channel slot just freed, so wake the loop to flush more and reopen the window.
                self.drain_notify.notify_one();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let nt = self.network_tuple();
        self.reset_timeout();

        // Register before checking readiness so a concurrent ACK cannot miss this writer.
        self.write_notify.register(cx.waker());
        let mut tcb = self.tcb.lock().unwrap();
        let state = tcb.get_state();
        let send_window = tcb.get_send_window();
        let is_full = tcb.is_send_buffer_full();

        if self.shutdown.is_initiated()
            || matches!(
                state,
                TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing | TcpState::TimeWait | TcpState::LastAck | TcpState::Closed
            )
        {
            if state == TcpState::Closed {
                self.shutdown.complete();
                self.read_notify.wake();
            }
            return Poll::Ready(Err(std::io::Error::new(BrokenPipe, "TCP connection closed")));
        }

        // Hold writes until the 3-way handshake completes (Established), so data cannot leave
        // ahead of the SYN-ACK or before the peer's final ACK arrives.
        if matches!(state, TcpState::Listen | TcpState::SynReceived) {
            return Poll::Pending;
        }

        if send_window == 0 || is_full {
            if send_window == 0 && !buf.is_empty() && tcb.arm_persist_probe() {
                self.arm_notify.notify_one();
            }
            log::trace!(
                "{nt} {state:?}: [poll_write] current send window: {send_window}, send buffer full: {is_full}, waiting for the other side to send ACK..."
            );
            return Poll::Pending;
        }

        // A segment past the right edge of the peer window is trimmed by the peer (RFC 9293 §3.10.7.4).
        let buf = &buf[..buf.len().min(tcb.get_usable_send_window() as usize)];
        let sender = &self.up_packet_sender;
        let payload_len = write_packet_to_device(sender, nt, &tcb, None, ACK | PSH, None, Some(buf.to_vec()))?;
        let was_empty = tcb.is_inflight_queue_empty();
        tcb.add_inflight_packet(buf[..payload_len].to_vec())?;
        if was_empty {
            // The loop reads the deadline when it enters `select!`, so the segment that reopens an
            // empty queue has to wake it; a later one sits behind a deadline it already waits on.
            self.arm_notify.notify_one();
        }

        let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
        let l_info = LocalInfo(seq, ack);
        log::trace!("{nt} {state:?}: [poll_write] {l_info} upstream data written to device, len = {payload_len}");

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.shutdown.poll_ready(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }
        let (nt, state, seq, is_ready, newly_initiated) = {
            let mut tcb = self.tcb.lock().unwrap();
            let newly_initiated = self.shutdown.initiate();
            begin_close(&mut tcb);
            let is_ready = tcb.get_inflight_packets_total_len() == 0;
            (self.network_tuple(), tcb.get_state(), tcb.get_seq(), is_ready, newly_initiated)
        };
        if newly_initiated {
            self.write_notify.wake();
        }
        log::trace!("{nt} {state:?}: [poll_shutdown] seq = {seq}, ready = {is_ready}",);
        #[cfg(test)]
        tests::run_after_state_snapshot();
        if matches!(state, TcpState::FinWait2 | TcpState::TimeWait | TcpState::Closed) {
            self.shutdown.complete();
            return Poll::Ready(Ok(()));
        }
        if is_ready && matches!(state, TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck) {
            let fin = {
                let mut tcb = self.tcb.lock().unwrap();
                send_fin("[poll_shutdown]", nt, &self.up_packet_sender, &mut tcb)?
            };
            if fin.is_some() {
                self.write_notify.wake();
                self.arm_notify.notify_one();
            }
        }
        // Completion may have happened since the initial poll or state snapshot.
        self.shutdown.poll_ready(cx).map(Ok)
    }
}

fn begin_close(tcb: &mut Tcb) {
    match tcb.get_state() {
        TcpState::Established => tcb.change_state(TcpState::FinWait1),
        TcpState::CloseWait => tcb.change_state(TcpState::LastAck),
        _ => {}
    }
}

fn send_fin(hint: &str, nt: NetworkTuple, sender: &PacketSender, tcb: &mut Tcb) -> std::io::Result<Option<SeqNum>> {
    begin_close(tcb);
    let state = tcb.get_state();
    if !matches!(state, TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck) {
        log::debug!("{nt} {state:?}: {hint} session is not in a valid state to send FIN, skipping...");
        return Ok(None);
    }
    if tcb.inflight_fin_seq().is_some() {
        return Ok(None);
    }
    if tcb.get_inflight_packets_total_len() != 0 {
        log::debug!("{nt} {state:?}: {hint} session has inflight data, skipping FIN...");
        return Ok(None);
    }

    log::debug!("{nt} {state:?}: {hint} actively send a farewell packet to the other side...");
    let fin_seq = tcb.get_seq();
    write_packet_to_device(sender, nt, tcb, None, ACK | FIN, Some(fin_seq), None)?;
    tcb.increase_seq();
    tcb.arm_inflight_fin(fin_seq);
    log::debug!("{nt} {state:?}: {hint} now in {state:?} state");

    Ok(Some(fin_seq))
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        enum DropAction {
            Abort,
            KeepAlive,
            FinSent,
        }

        let (nt, state) = (self.network_tuple(), self.tcb.lock().unwrap().get_state());
        log::trace!("{nt} {state:?}: [drop] session dropping, ========================= ");
        if let Some(task_handle) = self.task_handle.take() {
            if !task_handle.is_finished() {
                // The farewell packet reaches the device through an unbounded channel, so it
                // is sent here rather than left to the task.
                let action = {
                    let mut tcb = self.tcb.lock().unwrap();
                    self.shutdown.drop_requested.store(true, Ordering::Release);
                    match send_fin("[drop]", nt, &self.up_packet_sender, &mut tcb) {
                        Ok(Some(_)) => DropAction::FinSent,
                        Ok(_) if matches!(tcb.get_state(), TcpState::Listen | TcpState::SynReceived | TcpState::Closed) => {
                            DropAction::Abort
                        }
                        Ok(_) => DropAction::KeepAlive,
                        Err(e) => {
                            log::debug!("{nt} {state:?}: [drop] cannot send the farewell packet: {e}");
                            DropAction::Abort
                        }
                    }
                };
                if matches!(action, DropAction::FinSent) {
                    self.arm_notify.notify_one();
                }
                match action {
                    DropAction::Abort => {
                        if let Some(notifier) = self.exit_notifier.take() {
                            // The channel holds ten slots and one signal ends the task, so the send
                            // needs no runtime of its own.
                            _ = notifier.try_send(());
                        }
                        // Dropping the task drops its `destroy_messenger`, which wakes the watcher
                        // that removes this session from the stack.
                        task_handle.abort();
                    }
                    DropAction::KeepAlive | DropAction::FinSent => {
                        if let Some(exit) = self.exit_notifier.clone() {
                            let tcb = self.tcb.clone();
                            let up = self.up_packet_sender.clone();
                            let timeout = self.config.timeout;
                            tokio::spawn(async move {
                                tokio::select! {
                                    _ = exit.closed() => return,
                                    _ = tokio::time::sleep(timeout) => {}
                                }
                                {
                                    let mut tcb = tcb.lock().unwrap();
                                    if tcb.get_state() == TcpState::Closed {
                                        return;
                                    }
                                    _ = write_packet_to_device(&up, nt, &tcb, None, ACK | RST, None, None);
                                    tcb.change_state(TcpState::Closed);
                                }
                                _ = exit.send(()).await;
                            });
                        }
                    }
                }
            } else {
                log::trace!("{nt} {state:?}: [drop] task already finished, no need to wait exiting");
            }
        }
        let sessions = SESSION_COUNTER.fetch_sub(1, std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
        log::debug!("{nt} {state:?}: [drop] session dropped, total TCP sessions: {sessions}");
    }
}

impl IpStackTcpStream {
    fn spawn_tasks(&mut self) -> std::io::Result<()> {
        let network_tuple = self.network_tuple();

        // task: data receiving and processing
        let tcb = self.tcb.clone();
        let stream_receiver = self.stream_receiver.take().unwrap();
        let up_packet_sender = self.up_packet_sender.clone();
        let shutdown = self.shutdown.clone();
        let write_notify = self.write_notify.clone();
        let read_notify = self.read_notify.clone();
        let data_tx = self.data_tx.clone();
        let drain_notify = self.drain_notify.clone();
        let arm_notify = self.arm_notify.clone();
        let destroy_messenger = self.destroy_messenger.take();

        let (tcb_end, read_end, write_end) = (self.tcb.clone(), self.read_notify.clone(), self.write_notify.clone());

        let (exit_task_notifier, exit_monitor) = tokio::sync::mpsc::channel::<()>(10);
        let exit_notifier = exit_task_notifier.clone();
        let config = self.config.clone();
        self.exit_notifier = Some(exit_task_notifier);

        let task_handle = tokio::spawn(async move {
            let v = tcp_main_logic_loop(
                tcb,
                config,
                stream_receiver,
                up_packet_sender,
                exit_notifier,
                network_tuple,
                write_notify,
                read_notify,
                data_tx,
                drain_notify,
                arm_notify,
                exit_monitor,
                shutdown.clone(),
            )
            .await;
            if let Err(e) = &v {
                log::warn!("{network_tuple} task error: {e}");
            }
            tcb_end.lock().unwrap().change_state(TcpState::Closed);
            read_end.wake();
            write_end.wake();
            _ = destroy_messenger.map(|m| m.send(())).unwrap_or(Ok(()));
            log::trace!("{network_tuple} task completed, destroy messenger sent successfully");
            shutdown.complete();
            log::trace!("{network_tuple} shutdown completed");
            v
        });
        self.task_handle = Some(task_handle);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_main_logic_loop(
    tcb: TcbPtr,
    config: Arc<TcpConfig>,
    mut stream_receiver: PacketReceiver,
    up_packet_sender: PacketSender,
    exit_notifier: tokio::sync::mpsc::Sender<()>,
    network_tuple: NetworkTuple,
    write_notify: Arc<AtomicWaker>,
    read_notify: Arc<AtomicWaker>,
    data_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    drain_notify: Arc<tokio::sync::Notify>,
    arm_notify: Arc<tokio::sync::Notify>,
    mut exit_monitor: tokio::sync::mpsc::Receiver<()>,
    shutdown: Arc<ShutdownSignal>,
) -> std::io::Result<()> {
    {
        let mut tcb = tcb.lock().unwrap();

        let state = tcb.get_state();
        if state != TcpState::Listen {
            log::warn!("{network_tuple} {state:?}: Invalid TCP state, not in Listen state");
            return Ok::<(), std::io::Error>(());
        }

        tcb.increase_ack();
        let (syn_seq, ack) = (tcb.get_seq(), tcb.get_ack());
        let l_info = LocalInfo(syn_seq.0, ack.0);
        log::trace!("{network_tuple} {state:?}: {l_info} session begins");
        write_packet_to_device(
            &up_packet_sender,
            network_tuple,
            &tcb,
            config.options.as_ref(),
            ACK | SYN,
            Some(syn_seq),
            None,
        )?;
        tcb.increase_seq();
        tcb.change_state(TcpState::SynReceived);
        tcb.arm_inflight_syn(syn_seq);
        let state = tcb.get_state();
        log::trace!("{network_tuple} {state:?}: session now in {state:?} state");
    }

    let tcb_clone = tcb.clone();

    async fn task_wait_to_close(tcb: TcbPtr, exit_notifier: tokio::sync::mpsc::Sender<()>, nt: NetworkTuple, two_msl: Duration) {
        loop {
            let deadline = { tcb.lock().unwrap().time_wait_deadline() };
            let Some(deadline) = deadline else {
                return;
            };
            tokio::time::sleep_until(deadline).await;
            let mut tcb = tcb.lock().unwrap();
            if tcb.get_state() != TcpState::TimeWait {
                return;
            }
            if let Some(next_deadline) = tcb.time_wait_deadline()
                && next_deadline > tokio::time::Instant::now()
            {
                continue;
            }
            tcb.clear_time_wait_deadline();
            tcb.change_state(TcpState::Closed);
            let state = tcb.get_state();
            log::debug!("{nt} {state:?}: [task_wait_to_close] session closed after {two_msl:?}");
            break;
        }
        exit_notifier.send(()).await.unwrap_or(());
    }

    loop {
        let exit_notifier = exit_notifier.clone();

        let network_packet = tokio::select! {
            _ = exit_monitor.recv() => {
                log::debug!("{network_tuple} task exited due to exit signal");
                read_notify.wake();
                write_notify.wake();
                break;
            }
            _ = drain_notify.notified() => {
                // The upstream reader freed channel space, so flush whatever is buffered and
                // let the follow-up ACK carry the reopened window.
                let mut tcb = tcb.lock().unwrap();
                extract_data_n_write_upstream(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
                continue;
            }
            _ = wait_retransmission_deadline(&tcb, &arm_notify) => {
                // Either a deadline passed or the queue just reopened, so ask once who is overdue.
                let mut tcb = tcb.lock().unwrap();
                let state = tcb.get_state();
                if state == TcpState::Closed {
                    log::debug!("{network_tuple} {state:?}: session finished, exiting task...");
                    break;
                }
                let (packet, packets_exhausted) = tcb.collect_timed_out_inflight_packet();
                let (syn_seq, syn_exhausted) = tcb.collect_timed_out_inflight_syn();
                let (fin_seq, fin_exhausted) = tcb.collect_timed_out_inflight_fin();
                let (probe_seq, probe_exhausted) = tcb.collect_timed_out_persist_probe();
                if packets_exhausted || syn_exhausted || fin_exhausted || probe_exhausted {
                    // RFC 9293 §3.8.3: R2 transmissions of the same segment close the connection.
                    log::warn!("{network_tuple} segment reached R2 transmissions, closing session");
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | RST, None, None)?;
                    tcb.change_state(TcpState::Closed);
                    tcb.clear_inflight_syn();
                    tcb.clear_inflight_fin();
                    drop(tcb);
                    shutdown.complete();
                    write_notify.wake();
                    read_notify.wake();
                    break;
                }
                if let Some(seq) = syn_seq {
                    log::debug!("{network_tuple} {state:?}: SYN|ACK retransmission timeout: {seq:?}");
                    write_packet_to_device(
                        &up_packet_sender,
                        network_tuple,
                        &tcb,
                        config.options.as_ref(),
                        ACK | SYN,
                        Some(seq),
                        None,
                    )?;
                }
                if let Some(packet) = packet {
                    let (seq, count) = (packet.seq, packet.retransmit_count);
                    if tcb.get_send_window() == 0 {
                        log::debug!("{network_tuple} {state:?}: zero-window probe for inflight packet: {seq:?}");
                        write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, Some(seq - 1), None)?;
                    } else {
                        log::debug!("{network_tuple} inflight packet retransmission timeout: {seq:?}, retransmit_count: {count}",);
                        write_packet_to_device(
                            &up_packet_sender,
                            network_tuple,
                            &tcb,
                            None,
                            ACK | PSH,
                            Some(seq),
                            Some(packet.payload),
                        )?;
                    }
                }
                if let Some(seq) = fin_seq {
                    log::debug!("{network_tuple} {state:?}: FIN retransmission timeout: {seq:?}");
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | FIN, Some(seq), None)?;
                }
                if let Some(seq) = probe_seq {
                    log::debug!("{network_tuple} {state:?}: persist zero-window probe: {seq:?}");
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, Some(seq), None)?;
                }
                continue;
            }
            network_packet = stream_receiver.recv() => network_packet,
        };

        let Some(mut network_packet) = network_packet else {
            let state = { tcb.lock().unwrap().get_state() };
            log::debug!("{network_tuple} {state:?}: session closed unexpectedly by pipe broken, exiting task");
            tcb.lock().unwrap().change_state(TcpState::Closed);
            write_notify.wake();
            read_notify.wake();
            break;
        };

        let payload = network_packet.payload.take().unwrap_or_default();
        let TransportHeader::Tcp(tcp_header) = network_packet.transport_header() else {
            log::warn!("{network_tuple} Invalid TCP packet");
            continue;
        };
        let flags = tcp_header_flags(tcp_header);
        let incoming_ack: SeqNum = tcp_header.acknowledgment_number.into();
        let incoming_seq: SeqNum = tcp_header.sequence_number.into();

        let mut tcb = tcb.lock().unwrap();

        let state = tcb.get_state();
        if state == TcpState::Closed {
            log::debug!("{network_tuple} {state:?}: session finished, exiting task...");
            break;
        }

        // RFC 9293 §3.10.7.4 / RFC 5961 §3.2: validate RST sequence number against RCV.NXT
        // and the receive window before resetting the connection.
        if flags.contains(RST) {
            if incoming_seq == tcb.get_ack() {
                tcb.clear_inflight_syn();
                tcb.clear_inflight_fin();
                tcb.change_state(TcpState::Closed);
                drop(tcb);
                write_notify.wake();
                read_notify.wake();
                // Finish the task so its destroy notification and shutdown waker are delivered
                // even if the peer never sends another packet.
                break;
            }
            if tcb.is_seq_in_recv_window(incoming_seq) {
                log::trace!(
                    "{network_tuple} {state:?}: in-window RST seq = {incoming_seq} != RCV.NXT {}, sending challenge ACK",
                    tcb.get_ack()
                );
                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
            } else {
                log::trace!(
                    "{network_tuple} {state:?}: ignoring out-of-window RST seq = {incoming_seq}, RCV.NXT = {}",
                    tcb.get_ack()
                );
            }
            continue;
        }

        // A retransmitted SYN carries no ACK (typically ack = 0), so handle it before
        // sequence and ACK validation.
        if state == TcpState::SynReceived && flags.contains(SYN) && !flags.contains(ACK) && !flags.contains(FIN) {
            if incoming_seq == tcb.get_ack() - 1
                && let Some(syn_seq) = tcb.inflight_syn_seq()
            {
                log::trace!("{network_tuple} {state:?}: retransmitted SYN received, resending SYN|ACK seq = {syn_seq}");
                write_packet_to_device(
                    &up_packet_sender,
                    network_tuple,
                    &tcb,
                    config.options.as_ref(),
                    ACK | SYN,
                    Some(syn_seq),
                    None,
                )?;
            } else {
                log::trace!("{network_tuple} {state:?}: ignoring unexpected SYN seq = {incoming_seq}");
            }
            continue;
        }

        // RFC 9293 §3.10.7.4 Step 1: check sequence number against the receive window.
        // In states after the peer's FIN has been accepted, a retransmitted duplicate of that FIN
        // ends at RCV.NXT (`incoming_seq + payload.len() + 1 == RCV.NXT`) and still needs an ACK
        // (and 2MSL restart in TimeWait, or final ACK handling in LastAck/Closing).
        let seg_len = payload.len() + usize::from(flags.contains(SYN)) + usize::from(flags.contains(FIN));
        let is_retransmitted_fin = matches!(
            state,
            TcpState::CloseWait | TcpState::LastAck | TcpState::Closing | TcpState::TimeWait
        ) && flags.contains(FIN)
            && !flags.contains(SYN)
            && incoming_seq + (payload.len() as u32) + 1 == tcb.get_ack();

        if !tcb.is_segment_acceptable(incoming_seq, seg_len) && !is_retransmitted_fin {
            log::trace!(
                "{network_tuple} {state:?}: unacceptable segment seq = {incoming_seq}, len = {seg_len}, RCV.NXT = {}, sending ACK",
                tcb.get_ack()
            );
            write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
            continue;
        }

        // RFC 9293 §3.10.7.4 Step 4 / RFC 5961 §4.2: reject segments carrying SYN in
        // synchronized states (and unexpected SYN variants in SynReceived) with a challenge ACK.
        if flags.contains(SYN) {
            log::trace!("{network_tuple} {state:?}: unexpected SYN segment seq = {incoming_seq}, sending challenge ACK");
            write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
            continue;
        }

        // RFC 9293 §3.10.7.4 Step 5: if the ACK bit is off, drop the segment and return.
        if !flags.contains(ACK) {
            log::trace!("{network_tuple} {state:?}: dropping segment without ACK flag");
            continue;
        }

        // Validate SEG.ACK before mutating any ACK-dependent TCB state.
        if state == TcpState::SynReceived {
            if incoming_ack == tcb.get_last_received_ack() {
                log::trace!(
                    "{network_tuple} {state:?}: ignoring ACK {incoming_ack} not covering SYN|ACK (expected {})",
                    tcb.get_seq()
                );
                continue;
            }
            if incoming_ack != tcb.get_seq() {
                // RFC 9293 §3.10.7.4: unacceptable ACK in SYN-RECEIVED triggers <SEQ=SEG.ACK><CTL=RST>.
                log::trace!(
                    "{network_tuple} {state:?}: unacceptable ACK {incoming_ack} != {}, sending RST",
                    tcb.get_seq()
                );
                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, RST, Some(incoming_ack), None)?;
                continue;
            }
            // RFC 9293 §3.10.7.4: enter ESTABLISHED and continue processing this segment (including any payload or FIN).
            tcb.clear_inflight_syn();
            tcb.change_state(TcpState::Established);
            write_notify.wake();
        } else if incoming_ack > tcb.get_seq() {
            // RFC 9293 §3.10.7.4: SEG.ACK > SND.NXT -> send ACK and drop the segment.
            log::trace!(
                "{network_tuple} {state:?}: ACK {incoming_ack} > SND.NXT {}, sending ACK and dropping segment",
                tcb.get_seq()
            );
            write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
            continue;
        }

        let is_old_ack = incoming_ack < tcb.get_last_received_ack();
        if !is_old_ack {
            tcb.update_duplicate_ack_count(tcp_header, &payload);
            if incoming_ack > tcb.get_last_received_ack() {
                tcb.update_inflight_packet_queue(incoming_ack);
            }
        }

        let pkt_type = tcb.check_pkt_type(tcp_header, &payload);

        let (state, seq, ack) = { (tcb.get_state(), tcb.get_seq(), tcb.get_ack()) };
        let len = payload.len();
        let l_info = LocalInfo(seq, ack);
        if log::log_enabled!(log::Level::Trace) {
            let info = tcp_header_fmt(tcp_header);
            log::trace!("{network_tuple} {state:?}: {l_info} {info}, {pkt_type:?}, len = {len}");
        }
        if pkt_type == PacketType::Invalid {
            continue;
        }

        match state {
            TcpState::Established => {
                let fin_taken = if flags.contains(FIN) {
                    receive_segment(
                        &up_packet_sender,
                        &mut tcb,
                        network_tuple,
                        incoming_seq,
                        payload,
                        true,
                        &data_tx,
                        &read_notify,
                    )?
                } else if pkt_type == PacketType::NewPacket {
                    // RFC 9293 §3.10.7.4: process accepted segment data regardless of PSH/URG/ECE/CWR flags.
                    if !payload.is_empty() {
                        receive_segment(
                            &up_packet_sender,
                            &mut tcb,
                            network_tuple,
                            incoming_seq,
                            payload,
                            false,
                            &data_tx,
                            &read_notify,
                        )?
                    } else {
                        false
                    }
                } else {
                    handle_ack_packet(&up_packet_sender, &mut tcb, network_tuple, pkt_type, incoming_ack, &write_notify)?;
                    false
                };
                if fin_taken {
                    // Peer half-closed: ACK was sent for the FIN, keep write side open in CloseWait.
                    tcb.change_state(TcpState::CloseWait);
                    log::debug!("{network_tuple} CloseWait: peer closed write side, waiting for upstream shutdown");
                }
                if flags.contains(FIN) || pkt_type == PacketType::NewPacket {
                    write_notify.wake();
                }
            }
            TcpState::CloseWait => {
                if flags.contains(FIN) {
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                    write_notify.wake();
                } else if flags == ACK || (flags == (ACK | PSH) && payload.is_empty()) {
                    handle_ack_packet(&up_packet_sender, &mut tcb, network_tuple, pkt_type, incoming_ack, &write_notify)?;
                }
            }
            TcpState::LastAck => {
                if flags.contains(FIN) {
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                }
                if flags.contains(ACK) && tcb.inflight_fin_seq().is_some() && incoming_ack == tcb.get_seq() {
                    tcb.clear_inflight_fin();
                    tcb.change_state(TcpState::Closed);
                    shutdown.complete();
                    let new_state = tcb.get_state();
                    log::trace!("{network_tuple} {state:?}: Received final ACK, transitioned to {new_state:?}");
                    break;
                }
                if tcb.inflight_fin_seq().is_none() && (flags == ACK || (flags == (ACK | PSH) && payload.is_empty())) {
                    handle_ack_packet(&up_packet_sender, &mut tcb, network_tuple, pkt_type, incoming_ack, &write_notify)?;
                }
            }
            TcpState::Closing => {
                if flags.contains(FIN) {
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                }
                if flags.contains(ACK) && tcb.inflight_fin_seq().is_some() && incoming_ack == tcb.get_seq() {
                    tcb.clear_inflight_fin();
                    tcb.change_state(TcpState::TimeWait);
                    tcb.restart_time_wait(config.two_msl);
                    tokio::spawn(task_wait_to_close(
                        tcb_clone.clone(),
                        exit_notifier.clone(),
                        network_tuple,
                        config.two_msl,
                    ));
                    shutdown.complete();
                    let new_state = tcb.get_state();
                    log::trace!("{network_tuple} {state:?}: Received final ACK, transitioned to {new_state:?}");
                } else if tcb.inflight_fin_seq().is_none() && pkt_type == PacketType::RetransmissionRequest {
                    handle_ack_packet(&up_packet_sender, &mut tcb, network_tuple, pkt_type, incoming_ack, &write_notify)?;
                }
            }
            TcpState::FinWait1 | TcpState::FinWait2 if flags.contains(ACK) => {
                let acked_fin = state == TcpState::FinWait1 && tcb.inflight_fin_seq().is_some() && incoming_ack == tcb.get_seq();
                if acked_fin {
                    tcb.clear_inflight_fin();
                    tcb.change_state(TcpState::FinWait2);
                }
                let fin_taken = if flags.contains(FIN) {
                    let taken = receive_segment(
                        &up_packet_sender,
                        &mut tcb,
                        network_tuple,
                        incoming_seq,
                        payload,
                        true,
                        &data_tx,
                        &read_notify,
                    )?;
                    if len > 0 {
                        write_notify.wake();
                    }
                    taken
                } else if pkt_type == PacketType::KeepAlive {
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                    false
                } else if len > 0 {
                    let taken = receive_segment(
                        &up_packet_sender,
                        &mut tcb,
                        network_tuple,
                        incoming_seq,
                        payload,
                        false,
                        &data_tx,
                        &read_notify,
                    )?;
                    write_notify.wake();
                    taken
                } else if pkt_type == PacketType::RetransmissionRequest && tcb.inflight_fin_seq().is_none() {
                    handle_ack_packet(&up_packet_sender, &mut tcb, network_tuple, pkt_type, incoming_ack, &write_notify)?;
                    false
                } else {
                    if state == TcpState::FinWait2 && incoming_seq < tcb.get_ack() {
                        log::trace!(
                            "{network_tuple} {state:?}: Ignoring duplicate ACK, seq {incoming_seq}, expected {}",
                            tcb.get_ack()
                        );
                    }
                    false
                };
                if fin_taken {
                    if tcb.get_state() == TcpState::FinWait1 {
                        tcb.change_state(TcpState::Closing);
                    } else {
                        tcb.change_state(TcpState::TimeWait);
                        tcb.restart_time_wait(config.two_msl);
                        tokio::spawn(task_wait_to_close(
                            tcb_clone.clone(),
                            exit_notifier.clone(),
                            network_tuple,
                            config.two_msl,
                        ));
                    }
                }
                if acked_fin {
                    shutdown.complete();
                }
                let new_state = tcb.get_state();
                log::trace!("{network_tuple} {state:?}: {l_info}, {pkt_type:?}, transitioned to {new_state:?}");
            }
            TcpState::TimeWait if flags.contains(ACK | FIN) => {
                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                tcb.restart_time_wait(config.two_msl);
                // wait to timeout, can't call `tcb.change_state(TcpState::Closed);` to change state here
                // now we need to wait for the timeout to reach...
            }
            _ => {}
        } // end of match state

        let prev_send_window = tcb.get_send_window();
        if !is_old_ack {
            if incoming_ack > tcb.get_last_received_ack() {
                tcb.update_last_received_ack(incoming_ack);
            }
            tcb.update_send_window_if_newer(tcp_header);
            tcb.reset_unanswered_probes();
        }
        // RFC 9293 §3.8.6.1: a peer with a zero receive window may have dropped our FIN or data;
        // resend it and wake parked writers when the window reopens.
        if prev_send_window == 0 && tcb.get_send_window() > 0 {
            write_notify.wake();
            if matches!(tcb.get_state(), TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck)
                && incoming_ack != tcb.get_seq()
                && let Some(fin_seq) = tcb.inflight_fin_seq()
            {
                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | FIN, Some(fin_seq), None)?;
            }
            if let Some(packet) = tcb.take_probed_inflight_packet() {
                write_packet_to_device(
                    &up_packet_sender,
                    network_tuple,
                    &tcb,
                    None,
                    ACK | PSH,
                    Some(packet.seq),
                    Some(packet.payload),
                )?;
            }
        }
        // ACKs with or without data can retire the last outstanding bytes. The
        // shutdown waiter may belong to a different task than the writer.
        if flags.contains(ACK)
            && matches!(
                tcb.get_state(),
                TcpState::Established | TcpState::CloseWait | TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
            )
            && tcb.is_inflight_queue_empty()
            && tcb.inflight_fin_seq().is_none()
        {
            if shutdown.is_initiated() || shutdown.drop_requested.load(Ordering::Acquire) {
                let _ = send_fin("[shutdown]", network_tuple, &up_packet_sender, &mut tcb)?;
            }
            shutdown.wake();
        }
    } // end of loop
    Ok::<(), std::io::Error>(())
}

fn handle_ack_packet(
    up_packet_sender: &PacketSender,
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    pkt_type: PacketType,
    incoming_ack: SeqNum,
    write_notify: &AtomicWaker,
) -> std::io::Result<()> {
    match pkt_type {
        PacketType::WindowUpdate | PacketType::Ack => {
            write_notify.wake();
        }
        PacketType::KeepAlive => {
            write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK, None, None)?;
        }
        PacketType::RetransmissionRequest => {
            if let Some(packet) = tcb.find_inflight_packet_mut(incoming_ack) {
                packet.retransmit_count += 1;
                let (s, p) = (packet.seq, packet.payload.clone());
                let state = tcb.get_state();
                let l_info = LocalInfo(tcb.get_seq(), tcb.get_ack());
                log::debug!(
                    "{network_tuple} {state:?}: {l_info}, {pkt_type:?}, retransmission request, seq = {s}, len = {}",
                    p.len()
                );
                write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK | PSH, Some(s), Some(p))?;
            }
        }
        PacketType::NewPacket | PacketType::Invalid => {}
    }
    Ok(())
}

/// Wait for the connection's retransmission deadline, which RFC 6298 §5.6 sets after every
/// backoff and §5.4 acts on by retransmitting the earliest unacknowledged segment. A connection with nothing
/// outstanding has no deadline, so it waits for `arm_notify` to say a segment reopened the inflight
/// queue; the caller re-enters `select!` afterwards and reads the deadline that segment created.
async fn wait_retransmission_deadline(tcb: &TcbPtr, arm_notify: &tokio::sync::Notify) {
    let deadline = { tcb.lock().unwrap().get_retransmission_deadline() };
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => arm_notify.notified().await,
    }
}

/// Stores a data/FIN segment that arrived from the peer and acknowledges it; returns whether a FIN was taken.
///
/// The ACK goes out even when no new data reaches the reader: a segment that arrives out of order,
/// or one already received, is answered with a duplicate ACK at once (RFC 5681 §4.2), which is
/// what lets the peer fast-retransmit the segment in the gap instead of waiting out its timer.
/// If the segment carries FIN and fits in the receive window, its FIN sequence number is persisted
/// so filling a preceding gap takes the FIN immediately without requiring a FIN retransmission.
#[allow(clippy::too_many_arguments)]
fn receive_segment(
    up_packet_sender: &PacketSender,
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    seq: SeqNum,
    payload: Vec<u8>,
    has_fin: bool,
    data_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    read_notify: &AtomicWaker,
) -> std::io::Result<bool> {
    let fin_seq = seq + payload.len() as u32;
    if tcb.add_unordered_packet(seq, payload) && has_fin {
        tcb.record_unordered_fin(fin_seq);
    }
    tcb.acknowledge_unordered_packets();
    let fin_taken = tcb.take_unordered_fin();
    if !extract_data_n_write_upstream(up_packet_sender, tcb, network_tuple, data_tx, read_notify)? {
        write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK, None, None)?;
    }
    if fin_taken {
        read_notify.wake();
    }
    Ok(fin_taken)
}

/// Hands acknowledged data to the reader. Returns whether an ACK was written, or none is due
/// because the session is closed.
fn extract_data_n_write_upstream(
    up_packet_sender: &PacketSender,
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    data_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    read_notify: &AtomicWaker,
) -> std::io::Result<bool> {
    let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
    let l_info = LocalInfo(seq, ack);
    if state == TcpState::Closed {
        log::debug!("{network_tuple} {state:?}: {l_info} session closed, exiting \"data extraction task\"...");
        return Ok(true);
    }

    // Reserve the handoff slot before taking acknowledged data.
    let permit = match data_tx.try_reserve() {
        Ok(permit) => permit,
        Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {
            write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK, None, None)?;
            return Ok(true);
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
            return Err(std::io::Error::new(BrokenPipe, "data channel closed"));
        }
    };

    if let Some(data) = tcb.take_received(READ_CHUNK) {
        let hint = if state == TcpState::Established { "normally" } else { "still" };
        log::trace!("{network_tuple} {state:?}: {l_info} {hint} receiving data, len = {}", data.len());
        permit.send(data);
        read_notify.wake();
        write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK, None, None)?;
        return Ok(true);
    }
    Ok(false)
}

/// Send a TCP packet to the downstream device, with the specified flags, sequence number, and payload.
/// `local { seq, ack }` for log lines, formatted only when a line is actually emitted: the session
/// loop builds one for every packet, whether or not anything is logged.
struct LocalInfo<S, A>(S, A);

impl<S: std::fmt::Display, A: std::fmt::Display> std::fmt::Display for LocalInfo<S, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local {{ seq: {}, ack: {} }}", self.0, self.1)
    }
}

/// The returned value is the length of the `payload` sent, it may be shorter than the length of the incoming parameter `payload`.
pub(crate) fn write_packet_to_device(
    up_packet_sender: &PacketSender,
    tuple: NetworkTuple,
    tcb: &Tcb,
    options: Option<&Vec<TcpOptions>>,
    flags: TcpFlags,
    seq: Option<SeqNum>,
    payload: Option<Vec<u8>>,
) -> std::io::Result<usize> {
    use std::io::Error;
    let seq = seq.unwrap_or(tcb.get_seq()).0;
    let recv_window = tcb.get_recv_window();
    // RFC 7323 §2.2: the window field of a segment carrying SYN is not scaled.
    let advertised = if flags.contains(SYN) {
        recv_window
    } else {
        tcb.get_scaled_recv_window()
    };
    let window_size = advertised;
    let ack = tcb.get_ack().0;
    let (src, dst) = (tuple.dst, tuple.src); // Note: The address is reversed here
    let mut tcp_options = Vec::new();
    // Note: Instead of an `if let Some ... ` a loop is used as the enum is #[non_exhaustive]
    for option in options.into_iter().flatten() {
        match option {
            TcpOptions::MaximumSegmentSize(mss) => tcp_options.push(TcpOptionElement::MaximumSegmentSize(*mss)),
        }
    }
    // RFC 7323 §2.2: the window scale option travels only on a segment carrying SYN, and only when
    // the peer's SYN carried one.
    if flags.contains(SYN)
        && let Some(shift) = tcb.get_recv_window_shift()
    {
        tcp_options.push(TcpOptionElement::WindowScale(shift));
    }
    let calc = |ip_header_len: usize, tcp_header_len: usize| tcb.calculate_payload_max_len(ip_header_len, tcp_header_len);
    let packet = create_raw_packet(
        src,
        dst,
        calc,
        flags,
        TTL,
        seq,
        ack,
        window_size,
        payload.unwrap_or_default(),
        &tcp_options,
    )?;
    let len = packet.payload.as_ref().map(|p| p.len()).unwrap_or(0);
    up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
    Ok(len)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_raw_packet(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    calculate_payload_max_len: impl Fn(usize, usize) -> usize,
    flags: TcpFlags,
    ttl: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mut payload: Vec<u8>,
    options: &[TcpOptionElement],
) -> std::io::Result<NetworkPacket> {
    let mut tcp_header = etherparse::TcpHeader::new(src_addr.port(), dst_addr.port(), seq, win);
    tcp_header.acknowledgment_number = ack;
    tcp_header.syn = flags.contains(SYN);
    tcp_header.ack = flags.contains(ACK);
    tcp_header.rst = flags.contains(RST);
    tcp_header.fin = flags.contains(FIN);
    tcp_header.psh = flags.contains(PSH);
    tcp_header.urg = flags.contains(TcpFlags::URG);

    tcp_header.set_options(options).map_err(|e| std::io::Error::new(InvalidInput, e))?;

    let ip_header = match (src_addr.ip(), dst_addr.ip()) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            let mut ip_h =
                Ipv4Header::new(0, ttl, IpNumber::TCP, src.octets(), dst.octets()).map_err(|e| std::io::Error::new(InvalidInput, e))?;
            let payload_len = calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
            payload.truncate(payload_len);
            ip_h.set_payload_len(payload.len() + tcp_header.header_len())
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
            ip_h.dont_fragment = true;
            IpHeader::Ipv4(ip_h)
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            let mut ip_h = etherparse::Ipv6Header {
                traffic_class: 0,
                flow_label: Ipv6FlowLabel::ZERO,
                payload_length: 0,
                next_header: IpNumber::TCP,
                hop_limit: ttl,
                source: src.octets(),
                destination: dst.octets(),
            };
            let payload_len = calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
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
        payload: Some(payload),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::tcb::{MAX_COUNT_FOR_DUP_ACK, MAX_RETRANSMIT_COUNT, MAX_UNACK, READ_BUFFER_SIZE, RTO};
    use rstest::rstest;
    use std::task::Waker;
    use tokio::io::AsyncWriteExt;

    const PEER: &str = "10.0.0.2:12345";
    const LOCAL: &str = "10.0.0.1:80";
    /// The intervals RFC 6298 §5.5 produces from a one-second timeout doubling to the §2.5 ceiling.
    const BACKOFF: [u64; MAX_RETRANSMIT_COUNT] = [1, 2, 4, 8, 16, 32, 60];

    thread_local! {
        // Thread-local so unrelated tests and TCP workers cannot consume this hook.
        static AFTER_STATE_SNAPSHOT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    }

    pub(super) fn run_after_state_snapshot() {
        let hook = AFTER_STATE_SNAPSHOT.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Arrange for a real TCP worker to finish processing RST after a poll method has
    /// read the old state. This exercises early read registration and the shutdown
    /// state recheck after registration. No state is mocked.
    fn reset_after_state_snapshot(stream: &mut IpStackTcpStream, local_seq: u32) {
        let sender = stream.stream_sender();
        let task = stream.task_handle.take().unwrap();
        let runtime = tokio::runtime::Handle::current();
        AFTER_STATE_SNAPSHOT.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::thread::spawn(move || {
                    sender.send(peer_segment(1001, local_seq, RST | ACK, u16::MAX, &[])).unwrap();
                    runtime.block_on(async {
                        tokio::time::timeout(Duration::from_secs(1), task)
                            .await
                            .expect("RST did not finish the TCP task")
                            .expect("TCP task panicked")
                            .expect("TCP task failed");
                    });
                })
                .join()
                .expect("reset worker panicked");
            }));
        });
    }

    /// A waker that records whether it was woken, and the flag it sets.
    fn recording_waker() -> (Arc<std::sync::atomic::AtomicBool>, Waker) {
        struct Recording(Arc<std::sync::atomic::AtomicBool>);
        impl std::task::Wake for Recording {
            fn wake(self: Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let woken = Arc::new(std::sync::atomic::AtomicBool::new(false));
        (woken.clone(), Waker::from(Arc::new(Recording(woken))))
    }

    /// Takes the TCP header of a packet the stack wrote to the device.
    fn tcp_header_of(packet: &NetworkPacket) -> &TcpHeader {
        match packet.transport_header() {
            TransportHeader::Tcp(header) => header,
            _ => panic!("the stack wrote a packet that is not TCP"),
        }
    }

    /// Opens a connection and completes its handshake, returning the stream, the device receiver,
    /// and the sequence number the stack sends its first data byte at.
    async fn established() -> (IpStackTcpStream, PacketReceiver, u32) {
        established_with_destroy(None).await
    }

    async fn established_with_destroy(destroy: Option<tokio::sync::oneshot::Sender<()>>) -> (IpStackTcpStream, PacketReceiver, u32) {
        established_with(destroy, TcpConfig::default()).await
    }

    async fn established_with(
        destroy: Option<tokio::sync::oneshot::Sender<()>>,
        config: TcpConfig,
    ) -> (IpStackTcpStream, PacketReceiver, u32) {
        let (peer, local) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();

        let mut syn = TcpHeader::new(12345, 80, 1000, u16::MAX);
        syn.syn = true;
        let stream = IpStackTcpStream::new(peer, local, syn, 0, up_tx, 1500, destroy, Arc::new(config)).unwrap();

        let syn_ack = tokio::time::timeout(Duration::from_secs(1), up_rx.recv())
            .await
            .expect("SYN-ACK did not arrive")
            .expect("TCP task closed before SYN-ACK");
        let local_seq = tcp_header_of(&syn_ack).sequence_number + 1;
        stream.stream_sender().send(peer_ack(1001, local_seq)).unwrap();
        wait_for_handshake(&stream).await.expect("handshake did not complete");

        (stream, up_rx, local_seq)
    }

    async fn wait_for_handshake(stream: &IpStackTcpStream) -> Result<(), tokio::time::error::Elapsed> {
        tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                let tcb = stream.tcb.lock().unwrap();
                if tcb.get_state() == TcpState::Established {
                    Poll::Ready(())
                } else {
                    // The handshake transition holds tcb and wakes write_notify. Register
                    // under the same state lock so that the transition cannot be missed.
                    stream.write_notify.register(cx.waker());
                    Poll::Pending
                }
            }),
        )
        .await
    }

    /// Opens a connection with a SYN advertising `window` and `syn_options`, returning the stream
    /// and the SYN-ACK the stack emitted.
    async fn open(window: u16, syn_options: &[TcpOptionElement]) -> (IpStackTcpStream, TcpHeader, PacketReceiver) {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let (src, dst) = (SocketAddr::from(([10, 0, 0, 2], 40000)), SocketAddr::from(([10, 0, 0, 1], 80)));

        let mut syn = TcpHeader::new(src.port(), dst.port(), 1000, window);
        syn.syn = true;
        syn.set_options(syn_options).unwrap();

        let stream = IpStackTcpStream::new(src, dst, syn, 0, up_tx, 1500, None, Arc::new(TcpConfig::default())).unwrap();
        let packet = up_rx.recv().await.expect("the stack emitted no SYN-ACK");
        let TransportHeader::Tcp(syn_ack) = packet.transport_header() else {
            panic!("the emitted SYN-ACK is not a TCP packet");
        };
        (stream, syn_ack.clone(), up_rx)
    }

    #[tokio::test]
    async fn mtu_larger_than_read_buffer_keeps_initial_window_open() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let (src, dst) = (SocketAddr::from(([10, 0, 0, 2], 40000)), SocketAddr::from(([10, 0, 0, 1], 80)));
        let mut syn = TcpHeader::new(src.port(), dst.port(), 1000, u16::MAX);
        syn.syn = true;

        let config = TcpConfig {
            read_buffer_size: 16 * 1024,
            ..TcpConfig::default()
        };
        let _stream = IpStackTcpStream::new(src, dst, syn, 0, up_tx, u16::MAX, None, Arc::new(config)).unwrap();
        let syn_ack = up_rx.recv().await.expect("the stack emitted no SYN-ACK");

        assert_eq!(tcp_header_of(&syn_ack).window_size, 16 * 1024);
    }

    #[tokio::test]
    async fn partially_available_window_is_not_advertised_as_zero() {
        let (stream, _, mut up_rx) = open(u16::MAX, &[]).await;
        {
            let mut tcb = stream.tcb.lock().unwrap();
            let ack = tcb.get_ack();
            assert!(tcb.add_unordered_packet(ack, vec![0; 15 * 1024]));
            tcb.acknowledge_unordered_packets();
        }

        write_packet_to_device(
            &stream.up_packet_sender,
            stream.network_tuple(),
            &stream.tcb.lock().unwrap(),
            None,
            ACK,
            None,
            None,
        )
        .unwrap();
        let ack = up_rx.recv().await.expect("the stack emitted no window update");

        assert_eq!(tcp_header_of(&ack).window_size, 1024);
    }

    /// Feeds `stream` a segment advertising `window`, carrying `payload` at `seq`.
    fn feed(stream: &IpStackTcpStream, syn_ack: &TcpHeader, seq: SeqNum, window: u16, payload: &[u8]) {
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], TTL)
            .tcp(40000, 80, seq.0, window)
            .ack((SeqNum(syn_ack.sequence_number) + 1).0)
            .psh();
        let mut buf = Vec::new();
        builder.write(&mut buf, payload).unwrap();
        stream.stream_sender().send(NetworkPacket::parse(&buf).unwrap()).unwrap();
    }

    /// Returns the shift count of the window scale option in `header`, if it carries one.
    fn window_scale_of(header: &TcpHeader) -> Option<u8> {
        header.options_iterator().flatten().find_map(|option| match option {
            TcpOptionElement::WindowScale(shift) => Some(shift),
            _ => None,
        })
    }

    /// An acknowledgement from the peer, carrying no data.
    fn peer_ack(seq: u32, ack: u32) -> NetworkPacket {
        let (src, dst) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
        create_raw_packet(src, dst, |_, _| usize::MAX, ACK, TTL, seq, ack, u16::MAX, Vec::new(), &[]).unwrap()
    }

    /// A segment from the peer carrying `payload` at `seq`, with `flags` and a raw `window`.
    fn peer_segment(seq: u32, ack: u32, flags: TcpFlags, window: u16, payload: &[u8]) -> NetworkPacket {
        let (src, dst) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
        create_raw_packet(src, dst, |_, _| usize::MAX, flags, TTL, seq, ack, window, payload.to_vec(), &[]).unwrap()
    }

    /// Drains what the stack wrote to the device so far.
    async fn written(up_rx: &mut PacketReceiver) -> Vec<NetworkPacket> {
        tokio::task::yield_now().await;
        let mut packets = Vec::new();
        while let Ok(packet) = up_rx.try_recv() {
            packets.push(packet);
        }
        packets
    }

    /// The acknowledgment numbers of the pure ACKs the stack wrote (our own FINs excluded).
    async fn acks(up_rx: &mut PacketReceiver) -> Vec<u32> {
        let packets = written(up_rx).await;
        packets
            .iter()
            .map(tcp_header_of)
            .filter(|h| !h.fin)
            .map(|h| h.acknowledgment_number)
            .collect()
    }

    /// Advances the clock by `by` and returns what the stack wrote to the device.
    async fn advance(by: Duration, up_rx: &mut PacketReceiver) -> Option<NetworkPacket> {
        tokio::time::advance(by).await;
        tokio::task::yield_now().await;
        up_rx.try_recv().ok()
    }

    // --- Handshake & initial write tests ---

    #[tokio::test(start_paused = true)]
    async fn handshake_wait_times_out_without_peer_ack() {
        let (stream, _syn_ack, _up_rx) = open(u16::MAX, &[]).await;
        let started = tokio::time::Instant::now();
        assert!(wait_for_handshake(&stream).await.is_err());
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::SynReceived);
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_wait_is_woken_by_peer_ack() {
        let (stream, syn_ack, mut up_rx) = open(u16::MAX, &[]).await;
        let started = tokio::time::Instant::now();
        let wait = wait_for_handshake(&stream);
        tokio::pin!(wait);
        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(std::future::Future::poll(wait.as_mut(), &mut cx).is_pending());
        stream
            .stream_sender()
            .send(peer_ack(syn_ack.acknowledgment_number, syn_ack.sequence_number.wrapping_add(1)))
            .unwrap();
        written(&mut up_rx).await;
        assert!(woken.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(std::future::Future::poll(wait.as_mut(), &mut cx), Poll::Ready(Ok(()))));
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// Data written before the 3-way handshake completes must wait through both `Listen` and
    /// `SynReceived`, and only be transmitted once the connection enters `Established`.
    #[tokio::test]
    async fn write_before_the_handshake_waits_for_it() {
        let (peer, local) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let mut syn = TcpHeader::new(12345, 80, 1000, u16::MAX);
        syn.syn = true;
        let mut stream = IpStackTcpStream::new(peer, local, syn, 0, up_tx, 1500, None, Arc::new(TcpConfig::default())).unwrap();

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            Pin::new(&mut stream).poll_write(&mut cx, b"early").is_pending(),
            "a write was accepted before the SYN-ACK went out"
        );
        let packets = written(&mut up_rx).await;
        assert!(
            matches!(packets.as_slice(), [packet] if tcp_header_of(packet).syn),
            "the SYN-ACK is not the first packet"
        );
        let syn_ack = tcp_header_of(&packets[0]).clone();
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::SynReceived);
        assert!(
            !woken.load(Ordering::SeqCst),
            "entering SynReceived must not wake the writer before the handshake completes"
        );
        assert!(
            Pin::new(&mut stream).poll_write(&mut cx, b"early").is_pending(),
            "a write was accepted in SynReceived before the 3-way handshake completed"
        );
        assert!(written(&mut up_rx).await.is_empty(), "data was transmitted in SynReceived");

        let local_seq = syn_ack.sequence_number.wrapping_add(1);
        stream.stream_sender().send(peer_ack(1001, local_seq)).unwrap();
        tokio::task::yield_now().await;
        assert!(woken.load(Ordering::SeqCst), "completing the handshake did not wake the writer");
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);

        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"early"), Poll::Ready(Ok(5))));
        let packets = written(&mut up_rx).await;
        assert_eq!(packets.len(), 1);
        assert_eq!(tcp_header_of(&packets[0]).sequence_number, local_seq);
        assert_eq!(packets[0].payload.as_deref(), Some(&b"early"[..]));
    }

    #[tokio::test]
    async fn write_in_syn_received_waits_for_handshake_ack() {
        let (mut stream, syn_ack, mut up_rx) = open(u16::MAX, &[]).await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::SynReceived);

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            Pin::new(&mut stream).poll_write(&mut cx, b"hello").is_pending(),
            "a write was accepted in SynReceived"
        );
        assert!(written(&mut up_rx).await.is_empty(), "data was transmitted before handshake ACK");

        let peer_seq = SeqNum(syn_ack.acknowledgment_number);
        feed(&stream, &syn_ack, peer_seq, u16::MAX, &[]);
        tokio::task::yield_now().await;
        assert!(woken.load(Ordering::SeqCst), "handshake ACK did not wake the pending writer");
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);

        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"hello"), Poll::Ready(Ok(5))));
        let packets = written(&mut up_rx).await;
        assert_eq!(packets.len(), 1);
        assert_eq!(tcp_header_of(&packets[0]).sequence_number, syn_ack.sequence_number.wrapping_add(1));
        assert_eq!(packets[0].payload.as_deref(), Some(&b"hello"[..]));
    }

    #[tokio::test]
    async fn write_in_syn_received_fails_with_broken_pipe_on_rst() {
        let (mut stream, syn_ack, mut up_rx) = open(u16::MAX, &[]).await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::SynReceived);

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_write(&mut cx, b"hello").is_pending());

        let local_seq = syn_ack.sequence_number.wrapping_add(1);
        stream
            .stream_sender()
            .send(peer_segment(syn_ack.acknowledgment_number, local_seq, RST | ACK, 0, &[]))
            .unwrap();
        tokio::task::yield_now().await;

        assert!(woken.load(Ordering::SeqCst), "RST in SynReceived did not wake the pending writer");
        assert!(written(&mut up_rx).await.is_empty());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"hello"),
            Poll::Ready(Err(err)) if err.kind() == BrokenPipe
        ));
    }

    fn mss_of(header: &TcpHeader) -> Option<u16> {
        header.options_iterator().flatten().find_map(|option| match option {
            TcpOptionElement::MaximumSegmentSize(mss) => Some(mss),
            _ => None,
        })
    }

    /// RFC 9293 §3.8.3 / RFC 6298: an unacknowledged SYN|ACK is retransmitted with exponential
    /// backoff (preserving its sequence number and options) until R2 transmissions close the
    /// connection.
    #[tokio::test(start_paused = true)]
    async fn syn_received_retransmits_syn_ack_with_backoff_and_closes_at_r2() {
        let (peer, local) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let config = TcpConfig {
            options: Some(vec![TcpOptions::MaximumSegmentSize(1380)]),
            ..TcpConfig::default()
        };
        let mut syn = TcpHeader::new(12345, 80, 1000, 0);
        syn.syn = true;
        syn.set_options(&[TcpOptionElement::WindowScale(7)]).unwrap();

        let mut stream = IpStackTcpStream::new(peer, local, syn, 0, up_tx, 1500, Some(destroy_tx), Arc::new(config)).unwrap();
        let initial = up_rx.recv().await.unwrap();
        let initial_hdr = tcp_header_of(&initial).clone();
        assert!(initial_hdr.syn && initial_hdr.ack);
        assert_eq!(mss_of(&initial_hdr), Some(1380));
        assert_eq!(window_scale_of(&initial_hdr), Some(0));

        let opened = tokio::time::Instant::now();
        let just_before = |seconds: u64| Duration::from_secs(seconds) - Duration::from_millis(1);

        for seconds in BACKOFF.iter().take(MAX_RETRANSMIT_COUNT - 1) {
            assert!(advance(just_before(*seconds), &mut up_rx).await.is_none());
            let retry = advance(Duration::from_millis(1), &mut up_rx)
                .await
                .expect("expected SYN|ACK retransmission");
            let hdr = tcp_header_of(&retry);
            assert!(hdr.syn && hdr.ack && !hdr.rst);
            assert_eq!(hdr.sequence_number, initial_hdr.sequence_number);
            assert_eq!(hdr.acknowledgment_number, initial_hdr.acknowledgment_number);
            assert_eq!(hdr.window_size, initial_hdr.window_size);
            assert_eq!(mss_of(hdr), Some(1380));
            assert_eq!(window_scale_of(hdr), Some(0));
            assert!(destroy_rx.try_recv().is_err());
        }

        assert!(advance(just_before(BACKOFF[MAX_RETRANSMIT_COUNT - 1]), &mut up_rx).await.is_none());

        stream.reset_timeout();
        let (reader_woken, reader_waker) = recording_waker();
        let mut read_cx = Context::from_waker(&reader_waker);
        let mut bytes = [0; 1];
        let mut read_buf = tokio::io::ReadBuf::new(&mut bytes);
        assert!(Pin::new(&mut stream).poll_read(&mut read_cx, &mut read_buf).is_pending());

        let (writer_woken, writer_waker) = recording_waker();
        let mut write_cx = Context::from_waker(&writer_waker);
        assert!(Pin::new(&mut stream).poll_write(&mut write_cx, b"hi").is_pending());

        let (shutdown_woken, shutdown_waker) = recording_waker();
        let mut shutdown_cx = Context::from_waker(&shutdown_waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx).is_pending());

        let reset = advance(Duration::from_millis(1), &mut up_rx).await.expect("expected RST at R2");
        assert!(tcp_header_of(&reset).rst);
        assert!(up_rx.try_recv().is_err());
        assert!((tokio::time::Instant::now() - opened).as_secs() > 100);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert_eq!(destroy_rx.try_recv(), Ok(()));
        assert!(reader_woken.load(Ordering::SeqCst));
        assert!(writer_woken.load(Ordering::SeqCst));
        assert!(shutdown_woken.load(Ordering::SeqCst));
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut read_cx, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        assert!(read_buf.filled().is_empty());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut write_cx, b"hi"),
            Poll::Ready(Err(err)) if err.kind() == BrokenPipe
        ));
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx), Poll::Ready(Ok(()))));
    }

    #[tokio::test(start_paused = true)]
    async fn syn_ack_retransmission_stops_on_handshake_ack() {
        let (mut stream, syn_ack, mut up_rx) = open(u16::MAX, &[]).await;

        for seconds in BACKOFF.iter().take(2) {
            let retry = advance(Duration::from_secs(*seconds), &mut up_rx)
                .await
                .expect("expected SYN|ACK retransmission");
            assert!(tcp_header_of(&retry).syn && tcp_header_of(&retry).ack);
            assert_eq!(tcp_header_of(&retry).sequence_number, syn_ack.sequence_number);
        }

        let local_seq = syn_ack.sequence_number.wrapping_add(1);
        stream
            .stream_sender()
            .send(peer_ack(syn_ack.acknowledgment_number, local_seq))
            .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);
        assert!(stream.tcb.lock().unwrap().get_retransmission_deadline().is_none());
        assert!(advance(Duration::from_secs(BACKOFF[2]), &mut up_rx).await.is_none());

        stream.write_all(b"hello").await.unwrap();
        let data = up_rx.recv().await.unwrap();
        assert_eq!(tcp_header_of(&data).sequence_number, local_seq);
        assert_eq!(data.payload.as_deref(), Some(&b"hello"[..]));
    }

    #[tokio::test(start_paused = true)]
    async fn syn_received_responds_to_retransmitted_syn_and_ignores_wrong_seq() {
        let (peer, local) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let config = TcpConfig {
            options: Some(vec![TcpOptions::MaximumSegmentSize(1400)]),
            ..TcpConfig::default()
        };
        let mut syn = TcpHeader::new(12345, 80, 1000, u16::MAX);
        syn.syn = true;
        syn.set_options(&[TcpOptionElement::WindowScale(4)]).unwrap();

        let mut stream = IpStackTcpStream::new(peer, local, syn, 0, up_tx, 1500, None, Arc::new(config)).unwrap();
        let initial = up_rx.recv().await.unwrap();
        let initial_hdr = tcp_header_of(&initial).clone();

        // Wrong-ISN SYN must be ignored without emitting SYN|ACK.
        stream.stream_sender().send(peer_segment(999, 0, SYN, u16::MAX, &[])).unwrap();
        assert!(written(&mut up_rx).await.is_empty());

        // Retransmitted SYN with matching ISN and ack = 0 triggers immediate SYN|ACK resend.
        tokio::time::advance(Duration::from_millis(500)).await;
        stream.stream_sender().send(peer_segment(1000, 0, SYN, u16::MAX, &[])).unwrap();
        let responses = written(&mut up_rx).await;
        assert_eq!(responses.len(), 1);
        let hdr = tcp_header_of(&responses[0]);
        assert!(hdr.syn && hdr.ack);
        assert_eq!(hdr.sequence_number, initial_hdr.sequence_number);
        assert_eq!(hdr.acknowledgment_number, initial_hdr.acknowledgment_number);
        assert_eq!(mss_of(hdr), Some(1400));
        assert_eq!(window_scale_of(hdr), Some(0));

        // Peer's final ACK completes the handshake and leaves send window / last_received_ack intact.
        let local_seq = initial_hdr.sequence_number.wrapping_add(1);
        stream
            .stream_sender()
            .send(peer_ack(initial_hdr.acknowledgment_number, local_seq))
            .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);

        stream.write_all(b"after-retransmitted-syn").await.unwrap();
        let sent = up_rx.recv().await.unwrap();
        assert_eq!(tcp_header_of(&sent).sequence_number, local_seq);
        assert_eq!(sent.payload.as_deref(), Some(&b"after-retransmitted-syn"[..]));
    }

    #[tokio::test(start_paused = true)]
    async fn retransmitted_syns_do_not_stall_r2_closure() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (stream, _syn_ack, mut up_rx) = {
            let (peer, local) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
            let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
            let mut syn = TcpHeader::new(12345, 80, 1000, u16::MAX);
            syn.syn = true;
            let stream = IpStackTcpStream::new(peer, local, syn, 0, up_tx, 1500, Some(destroy_tx), Arc::new(TcpConfig::default())).unwrap();
            let syn_ack = up_rx.recv().await.unwrap();
            (stream, tcp_header_of(&syn_ack).clone(), up_rx)
        };

        // Keep sending duplicate SYNs every 500ms; the RTO timer must still reach R2 and close.
        for _ in 0..300 {
            tokio::time::advance(Duration::from_millis(500)).await;
            tokio::task::yield_now().await;
            let _ = written(&mut up_rx).await;
            if stream.tcb.lock().unwrap().get_state() == TcpState::Closed {
                break;
            }
            let _ = stream.stream_sender().send(peer_segment(1000, 0, SYN, u16::MAX, &[]));
        }

        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn syn_received_ignores_unacceptable_ack_and_rst_stops_retransmission() {
        let (stream, syn_ack, mut up_rx) = open(u16::MAX, &[]).await;

        // ACK that does not cover our SYN|ACK (syn_seq instead of syn_seq + 1) keeps SynReceived.
        stream
            .stream_sender()
            .send(peer_ack(syn_ack.acknowledgment_number, syn_ack.sequence_number))
            .unwrap();
        assert!(written(&mut up_rx).await.is_empty());
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::SynReceived);

        // RST closes the session and stops further SYN|ACK retransmissions.
        stream
            .stream_sender()
            .send(peer_segment(
                syn_ack.acknowledgment_number,
                syn_ack.sequence_number.wrapping_add(1),
                RST,
                0,
                &[],
            ))
            .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(advance(Duration::from_secs(BACKOFF[0]), &mut up_rx).await.is_none());
    }

    // --- Window scaling, MSS & send-window flow-control tests ---

    /// A peer offering a window scale gets this stack's shift of 0 back and has its windows
    /// honoured shifted by the offered count, clamped to RFC 7323 §2.3's maximum of 14.
    #[rstest]
    #[case::valid(7, 7)]
    #[case::clamped(20, 14)]
    #[tokio::test]
    async fn syn_with_window_scale_is_answered_and_honoured(#[case] offered_shift: u8, #[case] applied_shift: u8) {
        let (stream, syn_ack, mut up_rx) = open(4000, &[TcpOptionElement::WindowScale(offered_shift)]).await;
        assert_eq!(
            window_scale_of(&syn_ack),
            Some(0),
            "the SYN-ACK does not carry this stack's window scale"
        );

        let peer_seq = SeqNum(syn_ack.acknowledgment_number);
        feed(&stream, &syn_ack, peer_seq, 40_000, &[1; 4]);
        feed(&stream, &syn_ack, peer_seq + 4, 40_000, &[2; 4]);
        up_rx.recv().await.unwrap();
        up_rx.recv().await.unwrap();

        let tcb = stream.tcb.lock().unwrap();
        assert_eq!(tcb.get_state(), TcpState::Established);
        assert_eq!(tcb.get_send_window(), 40_000 << applied_shift);
    }

    /// RFC 9293 §3.7.1: a segment never carries more payload than the MSS the peer announced in its
    /// SYN, and an announced MSS below 88 (Linux's TCP_MIN_MSS) is read as 88.
    #[rstest]
    #[case(600, 600)]
    #[case(100, 100)]
    #[case::clamped_to_min_mss(40, 88)]
    #[tokio::test]
    async fn segments_stay_within_the_peers_mss(#[case] announced: u16, #[case] expected: usize) {
        let (mut stream, syn_ack, mut up_rx) = open(u16::MAX, &[TcpOptionElement::MaximumSegmentSize(announced)]).await;
        let peer_seq = SeqNum(syn_ack.acknowledgment_number);
        feed(&stream, &syn_ack, peer_seq, u16::MAX, &[1; 4]);
        up_rx.recv().await.unwrap();

        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        let written = match Pin::new(&mut stream).poll_write(&mut cx, &[7; 1460]) {
            Poll::Ready(Ok(n)) => n,
            other => panic!("the write did not complete: {other:?}"),
        };
        assert_eq!(written, expected, "peer MSS {announced}: wrong write size");
        assert_eq!(up_rx.recv().await.unwrap().payload.map(|p| p.len()), Some(expected));
    }

    /// A closed peer window holds the writer, and the segment that reopens it wakes the writer, both
    /// when it completes the handshake and when it arrives on an established connection.
    #[tokio::test]
    async fn zero_peer_window_holds_the_writer_until_it_reopens() {
        let (mut stream, syn_ack, mut up_rx) = open(0, &[]).await;
        let peer_seq = SeqNum(syn_ack.acknowledgment_number);

        // the segment completing the handshake reopens the window
        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_write(&mut cx, b"held").is_pending());
        feed(&stream, &syn_ack, peer_seq, 40_000, &[1; 4]);
        up_rx.recv().await.unwrap();
        assert!(
            woken.load(std::sync::atomic::Ordering::SeqCst),
            "the handshake reopened the window without waking the writer"
        );
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"held"), Poll::Ready(Ok(4))));
        assert_eq!(up_rx.recv().await.unwrap().payload.as_deref(), Some(&b"held"[..]));

        // a data segment closes the window and a later one reopens it
        feed(&stream, &syn_ack, peer_seq + 4, 0, &[2; 4]);
        up_rx.recv().await.unwrap();
        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_write(&mut cx, b"sent").is_pending());
        feed(&stream, &syn_ack, peer_seq + 8, 40_000, &[3; 4]);
        up_rx.recv().await.unwrap();
        assert!(
            woken.load(std::sync::atomic::Ordering::SeqCst),
            "a data segment reopened the window without waking the writer"
        );
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"sent"), Poll::Ready(Ok(4))));
        assert_eq!(up_rx.recv().await.unwrap().payload.as_deref(), Some(&b"sent"[..]));
    }

    /// A write that would pass the right edge of the peer window is cut at the edge, and the next
    /// one waits for an ACK instead of sending past it.
    #[tokio::test]
    async fn writer_stops_at_the_right_edge_of_the_peer_window() {
        let (mut stream, syn_ack, mut up_rx) = open(2000, &[]).await;
        let peer_seq = SeqNum(syn_ack.acknowledgment_number);
        feed(&stream, &syn_ack, peer_seq, 2000, &[1; 4]);
        up_rx.recv().await.unwrap();

        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        let chunk = [7; 1460];
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, &chunk), Poll::Ready(Ok(1460))));
        assert_eq!(up_rx.recv().await.unwrap().payload.map(|p| p.len()), Some(1460));

        assert!(
            matches!(Pin::new(&mut stream).poll_write(&mut cx, &chunk), Poll::Ready(Ok(540))),
            "the second write is not cut at the right edge of the 2000-byte window"
        );
        assert_eq!(up_rx.recv().await.unwrap().payload.map(|p| p.len()), Some(540));

        assert!(Pin::new(&mut stream).poll_write(&mut cx, &chunk).is_pending());
    }

    /// RFC 9293 §3.8.6.1: a sender keeps the data in flight within the peer's window, so the last
    /// segment before the window fills is cut to the room left rather than sent whole.
    #[tokio::test]
    async fn segments_stay_inside_the_peers_window() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream.stream_sender().send(peer_segment(1001, local_seq, ACK, 3000, &[])).unwrap();
        written(&mut up_rx).await;

        // More than the window: the write parks once the window is full.
        let _ = tokio::time::timeout(Duration::from_millis(100), stream.write_all(&[7; 4000])).await;
        let sent: Vec<usize> = written(&mut up_rx)
            .await
            .iter()
            .filter_map(|p| p.payload.as_ref().map(Vec::len))
            .collect();
        assert_eq!(sent.iter().sum::<usize>(), 3000, "sent {sent:?} into a 3000-byte window");
    }

    // --- Receive path, out-of-order & FIN-with-data tests ---

    #[tokio::test]
    async fn pending_reader_wakes_for_each_new_segment() {
        let (mut stream, syn_ack, mut up_rx) = open(4000, &[]).await;
        let peer_seq = SeqNum(syn_ack.acknowledgment_number);
        feed(&stream, &syn_ack, peer_seq, 4000, &[]);
        tokio::task::yield_now().await;

        for offset in 0..2 {
            let (woken, waker) = recording_waker();
            let mut cx = Context::from_waker(&waker);
            let mut bytes = [0; 4];
            let mut buf = tokio::io::ReadBuf::new(&mut bytes);
            assert!(Pin::new(&mut stream).poll_read(&mut cx, &mut buf).is_pending());

            feed(&stream, &syn_ack, peer_seq + offset * 4, 4000, b"data");
            up_rx.recv().await.unwrap();
            assert!(woken.load(std::sync::atomic::Ordering::SeqCst));
            assert!(matches!(Pin::new(&mut stream).poll_read(&mut cx, &mut buf), Poll::Ready(Ok(()))));
            assert_eq!(buf.filled(), b"data");
        }
    }

    #[tokio::test]
    async fn extract_reserves_before_consuming() {
        let (up_tx, _up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let (data_tx, mut data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let read_notify = Arc::new(AtomicWaker::new());
        let nt = NetworkTuple::new("1.1.1.1:1".parse().unwrap(), "2.2.2.2:2".parse().unwrap(), true);

        let mut tcb = Tcb::new(
            SeqNum(1000),
            u16::MAX,
            None,
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );
        tcb.change_state(TcpState::Established);
        tcb.add_unordered_packet(SeqNum(1000), vec![1; 500]);
        tcb.add_unordered_packet(SeqNum(1500), vec![2; 500]);
        tcb.acknowledge_unordered_packets();

        // first extract fills the single channel slot and advances ack over the first chunk
        extract_data_n_write_upstream(&up_tx, &mut tcb, nt, &data_tx, &read_notify).unwrap();
        assert_eq!(tcb.get_ack(), SeqNum(2000));

        // channel is full: extract advances ack over the tail and holds it for the reader
        tcb.add_unordered_packet(SeqNum(2000), vec![3; 500]);
        tcb.acknowledge_unordered_packets();
        extract_data_n_write_upstream(&up_tx, &mut tcb, nt, &data_tx, &read_notify).unwrap();
        assert_eq!(tcb.get_ack(), SeqNum(2500));
        assert_eq!(tcb.get_available_read_buffer_size(), READ_BUFFER_SIZE - 500);

        // draining the reader frees a slot, and the next extract flushes the tail
        let first = data_rx.recv().await.unwrap();
        assert_eq!(first.len(), 1000);
        extract_data_n_write_upstream(&up_tx, &mut tcb, nt, &data_tx, &read_notify).unwrap();
        assert_eq!(tcb.get_ack(), SeqNum(2500));
        assert_eq!(tcb.get_available_read_buffer_size(), READ_BUFFER_SIZE);
    }

    /// A multi-segment upload reaches `read_to_end` whole, whether the peer's FIN arrives on its
    /// own segment afterward or rides on the last data segment.
    #[rstest]
    #[case::separate_fin(false)]
    #[case::fin_on_last_segment(true)]
    #[tokio::test(start_paused = true)]
    async fn upload_arrives_whole(#[case] fin_with_data: bool) {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let data: Vec<u8> = (0..4321).map(|i| (i % 251) as u8).collect();
        let chunks: Vec<&[u8]> = data.chunks(1000).collect();
        let mut seq = 1001;
        for (i, chunk) in chunks.iter().enumerate() {
            let is_last = i + 1 == chunks.len();
            let flags = if fin_with_data && is_last { ACK | PSH | FIN } else { ACK | PSH };
            stream
                .stream_sender()
                .send(peer_segment(seq, local_seq, flags, u16::MAX, chunk))
                .unwrap();
            seq += chunk.len() as u32;
        }
        if !fin_with_data {
            stream
                .stream_sender()
                .send(peer_segment(seq, local_seq, ACK | FIN, u16::MAX, &[]))
                .unwrap();
        }
        let mut received = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut received).await.unwrap();
        assert_eq!(received, data);
        assert_eq!(acks(&mut up_rx).await.last(), Some(&(seq + 1)));
    }

    /// RFC 5681 §4.2: an out-of-order segment is answered at once with a duplicate ACK, whether or
    /// not it carries PSH, and is kept for when the gap fills.
    #[rstest]
    #[case::ack(ACK)]
    #[case::ack_psh(ACK | PSH)]
    #[tokio::test(start_paused = true)]
    async fn out_of_order_segment_is_answered_with_a_duplicate_ack(#[case] flags: TcpFlags) {
        let (mut stream, mut up_rx, local_seq) = established().await;

        // Bytes 1001..1009 are missing; 1009..1013 arrive first.
        stream
            .stream_sender()
            .send(peer_segment(1009, local_seq, flags, u16::MAX, &[3; 4]))
            .unwrap();
        let acks: Vec<u32> = written(&mut up_rx)
            .await
            .iter()
            .map(|p| tcp_header_of(p).acknowledgment_number)
            .collect();
        assert_eq!(acks, [1001], "flags {flags:?}: the out-of-order segment got no duplicate ACK");

        // The gap fills: the ACK covers both segments and the reader sees them in order.
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, flags, u16::MAX, &[1; 8]))
            .unwrap();
        let acks: Vec<u32> = written(&mut up_rx)
            .await
            .iter()
            .map(|p| tcp_header_of(p).acknowledgment_number)
            .collect();
        assert_eq!(acks.last(), Some(&1013), "flags {flags:?}: the buffered segment was not kept");
        let mut buf = [0u8; 12];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await.unwrap();
        assert_eq!(buf[..8], [1; 8]);
        assert_eq!(buf[8..], [3; 4]);
    }

    /// RFC 9293 §3.10.7.4: a FIN may ride on the last data segment (Linux does this on
    /// `shutdown(SHUT_WR)` with data queued). The payload must reach the reader and be
    /// acknowledged together with the FIN, whether or not PSH is set.
    #[rstest]
    #[case::ack_fin(ACK | FIN)]
    #[case::ack_psh_fin(ACK | PSH | FIN)]
    #[tokio::test(start_paused = true)]
    async fn data_segment_carrying_fin_keeps_its_payload(#[case] flags: TcpFlags) {
        let (mut stream, mut up_rx, local_seq) = established().await;

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, flags, u16::MAX, b"tail"))
            .unwrap();
        // One ACK covering the 4 payload bytes and the FIN together.
        assert_eq!(
            acks(&mut up_rx).await,
            [1006],
            "flags {flags:?}: payload and FIN must be acknowledged by one ACK"
        );

        let mut buf = [0u8; 4];
        let read = tokio::time::timeout(Duration::from_secs(1), tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)).await;
        assert!(
            matches!(read, Ok(Ok(_))),
            "flags {flags:?}: payload of the FIN segment never reached the reader"
        );
        assert_eq!(&buf, b"tail", "flags {flags:?}");
    }

    /// RFC 5681 §4.2: a FIN segment arriving after a gap buffers its payload and FIN sequence
    /// number and answers with a duplicate ACK. Filling the gap delivers the full stream and
    /// immediately takes the buffered FIN without needing a retransmission.
    #[rstest]
    #[case::ack_fin(ACK | FIN)]
    #[case::ack_psh_fin(ACK | PSH | FIN)]
    #[tokio::test(start_paused = true)]
    async fn out_of_order_fin_segment_gets_duplicate_ack(#[case] flags: TcpFlags) {
        let (mut stream, mut up_rx, local_seq) = established().await;

        stream
            .stream_sender()
            .send(peer_segment(1005, local_seq, flags, u16::MAX, b"tail"))
            .unwrap();
        assert_eq!(
            acks(&mut up_rx).await,
            [1001],
            "flags {flags:?}: out-of-order FIN segment got no duplicate ACK"
        );
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);

        // The gap fills: ACK covers both segments and the buffered FIN, entering CloseWait.
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK, u16::MAX, b"head"))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await.last(), Some(&1010), "flags {flags:?}");
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);

        // Any duplicate retransmission of the FIN segment in CloseWait is still ACKed at 1010.
        stream
            .stream_sender()
            .send(peer_segment(1005, local_seq, flags, u16::MAX, b"tail"))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [1010], "flags {flags:?}");

        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"headtail");
    }

    /// When the receive window takes only part of a FIN segment, the peer retransmits the whole
    /// segment from its original sequence number, now behind our ACK. The overlap is trimmed and
    /// the FIN is taken once the remaining payload fits.
    #[tokio::test(start_paused = true)]
    async fn retransmitted_fin_segment_after_partial_accept_is_taken() {
        let config = TcpConfig {
            read_buffer_size: 4,
            ..TcpConfig::default()
        };
        let (mut stream, mut up_rx, local_seq) = established_with(None, config).await;
        let payload = b"tail-data"; // 9 bytes: needs several rounds through a 4-byte window.

        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        let mut received = Vec::new();
        let mut last_ack = 0;
        for _ in 0..10 {
            stream
                .stream_sender()
                .send(peer_segment(1001, local_seq, ACK | PSH | FIN, u16::MAX, payload))
                .unwrap();
            last_ack = written(&mut up_rx)
                .await
                .iter()
                .map(|p| tcp_header_of(p).acknowledgment_number)
                .max()
                .unwrap_or(last_ack);
            // The application drains what has arrived, reopening the window.
            loop {
                let mut storage = [0u8; 16];
                let mut read = tokio::io::ReadBuf::new(&mut storage);
                match Pin::new(&mut stream).poll_read(&mut cx, &mut read) {
                    Poll::Ready(Ok(())) if !read.filled().is_empty() => received.extend_from_slice(read.filled()),
                    _ => break,
                }
            }
            if last_ack == 1011 {
                break;
            }
            assert!(last_ack < 1010, "FIN acknowledged before all payload was accepted: ack {last_ack}");
        }
        assert_eq!(last_ack, 1011, "retransmitted FIN segment was never taken, last ack {last_ack}");
        assert_eq!(received, payload);
    }

    // --- Retransmission & R2 backoff tests ---

    /// RFC 6298 §5.4: a segment with nothing behind it is retransmitted once its deadline passes,
    /// with no packet arriving to prompt it.
    #[tokio::test(start_paused = true)]
    async fn lost_segment_is_retransmitted_without_an_arrival() {
        let (mut stream, mut up_rx, local_seq) = established().await;

        stream.write_all(b"hello").await.unwrap();
        let sent = up_rx.recv().await.unwrap();
        assert_eq!(tcp_header_of(&sent).sequence_number, local_seq);

        let again = advance(Duration::from_secs(BACKOFF[0]), &mut up_rx)
            .await
            .expect("no retransmission");
        assert_eq!(tcp_header_of(&again).sequence_number, local_seq);
        assert_eq!(again.payload.as_deref(), Some(&b"hello"[..]));
    }

    /// RFC 6298 §5.4 retransmits the earliest unacknowledged segment, so every attempt carries the
    /// sequence number and payload of the first.
    #[tokio::test(start_paused = true)]
    async fn retransmissions_carry_the_original_segment() {
        let (mut stream, mut up_rx, local_seq) = established().await;

        stream.write_all(b"hello").await.unwrap();
        up_rx.recv().await.unwrap();

        for seconds in BACKOFF.iter().take(4) {
            let packet = advance(Duration::from_secs(*seconds), &mut up_rx).await.expect("no retransmission");
            assert_eq!(tcp_header_of(&packet).sequence_number, local_seq);
            assert_eq!(packet.payload.as_deref(), Some(&b"hello"[..]));
        }
    }

    /// An acknowledgement retires the segment, so no deadline remains, the connection stays open,
    /// and a further segment flows.
    #[tokio::test(start_paused = true)]
    async fn an_acknowledgement_stops_retransmission() {
        let (mut stream, mut up_rx, local_seq) = established().await;

        stream.write_all(b"hello").await.unwrap();
        up_rx.recv().await.unwrap();

        for seconds in BACKOFF.iter().take(5) {
            advance(Duration::from_secs(*seconds), &mut up_rx).await.expect("no retransmission");
        }

        stream.stream_sender().send(peer_ack(1001, local_seq + 5)).unwrap();
        tokio::task::yield_now().await;
        assert!(stream.tcb.lock().unwrap().get_retransmission_deadline().is_none());
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);

        stream.write_all(b"more").await.unwrap();
        let sent = up_rx.recv().await.unwrap();
        assert_eq!(sent.payload.as_deref(), Some(&b"more"[..]));
    }

    /// RFC 9293 §3.8.3: the connection closes when a segment's transmissions reach R2, one timeout
    /// after the last retransmission and past the 100 seconds SHLD-11 asks for.
    #[tokio::test(start_paused = true)]
    async fn unacknowledged_segment_closes_the_connection_at_r2() {
        let (mut stream, mut up_rx, _) = established().await;
        let opened = tokio::time::Instant::now();
        let just_before = |seconds: u64| Duration::from_secs(seconds) - Duration::from_millis(1);

        stream.write_all(b"hello").await.unwrap();
        up_rx.recv().await.unwrap();

        for seconds in BACKOFF.iter().take(MAX_RETRANSMIT_COUNT - 1) {
            assert!(advance(just_before(*seconds), &mut up_rx).await.is_none());
            let packet = advance(Duration::from_millis(1), &mut up_rx).await.expect("no retransmission");
            assert!(!tcp_header_of(&packet).rst);
        }

        assert!(advance(just_before(BACKOFF[MAX_RETRANSMIT_COUNT - 1]), &mut up_rx).await.is_none());

        // Leave both halves waiting immediately before the final timeout closes the connection.
        stream.reset_timeout();
        let (reader_woken, reader_waker) = recording_waker();
        let mut read_cx = Context::from_waker(&reader_waker);
        let mut bytes = [0; 1];
        let mut read_buf = tokio::io::ReadBuf::new(&mut bytes);
        assert!(Pin::new(&mut stream).poll_read(&mut read_cx, &mut read_buf).is_pending());
        // The default window cap is 16 KiB; fill the remainder behind the initial five bytes.
        let remaining = vec![0; MAX_UNACK as usize - 5];
        stream.tcb.lock().unwrap().add_inflight_packet(remaining).unwrap();
        let (writer_woken, writer_waker) = recording_waker();
        let mut write_cx = Context::from_waker(&writer_waker);
        assert!(Pin::new(&mut stream).poll_write(&mut write_cx, b"waiting").is_pending());

        let reset = advance(Duration::from_millis(1), &mut up_rx).await.expect("no reset");
        assert!(tcp_header_of(&reset).rst);
        assert!(up_rx.try_recv().is_err());

        assert!((tokio::time::Instant::now() - opened).as_secs() > 100);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(reader_woken.load(std::sync::atomic::Ordering::SeqCst));
        assert!(writer_woken.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut read_cx, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        assert!(read_buf.filled().is_empty());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut write_cx, b"waiting"),
            Poll::Ready(Err(err)) if err.kind() == BrokenPipe
        ));
    }

    /// RFC 6298 §5.4: RTO expiry retransmits only the earliest unacknowledged segment, even when
    /// multiple segments are in flight and after multiple expiries.
    #[tokio::test(start_paused = true)]
    async fn rto_retransmits_only_earliest_inflight_segment() {
        let (mut stream, mut up_rx, local_seq) = established().await;

        stream.write_all(b"first").await.unwrap();
        let pkt1 = up_rx.recv().await.unwrap();
        assert_eq!(pkt1.payload.as_deref(), Some(&b"first"[..]));

        tokio::time::advance(Duration::from_millis(500)).await;
        stream.write_all(b"second").await.unwrap();
        let pkt2 = up_rx.recv().await.unwrap();
        assert_eq!(pkt2.payload.as_deref(), Some(&b"second"[..]));

        // First RTO (1s from first write): only "first" is retransmitted.
        tokio::time::advance(Duration::from_millis(500)).await;
        let sent = written(&mut up_rx).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(tcp_header_of(&sent[0]).sequence_number, local_seq);
        assert_eq!(sent[0].payload.as_deref(), Some(&b"first"[..]));

        // Second RTO (2s later): still only "first" is retransmitted, not a burst of both.
        assert!(
            advance(Duration::from_secs(2) - Duration::from_millis(1), &mut up_rx)
                .await
                .is_none()
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        let sent = written(&mut up_rx).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(tcp_header_of(&sent[0]).sequence_number, local_seq);
        assert_eq!(sent[0].payload.as_deref(), Some(&b"first"[..]));

        // ACKing "first" leaves "second" with a restarted 4s timer (Karn's algorithm keeps RTO=4s).
        stream.stream_sender().send(peer_ack(1001, local_seq + 5)).unwrap();
        assert!(written(&mut up_rx).await.is_empty());
        assert!(
            advance(Duration::from_secs(4) - Duration::from_millis(1), &mut up_rx)
                .await
                .is_none()
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        let sent = written(&mut up_rx).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(tcp_header_of(&sent[0]).sequence_number, local_seq + 5);
        assert_eq!(sent[0].payload.as_deref(), Some(&b"second"[..]));
    }

    /// RFC 5681 §2 / §3.2 & Karn's algorithm: data segments, window updates, and keepalives are not
    /// counted as duplicate ACKs; Fast Retransmit fires once on the 3rd duplicate ACK and
    /// increments `retransmit_count` so Karn's algorithm does not collapse backed-off RTO.
    #[tokio::test(start_paused = true)]
    async fn fast_retransmit_fires_once_ignores_non_dup_acks_and_preserves_backoff() {
        let (mut stream, mut up_rx, mut local_seq) = established().await;

        // Back off RTO to 2s via an RTO retransmission before testing Fast Retransmit.
        stream.write_all(b"warm").await.unwrap();
        up_rx.recv().await.unwrap();
        let retry = advance(RTO, &mut up_rx).await.expect("expected RTO retry");
        assert_eq!(retry.payload.as_deref(), Some(&b"warm"[..]));
        local_seq += 4;
        stream.stream_sender().send(peer_ack(1001, local_seq)).unwrap();
        tokio::task::yield_now().await;

        stream.write_all(b"lost").await.unwrap();
        up_rx.recv().await.unwrap();
        stream.write_all(b"tail").await.unwrap();
        up_rx.recv().await.unwrap();

        // Non-duplicate-ACK segments (data, window updates, keepalives) must not trigger Fast Retransmit.
        let mut peer_seq = 1001;
        for i in 0u16..4 {
            stream
                .stream_sender()
                .send(peer_segment(peer_seq, local_seq, ACK | PSH, u16::MAX, b"x"))
                .unwrap();
            peer_seq += 1;
            let _ = written(&mut up_rx).await;

            stream
                .stream_sender()
                .send(peer_segment(peer_seq, local_seq, ACK, u16::MAX - 10 - i, &[]))
                .unwrap();
            assert!(written(&mut up_rx).await.is_empty());

            stream
                .stream_sender()
                .send(peer_segment(peer_seq - 1, local_seq, ACK, u16::MAX - 10 - i, &[]))
                .unwrap();
            let ka_ack = written(&mut up_rx).await;
            assert_eq!(ka_ack.len(), 1);
            assert!(ka_ack[0].payload.as_deref().unwrap_or_default().is_empty());
        }

        let current_win = u16::MAX - 13;
        // 1st and 2nd pure duplicate ACKs do not trigger Fast Retransmit.
        for _ in 0..2 {
            stream
                .stream_sender()
                .send(peer_segment(peer_seq, local_seq, ACK, current_win, &[]))
                .unwrap();
            assert!(written(&mut up_rx).await.is_empty());
        }

        // 3rd pure duplicate ACK triggers Fast Retransmit once.
        stream
            .stream_sender()
            .send(peer_segment(peer_seq, local_seq, ACK, current_win, &[]))
            .unwrap();
        let fast = written(&mut up_rx).await;
        assert_eq!(fast.len(), 1);
        assert_eq!(tcp_header_of(&fast[0]).sequence_number, local_seq);
        assert_eq!(fast[0].payload.as_deref(), Some(&b"lost"[..]));

        // 4th and 5th pure duplicate ACKs must not retransmit again.
        for _ in 0..2 {
            stream
                .stream_sender()
                .send(peer_segment(peer_seq, local_seq, ACK, current_win, &[]))
                .unwrap();
            assert!(written(&mut up_rx).await.is_empty());
        }

        // ACKing only the fast-retransmitted segment must NOT collapse current_rto (still 2s).
        stream
            .stream_sender()
            .send(peer_segment(peer_seq, local_seq + 4, ACK, current_win, &[]))
            .unwrap();
        assert!(written(&mut up_rx).await.is_empty());
        assert!(
            advance(RTO, &mut up_rx).await.is_none(),
            "Karn's algorithm violated: RTO collapsed after Fast Retransmit"
        );
        let tail_retry = advance(RTO, &mut up_rx).await.expect("expected RTO retry for tail at 2s");
        assert_eq!(tcp_header_of(&tail_retry).sequence_number, local_seq + 4);
        assert_eq!(tail_retry.payload.as_deref(), Some(&b"tail"[..]));
    }

    // --- Reset (RST) handling tests ---

    /// A reset wakes blocked operations and ends the session task without waiting for a timer
    /// or a second packet. Exercise both RST and RST|ACK with no time advancement.
    #[rstest]
    #[case::rst(RST)]
    #[case::rst_ack(RST | ACK)]
    #[tokio::test(start_paused = true)]
    async fn reset_wakes_pending_read_write_and_shutdown(#[case] flags: TcpFlags) {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        stream.write_all(b"outstanding").await.unwrap();
        written(&mut up_rx).await;
        stream.stream_sender().send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
        written(&mut up_rx).await;

        let (read_woken, read_waker) = recording_waker();
        let mut read_cx = Context::from_waker(&read_waker);
        let mut storage = [0; 16];
        let mut read = tokio::io::ReadBuf::new(&mut storage);
        assert!(Pin::new(&mut stream).poll_read(&mut read_cx, &mut read).is_pending());

        let (write_woken, write_waker) = recording_waker();
        let mut write_cx = Context::from_waker(&write_waker);
        assert!(Pin::new(&mut stream).poll_write(&mut write_cx, b"blocked").is_pending());

        let (shutdown_woken, shutdown_waker) = recording_waker();
        let mut shutdown_cx = Context::from_waker(&shutdown_waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx).is_pending());

        let now = tokio::time::Instant::now();
        stream.stream_sender().send(peer_segment(1001, local_seq, flags, 0, &[])).unwrap();
        written(&mut up_rx).await;
        assert_eq!(tokio::time::Instant::now(), now);
        assert!(read_woken.load(std::sync::atomic::Ordering::SeqCst), "RST did not wake the reader");
        assert!(write_woken.load(std::sync::atomic::Ordering::SeqCst), "RST did not wake the writer");
        assert!(
            shutdown_woken.load(std::sync::atomic::Ordering::SeqCst),
            "RST did not wake shutdown"
        );
        assert!(
            stream.task_handle.as_ref().unwrap().is_finished(),
            "the reset session task is still running"
        );
        assert_eq!(destroy_rx.try_recv(), Ok(()), "RST must notify the stack to clean up the session");

        let mut read = tokio::io::ReadBuf::new(&mut storage);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut read_cx, &mut read),
            Poll::Ready(Ok(()))
        ));
        assert!(read.filled().is_empty());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut write_cx, b"blocked"),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx), Poll::Ready(Ok(()))));
    }

    /// Closing on RST must not discard bytes already accepted for the application.
    #[tokio::test(start_paused = true)]
    async fn reset_preserves_queued_data_before_eof() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | PSH, u16::MAX, b"hello"))
            .unwrap();
        written(&mut up_rx).await;
        stream
            .stream_sender()
            .send(peer_segment(1006, local_seq, RST | ACK, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;
        assert!(stream.task_handle.as_ref().unwrap().is_finished());

        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        let mut output = Vec::new();
        // Small reads exercise both the queued data and the temporary read buffer.
        loop {
            let mut storage = [0; 2];
            let mut read = tokio::io::ReadBuf::new(&mut storage);
            assert!(matches!(Pin::new(&mut stream).poll_read(&mut cx, &mut read), Poll::Ready(Ok(()))));
            if read.filled().is_empty() {
                break;
            }
            output.extend_from_slice(read.filled());
            assert!(output.len() <= 5);
        }
        assert_eq!(output, b"hello");
        assert!(stream.write_all(b"late").await.is_err());
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn reset_wakes_the_latest_shutdown_waiter() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let (old_woken, old_waker) = recording_waker();
        let mut old_cx = Context::from_waker(&old_waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut old_cx).is_pending());
        written(&mut up_rx).await;

        let (new_woken, new_waker) = recording_waker();
        let mut new_cx = Context::from_waker(&new_waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut new_cx).is_pending());
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, RST | ACK, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;
        assert!(new_woken.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!old_woken.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut new_cx), Poll::Ready(Ok(()))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_during_read_registration_does_not_lose_wakeup() {
        let (mut stream, _up_rx, local_seq) = established().await;
        reset_after_state_snapshot(&mut stream, local_seq);
        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        let mut storage = [0; 16];
        let mut read = tokio::io::ReadBuf::new(&mut storage);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        if result.is_pending() {
            assert!(
                woken.load(std::sync::atomic::Ordering::SeqCst),
                "read missed RST during registration"
            );
            assert!(matches!(Pin::new(&mut stream).poll_read(&mut cx, &mut read), Poll::Ready(Ok(()))));
        } else {
            assert!(matches!(result, Poll::Ready(Ok(()))));
        }
        assert!(read.filled().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_during_shutdown_registration_does_not_lose_wakeup() {
        let (mut stream, _up_rx, local_seq) = established().await;
        reset_after_state_snapshot(&mut stream, local_seq);
        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(stream.shutdown.poll_ready(&mut cx).is_ready());
    }

    /// RFC 9293 §3.10.7.4: a reset closes the connection and ends its retransmission.
    #[tokio::test(start_paused = true)]
    async fn a_reset_stops_retransmission() {
        let (mut stream, mut up_rx, local_seq) = established().await;

        stream.write_all(b"hello").await.unwrap();
        up_rx.recv().await.unwrap();

        let (src, dst) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
        let reset = create_raw_packet(src, dst, |_, _| usize::MAX, RST, TTL, 1001, local_seq, u16::MAX, Vec::new(), &[]).unwrap();
        stream.stream_sender().send(reset).unwrap();
        tokio::task::yield_now().await;

        assert!(advance(Duration::from_secs(BACKOFF[0]), &mut up_rx).await.is_none());
    }

    // --- Shutdown, half-close & close state-machine tests ---

    #[test]
    fn shutdown_completion_is_remembered_before_any_waiter() {
        let signal = ShutdownSignal::default();
        signal.complete();
        signal.complete();

        // Completion stays ready across polls, including polls with a different task waker.
        for _ in 0..2 {
            let (_, waker) = recording_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(signal.poll_ready(&mut cx).is_ready());
        }
    }

    #[rstest]
    #[tokio::test]
    async fn final_ack_wakes_shutdown(#[values(true, false)] same_task: bool, #[values(ACK, ACK | PSH)] ack_flags: TcpFlags) {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let (write_woken, write_waker) = recording_waker();
        let mut write_cx = Context::from_waker(&write_waker);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut write_cx, b"hello"),
            Poll::Ready(Ok(5))
        ));
        up_rx.recv().await.unwrap();

        let (shutdown_woken, shutdown_waker) = if same_task { (write_woken, write_waker) } else { recording_waker() };
        let mut shutdown_cx = Context::from_waker(&shutdown_waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx).is_pending());
        assert!(up_rx.try_recv().is_err(), "FIN must wait for outstanding data");

        // A partial ACK must not send FIN or wake an independent shutdown waiter.
        stream.stream_sender().send(peer_ack(1001, local_seq + 2)).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while stream.tcb.lock().unwrap().get_inflight_packets_total_len() != 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(up_rx.try_recv().is_err());
        if !same_task {
            assert!(!shutdown_woken.load(Ordering::SeqCst));
        }
        assert!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx).is_pending());
        shutdown_woken.store(false, Ordering::SeqCst);

        // The final ACK can also carry peer data; both paths must wake shutdown.
        let payload: &[u8] = if ack_flags.contains(PSH) { b"reply" } else { b"" };
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq + 5, ack_flags, u16::MAX, payload))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !stream.tcb.lock().unwrap().is_inflight_queue_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(shutdown_woken.load(Ordering::SeqCst), "final ACK did not wake shutdown");

        // Waking requests another poll; it must not mark shutdown complete.
        assert!(!stream.shutdown.completed.load(Ordering::Acquire));
        assert!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx).is_pending());
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::FinWait1);
        let packets = written(&mut up_rx).await;
        let fins: Vec<_> = packets.iter().map(tcp_header_of).filter(|header| header.fin).collect();
        assert_eq!(fins.len(), 1, "shutdown must send exactly one FIN");
        assert_eq!(fins[0].sequence_number, local_seq + 5);
    }

    /// The application writes a request, shuts its write side down (`shutdown`), and reads the
    /// peer's multi-segment reply until EOF:
    /// - `fin_with_reply`: the peer's FIN rides on the last reply segment rather than a separate one
    /// - `before_ack`: the peer sends the reply and its FIN before acknowledging our FIN
    #[rstest]
    #[case::then_separate_fin(false, false)]
    #[case::with_fin(true, false)]
    #[case::with_fin_before_our_fin_is_acknowledged(true, true)]
    #[tokio::test(start_paused = true)]
    async fn shutdown_then_reply(#[case] fin_with_reply: bool, #[case] before_ack: bool) {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();
        let reply: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();

        let app = async {
            stream.write_all(b"request").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut received = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut received).await.unwrap();
            received
        };
        let remote = async {
            let data_pkt = up_rx.recv().await.unwrap();
            assert_eq!(data_pkt.payload.as_deref(), Some(&b"request"[..]));
            let after_req = local_seq + b"request".len() as u32;
            sender.send(peer_ack(1001, after_req)).unwrap();

            let fin_pkt = up_rx.recv().await.unwrap();
            assert!(tcp_header_of(&fin_pkt).fin);
            let fin_ack = if before_ack {
                after_req
            } else {
                let ack = after_req + 1;
                sender.send(peer_ack(1001, ack)).unwrap();
                ack
            };

            let chunks: Vec<&[u8]> = reply.chunks(1000).collect();
            let mut seq = 1001;
            for (i, chunk) in chunks.iter().enumerate() {
                let is_last = i + 1 == chunks.len();
                let flags = if fin_with_reply && is_last { ACK | PSH | FIN } else { ACK | PSH };
                sender.send(peer_segment(seq, fin_ack, flags, u16::MAX, chunk)).unwrap();
                seq += chunk.len() as u32;
            }
            if !fin_with_reply {
                sender.send(peer_segment(seq, fin_ack, ACK | FIN, u16::MAX, &[])).unwrap();
            }
            if before_ack {
                sender.send(peer_ack(seq + 1, after_req + 1)).unwrap();
            }
        };

        let (received, ()) = tokio::join!(app, remote);
        assert_eq!(received, reply);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::TimeWait);

        drop(stream);
        tokio::time::advance(TWO_MSL).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    /// In FinWait1, a data segment carrying the peer's FIN must deliver its payload and take the
    /// FIN (moving to TimeWait), not leave the connection waiting in FinWait2.
    #[rstest]
    #[case::ack_fin(ACK | FIN)]
    #[case::ack_psh_fin(ACK | PSH | FIN)]
    #[tokio::test(start_paused = true)]
    async fn fin_wait1_data_segment_carrying_fin_is_taken(#[case] flags: TcpFlags) {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        let sent = written(&mut up_rx).await;
        assert!(sent.iter().any(|p| tcp_header_of(p).fin), "shutdown did not send FIN");
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::FinWait1);

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq + 1, flags, u16::MAX, b"tail"))
            .unwrap();
        assert_eq!(
            acks(&mut up_rx).await,
            [1006],
            "flags {flags:?}: payload and FIN must be acknowledged by one ACK"
        );
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::TimeWait, "flags {flags:?}");

        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await.unwrap();
        assert_eq!(buf, b"tail");
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
    }

    #[rstest]
    #[case::fin_wait1_to_closing(false, TcpState::Closing)]
    #[case::fin_wait2_to_time_wait(true, TcpState::TimeWait)]
    #[tokio::test(start_paused = true)]
    async fn fin_wait_out_of_order_fin_is_taken_when_gap_filled(#[case] ack_our_fin: bool, #[case] expected_state: TcpState) {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        let sent = written(&mut up_rx).await;
        assert!(sent.iter().any(|p| tcp_header_of(p).fin));

        let peer_ack = if ack_our_fin { local_seq + 1 } else { local_seq };
        // Out-of-order FIN segment after a 4-byte gap.
        stream
            .stream_sender()
            .send(peer_segment(1005, peer_ack, ACK | FIN, u16::MAX, b"tail"))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [1001]);

        // Gap-filling data segment without FIN must take the buffered FIN immediately.
        stream
            .stream_sender()
            .send(peer_segment(1001, peer_ack, ACK | PSH, u16::MAX, b"head"))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [1010]);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), expected_state);

        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await.unwrap();
        assert_eq!(buf, b"headtail");
    }

    #[tokio::test(start_paused = true)]
    async fn fin_wait1_slow_reader_probes_without_reset_and_resends_when_window_reopens() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let sender = stream.stream_sender();

        // Slow reader advertises a zero receive window before shutdown.
        sender.send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
        tokio::task::yield_now().await;

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        let first_fin = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&first_fin).fin);

        // Over 100 minutes with window == 0, an alive slow reader answering probes keeps the
        // connection open without exhausting R2.
        let mut probe_count = 0;
        for _ in 0..100 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
            let sent = written(&mut up_rx).await;
            assert!(!sent.is_empty());
            assert!(sent.iter().all(|p| {
                let h = tcp_header_of(p);
                h.fin && !h.rst && h.sequence_number == local_seq
            }));
            probe_count += sent.len();
            sender.send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
            tokio::task::yield_now().await;
        }
        assert!(probe_count >= 100);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::FinWait1);
        assert!(!woken.load(Ordering::SeqCst));

        // Peer opens its window without ACKing the FIN -> stack immediately resends FIN.
        sender.send(peer_segment(1001, local_seq, ACK, u16::MAX, &[])).unwrap();
        let resent_fin = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&resent_fin).fin);
        assert_eq!(tcp_header_of(&resent_fin).sequence_number, local_seq);

        // With window > 0, if that resend is also lost, the timer retries and counts toward R2.
        let timed_out_fin = advance(Duration::from_secs(60), &mut up_rx)
            .await
            .expect("expected RTO FIN resend after reopen");
        assert!(tcp_header_of(&timed_out_fin).fin);
        assert_eq!(tcp_header_of(&timed_out_fin).sequence_number, local_seq);

        sender.send(peer_ack(1001, local_seq + 1)).unwrap();
        tokio::task::yield_now().await;
        assert!(woken.load(Ordering::SeqCst));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::FinWait2);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
    }

    #[tokio::test(start_paused = true)]
    async fn fin_wait1_window_flapping_still_reaches_r2() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert!(tcp_header_of(&up_rx.recv().await.unwrap()).fin);

        // Even if the peer opens mid-interval and drops back to 0 right before every timer tick,
        // the connection still reaches R2.
        for _ in 0..200 {
            sender.send(peer_segment(1001, local_seq, ACK, u16::MAX, &[])).unwrap();
            tokio::time::advance(Duration::from_millis(500)).await;
            tokio::task::yield_now().await;
            sender.send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
            tokio::time::advance(Duration::from_millis(500)).await;
            tokio::task::yield_now().await;
            if stream.tcb.lock().unwrap().get_state() == TcpState::Closed {
                break;
            }
        }

        let packets = written(&mut up_rx).await;
        assert!(packets.iter().any(|p| tcp_header_of(p).rst));
        assert!(woken.load(Ordering::SeqCst));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn fin_wait1_dead_zero_window_peer_closes_after_unanswered_probes() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();

        sender.send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
        tokio::task::yield_now().await;

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert!(tcp_header_of(&up_rx.recv().await.unwrap()).fin);

        let mut rto = RTO;
        for _ in 1..MAX_RETRANSMIT_COUNT {
            let probe = advance(rto, &mut up_rx).await.expect("expected zero-window probe");
            let hdr = tcp_header_of(&probe);
            assert!(hdr.fin && !hdr.rst);
            assert_eq!(hdr.sequence_number, local_seq);
            assert!(destroy_rx.try_recv().is_err());
            rto = (rto * 2).min(Duration::from_secs(60));
        }

        let rst = advance(rto, &mut up_rx)
            .await
            .expect("expected RST after unanswered zero-window probes");
        assert!(tcp_header_of(&rst).rst);
        tokio::task::yield_now().await;
        assert!(woken.load(Ordering::SeqCst));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn drop_in_fin_wait1_cleans_up_after_timeout() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (stream, mut up_rx, _) = established_with_destroy(Some(destroy_tx)).await;

        drop(stream);
        let fin = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&fin).fin);
        assert!(destroy_rx.try_recv().is_err());

        tokio::task::yield_now().await;
        tokio::time::advance(TIMEOUT).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn drop_with_inflight_data_sends_fin_after_ack() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();

        stream.write_all(b"reply").await.unwrap();
        let data_pkt = up_rx.recv().await.unwrap();
        assert_eq!(data_pkt.payload.as_deref(), Some(&b"reply"[..]));

        // Dropping while data is in flight must not send FIN yet or destroy the session.
        drop(stream);
        assert!(written(&mut up_rx).await.is_empty());
        assert!(destroy_rx.try_recv().is_err());

        // Once the peer ACKs the in-flight data, the stack sends FIN.
        sender.send(peer_ack(1001, local_seq + 5)).unwrap();
        let packets = written(&mut up_rx).await;
        assert!(packets.iter().any(|p| tcp_header_of(p).fin));
    }

    #[tokio::test(start_paused = true)]
    async fn peer_fin_half_closes_and_keeps_write_open() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;

        let (read_woken, read_waker) = recording_waker();
        let mut read_cx = Context::from_waker(&read_waker);
        let mut storage = [0; 16];
        let mut read = tokio::io::ReadBuf::new(&mut storage);
        assert!(Pin::new(&mut stream).poll_read(&mut read_cx, &mut read).is_pending());

        // Peer half-closes: stack must ACK without sending FIN and wake the reader with EOF.
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        let sent = written(&mut up_rx).await;
        assert_eq!(sent.len(), 1);
        let hdr = tcp_header_of(&sent[0]);
        assert!(hdr.ack && !hdr.fin);
        assert_eq!(hdr.acknowledgment_number, 1002);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);
        assert!(read_woken.load(Ordering::SeqCst));
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut read_cx, &mut read),
            Poll::Ready(Ok(()))
        ));
        assert!(read.filled().is_empty());

        // Write side remains open in CloseWait until poll_shutdown.
        stream.write_all(b"reply").await.unwrap();
        let data_pkt = up_rx.recv().await.unwrap();
        assert_eq!(data_pkt.payload.as_deref(), Some(&b"reply"[..]));
        stream.stream_sender().send(peer_ack(1002, local_seq + 5)).unwrap();
        tokio::task::yield_now().await;

        let (shutdown_woken, shutdown_waker) = recording_waker();
        let mut shutdown_cx = Context::from_waker(&shutdown_waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx).is_pending());
        let sent = written(&mut up_rx).await;
        assert!(sent.iter().any(|p| tcp_header_of(p).fin));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::LastAck);

        stream.stream_sender().send(peer_ack(1002, local_seq + 6)).unwrap();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(shutdown_woken.load(Ordering::SeqCst));
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx), Poll::Ready(Ok(()))));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn close_wait_stays_open_past_timeout_while_stream_is_alive() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);

        // Stay idle well past TIMEOUT; CloseWait must remain open until shutdown or drop.
        tokio::time::advance(TIMEOUT * 10).await;
        tokio::task::yield_now().await;
        assert!(written(&mut up_rx).await.is_empty());
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);
        assert!(destroy_rx.try_recv().is_err());

        // Write side remains usable after long idle periods in CloseWait.
        stream.write_all(b"delayed-reply").await.unwrap();
        let data_pkt = up_rx.recv().await.unwrap();
        assert_eq!(data_pkt.payload.as_deref(), Some(&b"delayed-reply"[..]));
        stream.stream_sender().send(peer_ack(1002, local_seq + 13)).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);

        // Explicit shutdown sends FIN and completes cleanly on peer ACK.
        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        let fin_pkt = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&fin_pkt).fin);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::LastAck);

        stream.stream_sender().send(peer_ack(1002, local_seq + 14)).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn close_wait_retransmits_inflight_data_and_closes_at_r2() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;

        stream.write_all(b"reply").await.unwrap();
        up_rx.recv().await.unwrap();

        for seconds in BACKOFF.iter().take(MAX_RETRANSMIT_COUNT - 1) {
            let retry = advance(Duration::from_secs(*seconds), &mut up_rx)
                .await
                .expect("expected data retransmission in CloseWait");
            assert_eq!(retry.payload.as_deref(), Some(&b"reply"[..]));
            assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);
        }

        let rst = advance(Duration::from_secs(BACKOFF[MAX_RETRANSMIT_COUNT - 1]), &mut up_rx)
            .await
            .expect("expected RST at R2 in CloseWait");
        assert!(tcp_header_of(&rst).rst);
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn drop_in_close_wait_retries_fin_and_closes_on_ack() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();

        sender.send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[])).unwrap();
        written(&mut up_rx).await;

        drop(stream);
        let first_fin = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&first_fin).fin);
        assert!(destroy_rx.try_recv().is_err());

        tokio::task::yield_now().await;
        let retry_fin = advance(RTO, &mut up_rx).await.expect("no FIN retry after drop");
        assert!(tcp_header_of(&retry_fin).fin);
        assert_eq!(tcp_header_of(&retry_fin).sequence_number, local_seq);

        sender.send(peer_ack(1002, local_seq + 1)).unwrap();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn last_ack_retransmits_fin_with_original_seq() {
        let (mut stream, mut up_rx, local_seq) = established().await;

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;

        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        let first_fin = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&first_fin).fin);
        assert_eq!(tcp_header_of(&first_fin).sequence_number, local_seq);

        tokio::task::yield_now().await;
        let retry_fin = advance(RTO, &mut up_rx).await.expect("no FIN retransmission");
        assert!(tcp_header_of(&retry_fin).fin);
        assert_eq!(tcp_header_of(&retry_fin).sequence_number, local_seq);
    }

    #[tokio::test(start_paused = true)]
    async fn last_ack_ignores_duplicate_ack_before_fin_ack() {
        let (mut stream, mut up_rx, local_seq) = established().await;

        stream.write_all(b"reply").await.unwrap();
        up_rx.recv().await.unwrap();
        stream.stream_sender().send(peer_ack(1001, local_seq + 5)).unwrap();
        tokio::task::yield_now().await;

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq + 5, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;

        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        written(&mut up_rx).await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::LastAck);

        // Duplicate ACK for data (does not acknowledge our FIN at local_seq + 5).
        stream.stream_sender().send(peer_ack(1002, local_seq + 5)).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::LastAck);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());

        // Retransmitted peer FIN with older ACK is ACKed without closing LastAck.
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq + 5, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [1002]);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::LastAck);

        // Final ACK covering our FIN closes the connection.
        stream.stream_sender().send(peer_ack(1002, local_seq + 6)).unwrap();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
    }

    #[tokio::test(start_paused = true)]
    async fn last_ack_acks_retransmitted_fin_even_with_final_ack() {
        let (mut stream, mut up_rx, local_seq) = established().await;

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;

        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        written(&mut up_rx).await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::LastAck);

        // Peer retransmits FIN in the same packet that ACKs our FIN.
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq + 1, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [1002]);
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
    }

    #[tokio::test(start_paused = true)]
    async fn last_ack_resends_lost_fin_with_backoff_and_closes_at_r2() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        let first_fin = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&first_fin).fin);

        let opened = tokio::time::Instant::now();
        let just_before = |seconds: u64| Duration::from_secs(seconds) - Duration::from_millis(1);
        for seconds in BACKOFF.iter().take(MAX_RETRANSMIT_COUNT - 1) {
            assert!(advance(just_before(*seconds), &mut up_rx).await.is_none());
            let retry = advance(Duration::from_millis(1), &mut up_rx)
                .await
                .expect("expected LastAck FIN retry");
            let hdr = tcp_header_of(&retry);
            assert!(hdr.fin && !hdr.rst);
            assert_eq!(hdr.sequence_number, local_seq);
            assert!(destroy_rx.try_recv().is_err());
        }

        assert!(advance(just_before(BACKOFF[MAX_RETRANSMIT_COUNT - 1]), &mut up_rx).await.is_none());
        let rst = advance(Duration::from_millis(1), &mut up_rx)
            .await
            .expect("expected RST at R2 in LastAck");
        assert!(tcp_header_of(&rst).rst);
        tokio::task::yield_now().await;
        assert!((tokio::time::Instant::now() - opened).as_secs() > 100);
        assert!(woken.load(Ordering::SeqCst));
        assert!(stream.shutdown.completed.load(Ordering::Acquire));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn last_ack_probes_zero_window_without_reset_and_recovers_when_open() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let sender = stream.stream_sender();

        sender.send(peer_segment(1001, local_seq, ACK | FIN, 0, &[])).unwrap();
        written(&mut up_rx).await;

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert!(tcp_header_of(&up_rx.recv().await.unwrap()).fin);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::LastAck);

        for _ in 0..10 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
            let sent = written(&mut up_rx).await;
            assert!(!sent.is_empty());
            assert!(sent.iter().all(|p| {
                let h = tcp_header_of(p);
                h.fin && !h.rst && h.sequence_number == local_seq
            }));
            sender.send(peer_segment(1002, local_seq, ACK, 0, &[])).unwrap();
            tokio::task::yield_now().await;
        }
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::LastAck);

        sender.send(peer_segment(1002, local_seq, ACK, u16::MAX, &[])).unwrap();
        let resent = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&resent).fin);
        assert_eq!(tcp_header_of(&resent).sequence_number, local_seq);

        sender.send(peer_ack(1002, local_seq + 1)).unwrap();
        tokio::task::yield_now().await;
        assert!(woken.load(Ordering::SeqCst));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
    }

    #[rstest]
    #[case::established(false)]
    #[case::close_wait(true)]
    #[tokio::test(start_paused = true)]
    async fn poll_shutdown_with_inflight_data_blocks_subsequent_writes(#[case] peer_closed: bool) {
        let (mut stream, mut up_rx, local_seq) = established().await;
        if peer_closed {
            stream
                .stream_sender()
                .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
                .unwrap();
            written(&mut up_rx).await;
        }
        let expected_ack = if peer_closed { 1002 } else { 1001 };

        stream.write_all(b"first").await.unwrap();
        let data_pkt = up_rx.recv().await.unwrap();
        assert_eq!(data_pkt.payload.as_deref(), Some(&b"first"[..]));

        let (shutdown_woken, shutdown_waker) = recording_waker();
        let mut shutdown_cx = Context::from_waker(&shutdown_waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx).is_pending());
        let expected_state = if peer_closed { TcpState::LastAck } else { TcpState::FinWait1 };
        assert_eq!(stream.tcb.lock().unwrap().get_state(), expected_state);
        assert!(written(&mut up_rx).await.is_empty(), "FIN must wait for inflight data");

        // Any subsequent write after shutdown is initiated must fail with BrokenPipe.
        let (_, write_waker) = recording_waker();
        let mut write_cx = Context::from_waker(&write_waker);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut write_cx, b"second"),
            Poll::Ready(Err(ref e)) if e.kind() == BrokenPipe
        ));
        assert!(written(&mut up_rx).await.is_empty());

        // Once inflight data is ACKed, the deferred FIN is sent immediately without re-polling poll_shutdown.
        stream.stream_sender().send(peer_ack(expected_ack, local_seq + 5)).unwrap();
        tokio::task::yield_now().await;
        assert!(shutdown_woken.load(Ordering::SeqCst));
        let fin_pkt = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&fin_pkt).fin);
        assert_eq!(tcp_header_of(&fin_pkt).sequence_number, local_seq + 5);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), expected_state);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx).is_pending());
        assert!(written(&mut up_rx).await.is_empty(), "re-polling must not send a duplicate FIN");

        // Final ACK covering the FIN completes shutdown.
        stream.stream_sender().send(peer_ack(expected_ack, local_seq + 6)).unwrap();
        tokio::task::yield_now().await;
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx), Poll::Ready(Ok(()))));
    }

    #[rstest]
    #[case::fin_before_data_ack(false)]
    #[case::fin_with_data_ack(true)]
    #[tokio::test(start_paused = true)]
    async fn simultaneous_close_while_data_in_flight_enters_closing_and_time_wait(#[case] ack_data_with_fin: bool) {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();

        stream.write_all(b"first").await.unwrap();
        assert_eq!(up_rx.recv().await.unwrap().payload.as_deref(), Some(&b"first"[..]));

        let (shutdown_woken, shutdown_waker) = recording_waker();
        let mut shutdown_cx = Context::from_waker(&shutdown_waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx).is_pending());
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::FinWait1);
        assert!(written(&mut up_rx).await.is_empty());

        // Peer FIN arrives while our data is in flight -> Closing (not CloseWait).
        let peer_fin_ack = if ack_data_with_fin { local_seq + 5 } else { local_seq };
        sender.send(peer_segment(1001, peer_fin_ack, ACK | FIN, u16::MAX, &[])).unwrap();
        let packets = written(&mut up_rx).await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closing);
        assert!(packets.iter().any(|p| tcp_header_of(p).acknowledgment_number == 1002));

        if !ack_data_with_fin {
            // Before data is ACKed, our FIN has not gone out yet.
            assert!(packets.iter().all(|p| !tcp_header_of(p).fin));
            // Peer ACKs our data: must stay in Closing (not jump to TimeWait) and send our FIN.
            sender.send(peer_ack(1002, local_seq + 5)).unwrap();
            let after_data_ack = written(&mut up_rx).await;
            let fins: Vec<_> = after_data_ack.iter().filter(|p| tcp_header_of(p).fin).collect();
            assert_eq!(fins.len(), 1);
            assert_eq!(tcp_header_of(fins[0]).sequence_number, local_seq + 5);
            assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closing);
        } else {
            let fins: Vec<_> = packets.iter().filter(|p| tcp_header_of(p).fin).collect();
            assert_eq!(fins.len(), 1);
            assert_eq!(tcp_header_of(fins[0]).sequence_number, local_seq + 5);
        }

        // Peer ACKs our FIN -> TimeWait (2MSL) -> Closed.
        sender.send(peer_ack(1002, local_seq + 6)).unwrap();
        tokio::task::yield_now().await;
        assert!(shutdown_woken.load(Ordering::SeqCst));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::TimeWait);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx), Poll::Ready(Ok(()))));
        assert!(destroy_rx.try_recv().is_err());

        tokio::time::advance(TWO_MSL).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn poll_shutdown_wakes_parked_writer_with_broken_pipe() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream.write_all(b"first").await.unwrap();
        up_rx.recv().await.unwrap();

        // Peer closes its window so a writer parks on poll_write.
        stream.stream_sender().send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
        tokio::task::yield_now().await;

        let (write_woken, write_waker) = recording_waker();
        let mut write_cx = Context::from_waker(&write_waker);
        assert!(Pin::new(&mut stream).poll_write(&mut write_cx, b"parked").is_pending());

        // Initiating shutdown while data is in flight wakes the parked writer with BrokenPipe.
        let (_, shutdown_waker) = recording_waker();
        let mut shutdown_cx = Context::from_waker(&shutdown_waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx).is_pending());
        assert!(write_woken.load(Ordering::SeqCst));
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut write_cx, b"parked"),
            Poll::Ready(Err(ref e)) if e.kind() == BrokenPipe
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn closing_resends_lost_fin_and_closes_at_r2() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert!(tcp_header_of(&up_rx.recv().await.unwrap()).fin);

        // Our FIN was lost, and the peer closes on its side without ACKing our FIN -> Closing.
        sender.send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[])).unwrap();
        assert_eq!(acks(&mut up_rx).await, [1002]);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closing);
        assert!(!woken.load(Ordering::SeqCst));

        // While window > 0, Closing keeps retransmitting our FIN with exponential backoff up to R2.
        let mut rto = RTO;
        for _ in 1..MAX_RETRANSMIT_COUNT {
            let retry = advance(rto, &mut up_rx).await.expect("expected FIN retry in Closing");
            let hdr = tcp_header_of(&retry);
            assert!(hdr.fin);
            assert_eq!(hdr.sequence_number, local_seq);
            assert_eq!(hdr.acknowledgment_number, 1002);
            assert!(destroy_rx.try_recv().is_err());
            rto = (rto * 2).min(Duration::from_secs(60));
        }

        // At R2, the connection resets and completes shutdown rather than hanging in Closing forever.
        let rst = advance(rto, &mut up_rx).await.expect("expected RST at R2 in Closing");
        assert!(tcp_header_of(&rst).rst);
        tokio::task::yield_now().await;
        assert!(woken.load(Ordering::SeqCst));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn closing_probes_zero_window_without_reset_and_recovers_when_open() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let sender = stream.stream_sender();

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert!(tcp_header_of(&up_rx.recv().await.unwrap()).fin);

        // Peer closes while advertising window = 0 -> Closing, zero-window probes do not exhaust R2.
        sender.send(peer_segment(1001, local_seq, ACK | FIN, 0, &[])).unwrap();
        assert_eq!(acks(&mut up_rx).await, [1002]);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closing);

        let mut probe_count = 0;
        for _ in 0..100 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
            let sent = written(&mut up_rx).await;
            assert!(!sent.is_empty());
            assert!(sent.iter().all(|p| {
                let h = tcp_header_of(p);
                h.fin && !h.rst && h.sequence_number == local_seq
            }));
            probe_count += sent.len();
            sender.send(peer_segment(1002, local_seq, ACK, 0, &[])).unwrap();
            tokio::task::yield_now().await;
        }
        assert!(probe_count >= 100);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closing);

        // Window reopens -> FIN resent; peer ACKs it -> TimeWait + shutdown Ready.
        sender.send(peer_segment(1002, local_seq, ACK, u16::MAX, &[])).unwrap();
        let resent = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&resent).fin);
        assert_eq!(tcp_header_of(&resent).sequence_number, local_seq);

        sender.send(peer_ack(1002, local_seq + 1)).unwrap();
        tokio::task::yield_now().await;
        assert!(woken.load(Ordering::SeqCst));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::TimeWait);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
    }

    #[tokio::test(start_paused = true)]
    async fn simultaneous_close_and_time_wait_survives_drop_until_two_msl() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();

        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert!(tcp_header_of(&up_rx.recv().await.unwrap()).fin);

        // Peer FIN crosses ours without acknowledging it -> Closing.
        sender.send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[])).unwrap();
        assert_eq!(acks(&mut up_rx).await, [1002]);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closing);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());

        // Read side is at EOF and write side is closed in Closing.
        let mut storage = [0; 8];
        let mut read = tokio::io::ReadBuf::new(&mut storage);
        assert!(matches!(Pin::new(&mut stream).poll_read(&mut cx, &mut read), Poll::Ready(Ok(()))));
        assert!(read.filled().is_empty());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"late"),
            Poll::Ready(Err(ref e)) if e.kind() == BrokenPipe
        ));

        // Duplicate ACK stays in Closing; retransmitted peer FIN is ACKed.
        sender.send(peer_ack(1002, local_seq)).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closing);
        sender.send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[])).unwrap();
        assert_eq!(acks(&mut up_rx).await, [1002]);

        // Final ACK of our FIN moves Closing -> TimeWait and completes shutdown.
        sender.send(peer_ack(1002, local_seq + 1)).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::TimeWait);
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));

        // Dropping in TimeWait preserves 2 MSL, ACKs retransmitted peer FINs, and restarts 2 MSL.
        drop(stream);
        tokio::time::advance(TWO_MSL / 2).await;
        tokio::task::yield_now().await;
        assert!(destroy_rx.try_recv().is_err());
        sender.send(peer_segment(1001, local_seq + 1, ACK | FIN, u16::MAX, &[])).unwrap();
        assert_eq!(acks(&mut up_rx).await, [1002]);

        tokio::time::advance(TWO_MSL / 2).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(destroy_rx.try_recv().is_err(), "retransmitted FIN must restart 2 MSL");

        tokio::time::advance(TWO_MSL / 2).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    // --- Segment validation & security tests ---

    #[tokio::test(start_paused = true)]
    async fn out_of_window_and_in_window_rst_are_validated_against_rcv_nxt() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream.write_all(b"keepalive").await.unwrap();
        up_rx.recv().await.unwrap();

        // Out-of-window RST (below RCV.NXT and beyond RCV.NXT + RCV.WND) is silently dropped.
        for bad_seq in [1000, 1001 + READ_BUFFER_SIZE as u32] {
            stream
                .stream_sender()
                .send(peer_segment(bad_seq, local_seq, RST | ACK, u16::MAX, &[]))
                .unwrap();
            assert!(
                written(&mut up_rx).await.is_empty(),
                "out-of-window RST seq {bad_seq} must not emit ACK"
            );
            assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);
        }

        // In-window RST not matching RCV.NXT triggers a challenge ACK and keeps the connection open.
        stream
            .stream_sender()
            .send(peer_segment(1005, local_seq, RST | ACK, u16::MAX, &[]))
            .unwrap();
        let responses = written(&mut up_rx).await;
        assert_eq!(responses.len(), 1);
        let hdr = tcp_header_of(&responses[0]);
        assert!(hdr.ack && !hdr.rst);
        assert_eq!(hdr.acknowledgment_number, 1001);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);

        // Exact RCV.NXT RST closes the connection immediately.
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, RST | ACK, u16::MAX, &[]))
            .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn segment_without_ack_flag_does_not_mutate_inflight_or_ack_state() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream.write_all(b"secret").await.unwrap();
        up_rx.recv().await.unwrap();

        // Forged segment without ACK flag carrying acknowledgment_number past our data and win = 0.
        for flags in [TcpFlags::PSH, TcpFlags::FIN, TcpFlags::PSH | TcpFlags::FIN] {
            stream
                .stream_sender()
                .send(peer_segment(1001, local_seq + 6, flags, 0, b"inject"))
                .unwrap();
            tokio::task::yield_now().await;
        }

        let tcb = stream.tcb.lock().unwrap();
        assert_eq!(tcb.get_state(), TcpState::Established);
        assert_eq!(tcb.get_last_received_ack(), SeqNum(local_seq));
        assert_eq!(tcb.get_inflight_packets_total_len(), 6);
        assert_eq!(tcb.get_send_window(), u16::MAX as u32);
        assert_eq!(tcb.get_ack(), SeqNum(1001));
    }

    #[tokio::test(start_paused = true)]
    async fn stale_ack_below_snd_una_still_delivers_data_and_fin() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream.write_all(b"first").await.unwrap();
        up_rx.recv().await.unwrap();
        stream.stream_sender().send(peer_ack(1001, local_seq + 5)).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_last_received_ack(), SeqNum(local_seq + 5));

        // Segment arrives with SEG.ACK < SND.UNA (stale ACK = local_seq, stale win = 0) and new data.
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | PSH, 0, b"payload"))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [1008]);

        let mut buf = [0u8; 7];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"payload");
        {
            let tcb = stream.tcb.lock().unwrap();
            assert_eq!(tcb.get_last_received_ack(), SeqNum(local_seq + 5));
            assert_eq!(tcb.get_send_window(), u16::MAX as u32);
        }

        // Segment with SEG.ACK < SND.UNA and FIN still transitions Established -> CloseWait.
        stream
            .stream_sender()
            .send(peer_segment(1008, local_seq, ACK | FIN, 0, &[]))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [1009]);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);
    }

    #[tokio::test(start_paused = true)]
    async fn ack_above_snd_nxt_sends_ack_and_drops_segment() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream.write_all(b"data").await.unwrap();
        up_rx.recv().await.unwrap();

        // SEG.ACK > SND.NXT in Established sends an ACK and drops the segment (no payload, no inflight clear).
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq + 100, ACK | PSH, 0, b"ignored"))
            .unwrap();
        let responses = written(&mut up_rx).await;
        assert_eq!(responses.len(), 1);
        let hdr = tcp_header_of(&responses[0]);
        assert!(hdr.ack && !hdr.rst);
        assert_eq!(hdr.sequence_number, local_seq + 4);
        assert_eq!(hdr.acknowledgment_number, 1001);
        {
            let tcb = stream.tcb.lock().unwrap();
            assert_eq!(tcb.get_ack(), SeqNum(1001));
            assert_eq!(tcb.get_inflight_packets_total_len(), 4);
            assert_eq!(tcb.get_last_received_ack(), SeqNum(local_seq));
            assert_eq!(tcb.get_send_window(), u16::MAX as u32);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn syn_received_rejects_ack_above_snd_nxt_with_rst() {
        let (stream, syn_ack, mut up_rx) = open(u16::MAX, &[]).await;

        stream
            .stream_sender()
            .send(peer_ack(syn_ack.acknowledgment_number, syn_ack.sequence_number.wrapping_add(50)))
            .unwrap();
        let responses = written(&mut up_rx).await;
        assert_eq!(responses.len(), 1);
        let hdr = tcp_header_of(&responses[0]);
        assert!(hdr.rst && !hdr.ack);
        assert_eq!(hdr.sequence_number, syn_ack.sequence_number.wrapping_add(50));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::SynReceived);
    }

    #[rstest]
    #[case::syn(SYN)]
    #[case::syn_ack(SYN | ACK)]
    #[case::syn_ack_fin(SYN | ACK | FIN)]
    #[tokio::test(start_paused = true)]
    async fn syn_in_synchronized_states_is_rejected_with_challenge_ack(#[case] flags: TcpFlags) {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream.write_all(b"stay").await.unwrap();
        up_rx.recv().await.unwrap();

        // SYN in Established triggers a challenge ACK and drops payload/ACK/FIN.
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq + 4, flags, 0, b"rogue"))
            .unwrap();
        let responses = written(&mut up_rx).await;
        assert_eq!(responses.len(), 1);
        let hdr = tcp_header_of(&responses[0]);
        assert!(hdr.ack && !hdr.rst && !hdr.syn);
        assert_eq!(hdr.acknowledgment_number, 1001);
        {
            let tcb = stream.tcb.lock().unwrap();
            assert_eq!(tcb.get_state(), TcpState::Established);
            assert_eq!(tcb.get_ack(), SeqNum(1001));
            assert_eq!(tcb.get_inflight_packets_total_len(), 4);
            assert_eq!(tcb.get_send_window(), u16::MAX as u32);
        }

        // Also verify SYN|ACK in FinWait1 does not transition to FinWait2.
        stream.stream_sender().send(peer_ack(1001, local_seq + 4)).unwrap();
        tokio::task::yield_now().await;
        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert!(tcp_header_of(&up_rx.recv().await.unwrap()).fin);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::FinWait1);

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq + 5, flags, u16::MAX, &[]))
            .unwrap();
        let responses = written(&mut up_rx).await;
        assert_eq!(responses.len(), 1);
        assert!(tcp_header_of(&responses[0]).ack && !tcp_header_of(&responses[0]).rst);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::FinWait1);
    }

    #[rstest]
    #[case::syn_rst(SYN | RST, 0, false, false)]
    #[case::syn_rst_ack(SYN | RST | ACK, 0, false, false)]
    #[case::rst(RST, 0, false, false)]
    #[case::rst_ack(RST | ACK, 0, false, false)]
    #[case::syn_ack(SYN | ACK, 0, true, false)]
    #[case::ack(ACK, 0, true, false)]
    #[case::ack_payload(ACK | PSH, 5, true, false)]
    #[case::fin_ack(FIN | ACK, 0, true, false)]
    #[case::fin(FIN, 0, true, true)]
    #[case::fin_payload(FIN | PSH, 4, true, true)]
    #[case::psh_payload(PSH, 4, true, true)]
    #[case::psh_empty(PSH, 0, true, true)]
    #[tokio::test]
    async fn listen_rejects_invalid_initial_segments(
        #[case] flags: TcpFlags,
        #[case] payload_len: usize,
        #[case] expects_rst: bool,
        #[case] expects_ack_on_rst: bool,
    ) {
        let (peer, local) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();

        let mut hdr = TcpHeader::new(12345, 80, 1000, u16::MAX);
        hdr.syn = flags.contains(SYN);
        hdr.rst = flags.contains(RST);
        hdr.ack = flags.contains(ACK);
        hdr.fin = flags.contains(FIN);
        hdr.psh = flags.contains(PSH);
        hdr.acknowledgment_number = if hdr.ack { 7777 } else { 0 };

        let err = match IpStackTcpStream::new(peer, local, hdr, payload_len, up_tx, 1500, None, Arc::new(TcpConfig::default())) {
            Ok(_) => panic!("expected invalid initial segment {flags:?} to be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, IpStackError::IoError(e) if e.kind() == ConnectionRefused));

        let responses = written(&mut up_rx).await;
        if !expects_rst {
            assert!(responses.is_empty(), "RST-bearing segment {flags:?} must not trigger a response");
        } else {
            assert_eq!(responses.len(), 1, "expected single RST response for {flags:?}");
            let rst_hdr = tcp_header_of(&responses[0]);
            assert!(rst_hdr.rst && !rst_hdr.syn);
            assert_eq!(rst_hdr.ack, expects_ack_on_rst);
            if expects_ack_on_rst {
                let expected_ack = 1000u32
                    .wrapping_add(payload_len as u32)
                    .wrapping_add(u32::from(flags.contains(SYN)))
                    .wrapping_add(u32::from(flags.contains(FIN)));
                assert_eq!(rst_hdr.sequence_number, 0);
                assert_eq!(rst_hdr.acknowledgment_number, expected_ack);
            } else {
                assert_eq!(rst_hdr.sequence_number, 7777);
                assert_eq!(rst_hdr.acknowledgment_number, 0);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn syn_received_rejects_syn_ack_with_challenge_ack_and_ignores_ack_eq_isn_with_payload() {
        let (stream, syn_ack, mut up_rx) = open(u16::MAX, &[]).await;

        // SYN|ACK in SynReceived triggers a challenge ACK and does not establish.
        stream
            .stream_sender()
            .send(peer_segment(
                syn_ack.acknowledgment_number,
                syn_ack.sequence_number.wrapping_add(1),
                SYN | ACK,
                u16::MAX,
                &[],
            ))
            .unwrap();
        let responses = written(&mut up_rx).await;
        assert_eq!(responses.len(), 1);
        let hdr = tcp_header_of(&responses[0]);
        assert!(hdr.ack && !hdr.syn && !hdr.rst);
        assert_eq!(hdr.acknowledgment_number, syn_ack.acknowledgment_number);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::SynReceived);

        // ACK == ISN carrying payload also stays in SynReceived and discards payload.
        stream
            .stream_sender()
            .send(peer_segment(
                syn_ack.acknowledgment_number,
                syn_ack.sequence_number,
                ACK | PSH,
                u16::MAX,
                b"early",
            ))
            .unwrap();
        assert!(written(&mut up_rx).await.is_empty());
        let tcb = stream.tcb.lock().unwrap();
        assert_eq!(tcb.get_state(), TcpState::SynReceived);
        assert_eq!(tcb.get_ack(), SeqNum(syn_ack.acknowledgment_number));
        assert_eq!(tcb.get_last_received_ack(), SeqNum(syn_ack.sequence_number));
    }

    #[rstest]
    #[case::ack_fin(ACK | FIN, b"" as &[u8])]
    #[case::ack_psh_fin(ACK | PSH | FIN, b"one-shot")]
    #[tokio::test(start_paused = true)]
    async fn syn_received_with_fin_enters_close_wait_and_delivers_data_and_eof(#[case] flags: TcpFlags, #[case] payload: &[u8]) {
        let (mut stream, syn_ack, mut up_rx) = open(u16::MAX, &[]).await;
        let peer_seq = syn_ack.acknowledgment_number;
        let local_seq = syn_ack.sequence_number.wrapping_add(1);

        stream
            .stream_sender()
            .send(peer_segment(peer_seq, local_seq, flags, u16::MAX, payload))
            .unwrap();

        let expected_ack = peer_seq.wrapping_add(payload.len() as u32).wrapping_add(1);
        assert_eq!(acks(&mut up_rx).await, [expected_ack]);
        {
            let tcb = stream.tcb.lock().unwrap();
            assert_eq!(tcb.get_state(), TcpState::CloseWait);
            assert_eq!(tcb.get_ack(), SeqNum(expected_ack));
            assert_eq!(tcb.get_last_received_ack(), SeqNum(local_seq));
            assert!(tcb.get_retransmission_deadline().is_none());
        }

        let mut received = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut received).await.unwrap();
        assert_eq!(received, payload);

        // Half-close write side remains usable in CloseWait, then shutdown sends FIN.
        stream.write_all(b"reply").await.unwrap();
        let data_pkt = up_rx.recv().await.unwrap();
        assert_eq!(tcp_header_of(&data_pkt).sequence_number, local_seq);
        assert_eq!(data_pkt.payload.as_deref(), Some(&b"reply"[..]));
        stream.stream_sender().send(peer_ack(expected_ack, local_seq + 5)).unwrap();
        tokio::task::yield_now().await;

        let (_, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        let fin_pkt = up_rx.recv().await.unwrap();
        assert!(tcp_header_of(&fin_pkt).fin);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::LastAck);
    }

    #[tokio::test(start_paused = true)]
    async fn syn_received_with_out_of_order_fin_enters_established_until_gap_filled() {
        let (mut stream, syn_ack, mut up_rx) = open(u16::MAX, &[]).await;
        let peer_seq = syn_ack.acknowledgment_number;
        let local_seq = syn_ack.sequence_number.wrapping_add(1);

        // Out-of-order ACK|FIN (gap of 4 bytes before it) completes handshake to Established without taking FIN.
        stream
            .stream_sender()
            .send(peer_segment(peer_seq + 4, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [peer_seq]);
        {
            let tcb = stream.tcb.lock().unwrap();
            assert_eq!(tcb.get_state(), TcpState::Established);
            assert_eq!(tcb.get_ack(), SeqNum(peer_seq));
            assert!(tcb.get_retransmission_deadline().is_none());
        }

        // Fill the gap: the previously buffered FIN is taken immediately to reach CloseWait and EOF.
        stream
            .stream_sender()
            .send(peer_segment(peer_seq, local_seq, ACK | PSH, u16::MAX, b"four"))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [peer_seq + 5]);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);

        // A duplicate FIN retransmission is still ACKed at peer_seq + 5.
        stream
            .stream_sender()
            .send(peer_segment(peer_seq + 4, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [peer_seq + 5]);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);

        let mut received = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut received).await.unwrap();
        assert_eq!(received, b"four");
    }

    #[rstest]
    #[case::ack_urg(ACK | TcpFlags::URG)]
    #[case::ack_psh_urg(ACK | PSH | TcpFlags::URG)]
    #[tokio::test(start_paused = true)]
    async fn syn_received_final_ack_with_urg_delivers_payload(#[case] flags: TcpFlags) {
        let (mut stream, syn_ack, mut up_rx) = open(u16::MAX, &[]).await;
        let peer_seq = syn_ack.acknowledgment_number;
        let local_seq = syn_ack.sequence_number.wrapping_add(1);

        stream
            .stream_sender()
            .send(peer_segment(peer_seq, local_seq, flags, u16::MAX, b"urgent-data"))
            .unwrap();

        assert_eq!(acks(&mut up_rx).await, [peer_seq + 11]);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);

        let mut buf = [0u8; 11];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"urgent-data");
    }

    #[rstest]
    #[case::established(false)]
    #[case::close_wait(true)]
    #[tokio::test(start_paused = true)]
    async fn empty_inflight_zero_window_probes_and_recovers_on_reopen(#[case] close_wait: bool) {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let sender = stream.stream_sender();

        let mut peer_seq = 1001;
        if close_wait {
            sender.send(peer_segment(peer_seq, local_seq, ACK | FIN, 0, &[])).unwrap();
            peer_seq += 1;
            assert_eq!(acks(&mut up_rx).await, [peer_seq]);
            assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);
        } else {
            sender.send(peer_segment(peer_seq, local_seq, ACK, 0, &[])).unwrap();
            tokio::task::yield_now().await;
        }

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_write(&mut cx, b"hello").is_pending());

        // Peer answers probes with window = 0 over many intervals without resetting the session.
        let mut probe_count = 0;
        for _ in 0..20 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
            let sent = written(&mut up_rx).await;
            assert!(!sent.is_empty());
            assert!(sent.iter().all(|p| {
                let h = tcp_header_of(p);
                h.ack && !h.rst && h.sequence_number == local_seq - 1 && p.payload.as_deref().unwrap_or_default().is_empty()
            }));
            probe_count += sent.len();
            sender.send(peer_segment(peer_seq, local_seq, ACK, 0, &[])).unwrap();
            tokio::task::yield_now().await;
            assert!(Pin::new(&mut stream).poll_write(&mut cx, b"hello").is_pending());
        }
        assert!(probe_count >= 20);
        woken.store(false, Ordering::SeqCst);

        // Next probe triggers a peer ACK carrying a reopened window (recovering from a lost update).
        let probe = advance(Duration::from_secs(60), &mut up_rx).await.expect("expected persist probe");
        assert_eq!(tcp_header_of(&probe).sequence_number, local_seq - 1);
        sender.send(peer_segment(peer_seq, local_seq, ACK, 4096, &[])).unwrap();
        tokio::task::yield_now().await;

        assert!(woken.load(Ordering::SeqCst));
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"hello"), Poll::Ready(Ok(5))));
        let pkt = up_rx.recv().await.unwrap();
        assert_eq!(tcp_header_of(&pkt).sequence_number, local_seq);
        assert_eq!(pkt.payload.as_deref(), Some(&b"hello"[..]));
    }

    #[tokio::test(start_paused = true)]
    async fn empty_inflight_zero_window_dead_peer_closes_after_unanswered_probes() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();

        sender.send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
        tokio::task::yield_now().await;

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_write(&mut cx, b"blocked").is_pending());

        let mut rto = RTO;
        for _ in 1..MAX_RETRANSMIT_COUNT {
            let probe = advance(rto, &mut up_rx).await.expect("expected persist probe");
            let hdr = tcp_header_of(&probe);
            assert!(hdr.ack && !hdr.rst);
            assert_eq!(hdr.sequence_number, local_seq - 1);
            assert!(destroy_rx.try_recv().is_err());
            rto = (rto * 2).min(Duration::from_secs(60));
        }

        let rst = advance(rto, &mut up_rx)
            .await
            .expect("expected RST after unanswered persist probes");
        assert!(tcp_header_of(&rst).rst);
        tokio::task::yield_now().await;
        assert!(woken.load(Ordering::SeqCst));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"blocked"),
            Poll::Ready(Err(ref e)) if e.kind() == BrokenPipe
        ));
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn inflight_data_with_zero_window_probes_without_r2_reset_and_recovers() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let sender = stream.stream_sender();

        stream.write_all(b"hello").await.unwrap();
        let first = up_rx.recv().await.unwrap();
        assert_eq!(first.payload.as_deref(), Some(&b"hello"[..]));

        // Peer closes its window without acknowledging the inflight segment.
        sender.send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
        tokio::task::yield_now().await;

        let mut probe_count = 0;
        for _ in 0..20 {
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::task::yield_now().await;
            let sent = written(&mut up_rx).await;
            assert!(!sent.is_empty());
            assert!(sent.iter().all(|p| {
                let h = tcp_header_of(p);
                h.ack && !h.rst && h.sequence_number == local_seq - 1 && p.payload.as_deref().unwrap_or_default().is_empty()
            }));
            probe_count += sent.len();
            sender.send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
            tokio::task::yield_now().await;
        }
        assert!(probe_count >= 20);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);

        // Reopening the window immediately resends the inflight segment.
        sender.send(peer_segment(1001, local_seq, ACK, 4096, &[])).unwrap();
        let resent = up_rx.recv().await.unwrap();
        assert_eq!(tcp_header_of(&resent).sequence_number, local_seq);
        assert_eq!(resent.payload.as_deref(), Some(&b"hello"[..]));

        sender.send(peer_ack(1001, local_seq + 5)).unwrap();
        tokio::task::yield_now().await;
        assert!(stream.tcb.lock().unwrap().is_inflight_queue_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn inflight_data_with_zero_window_dead_peer_closes_after_unanswered_probes() {
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        let (mut stream, mut up_rx, local_seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();

        stream.write_all(b"hello").await.unwrap();
        up_rx.recv().await.unwrap();
        sender.send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
        tokio::task::yield_now().await;

        let mut rto = RTO;
        // First expiry transitions window_opened -> false; next MAX_RETRANSMIT_COUNT - 1 probes
        // go unanswered before the final expiry sends RST.
        for _ in 0..MAX_RETRANSMIT_COUNT {
            let probe = advance(rto, &mut up_rx).await.expect("expected zero-window probe");
            let hdr = tcp_header_of(&probe);
            assert!(hdr.ack && !hdr.rst);
            assert_eq!(hdr.sequence_number, local_seq - 1);
            assert!(destroy_rx.try_recv().is_err());
            rto = (rto * 2).min(Duration::from_secs(60));
        }

        let rst = advance(rto, &mut up_rx).await.expect("expected RST after unanswered probes");
        assert!(tcp_header_of(&rst).rst);
        tokio::task::yield_now().await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn reordered_segment_with_older_seq_does_not_overwrite_send_window() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let sender = stream.stream_sender();

        // Newer segment arrives out of order with window = 4096.
        sender.send(peer_segment(1005, local_seq, ACK | PSH, 4096, b"tail")).unwrap();
        assert_eq!(acks(&mut up_rx).await, [1001]);

        // Delayed older segment arrives with same ACK and window = 0; must not clobber 4096.
        sender.send(peer_segment(1001, local_seq, ACK | PSH, 0, b"head")).unwrap();
        assert_eq!(acks(&mut up_rx).await, [1009]);
        assert_eq!(stream.tcb.lock().unwrap().get_send_window(), 4096);

        let mut buf = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"headtail");

        stream.write_all(b"ok").await.unwrap();
        let pkt = up_rx.recv().await.unwrap();
        assert_eq!(pkt.payload.as_deref(), Some(&b"ok"[..]));
    }

    #[tokio::test(start_paused = true)]
    async fn overlapping_out_of_order_segments_do_not_exhaust_window_or_corrupt_data() {
        let config = TcpConfig {
            read_buffer_size: 4000,
            ..TcpConfig::default()
        };
        let (mut stream, mut up_rx, local_seq) = established_with(None, config).await;
        let sender = stream.stream_sender();

        // Buffer [1200, 1800) (600 bytes).
        let expected_600: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        sender
            .send(peer_segment(1200, local_seq, ACK | PSH, u16::MAX, &expected_600))
            .unwrap();
        let ack1 = up_rx.recv().await.unwrap();
        assert_eq!(tcp_header_of(&ack1).acknowledgment_number, 1001);
        assert_eq!(tcp_header_of(&ack1).window_size, 3400);

        // Shorter retransmission at same seq [1200, 1300) and overlapping segments at distinct keys
        // must not overwrite [1200, 1800) or shrink the advertised window below 3400.
        sender
            .send(peer_segment(1200, local_seq, ACK | PSH, u16::MAX, &[0xAA; 100]))
            .unwrap();
        let ack2 = up_rx.recv().await.unwrap();
        assert_eq!(tcp_header_of(&ack2).window_size, 3400);

        for start in [1200u32, 1250, 1300, 1350, 1400, 1450, 1500] {
            sender
                .send(peer_segment(start, local_seq, ACK | PSH, u16::MAX, &[0xBB; 300]))
                .unwrap();
            let ack = up_rx.recv().await.unwrap();
            assert_eq!(tcp_header_of(&ack).window_size, 3400);
        }

        // Fill the gap [1001, 1200) -> full 799 bytes arrive intact.
        sender
            .send(peer_segment(1001, local_seq, ACK | PSH, u16::MAX, &[0x11; 199]))
            .unwrap();
        assert_eq!(acks(&mut up_rx).await, [1800]);

        let mut received = vec![0u8; 799];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut received).await.unwrap();
        assert_eq!(&received[..199], &[0x11; 199]);
        assert_eq!(&received[199..], &expected_600[..]);
    }
}
