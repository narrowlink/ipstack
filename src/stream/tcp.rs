use super::seqnum::SeqNum;
use crate::{
    PacketReceiver, PacketSender, TTL,
    error::IpStackError,
    packet::{IpHeader, NetworkPacket, NetworkTuple, TcpFlags, TransportHeader, tcp_header_flags, tcp_header_fmt},
    stream::tcb::{
        MAX_COUNT_FOR_DUP_ACK, MAX_RETRANSMIT_COUNT, MAX_RTO, MAX_UNACK, PacketType, READ_BUFFER_SIZE, READ_CHUNK, RTO, Tcb, TcpState,
    },
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

const CLOSE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const LAST_ACK_MAX_RETRIES: usize = 3;
const LAST_ACK_TIMEOUT: Duration = Duration::from_millis(500);
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
    /// Maximum FIN retransmissions in LastAck, FinWait1, or Closing. Default is 3.
    pub last_ack_max_retries: usize,
    /// Minimum FIN retry interval. The current data RTO is a floor; retries back off exponentially. Default is 500ms.
    pub last_ack_timeout: Duration,
    /// Timeout for the CLOSE_WAIT state: once this long passes with nothing sent or acknowledged, our FIN is
    /// sent for an application that has not shut down. Default is 5 seconds.
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
            last_ack_max_retries: LAST_ACK_MAX_RETRIES,
            last_ack_timeout: LAST_ACK_TIMEOUT,
            close_wait_timeout: CLOSE_WAIT_TIMEOUT,
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
    completed: AtomicBool,
    detached_close: AtomicBool,
    waker: AtomicWaker,
}

impl ShutdownSignal {
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
    pub(crate) fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp: TcpHeader,
        up_packet_sender: PacketSender,
        mtu: u16,
        destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
        config: Arc<TcpConfig>,
    ) -> Result<IpStackTcpStream, IpStackError> {
        // RFC 7323 §2.2: a window scale option is read only from a segment carrying SYN.
        let peer_window_shift = tcp
            .syn
            .then(|| {
                tcp.options_iterator().flatten().find_map(|option| match option {
                    TcpOptionElement::WindowScale(shift) => Some(shift),
                    _ => None,
                })
            })
            .flatten();
        let tcb = Tcb::new(
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
        let tuple = NetworkTuple::new(src_addr, dst_addr, true);
        if !tcp.syn {
            if !tcp.rst
                && let Err(err) = write_packet_to_device(&up_packet_sender, tuple, &tcb, None, ACK | RST, None, None)
            {
                log::warn!("Error sending RST/ACK packet: {err}");
            }
            let info = format!("Invalid TCP packet: {tuple} {}", tcp_header_fmt(&tcp));
            return Err(IpStackError::IoError(std::io::Error::new(ConnectionRefused, info)));
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
        if state == TcpState::Closed {
            // Data on hand reaches the reader before end-of-stream.
            let data = self.data_rx.try_recv().ok();
            if let Some(data) = data.or_else(|| self.tcb.lock().unwrap().take_received(usize::MAX)) {
                let len = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..len]);
                self.temp_read_buffer.extend_from_slice(&data[len..]);
                return Poll::Ready(Ok(()));
            }
            self.shutdown.complete();
            self.write_notify.wake();
            return Poll::Ready(Ok(()));
        }
        if matches!(
            state,
            TcpState::CloseWait | TcpState::LastAck | TcpState::Closing | TcpState::TimeWait
        ) {
            // The peer's FIN came after every byte it sent, so what is on hand is the rest of the
            // stream. The lock keeps the main loop from moving bytes into the channel in between.
            let tcb = self.tcb.clone();
            let mut tcb = tcb.lock().unwrap();
            if let Some(data) = self.data_rx.try_recv().ok().or_else(|| tcb.take_received(usize::MAX)) {
                let len = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..len]);
                self.temp_read_buffer.extend_from_slice(&data[len..]);
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

        if state == TcpState::Closed {
            self.shutdown.complete();
            self.read_notify.wake();
            return Poll::Ready(Err(std::io::Error::new(BrokenPipe, "TCP connection closed")));
        }
        if matches!(
            state,
            TcpState::LastAck | TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing | TcpState::TimeWait
        ) {
            // Our FIN is out, and nothing may follow it.
            return Poll::Ready(Err(std::io::Error::new(BrokenPipe, "TCP connection closing")));
        }

        // The task that answers the SYN may not have run yet. Data written now would leave ahead of
        // the SYN-ACK, under the initial sequence number.
        if state == TcpState::Listen {
            return Poll::Pending;
        }

        if send_window == 0 || is_full {
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
        let (nt, state, seq, is_ready) = {
            let tcb = self.tcb.lock().unwrap();
            let is_ready = tcb.get_inflight_packets_total_len() == 0;
            (self.network_tuple(), tcb.get_state(), tcb.get_seq(), is_ready)
        };
        log::trace!("{nt} {state:?}: [poll_shutdown] seq = {seq}, ready = {is_ready}",);
        #[cfg(test)]
        tests::run_after_state_snapshot();
        if state == TcpState::Closed {
            return Poll::Ready(Ok(()));
        }
        {
            let mut tcb = self.tcb.lock().unwrap();
            if tcb.is_inflight_queue_empty() {
                match tcb.get_state() {
                    TcpState::Established => {
                        send_fin_n_change_state_to_fin_wait1("[poll_shutdown]", nt, &self.up_packet_sender, &mut tcb)?;
                        if let Some(exit) = self.exit_notifier.clone() {
                            tokio::spawn(task_last_ack(
                                self.tcb.clone(),
                                exit,
                                nt,
                                self.up_packet_sender.clone(),
                                self.config.last_ack_timeout,
                                self.config.last_ack_max_retries,
                            ));
                        }
                    }
                    TcpState::CloseWait => {
                        send_fin_n_change_state_to_last_ack("[poll_shutdown]", nt, &self.up_packet_sender, &mut tcb)?;
                        if let Some(exit) = self.exit_notifier.clone() {
                            tokio::spawn(task_last_ack(
                                self.tcb.clone(),
                                exit,
                                nt,
                                self.up_packet_sender.clone(),
                                self.config.last_ack_timeout,
                                self.config.last_ack_max_retries,
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
        // Completion may have happened since the initial poll or state snapshot.
        self.shutdown.poll_ready(cx).map(Ok)
    }
}

fn send_fin_n_change_state_to_fin_wait1(hint: &str, nt: NetworkTuple, sender: &PacketSender, tcb: &mut Tcb) -> std::io::Result<()> {
    let state = tcb.get_state();
    if !(tcb.get_inflight_packets_total_len() == 0 && state == TcpState::Established) {
        log::debug!("{nt} {state:?}: {hint} session is not in a valid state to send FIN, skipping...");
        return Ok(());
    }

    log::debug!("{nt} {state:?}: {hint} actively send a farewell packet to the other side...");
    write_packet_to_device(sender, nt, tcb, None, ACK | FIN, None, None)?;
    tcb.increase_seq();
    tcb.change_state(TcpState::FinWait1);
    let state = tcb.get_state();
    log::debug!("{nt} {state:?}: {hint} now in {state:?} state");

    Ok(())
}

/// Sends our FIN after the peer's, which closes the connection in both directions.
fn send_fin_n_change_state_to_last_ack(hint: &str, nt: NetworkTuple, sender: &PacketSender, tcb: &mut Tcb) -> std::io::Result<()> {
    log::debug!("{nt} CloseWait: {hint} the peer has closed, send our FIN");
    write_packet_to_device(sender, nt, tcb, None, ACK | FIN, None, None)?;
    tcb.increase_seq();
    tcb.change_state(TcpState::LastAck);
    Ok(())
}

async fn task_last_ack(
    tcb: TcbPtr,
    exit_notifier: tokio::sync::mpsc::Sender<()>,
    nt: NetworkTuple,
    pkt_sdr: PacketSender,
    last_ack_timeout: Duration,
    last_ack_max_retries: usize,
) {
    let hint = "[task_last_ack]";
    let mut timeout = last_ack_timeout.max(tcb.lock().unwrap().retransmission_timeout());
    let ceiling = MAX_RTO.max(timeout);
    for idx in 1..=last_ack_max_retries {
        let state = { tcb.lock().unwrap().get_state() };
        if !matches!(state, TcpState::LastAck | TcpState::FinWait1 | TcpState::Closing) {
            log::debug!("{nt} {state:?}: {hint} session closed, exiting 1...");
            return;
        }

        tokio::time::sleep(timeout).await;

        {
            let tcb = tcb.lock().unwrap();
            let state = tcb.get_state();
            if !matches!(state, TcpState::LastAck | TcpState::FinWait1 | TcpState::Closing) {
                log::debug!("{nt} {state:?}: {hint} session closed, exiting 2...");
                return;
            }
            log::debug!("{nt} {state:?}: {hint} timer expired, resending ACK|FIN (retry {idx}/{last_ack_max_retries})");
            _ = write_packet_to_device(&pkt_sdr, nt, &tcb, None, ACK | FIN, Some(tcb.get_seq() - 1), None);
        }
        timeout = timeout.saturating_mul(2).min(ceiling);
    }
    // Give the last retransmission its backed-off response interval before giving up.
    tokio::time::sleep(timeout).await;
    {
        let mut tcb = tcb.lock().unwrap();
        if !matches!(tcb.get_state(), TcpState::LastAck | TcpState::FinWait1 | TcpState::Closing) {
            return;
        }
        tcb.change_state(TcpState::Closed);
        let state = tcb.get_state();
        log::warn!("{nt} {state:?}: {hint} max retries reached, forcibly closing session");
    }
    exit_notifier.send(()).await.unwrap_or(());
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        let (nt, state) = (self.network_tuple(), self.tcb.lock().unwrap().get_state());
        log::trace!("{nt} {state:?}: [drop] session dropping, ========================= ");
        if let Some(mut task) = self.task_handle.take()
            && !task.is_finished()
        {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                self.shutdown.detached_close.store(true, Ordering::Release);
                self.arm_notify.notify_one();
                let (_, empty_receiver) = tokio::sync::mpsc::channel(1);
                let mut receiver = std::mem::replace(&mut self.data_rx, empty_receiver);
                let keepalive = self.stream_sender.clone();
                let drain = self.drain_notify.clone();
                let tcb = self.tcb.clone();
                let sender = self.up_packet_sender.clone();
                let deadline = tokio::time::Instant::now() + self.config.timeout;
                runtime.spawn(async move {
                    // Keep the receive path and session alive until the close handshake ends.
                    let _keepalive = keepalive;
                    loop {
                        tokio::select! {
                            _ = &mut task => break,
                            _ = tokio::time::sleep_until(deadline) => {
                                {
                                    let mut tcb = tcb.lock().unwrap();
                                    if tcb.get_state() != TcpState::Closed {
                                        let _ = write_packet_to_device(&sender, nt, &tcb, None, ACK | RST, None, None);
                                        tcb.change_state(TcpState::Closed);
                                    }
                                }
                                task.abort();
                                let _ = task.await;
                                break;
                            }
                            Some(_) = receiver.recv() => drain.notify_one(),
                        }
                    }
                });
            } else {
                let mut tcb = self.tcb.lock().unwrap();
                let _ = write_packet_to_device(&self.up_packet_sender, nt, &tcb, None, ACK | RST, None, None);
                tcb.change_state(TcpState::Closed);
                task.abort();
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
        let (seq, ack) = (tcb.get_seq().0, tcb.get_ack().0);
        let l_info = LocalInfo(seq, ack);
        log::trace!("{network_tuple} {state:?}: {l_info} session begins");
        write_packet_to_device(
            &up_packet_sender,
            network_tuple,
            &tcb,
            config.options.as_ref(),
            ACK | SYN,
            None,
            None,
        )?;
        tcb.increase_seq();
        tcb.change_state(TcpState::SynReceived);
        let state = tcb.get_state();
        log::trace!("{network_tuple} {state:?}: session now in {state:?} state");
    }
    write_notify.wake();

    let tcb_clone = tcb.clone();

    async fn task_timed_out_for_close_wait(
        tcb: TcbPtr,
        exit_notifier: tokio::sync::mpsc::Sender<()>,
        nt: NetworkTuple,
        up_packet_sender: PacketSender,
        close_wait_timeout: Duration,
        last_ack_timeout: Duration,
        last_ack_max_retries: usize,
    ) -> std::io::Result<()> {
        // Check progress and send FIN under the same lock, so a concurrent write cannot
        // slip between the idle decision and the state transition. Outstanding data keeps
        // its existing retransmission/R2 deadline.
        let progress = |tcb: &Tcb| (tcb.get_seq(), tcb.get_last_received_ack());
        let mut last = progress(&tcb.lock().unwrap());
        loop {
            tokio::time::sleep(close_wait_timeout).await;
            let mut tcb = tcb.lock().unwrap();
            if tcb.get_state() != TcpState::CloseWait {
                return Ok(());
            }
            let now = progress(&tcb);
            if now == last && tcb.is_inflight_queue_empty() {
                send_fin_n_change_state_to_last_ack("[close_wait timeout]", nt, &up_packet_sender, &mut tcb)?;
                break;
            }
            last = now;
        }
        let tcb_clone = tcb.clone();

        // Here we set a timer to wait for the last ACK from the other side.
        tokio::spawn(task_last_ack(
            tcb_clone,
            exit_notifier,
            nt,
            up_packet_sender,
            last_ack_timeout,
            last_ack_max_retries,
        ));

        Ok::<(), std::io::Error>(())
    }

    let mut close_deadline: Option<tokio::time::Instant> = None;
    loop {
        let exit_notifier = exit_notifier.clone();
        if shutdown.detached_close.load(Ordering::Acquire) {
            let mut state = tcb.lock().unwrap();
            if state.is_inflight_queue_empty() && matches!(state.get_state(), TcpState::Established | TcpState::CloseWait) {
                if state.get_state() == TcpState::CloseWait {
                    send_fin_n_change_state_to_last_ack("[drop]", network_tuple, &up_packet_sender, &mut state)?;
                } else {
                    send_fin_n_change_state_to_fin_wait1("[drop]", network_tuple, &up_packet_sender, &mut state)?;
                }
                tokio::spawn(task_last_ack(
                    tcb.clone(),
                    exit_notifier.clone(),
                    network_tuple,
                    up_packet_sender.clone(),
                    config.last_ack_timeout,
                    config.last_ack_max_retries,
                ));
            }
        }

        let network_packet = tokio::select! {
            _ = async {
                match close_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                {
                    let mut tcb = tcb.lock().unwrap();
                    if tcb.get_state() == TcpState::FinWait2 {
                        write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | RST, None, None)?;
                    }
                    tcb.change_state(TcpState::Closed);
                }
                read_notify.wake();
                write_notify.wake();
                break;
            }
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
                let (packets, exhausted) = tcb.collect_timed_out_inflight_packets();
                if exhausted {
                    // RFC 9293 §3.8.3: R2 transmissions of the same segment close the connection.
                    log::warn!("{network_tuple} segment reached R2 transmissions, closing session");
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | RST, None, None)?;
                    tcb.change_state(TcpState::Closed);
                    write_notify.wake();
                    read_notify.wake();
                    break;
                }
                for packet in packets {
                    let (seq, count) = (packet.seq, packet.retransmit_count);
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

        if flags.contains(RST) {
            tcb.change_state(TcpState::Closed);
            drop(tcb);
            write_notify.wake();
            read_notify.wake();
            // Finish the task so its destroy notification and shutdown waker are delivered
            // even if the peer never sends another packet.
            break;
        }

        if !flags.contains(ACK) {
            continue;
        }
        tcb.update_duplicate_ack_count(incoming_ack);

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
        // An invalid ACK must not remove bytes that still need retransmission.
        tcb.update_inflight_packet_queue(incoming_ack);

        match state {
            TcpState::SynReceived if flags.contains(ACK) => {
                if len > 0 {
                    receive_segment(
                        &up_packet_sender,
                        &mut tcb,
                        network_tuple,
                        incoming_seq,
                        payload,
                        &data_tx,
                        &read_notify,
                    )?;
                }
                tcb.change_state(TcpState::Established);
                write_notify.wake();
            }
            TcpState::Established => {
                if flags == ACK {
                    match pkt_type {
                        PacketType::WindowUpdate => {
                            write_notify.wake();
                        }
                        PacketType::KeepAlive => {
                            write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                        }
                        PacketType::RetransmissionRequest => {
                            if let Some(packet) = tcb.find_inflight_packet(incoming_ack) {
                                let (s, p) = (packet.seq, packet.payload.clone());
                                log::debug!(
                                    "{network_tuple} {state:?}: {l_info}, {pkt_type:?}, retransmission request, seq = {s}, len = {}",
                                    p.len()
                                );
                                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | PSH, Some(s), Some(p))?;
                            }
                        }
                        PacketType::NewPacket => {
                            let nt = network_tuple;
                            receive_segment(&up_packet_sender, &mut tcb, nt, incoming_seq, payload, &data_tx, &read_notify)?;
                            write_notify.wake();
                        }
                        PacketType::Ack => {
                            write_notify.wake();
                        }
                        PacketType::Invalid => {}
                    }
                } else if flags == (ACK | FIN) || flags == (ACK | FIN | PSH) {
                    // RFC 9293 §3.10.7.4: the text of the segment is processed before its FIN, and the FIN is
                    // taken only once every byte before it has arrived; until then the peer retransmits it.
                    if len > 0 {
                        let nt = network_tuple;
                        receive_segment(&up_packet_sender, &mut tcb, nt, incoming_seq, payload, &data_tx, &read_notify)?;
                        write_notify.wake();
                    }
                    if tcb.get_ack() == incoming_seq + len as u32 {
                        // RFC 9293 §3.6: the peer has closed its direction only. Acknowledge its FIN and
                        // let the reader reach end of stream, but keep sending: our FIN waits for the
                        // application to shut down or drop the stream.
                        tcb.increase_ack();
                        write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                        tcb.change_state(TcpState::CloseWait);
                        read_notify.wake();
                        write_notify.wake();
                        let len = tcb.get_inflight_packets_total_len();
                        log::trace!("{network_tuple} CloseWait: {l_info}, closed by the other side, inflight: {len}");

                        // Spawn a timeout task to force FIN if upstream stays idle without closing
                        let tcb = tcb_clone.clone();
                        let up = up_packet_sender.clone();
                        tokio::spawn(task_timed_out_for_close_wait(
                            tcb,
                            exit_notifier,
                            network_tuple,
                            up,
                            config.close_wait_timeout,
                            config.last_ack_timeout,
                            config.last_ack_max_retries,
                        ));
                    }
                } else if flags == (ACK | PSH) && pkt_type == PacketType::NewPacket {
                    // PSH changes nothing about where a segment belongs: one that arrives out of order
                    // is kept and answered like any other.
                    if !payload.is_empty() {
                        receive_segment(
                            &up_packet_sender,
                            &mut tcb,
                            network_tuple,
                            incoming_seq,
                            payload,
                            &data_tx,
                            &read_notify,
                        )?;
                    }
                    write_notify.wake();
                } else {
                    // unnormal case, we do nothing here
                    log::trace!("{network_tuple} {state:?}: {l_info}, {pkt_type:?}, unnormal case, we do nothing here");
                }
            }
            TcpState::CloseWait => {
                // Our direction is still open: the peer acknowledges what we send, asks for what it
                // lost, and retransmits its FIN, or the segment carrying it, when our ACK was lost.
                match pkt_type {
                    PacketType::KeepAlive | PacketType::NewPacket => {
                        write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                    }
                    PacketType::RetransmissionRequest => {
                        if let Some(packet) = tcb.find_inflight_packet(incoming_ack) {
                            let (s, p) = (packet.seq, packet.payload.clone());
                            log::debug!(
                                "{network_tuple} {state:?}: {l_info}, retransmission request, seq = {s}, len = {}",
                                p.len()
                            );
                            write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | PSH, Some(s), Some(p))?;
                        }
                    }
                    _ => {}
                }
                write_notify.wake();
            }
            TcpState::LastAck if flags.contains(ACK) && incoming_ack == tcb.get_seq() => {
                tcb.change_state(TcpState::Closed);
                tokio::spawn(async move {
                    if let Err(e) = exit_notifier.send(()).await {
                        log::debug!("exit_notifier send failed: {e}");
                    }
                });
                let new_state = tcb.get_state();
                log::trace!("{network_tuple} {state:?}: Received final ACK, transitioned to {new_state:?}");
            }
            TcpState::FinWait1 | TcpState::FinWait2 if flags.contains(ACK) => {
                // Receiving the peer's FIN and acknowledging ours are independent events.
                let fin_acked = incoming_ack == tcb.get_seq();
                if len > 0 {
                    receive_segment(
                        &up_packet_sender,
                        &mut tcb,
                        network_tuple,
                        incoming_seq,
                        payload,
                        &data_tx,
                        &read_notify,
                    )?;
                }
                if flags.contains(FIN) && tcb.get_ack() == incoming_seq + len as u32 {
                    tcb.increase_ack();
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                    if state == TcpState::FinWait2 || fin_acked {
                        tcb.change_state(TcpState::TimeWait);
                        close_deadline = Some(tokio::time::Instant::now() + config.two_msl);
                    } else {
                        tcb.change_state(TcpState::Closing);
                    }
                    read_notify.wake();
                } else if state == TcpState::FinWait1 && fin_acked {
                    tcb.change_state(TcpState::FinWait2);
                    close_deadline = Some(tokio::time::Instant::now() + config.timeout);
                }
                if tcb.get_state() == TcpState::FinWait2 && len > 0 {
                    close_deadline = Some(tokio::time::Instant::now() + config.timeout);
                }
            }
            TcpState::Closing if flags.contains(ACK) => {
                if flags.contains(FIN) {
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                }
                if incoming_ack == tcb.get_seq() {
                    tcb.change_state(TcpState::TimeWait);
                    close_deadline = Some(tokio::time::Instant::now() + config.two_msl);
                }
            }
            TcpState::TimeWait if flags.contains(ACK | FIN) && incoming_seq + len as u32 + 1 == tcb.get_ack() => {
                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                // A retransmitted peer FIN restarts 2 MSL (RFC 9293 section 3.10.7).
                close_deadline = Some(tokio::time::Instant::now() + config.two_msl);
            }
            _ => {}
        } // end of match state

        tcb.update_last_received_ack(incoming_ack);
        tcb.update_send_window(tcp_header);
        // ACKs with or without data can retire the last outstanding bytes. The
        // shutdown waiter may belong to a different task than the writer.
        if flags.contains(ACK) && matches!(tcb.get_state(), TcpState::Established | TcpState::CloseWait) && tcb.is_inflight_queue_empty() {
            shutdown.wake();
        }
    } // end of loop
    Ok::<(), std::io::Error>(())
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

/// Stores a data segment that arrived from the peer and acknowledges it.
///
/// The ACK goes out even when no new data reaches the reader: a segment that arrives out of order,
/// or one already received, is answered with a duplicate ACK at once (RFC 5681 §4.2), which is
/// what lets the peer fast-retransmit the segment in the gap instead of waiting out its timer.
fn receive_segment(
    up_packet_sender: &PacketSender,
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    seq: SeqNum,
    payload: Vec<u8>,
    data_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    read_notify: &AtomicWaker,
) -> std::io::Result<()> {
    tcb.add_unordered_packet(seq, payload);
    if !extract_data_n_write_upstream(up_packet_sender, tcb, network_tuple, data_tx, read_notify)? {
        write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK, None, None)?;
    }
    Ok(())
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

    tcb.acknowledge_unordered_packets();

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
    // Silly-window-syndrome avoidance: advertise a real window only when a full segment fits,
    // otherwise advertise zero so the peer enters persist mode until the reader frees space.
    let recv_window = tcb.get_recv_window();
    // RFC 7323 §2.2: the window field of a segment carrying SYN is not scaled.
    let advertised = if flags.contains(SYN) {
        recv_window
    } else {
        tcb.get_scaled_recv_window()
    };
    let window_size = if recv_window >= tcb.get_mtu() { advertised } else { 0 };
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
    use std::task::Waker;

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

    use tokio::io::AsyncWriteExt;

    const PEER: &str = "10.0.0.2:12345";
    const LOCAL: &str = "10.0.0.1:80";

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
        let (peer, local) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();

        let mut syn = TcpHeader::new(12345, 80, 1000, u16::MAX);
        syn.syn = true;
        let stream = IpStackTcpStream::new(peer, local, syn, up_tx, 1500, destroy, Arc::new(TcpConfig::default())).unwrap();

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

    async fn shutdown_after_ack(same_task: bool, ack_flags: TcpFlags) {
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

    #[tokio::test]
    async fn final_ack_wakes_shutdown_from_the_writing_task() {
        for flags in [ACK, ACK | PSH] {
            shutdown_after_ack(true, flags).await;
        }
    }

    #[tokio::test]
    async fn final_ack_wakes_shutdown_from_a_different_task() {
        for flags in [ACK, ACK | PSH] {
            shutdown_after_ack(false, flags).await;
        }
    }

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

    /// A reset wakes blocked operations and ends the session task without waiting for a timer
    /// or a second packet. Exercise both RST and RST|ACK with no time advancement.
    #[tokio::test(start_paused = true)]
    async fn reset_wakes_pending_read_write_and_shutdown() {
        for flags in [RST, RST | ACK] {
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
    }

    /// Closing on RST must not discard bytes already accepted for the application.
    #[tokio::test(start_paused = true)]
    async fn reset_preserves_queued_data_before_eof() {
        let (mut stream, mut up_rx, local_seq) = established().await;
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
    }

    thread_local! {
        // Thread-local so unrelated tests and TCP workers cannot consume this hook.
        static AFTER_STATE_SNAPSHOT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
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

    /// RFC 5681 §4.2: an out-of-order segment is answered at once with a duplicate ACK, whether or
    /// not it carries PSH, and is kept for when the gap fills.
    #[tokio::test(start_paused = true)]
    async fn out_of_order_segment_is_answered_with_a_duplicate_ack() {
        for flags in [ACK, ACK | PSH] {
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
    }

    /// The ACK numbers of what the stack wrote to the device so far.
    async fn acks_written(up_rx: &mut PacketReceiver) -> Vec<u32> {
        written(up_rx)
            .await
            .iter()
            .map(|p| tcp_header_of(p).acknowledgment_number)
            .collect()
    }

    /// RFC 9293 §3.10.7.4: the text of a segment carrying FIN is processed before its FIN, whether
    /// or not it carries PSH, so the payload reaches the reader and the ACK covers both.
    #[tokio::test(start_paused = true)]
    async fn payload_of_a_fin_segment_reaches_the_reader() {
        for flags in [ACK | FIN, ACK | PSH | FIN] {
            let (mut stream, mut up_rx, local_seq) = established().await;

            stream
                .stream_sender()
                .send(peer_segment(1001, local_seq, flags, u16::MAX, b"tail"))
                .unwrap();
            let acks = acks_written(&mut up_rx).await;
            assert_eq!(
                acks.last(),
                Some(&1006),
                "flags {flags:?}: the ACK does not cover the payload and the FIN"
            );

            let mut buf = [0u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await.unwrap();
            assert_eq!(&buf, b"tail", "flags {flags:?}");
        }
    }

    /// A FIN segment that arrives ahead of a gap has its payload kept, but the FIN is taken only
    /// once every byte before it has arrived; until then the peer retransmits it.
    #[tokio::test(start_paused = true)]
    async fn fin_ahead_of_a_gap_waits_for_the_gap_to_fill() {
        for flags in [ACK | FIN, ACK | PSH | FIN] {
            let (mut stream, mut up_rx, local_seq) = established().await;

            // Bytes 1001..1005 are missing; the FIN segment carrying 1005..1009 arrives first.
            stream
                .stream_sender()
                .send(peer_segment(1005, local_seq, flags, u16::MAX, b"tail"))
                .unwrap();
            assert_eq!(acks_written(&mut up_rx).await, [1001], "flags {flags:?}: no duplicate ACK");
            assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);

            // The gap fills: the ACK covers the kept payload, but not the FIN that arrived out of order.
            stream
                .stream_sender()
                .send(peer_segment(1001, local_seq, ACK | PSH, u16::MAX, b"head"))
                .unwrap();
            assert_eq!(acks_written(&mut up_rx).await.last(), Some(&1009), "flags {flags:?}");
            assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);

            // The peer retransmits the FIN segment, and its FIN is now in sequence.
            stream
                .stream_sender()
                .send(peer_segment(1005, local_seq, flags, u16::MAX, b"tail"))
                .unwrap();
            assert_eq!(acks_written(&mut up_rx).await.last(), Some(&1010), "flags {flags:?}");

            let mut buf = [0u8; 8];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await.unwrap();
            assert_eq!(&buf, b"headtail", "flags {flags:?}");
        }
    }

    /// A FIN segment carrying data is answered like any other data segment, so one that reopens
    /// the peer window wakes the writer it held, even when its FIN is not yet in sequence.
    #[tokio::test(start_paused = true)]
    async fn fin_segment_reopening_the_window_wakes_the_writer() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream.stream_sender().send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
        written(&mut up_rx).await;

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_write(&mut cx, b"reply").is_pending());

        stream
            .stream_sender()
            .send(peer_segment(1005, local_seq, ACK | FIN, u16::MAX, b"tail"))
            .unwrap();
        written(&mut up_rx).await;
        assert!(
            woken.load(std::sync::atomic::Ordering::SeqCst),
            "the FIN segment reopened the window without waking the writer"
        );
    }

    /// The sequence numbers of the segments carrying FIN that the stack wrote to the device so far.
    async fn fins_written(up_rx: &mut PacketReceiver) -> Vec<u32> {
        written(up_rx)
            .await
            .iter()
            .map(tcp_header_of)
            .filter(|h| h.fin)
            .map(|h| h.sequence_number)
            .collect()
    }

    /// Lets the session task and the timers it spawned run until they wait again.
    async fn settle() {
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }

    /// Advances the clock by `by` in steps, letting each timer that falls due run in its turn.
    async fn pass(by: Duration) {
        let step = Duration::from_millis(100);
        let mut left = by;
        while !left.is_zero() {
            let by = step.min(left);
            tokio::time::advance(by).await;
            settle().await;
            left -= by;
        }
    }

    /// Polls `stream` for a read once, giving the bytes it read, none at end of stream.
    fn read_once(stream: &mut IpStackTcpStream, cx: &mut Context<'_>) -> Poll<std::io::Result<Vec<u8>>> {
        let mut storage = [0u8; 64];
        let mut buf = tokio::io::ReadBuf::new(&mut storage);
        Pin::new(stream).poll_read(cx, &mut buf).map_ok(|()| buf.filled().to_vec())
    }

    /// Reads `stream` to its end, which a half-closed connection reaches without waiting on a timer.
    async fn read_to_end_now(stream: &mut IpStackTcpStream) -> Vec<u8> {
        let mut data = Vec::new();
        let read = tokio::io::AsyncReadExt::read_to_end(stream, &mut data);
        tokio::time::timeout(Duration::from_millis(100), read)
            .await
            .expect("no end of stream after the peer's FIN")
            .unwrap();
        data
    }

    /// RFC 9293 §3.6: a FIN closes only the peer's direction. The stack acknowledges it and keeps
    /// sending, and its own FIN waits for the application to shut down, which takes it to LastAck.
    #[tokio::test(start_paused = true)]
    async fn peer_fin_leaves_the_write_side_open() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        let packets = written(&mut up_rx).await;
        assert!(
            packets.iter().all(|p| !tcp_header_of(p).fin),
            "the peer's FIN was answered with ours"
        );
        assert_eq!(packets.last().map(|p| tcp_header_of(p).acknowledgment_number), Some(1002));
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);

        // The reply still flows, and its acknowledgement does not close the connection.
        stream.write_all(b"reply").await.unwrap();
        let sent = up_rx.recv().await.unwrap();
        assert_eq!(sent.payload.as_deref(), Some(&b"reply"[..]));
        stream.stream_sender().send(peer_ack(1002, local_seq + 5)).unwrap();
        assert!(
            fins_written(&mut up_rx).await.is_empty(),
            "the stack closed with the application still open"
        );

        // Shutting down sends our FIN; nothing may be written after it, and reading stays at its end.
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert_eq!(fins_written(&mut up_rx).await, [local_seq + 5]);
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::LastAck);
        let write = Pin::new(&mut stream).poll_write(&mut cx, b"late");
        assert!(matches!(write, Poll::Ready(Err(ref e)) if e.kind() == BrokenPipe), "{write:?}");
        assert!(matches!(read_once(&mut stream, &mut cx), Poll::Ready(Ok(ref d)) if d.is_empty()));

        // The peer acknowledges our FIN, and the shutdown completes.
        stream.stream_sender().send(peer_ack(1002, local_seq + 6)).unwrap();
        written(&mut up_rx).await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        settle().await;
        assert!(woken.load(std::sync::atomic::Ordering::SeqCst), "the shutdown was not woken");
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
    }

    /// After the peer's FIN the reader gets every byte sent before it, then end of stream.
    #[tokio::test(start_paused = true)]
    async fn peer_fin_ends_the_stream_after_its_data() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | PSH, u16::MAX, b"abc"))
            .unwrap();
        stream
            .stream_sender()
            .send(peer_segment(1004, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;

        assert_eq!(read_to_end_now(&mut stream).await, b"abc");
        // End of stream holds on every later read.
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(read_once(&mut stream, &mut cx), Poll::Ready(Ok(ref d)) if d.is_empty()));
    }

    /// A writer held by a closed peer window is woken by the peer's FIN, which can reopen it.
    #[tokio::test(start_paused = true)]
    async fn peer_fin_reopening_the_window_wakes_the_writer() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream.stream_sender().send(peer_segment(1001, local_seq, ACK, 0, &[])).unwrap();
        written(&mut up_rx).await;

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_write(&mut cx, b"reply").is_pending());

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;
        assert!(
            woken.load(std::sync::atomic::Ordering::SeqCst),
            "the peer's FIN did not wake the writer"
        );
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"reply"), Poll::Ready(Ok(5))));
    }

    /// A reader waiting for data is woken by the peer's FIN and gets end of stream.
    #[tokio::test(start_paused = true)]
    async fn peer_fin_wakes_a_waiting_reader() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(read_once(&mut stream, &mut cx).is_pending());

        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;
        assert!(
            woken.load(std::sync::atomic::Ordering::SeqCst),
            "the peer's FIN did not wake the reader"
        );
        assert!(matches!(read_once(&mut stream, &mut cx), Poll::Ready(Ok(ref d)) if d.is_empty()));
    }

    /// Data acknowledged but not yet handed to a reader that fell behind still reaches it, in order,
    /// before end of stream.
    #[tokio::test(start_paused = true)]
    async fn peer_fin_ends_the_stream_after_data_the_reader_fell_behind_on() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        // Three segments, one more than the handoff channel holds, then the FIN.
        for (i, byte) in [1u8, 2, 3].into_iter().enumerate() {
            let seq = 1001 + 4 * i as u32;
            stream
                .stream_sender()
                .send(peer_segment(seq, local_seq, ACK | PSH, u16::MAX, &[byte; 4]))
                .unwrap();
        }
        stream
            .stream_sender()
            .send(peer_segment(1013, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        assert_eq!(acks_written(&mut up_rx).await.last(), Some(&1014));

        assert_eq!(read_to_end_now(&mut stream).await, [[1; 4], [2; 4], [3; 4]].concat());
    }

    /// The peer retransmits its FIN, or the segment carrying it, when our ACK was lost; each copy is
    /// acknowledged again, and none of them closes our direction.
    #[tokio::test(start_paused = true)]
    async fn retransmitted_peer_fin_is_acknowledged_again() {
        let (stream, mut up_rx, local_seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, b"tail"))
            .unwrap();
        assert_eq!(acks_written(&mut up_rx).await.last(), Some(&1006));

        // The whole segment again, then the FIN alone at its own sequence number.
        for (seq, payload) in [(1001, &b"tail"[..]), (1005, &b""[..])] {
            stream
                .stream_sender()
                .send(peer_segment(seq, local_seq, ACK | FIN, u16::MAX, payload))
                .unwrap();
            let packets = written(&mut up_rx).await;
            let acks: Vec<_> = packets.iter().map(|p| tcp_header_of(p).acknowledgment_number).collect();
            assert_eq!(acks, [1006], "seq {seq}: the retransmitted FIN was not acknowledged");
            assert!(packets.iter().all(|p| !tcp_header_of(p).fin), "seq {seq}: answered with our FIN");
        }
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::CloseWait);
    }

    /// After the peer's FIN, duplicate ACKs still ask for a fast retransmission of what we sent.
    #[tokio::test(start_paused = true)]
    async fn duplicate_acks_after_the_peer_fin_retransmit() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;
        stream.write_all(b"reply").await.unwrap();
        written(&mut up_rx).await;

        let mut payloads = Vec::new();
        for _ in 0..MAX_COUNT_FOR_DUP_ACK {
            stream.stream_sender().send(peer_ack(1002, local_seq)).unwrap();
            payloads.extend(
                written(&mut up_rx)
                    .await
                    .into_iter()
                    .filter_map(|p| p.payload.filter(|p| !p.is_empty())),
            );
        }
        assert_eq!(payloads, [b"reply".to_vec()], "the duplicate ACKs got no retransmission");
    }

    /// A shutdown with data still in flight sends our FIN once that data is acknowledged.
    #[tokio::test(start_paused = true)]
    async fn shutdown_after_the_peer_fin_waits_for_data_in_flight() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;
        stream.write_all(b"reply").await.unwrap();
        written(&mut up_rx).await;

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert!(
            fins_written(&mut up_rx).await.is_empty(),
            "our FIN went out ahead of unacknowledged data"
        );

        stream.stream_sender().send(peer_ack(1002, local_seq + 5)).unwrap();
        written(&mut up_rx).await;
        assert!(
            woken.load(std::sync::atomic::Ordering::SeqCst),
            "the acknowledgement did not wake the shutdown"
        );
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert_eq!(fins_written(&mut up_rx).await, [local_seq + 5]);
    }

    /// Our FIN, sent by a shutdown after the peer's, is retransmitted until the peer acknowledges it.
    #[tokio::test(start_paused = true)]
    async fn our_fin_after_the_peer_fin_is_retransmitted() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut up_rx).await;

        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert_eq!(fins_written(&mut up_rx).await.len(), 1);

        tokio::time::advance(TcpConfig::default().last_ack_timeout.max(RTO)).await;
        assert_eq!(fins_written(&mut up_rx).await.len(), 1, "our FIN was not retransmitted");
    }

    /// A stream dropped after the peer's FIN sends ours.
    #[tokio::test(start_paused = true)]
    async fn dropping_the_stream_after_the_peer_fin_sends_ours() {
        let (stream, mut up_rx, local_seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        assert!(fins_written(&mut up_rx).await.is_empty());

        drop(stream);
        assert_eq!(fins_written(&mut up_rx).await, [local_seq]);
    }

    /// An application that never shuts down after the peer's FIN gets our FIN sent for it once
    /// `close_wait_timeout` passes with nothing written and nothing acknowledged.
    #[tokio::test(start_paused = true)]
    async fn idle_close_wait_sends_our_fin_at_the_timeout() {
        let (stream, mut up_rx, local_seq) = established().await;
        let timeout = TcpConfig::default().close_wait_timeout;
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        settle().await;
        written(&mut up_rx).await;

        pass(timeout - Duration::from_millis(1)).await;
        assert!(fins_written(&mut up_rx).await.is_empty());
        pass(Duration::from_millis(1)).await;
        assert_eq!(
            fins_written(&mut up_rx).await,
            [local_seq],
            "no FIN after an idle close_wait_timeout"
        );
    }

    /// A reply still moving after the peer's FIN is not cut by `close_wait_timeout`, which counts only
    /// time without progress.
    #[tokio::test(start_paused = true)]
    async fn close_wait_timeout_does_not_cut_a_reply_in_progress() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        let timeout = TcpConfig::default().close_wait_timeout;
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        settle().await;
        written(&mut up_rx).await;

        // Within every `close_wait_timeout` a byte is written, and then the peer acknowledges one.
        let step = timeout - Duration::from_secs(1);
        for i in 1..=2 {
            pass(step).await;
            stream.write_all(b"x").await.unwrap();
            assert!(
                fins_written(&mut up_rx).await.is_empty(),
                "write {i}: the reply was cut while written"
            );
        }
        for i in 1..=2 {
            pass(step).await;
            stream.stream_sender().send(peer_ack(1002, local_seq + i)).unwrap();
            assert!(
                fins_written(&mut up_rx).await.is_empty(),
                "ack {i}: the reply was cut while acknowledged"
            );
        }

        // Once it stops, our FIN follows within two periods.
        pass(timeout * 2).await;
        assert_eq!(fins_written(&mut up_rx).await.first(), Some(&(local_seq + 2)));
    }

    /// A writer waiting for window when the connection closes under it is woken to see the close.
    #[tokio::test(start_paused = true)]
    async fn writer_waiting_for_window_is_woken_when_the_connection_ends() {
        let (mut stream, mut up_rx, local_seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, local_seq, ACK | FIN, 0, &[]))
            .unwrap();
        settle().await;
        written(&mut up_rx).await;

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_write(&mut cx, b"reply").is_pending());

        // The backstop sends our FIN, which is never acknowledged, and the connection ends.
        let config = TcpConfig::default();
        pass(config.close_wait_timeout + RTO * 15).await;
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed);
        assert!(woken.load(std::sync::atomic::Ordering::SeqCst), "the writer was left waiting");
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"reply"), Poll::Ready(Err(_))));
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

    /// The intervals RFC 6298 §5.5 produces from a one-second timeout doubling to the §2.5 ceiling.
    const BACKOFF: [u64; MAX_RETRANSMIT_COUNT] = [1, 2, 4, 8, 16, 32, 60];

    /// Advances the clock by `by` and returns what the stack wrote to the device.
    async fn advance(by: Duration, up_rx: &mut PacketReceiver) -> Option<NetworkPacket> {
        tokio::time::advance(by).await;
        tokio::task::yield_now().await;
        up_rx.try_recv().ok()
    }

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

        // first extract fills the single channel slot and advances ack over the first chunk
        extract_data_n_write_upstream(&up_tx, &mut tcb, nt, &data_tx, &read_notify).unwrap();
        assert_eq!(tcb.get_ack(), SeqNum(2000));

        // channel is full: extract advances ack over the tail and holds it for the reader
        tcb.add_unordered_packet(SeqNum(2000), vec![3; 500]);
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

    /// Opens a connection with a SYN advertising `window` and `syn_options`, returning the stream
    /// and the SYN-ACK the stack emitted.
    async fn open(window: u16, syn_options: &[TcpOptionElement]) -> (IpStackTcpStream, TcpHeader, PacketReceiver) {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let (src, dst) = (SocketAddr::from(([10, 0, 0, 2], 40000)), SocketAddr::from(([10, 0, 0, 1], 80)));

        let mut syn = TcpHeader::new(src.port(), dst.port(), 1000, window);
        syn.syn = true;
        syn.set_options(syn_options).unwrap();

        let stream = IpStackTcpStream::new(src, dst, syn, up_tx, 1500, None, Arc::new(TcpConfig::default())).unwrap();
        let packet = up_rx.recv().await.expect("the stack emitted no SYN-ACK");
        let TransportHeader::Tcp(syn_ack) = packet.transport_header() else {
            panic!("the emitted SYN-ACK is not a TCP packet");
        };
        (stream, syn_ack.clone(), up_rx)
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

    /// A peer offering a shift of 7 gets this stack's shift of 0 back and has its windows honoured
    /// shifted by 7.
    #[tokio::test]
    async fn syn_with_window_scale_is_answered_and_honoured() {
        let (stream, syn_ack, mut up_rx) = open(4000, &[TcpOptionElement::WindowScale(7)]).await;
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

        assert_eq!(stream.tcb.lock().unwrap().get_send_window(), 40_000 << 7);
    }

    /// A peer offering a shift above the RFC 7323 §2.3 maximum has its windows honoured shifted by 14.
    #[tokio::test]
    async fn syn_with_a_malformed_window_scale_is_clamped() {
        let (stream, syn_ack, mut up_rx) = open(4000, &[TcpOptionElement::WindowScale(20)]).await;

        let peer_seq = SeqNum(syn_ack.acknowledgment_number);
        feed(&stream, &syn_ack, peer_seq, 40_000, &[1; 4]);
        feed(&stream, &syn_ack, peer_seq + 4, 40_000, &[2; 4]);
        up_rx.recv().await.unwrap();
        up_rx.recv().await.unwrap();

        let tcb = stream.tcb.lock().unwrap();
        assert_eq!(tcb.get_state(), TcpState::Established);
        assert_eq!(tcb.get_send_window(), 40_000 << 14);
    }

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

    /// Data written before the task that answers the SYN has run must not leave ahead of the
    /// SYN-ACK.
    #[tokio::test]
    async fn write_before_the_syn_ack_waits_for_it() {
        let (peer, local) = (PEER.parse().unwrap(), LOCAL.parse().unwrap());
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let mut syn = TcpHeader::new(12345, 80, 1000, u16::MAX);
        syn.syn = true;
        let mut stream = IpStackTcpStream::new(peer, local, syn, up_tx, 1500, None, Arc::new(TcpConfig::default())).unwrap();

        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            Pin::new(&mut stream).poll_write(&mut cx, b"early").is_pending(),
            "a write was accepted before the SYN-ACK went out"
        );
        let packets = written(&mut up_rx).await;
        assert!(
            woken.load(std::sync::atomic::Ordering::SeqCst),
            "the SYN-ACK did not wake the writer"
        );
        assert!(
            matches!(packets.as_slice(), [packet] if tcp_header_of(packet).syn),
            "the SYN-ACK is not the first packet"
        );
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"early"), Poll::Ready(Ok(5))));
        let packets = written(&mut up_rx).await;
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].payload.as_deref(), Some(&b"early"[..]));
    }

    fn review_state(stream: &IpStackTcpStream) -> TcpState {
        stream.tcb.lock().unwrap().get_state()
    }
    #[tokio::test(start_paused = true)]
    async fn review_last_ack_must_cover_fin() {
        let (mut stream, mut rx, seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut rx).await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        written(&mut rx).await;
        stream.stream_sender().send(peer_ack(1002, seq)).unwrap();
        written(&mut rx).await;
        assert_eq!(review_state(&stream), TcpState::LastAck);
        stream.stream_sender().send(peer_ack(1002, seq.wrapping_add(1))).unwrap();
        written(&mut rx).await;
        assert_eq!(review_state(&stream), TcpState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn review_fin_retransmission_keeps_sequence() {
        let (mut stream, mut rx, seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        let mut packets = written(&mut rx).await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        packets.extend(written(&mut rx).await);
        let original = packets.iter().map(tcp_header_of).find(|h| h.fin).unwrap().sequence_number;
        tokio::time::advance(TcpConfig::default().last_ack_timeout.max(RTO)).await;
        let retry = written(&mut rx).await;
        assert_eq!(retry.iter().map(tcp_header_of).find(|h| h.fin).unwrap().sequence_number, original);
    }

    #[tokio::test(start_paused = true)]
    async fn review_fin_wait_requires_fin_ack() {
        let (mut stream, mut rx, seq) = established().await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        written(&mut rx).await;
        stream.stream_sender().send(peer_ack(1001, seq)).unwrap();
        written(&mut rx).await;
        assert_eq!(review_state(&stream), TcpState::FinWait1);
    }

    #[tokio::test(start_paused = true)]
    async fn review_fin_wait_preserves_fin_with_data() {
        let (mut stream, mut rx, seq) = established().await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        written(&mut rx).await;
        stream
            .stream_sender()
            .send(peer_segment(1001, seq.wrapping_add(1), ACK | FIN | PSH, u16::MAX, b"tail"))
            .unwrap();
        written(&mut rx).await;
        let (ack, state) = {
            let tcb = stream.tcb.lock().unwrap();
            (tcb.get_ack(), tcb.get_state())
        };
        assert_eq!(ack, SeqNum(1006));
        assert_eq!(state, TcpState::TimeWait);
    }

    #[tokio::test(start_paused = true)]
    async fn review_crossed_fin_waits_for_ack() {
        let (mut stream, mut rx, seq) = established().await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        written(&mut rx).await;
        stream
            .stream_sender()
            .send(peer_segment(1001, seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut rx).await;
        assert_ne!(review_state(&stream), TcpState::TimeWait);
        stream.stream_sender().send(peer_ack(1002, seq.wrapping_add(1))).unwrap();
        written(&mut rx).await;
        assert_eq!(review_state(&stream), TcpState::TimeWait);
    }

    #[tokio::test(start_paused = true)]
    async fn review_fin_ack_wakes_independent_shutdown() {
        let (mut stream, mut rx, seq) = established().await;
        stream.write_all(b"hello").await.unwrap();
        written(&mut rx).await;
        let (woken, waker) = recording_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        stream
            .stream_sender()
            .send(peer_segment(1001, seq.wrapping_add(5), ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut rx).await;
        assert!(woken.load(std::sync::atomic::Ordering::SeqCst));
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        let packets = written(&mut rx).await;
        assert_eq!(packets.iter().map(tcp_header_of).filter(|h| h.fin).count(), 1);
        assert_eq!(review_state(&stream), TcpState::LastAck);
    }
    #[tokio::test(start_paused = true)]
    async fn review_active_fin_retransmits_until_acknowledged() {
        let (mut stream, mut rx, seq) = established().await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        written(&mut rx).await;
        tokio::time::advance(TcpConfig::default().last_ack_timeout.max(RTO)).await;
        let packets = written(&mut rx).await;
        let fins: Vec<_> = packets
            .iter()
            .map(tcp_header_of)
            .filter(|h| h.fin)
            .map(|h| h.sequence_number)
            .collect();
        assert_eq!(fins, [seq]);
        stream.stream_sender().send(peer_ack(1001, seq.wrapping_add(1))).unwrap();
        written(&mut rx).await;
        tokio::time::advance(TcpConfig::default().last_ack_timeout.max(RTO)).await;
        let packets = written(&mut rx).await;
        assert!(!packets.iter().map(tcp_header_of).any(|h| h.fin));
        assert_eq!(review_state(&stream), TcpState::FinWait2);
    }

    #[tokio::test(start_paused = true)]
    async fn review_write_after_active_fin_is_rejected() {
        let (mut stream, mut rx, _) = established().await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        written(&mut rx).await;
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"late"),
            Poll::Ready(Err(e)) if e.kind() == BrokenPipe));
        assert!(written(&mut rx).await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn deeper_fin_sequence_wraps_and_ack_zero_closes() {
        for passive in [false, true] {
            let (mut stream, mut rx, _) = established().await;
            stream.tcb.lock().unwrap().set_test_send_sequence(SeqNum(u32::MAX));
            if passive {
                stream
                    .stream_sender()
                    .send(peer_segment(1001, u32::MAX, ACK | FIN, u16::MAX, &[]))
                    .unwrap();
                written(&mut rx).await;
            }
            let mut cx = Context::from_waker(Waker::noop());
            let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
            assert_eq!(fins_written(&mut rx).await, [u32::MAX]);
            tokio::time::advance(TcpConfig::default().last_ack_timeout.max(RTO)).await;
            assert_eq!(fins_written(&mut rx).await, [u32::MAX]);
            stream.stream_sender().send(peer_ack(if passive { 1002 } else { 1001 }, 0)).unwrap();
            written(&mut rx).await;
            assert_eq!(review_state(&stream), if passive { TcpState::Closed } else { TcpState::FinWait2 });
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deeper_last_fin_retry_has_time_for_ack() {
        let (mut stream, mut rx, seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut rx).await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        written(&mut rx).await;
        let config = TcpConfig::default();
        for retry in 0..config.last_ack_max_retries {
            pass(config.last_ack_timeout.max(RTO) * (1 << retry)).await;
            assert_eq!(fins_written(&mut rx).await, [seq]);
        }
        assert_eq!(review_state(&stream), TcpState::LastAck, "last retry must get a response interval");
        stream.stream_sender().send(peer_ack(1002, seq.wrapping_add(1))).unwrap();
        written(&mut rx).await;
        assert_eq!(review_state(&stream), TcpState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn deeper_close_wait_does_not_cut_unacknowledged_reply() {
        let (mut stream, mut rx, seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut rx).await;
        stream.write_all(b"reply").await.unwrap();
        written(&mut rx).await;
        pass(TcpConfig::default().close_wait_timeout * 2).await;
        assert_eq!(review_state(&stream), TcpState::CloseWait);
        assert!(fins_written(&mut rx).await.is_empty(), "FIN must wait for data ACK or R2 failure");
        stream.stream_sender().send(peer_ack(1002, seq + 5)).unwrap();
        written(&mut rx).await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        assert_eq!(fins_written(&mut rx).await, [seq + 5]);
    }

    #[tokio::test(start_paused = true)]
    async fn deeper_invalid_future_ack_does_not_discard_inflight_data() {
        let (mut stream, mut rx, seq) = established().await;
        stream.write_all(b"reply").await.unwrap();
        written(&mut rx).await;
        stream.stream_sender().send(peer_ack(1001, seq + 6)).unwrap();
        written(&mut rx).await;
        let outstanding = stream.tcb.lock().unwrap().get_inflight_packets_total_len();
        assert_eq!(outstanding, 5);
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        assert!(fins_written(&mut rx).await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn deeper_drop_retransmits_fin() {
        let (stream, mut rx, seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut rx).await;
        drop(stream);
        assert_eq!(fins_written(&mut rx).await, [seq]);
        pass(TcpConfig::default().last_ack_timeout.max(RTO)).await;
        assert_eq!(fins_written(&mut rx).await, [seq]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn deeper_concurrent_shutdown_and_peer_fin() {
        for iteration in 0..256 {
            let (mut stream, mut rx, seq) = established().await;
            stream.write_all(b"hello").await.unwrap();
            let sent = rx.recv().await.unwrap();
            assert_eq!(sent.payload.as_deref(), Some(&b"hello"[..]));
            let sender = stream.stream_sender();
            let barrier = Arc::new(tokio::sync::Barrier::new(2));
            let peer_barrier = barrier.clone();
            let peer = tokio::spawn(async move {
                peer_barrier.wait().await;
                if iteration % 2 == 0 {
                    tokio::task::yield_now().await;
                }
                sender
                    .send(peer_segment(1001, seq + 5, ACK | FIN | PSH, u16::MAX, b"tail"))
                    .unwrap();
                let fin = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let packet = rx.recv().await.expect("stream closed before FIN");
                        if tcp_header_of(&packet).fin {
                            break packet;
                        }
                    }
                })
                .await
                .expect("shutdown lost wakeup");
                assert_eq!(tcp_header_of(&fin).sequence_number, seq + 5);
                assert_eq!(tcp_header_of(&fin).acknowledgment_number, 1006);
                sender.send(peer_ack(1006, seq + 6)).unwrap();
            });
            barrier.wait().await;
            if iteration % 2 != 0 {
                tokio::task::yield_now().await;
            }
            tokio::time::timeout(Duration::from_secs(2), stream.shutdown())
                .await
                .expect("shutdown hung")
                .unwrap();
            peer.await.unwrap();
            assert_eq!(read_to_end_now(&mut stream).await, b"tail");
        }
    }
    #[tokio::test(start_paused = true)]
    async fn deeper_segment_without_ack_cannot_retire_data() {
        let (mut stream, mut rx, seq) = established().await;
        stream.write_all(b"reply").await.unwrap();
        written(&mut rx).await;
        stream
            .stream_sender()
            .send(peer_segment(1001, seq + 5, PSH, u16::MAX, b"ignored"))
            .unwrap();
        written(&mut rx).await;
        let outstanding = stream.tcb.lock().unwrap().get_inflight_packets_total_len();
        assert_eq!(outstanding, 5);
    }

    #[tokio::test(start_paused = true)]
    async fn deeper_close_wait_unacknowledged_data_still_reaches_r2() {
        let (mut stream, mut rx, seq) = established().await;
        stream
            .stream_sender()
            .send(peer_segment(1001, seq, ACK | FIN, u16::MAX, &[]))
            .unwrap();
        written(&mut rx).await;
        stream.write_all(b"reply").await.unwrap();
        written(&mut rx).await;
        pass(Duration::from_secs(BACKOFF.iter().take(MAX_RETRANSMIT_COUNT).sum())).await;
        let packets = written(&mut rx).await;
        assert!(packets.iter().map(tcp_header_of).any(|h| h.rst));
        assert!(!packets.iter().map(tcp_header_of).any(|h| h.fin));
        assert_eq!(review_state(&stream), TcpState::Closed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deeper_peer_fin_between_shutdown_snapshot_and_send() {
        let (mut stream, mut rx, seq) = established().await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let runtime = tokio::runtime::Handle::current();
        AFTER_STATE_SNAPSHOT.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::thread::spawn(move || {
                    sender.send(peer_segment(1001, seq, ACK | FIN, u16::MAX, &[])).unwrap();
                    runtime.block_on(async {
                        tokio::time::timeout(Duration::from_secs(1), async {
                            loop {
                                if tcb.lock().unwrap().get_state() == TcpState::CloseWait {
                                    break;
                                }
                                tokio::task::yield_now().await;
                            }
                        })
                        .await
                        .expect("peer FIN was not processed");
                    });
                })
                .join()
                .unwrap();
            }));
        });
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert_eq!(review_state(&stream), TcpState::LastAck);
        let packets = written(&mut rx).await;
        let fins: Vec<_> = packets.iter().map(tcp_header_of).filter(|h| h.fin).collect();
        assert_eq!(fins.len(), 1);
        assert_eq!(fins[0].sequence_number, seq);
        assert_eq!(fins[0].acknowledgment_number, 1002);
    }
    #[tokio::test(start_paused = true)]
    async fn deeper_retransmitted_peer_fin_restarts_time_wait() {
        let (mut stream, mut rx, seq) = established().await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        written(&mut rx).await;
        let peer_fin = || peer_segment(1001, seq + 1, ACK | FIN, u16::MAX, &[]);
        stream.stream_sender().send(peer_fin()).unwrap();
        written(&mut rx).await;
        assert_eq!(review_state(&stream), TcpState::TimeWait);
        let delay = TcpConfig::default().two_msl;
        pass(delay / 2).await;
        stream.stream_sender().send(peer_fin()).unwrap();
        let acks = written(&mut rx).await;
        assert!(acks.iter().map(tcp_header_of).any(|h| h.ack && h.acknowledgment_number == 1002));
        pass(delay / 2 + Duration::from_millis(1)).await;
        assert_eq!(review_state(&stream), TcpState::TimeWait, "old deadline survived duplicate FIN");
        pass(delay / 2).await;
        assert_eq!(review_state(&stream), TcpState::Closed);
    }
    #[tokio::test(start_paused = true)]
    async fn complete_drop_waits_for_data_and_fin_ack_before_destroy() {
        let (destroy_tx, mut destroyed) = tokio::sync::oneshot::channel();
        let (mut stream, mut rx, seq) = established_with_destroy(Some(destroy_tx)).await;
        let sender = stream.stream_sender();
        sender.send(peer_segment(1001, seq, ACK | FIN, u16::MAX, &[])).unwrap();
        written(&mut rx).await;
        stream.write_all(b"reply").await.unwrap();
        written(&mut rx).await;
        drop(stream);
        assert!(fins_written(&mut rx).await.is_empty());
        assert!(destroyed.try_recv().is_err());
        pass(RTO).await;
        let retry = written(&mut rx).await;
        assert!(retry.iter().any(|p| p.payload.as_deref() == Some(&b"reply"[..])));
        sender.send(peer_ack(1002, seq + 5)).unwrap();
        settle().await;
        assert_eq!(fins_written(&mut rx).await, [seq + 5]);
        assert!(destroyed.try_recv().is_err());
        sender.send(peer_ack(1002, seq + 6)).unwrap();
        settle().await;
        assert_eq!(destroyed.try_recv(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn complete_drop_deadline_aborts_and_removes_session() {
        let (destroy_tx, mut destroyed) = tokio::sync::oneshot::channel();
        let (mut stream, mut rx, _) = established_with_destroy(Some(destroy_tx)).await;
        Arc::make_mut(&mut stream.config).timeout = Duration::from_millis(100);
        let tcb = stream.tcb.clone();
        drop(stream);
        settle().await;
        pass(Duration::from_millis(100)).await;
        let packets = written(&mut rx).await;
        assert!(packets.iter().map(tcp_header_of).any(|h| h.rst));
        let state = tcb.lock().unwrap().get_state();
        assert_eq!(state, TcpState::Closed);
        assert_eq!(destroyed.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Closed));
    }

    #[tokio::test(start_paused = true)]
    async fn complete_fin_retry_uses_data_rto_and_exponential_backoff() {
        let (mut stream, mut rx, _) = established().await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        written(&mut rx).await;
        for seconds in [1, 2, 4] {
            pass(Duration::from_secs(seconds) - Duration::from_millis(1)).await;
            assert!(fins_written(&mut rx).await.is_empty());
            pass(Duration::from_millis(1)).await;
            assert_eq!(fins_written(&mut rx).await.len(), 1);
        }
        pass(Duration::from_secs(8) - Duration::from_millis(1)).await;
        assert_eq!(review_state(&stream), TcpState::FinWait1);
        pass(Duration::from_millis(1)).await;
        assert_eq!(review_state(&stream), TcpState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn complete_idle_fin_wait2_expires() {
        let (mut stream, mut rx, seq) = established().await;
        let mut cx = Context::from_waker(Waker::noop());
        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);
        written(&mut rx).await;
        stream.stream_sender().send(peer_ack(1001, seq + 1)).unwrap();
        settle().await;
        assert_eq!(review_state(&stream), TcpState::FinWait2);
        pass(TcpConfig::default().timeout).await;
        assert_eq!(review_state(&stream), TcpState::Closed);
        assert!(written(&mut rx).await.iter().map(tcp_header_of).any(|h| h.rst));
    }
}
