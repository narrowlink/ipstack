use super::seqnum::SeqNum;
use etherparse::TcpHeader;
use std::{collections::BTreeMap, time::Duration};

pub(super) const MAX_UNACK: u32 = 1024 * 16; // 16KB
pub(super) const READ_BUFFER_SIZE: usize = 1024 * 16; // 16KB
pub(super) const READ_CHUNK: usize = 8192; // 8KB, bytes drained from the reassembly buffer per handoff
pub(super) const MAX_COUNT_FOR_DUP_ACK: usize = 3; // Maximum number of duplicate ACKs before retransmission

/// Retransmission timeout, and the floor RFC 6298 §2.4 rounds a configured one up to
pub(super) const RTO: std::time::Duration = std::time::Duration::from_secs(1);

/// Ceiling on the backed-off retransmission timeout; RFC 6298 §2.5 permits one of at least 60 seconds
const MAX_RTO: std::time::Duration = std::time::Duration::from_secs(60);

/// R2, the transmission count at which the connection closes. Seven reaches 123 seconds against
/// RFC 9293 §3.8.3's SHLD-11 of at least 100.
pub(super) const MAX_RETRANSMIT_COUNT: usize = 7;

/// Maximum window scale shift count, which RFC 7323 §2.3 limits to 14 for a maximum window of 1 GiB
const MAX_WINDOW_SHIFT: u8 = 14;

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum TcpState {
    // Init, /* Since we always act as a server, it starts from `Listen`, so we don't use states Init & SynSent. */
    // SynSent,
    Listen,
    SynReceived,
    Established,
    FinWait1, // act as a client, actively send a farewell packet to the other side, followed with FinWait2, TimeWait, Closed
    FinWait2,
    TimeWait,
    CloseWait, // act as a server, followed with LastAck, Closed
    LastAck,
    Closed,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(super) enum PacketType {
    WindowUpdate,
    Invalid,
    RetransmissionRequest,
    NewPacket,
    Ack,
    KeepAlive,
}

/// TCP Control Block
/// - `inflight_packets` is prerepresented bytes stream from upstream application,
///   which have been sent to the lower device but not yet acknowledged.
/// - `unordered_packets` is the bytes stream received from the lower device,
///   which can be acknowledged and extracted by `consume_unordered_packets` method
///   then can be read by upstream application via `Tcp::poll_read` method.
/// - `send_window_shift` is the peer's window scale, applied to every window the peer advertises,
///   and `recv_window_shift` is this stack's own, applied to every window this stack advertises.
///   Both are settled by the SYN exchange, and `recv_window_shift` is `None` when the peer's SYN
///   carried no window scale option, which leaves both directions unscaled.
#[derive(Debug, Clone)]
pub(crate) struct Tcb {
    seq: SeqNum,
    ack: SeqNum,
    mtu: u16,
    last_received_ack: SeqNum,
    send_window: u32,
    send_window_shift: u8,
    recv_window_shift: Option<u8>,
    state: TcpState,
    inflight_packets: BTreeMap<SeqNum, InflightPacket>,
    unordered_packets: BTreeMap<SeqNum, Vec<u8>>,
    duplicate_ack_count: usize,
    duplicate_ack_count_helper: SeqNum,
    max_unacked_bytes: u32,
    read_buffer_size: usize,
    max_count_for_dup_ack: usize,
    /// Configured retransmission timeout, the value `current_rto` collapses back to.
    rto: std::time::Duration,
    /// Retransmission timeout in force, doubled on every expiry per RFC 6298 §5.5 up to `MAX_RTO` or `rto`, whichever is larger.
    /// RFC 6298 §2's round-trip estimator is absent, so this starts at the configured timeout and
    /// returns to it rather than being recomputed from a measurement.
    current_rto: std::time::Duration,
    max_retransmit_count: usize,
}

impl Tcb {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        ack: SeqNum,
        peer_window: u16,
        peer_window_shift: Option<u8>,
        mtu: u16,
        max_unacked_bytes: u32,
        read_buffer_size: usize,
        max_count_for_dup_ack: usize,
        rto: std::time::Duration,
        max_retransmit_count: usize,
    ) -> Tcb {
        let rto = rto.max(RTO);
        #[cfg(debug_assertions)]
        let seq = 100;
        #[cfg(not(debug_assertions))]
        let seq = rand::RngExt::random::<u32>(&mut rand::rng());
        let send_window_shift = peer_window_shift.map_or(0, |shift| {
            if shift > MAX_WINDOW_SHIFT {
                log::warn!("Peer window scale shift count {shift} is too large, limiting it to {MAX_WINDOW_SHIFT}");
                MAX_WINDOW_SHIFT
            } else {
                shift
            }
        });
        // The stack scales its own receive window by the smallest shift that expresses the whole
        // read buffer in the 16-bit window field.
        let recv_window_shift = peer_window_shift.map(|_| {
            (0..=MAX_WINDOW_SHIFT)
                .find(|&shift| read_buffer_size >> shift <= u16::MAX as usize)
                .unwrap_or_else(|| {
                    log::warn!("Read buffer size {read_buffer_size} is too large to scale, limiting the shift count to {MAX_WINDOW_SHIFT}");
                    MAX_WINDOW_SHIFT
                })
        });
        Tcb {
            seq: seq.into(),
            ack,
            mtu,
            last_received_ack: seq.into(),
            send_window: peer_window as u32,
            send_window_shift,
            recv_window_shift,
            state: TcpState::Listen,
            inflight_packets: BTreeMap::new(),
            unordered_packets: BTreeMap::new(),
            duplicate_ack_count: 0,
            duplicate_ack_count_helper: seq.into(),
            max_unacked_bytes,
            read_buffer_size,
            max_count_for_dup_ack,
            rto,
            current_rto: rto,
            max_retransmit_count,
        }
    }

    pub fn calculate_payload_max_len(&self, ip_header_size: usize, tcp_header_size: usize) -> usize {
        let send_window = self.get_send_window() as usize;
        let mtu = self.get_mtu() as usize;
        std::cmp::min(send_window, mtu.saturating_sub(ip_header_size + tcp_header_size))
    }

    pub fn update_duplicate_ack_count(&mut self, rcvd_ack: SeqNum) {
        // If the received rcvd_ack is the same as duplicate_ack_count_helper and not all data has been acknowledged (rcvd_ack < self.seq), increment the count.
        if rcvd_ack == self.duplicate_ack_count_helper && rcvd_ack < self.seq {
            self.duplicate_ack_count = self.duplicate_ack_count.saturating_add(1);
        } else {
            self.duplicate_ack_count_helper = rcvd_ack;
            self.duplicate_ack_count = 0; // reset duplicate ACK count
        }
    }

    pub fn is_duplicate_ack_count_exceeded(&self) -> bool {
        self.duplicate_ack_count >= self.max_count_for_dup_ack
    }

    pub(super) fn add_unordered_packet(&mut self, seq: SeqNum, buf: Vec<u8>) {
        if seq < self.ack {
            #[rustfmt::skip]
            log::warn!("{:?}: Received packet seq {seq} < self ack {}, len = {}", self.state, self.ack, buf.len());
            return;
        }
        // The head-of-line segment always advances the stream, so it is admitted even at the limit;
        // any other segment beyond the receive window is dropped for the peer's RTO to resend.
        if seq != self.ack && self.get_unordered_packets_total_len() >= self.read_buffer_size {
            #[rustfmt::skip]
            log::warn!("{:?}: Receive window full, dropping packet seq {seq}, len = {}", self.state, buf.len());
            return;
        }
        self.unordered_packets.insert(seq, buf);
    }
    pub(super) fn get_available_read_buffer_size(&self) -> usize {
        self.read_buffer_size.saturating_sub(self.get_unordered_packets_total_len())
    }
    #[inline]
    pub(crate) fn get_unordered_packets_total_len(&self) -> usize {
        self.unordered_packets.values().map(|p| p.len()).sum()
    }

    pub(super) fn consume_unordered_packets(&mut self, max_bytes: usize) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        let mut remaining_bytes = max_bytes;

        while remaining_bytes > 0 {
            if let Some(seq) = self.unordered_packets.keys().next().copied() {
                if seq > self.ack {
                    break; // sequence number is not continuous, stop extracting
                }

                if seq < self.ack {
                    // A retransmission re-segmented across `ack` left a stale head entry; trim the
                    // part already delivered so consumption can continue from `ack`.
                    let payload = self.unordered_packets.remove(&seq).unwrap();
                    let consumed = self.ack.distance(seq) as usize;
                    if consumed < payload.len() {
                        self.unordered_packets.insert(self.ack, payload[consumed..].to_vec());
                    }
                    continue;
                }

                // remove and get the first packet
                let mut payload = self.unordered_packets.remove(&seq).unwrap();
                let payload_len = payload.len();

                if payload_len <= remaining_bytes {
                    // current packet can be fully extracted
                    data.extend(payload);
                    self.ack += payload_len as u32;
                    remaining_bytes -= payload_len;
                } else {
                    // current packet can only be partially extracted
                    let remaining_payload = payload.split_off(remaining_bytes);
                    data.extend_from_slice(&payload);
                    self.ack += remaining_bytes as u32;
                    self.unordered_packets.insert(self.ack, remaining_payload);
                    break;
                }
            } else {
                break; // no more packets to extract
            }
        }

        if data.is_empty() { None } else { Some(data) }
    }

    pub(super) fn increase_seq(&mut self) {
        self.seq += 1;
    }
    pub(super) fn get_seq(&self) -> SeqNum {
        self.seq
    }
    pub(super) fn increase_ack(&mut self) {
        self.ack += 1;
    }
    pub(super) fn get_ack(&self) -> SeqNum {
        self.ack
    }
    pub(super) fn get_mtu(&self) -> u16 {
        self.mtu
    }
    pub(super) fn get_last_received_ack(&self) -> SeqNum {
        self.last_received_ack
    }
    pub(super) fn change_state(&mut self, state: TcpState) {
        self.state = state;
    }
    pub(super) fn get_state(&self) -> TcpState {
        self.state
    }
    fn honoured_window(&self, tcp_header: &TcpHeader) -> u32 {
        // RFC 7323 §2.3: SND.WND = SEG.WND << Snd.Wind.Shift, except on a segment carrying SYN,
        // whose window field is never scaled.
        let window = tcp_header.window_size as u32;
        if tcp_header.syn { window } else { window << self.send_window_shift }
    }
    pub(super) fn update_send_window(&mut self, tcp_header: &TcpHeader) {
        self.send_window = self.honoured_window(tcp_header);
    }
    pub(super) fn get_send_window(&self) -> u32 {
        self.send_window
    }
    pub(super) fn get_recv_window(&self) -> u16 {
        self.get_available_read_buffer_size().try_into().unwrap_or(u16::MAX)
    }
    pub(super) fn get_scaled_recv_window(&self) -> u16 {
        // RFC 7323 §2.3: SEG.WND = RCV.WND >> Rcv.Wind.Shift
        let window = self.get_available_read_buffer_size() >> self.recv_window_shift.unwrap_or(0);
        window.try_into().unwrap_or(u16::MAX)
    }
    pub(super) fn get_recv_window_shift(&self) -> Option<u8> {
        self.recv_window_shift
    }
    // #[inline(always)]
    // pub(super) fn buffer_size(&self, payload_len: u16) -> u16 {
    //     match MAX_UNACK - self.inflight_packets.len() as u32 {
    //         // b if b.saturating_sub(payload_len as u32 + 64) != 0 => payload_len,
    //         // b if b < 128 && b >= 4 => (b / 2) as u16,
    //         // b if b < 4 => b as u16,
    //         // b => (b - 64) as u16,
    //         b if b >= payload_len as u32 * 2 && b > 0 => payload_len,
    //         b if b < 4 => b as u16,
    //         b => (b / 2) as u16,
    //     }
    // }

    pub(super) fn check_pkt_type(&self, tcp_header: &TcpHeader, payload: &[u8]) -> PacketType {
        let rcvd_ack = SeqNum(tcp_header.acknowledgment_number);
        let rcvd_seq = SeqNum(tcp_header.sequence_number);
        let rcvd_window = self.honoured_window(tcp_header);
        let len = payload.len();
        let res = if rcvd_ack > self.seq {
            PacketType::Invalid
        } else {
            match rcvd_ack.cmp(&self.get_last_received_ack()) {
                std::cmp::Ordering::Less => PacketType::Invalid,
                std::cmp::Ordering::Equal => {
                    if self.ack - 1 == rcvd_seq && payload.len() <= 1 {
                        PacketType::KeepAlive
                    } else if !payload.is_empty() {
                        PacketType::NewPacket
                    } else if self.get_send_window() == rcvd_window && self.seq != rcvd_ack && self.is_duplicate_ack_count_exceeded() {
                        PacketType::RetransmissionRequest
                    } else {
                        PacketType::WindowUpdate
                    }
                }
                std::cmp::Ordering::Greater => {
                    if payload.is_empty() {
                        PacketType::Ack
                    } else {
                        PacketType::NewPacket
                    }
                }
            }
        };
        #[rustfmt::skip]
        log::trace!("received {{ ack = {:08X?}, seq = {:08X?}, window = {rcvd_window} }}, self {{ ack = {:08X?}, seq = {:08X?}, send_window = {} }}, len = {len}, {res:?}", rcvd_ack.0, rcvd_seq.0, self.ack.0, self.seq.0, self.get_send_window());
        res
    }

    pub(super) fn add_inflight_packet(&mut self, buf: Vec<u8>) -> std::io::Result<()> {
        if buf.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Empty payload"));
        }
        let buf_len = buf.len() as u32;
        self.inflight_packets.insert(self.seq, InflightPacket::new(self.seq, buf));
        self.seq += buf_len;
        Ok(())
    }

    pub(super) fn update_last_received_ack(&mut self, ack: SeqNum) {
        self.last_received_ack = ack;
    }

    pub(crate) fn update_inflight_packet_queue(&mut self, ack: SeqNum) {
        match self.inflight_packets.first_key_value() {
            None => return,
            Some((&seq, _)) if ack < seq => return,
            _ => {}
        }
        // RFC 6298 §3: a sample from a retransmitted segment is ambiguous, so only a segment sent
        // once is the measurement §5's note collapses the backed-off timeout on.
        let mut measured = false;
        if let Some(seq) = self
            .inflight_packets
            .iter()
            .find(|(_, p)| p.contains_seq_num(ack - 1))
            .map(|(&s, _)| s)
        {
            let mut inflight_packet = self.inflight_packets.remove(&seq).unwrap();
            let distance = ack.distance(inflight_packet.seq) as usize;
            if distance < inflight_packet.payload.len() {
                inflight_packet.payload.drain(0..distance);
                inflight_packet.seq = ack;
                self.inflight_packets.insert(ack, inflight_packet);
            } else {
                measured |= inflight_packet.retransmit_count == 0;
            }
        }
        self.inflight_packets.retain(|_, p| {
            if ack < p.seq + p.payload.len() as u32 {
                return true; // keep the packet in the inflight_packets
            }
            measured |= p.retransmit_count == 0;
            false // remove this packet
        });
        if measured {
            // With no estimator, the computation RFC 6298 §5's note calls for gives the configured
            // timeout back, collapsing whatever §5.5 backed it off to.
            self.current_rto = self.rto;
        }
    }

    pub(crate) fn find_inflight_packet(&self, seq: SeqNum) -> Option<&InflightPacket> {
        self.inflight_packets.get(&seq)
    }

    /// The deadline the connection waits on: the earliest send time in the inflight queue plus the
    /// current retransmission timeout, present while data is outstanding and the sum fits the clock.
    pub(crate) fn get_retransmission_deadline(&self) -> Option<tokio::time::Instant> {
        self.inflight_packets
            .values()
            .next()
            .and_then(|p| p.send_time.checked_add(self.current_rto))
    }

    #[must_use]
    /// The segments whose deadline has passed, and whether one of them reached R2, the transmission
    /// count RFC 9293 §3.8.3 closes the connection at. At R2 the list is empty.
    pub(crate) fn collect_timed_out_inflight_packets(&mut self) -> (Vec<InflightPacket>, bool) {
        let (rto, r2) = (self.current_rto, self.max_retransmit_count);
        if self
            .inflight_packets
            .values()
            .any(|p| p.is_timed_out(rto) && p.retransmit_count + 1 >= r2)
        {
            return (Vec::new(), true);
        }

        let mut retransmit_list = Vec::new();
        for packet in self.inflight_packets.values_mut() {
            if packet.is_timed_out(rto) {
                packet.retransmit_count += 1;
                retransmit_list.push(packet.clone());
            }
        }
        if !retransmit_list.is_empty() {
            let now = tokio::time::Instant::now();
            self.inflight_packets.values_mut().for_each(|packet| packet.send_time = now); // restart the timer, per RFC 6298 §5.6
            self.current_rto = self.current_rto.saturating_mul(2).min(MAX_RTO.max(self.rto)); // back off the timer, per RFC 6298 §5.5
        }
        (retransmit_list, false)
    }

    pub(crate) fn get_inflight_packets_total_len(&self) -> usize {
        self.inflight_packets.values().map(|p| p.payload.len()).sum()
    }

    pub(crate) fn is_inflight_queue_empty(&self) -> bool {
        self.inflight_packets.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn get_all_inflight_packets(&self) -> Vec<&InflightPacket> {
        self.inflight_packets.values().collect::<Vec<_>>()
    }

    pub fn is_send_buffer_full(&self) -> bool {
        // To respect the receiver's window (remote_window) size and avoid sending too many unacknowledged packets, which may cause packet loss
        // Simplified version: min(cwnd, rwnd)
        self.seq.distance(self.get_last_received_ack()) >= self.max_unacked_bytes.min(self.get_send_window())
    }
}

#[derive(Debug, Clone)]
pub struct InflightPacket {
    pub seq: SeqNum,
    pub payload: Vec<u8>,
    pub send_time: tokio::time::Instant,
    pub retransmit_count: usize,
}

impl InflightPacket {
    fn new(seq: SeqNum, payload: Vec<u8>) -> Self {
        Self {
            seq,
            payload,
            send_time: tokio::time::Instant::now(),
            retransmit_count: 0,
        }
    }
    pub(crate) fn contains_seq_num(&self, seq: SeqNum) -> bool {
        self.seq <= seq && seq < self.seq + self.payload.len() as u32
    }
    pub(crate) fn is_timed_out(&self, rto: Duration) -> bool {
        self.send_time.elapsed() >= rto
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_flight_packet() {
        let p = InflightPacket::new((u32::MAX - 1).into(), vec![10, 20, 30, 40, 50]);

        assert!(p.contains_seq_num((u32::MAX - 1).into()));
        assert!(p.contains_seq_num(u32::MAX.into()));
        assert!(p.contains_seq_num(0.into()));
        assert!(p.contains_seq_num(1.into()));
        assert!(p.contains_seq_num(2.into()));

        assert!(!p.contains_seq_num(3.into()));
    }

    #[test]
    fn test_get_unordered_packets_with_max_bytes() {
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

        // insert 3 consecutive packets
        tcb.add_unordered_packet(SeqNum(1000), vec![1; 500]); // seq=1000, len=500
        tcb.add_unordered_packet(SeqNum(1500), vec![2; 500]); // seq=1500, len=500
        tcb.add_unordered_packet(SeqNum(2000), vec![3; 500]); // seq=2000, len=500

        // test 1: extract up to 700 bytes
        let data = tcb.consume_unordered_packets(700).unwrap();
        assert_eq!(data.len(), 700); // extract 500 + 200
        assert_eq!(data[..500], vec![1; 500]); // the first packet
        assert_eq!(data[500..700], vec![2; 200]); // the first 200 bytes of the second packet
        assert_eq!(tcb.ack, SeqNum(1700)); // ack increased by 700
        assert_eq!(tcb.unordered_packets.len(), 2); // remaining two packets
        assert_eq!(tcb.unordered_packets.get(&SeqNum(1700)).unwrap().len(), 300); // the second packet remaining 300 bytes
        assert_eq!(tcb.unordered_packets.get(&SeqNum(2000)).unwrap().len(), 500); // the third packet unchanged

        // test 2: extract up to 800 bytes
        let data = tcb.consume_unordered_packets(800).unwrap();
        assert_eq!(data.len(), 800); // extract 300 bytes of the second packet and the third packet
        assert_eq!(data[..300], vec![2; 300]); // the remaining 300 bytes of the second packet
        assert_eq!(data[300..800], vec![3; 500]); // the third packet
        assert_eq!(tcb.ack, SeqNum(2500)); // ack increased by 800
        assert_eq!(tcb.unordered_packets.len(), 0); // no remaining packets

        // test 3: no data to extract
        let data = tcb.consume_unordered_packets(1000);
        assert!(data.is_none());
    }

    #[test]
    fn test_add_unordered_packet_enforces_read_buffer() {
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

        // fill the receive buffer to its limit with an out-of-order gap held open
        tcb.add_unordered_packet(SeqNum(1000 + READ_BUFFER_SIZE as u32), vec![7; READ_BUFFER_SIZE]);
        assert_eq!(tcb.get_unordered_packets_total_len(), READ_BUFFER_SIZE);

        // a further out-of-order segment is dropped, keeping the buffer bounded
        tcb.add_unordered_packet(SeqNum(1000 + 2 * READ_BUFFER_SIZE as u32), vec![8; 500]);
        assert_eq!(tcb.get_unordered_packets_total_len(), READ_BUFFER_SIZE);

        // the head-of-line segment is admitted even at the limit, so the stream advances
        tcb.add_unordered_packet(SeqNum(1000), vec![9; 500]);
        assert_eq!(tcb.unordered_packets.get(&SeqNum(1000)).unwrap().len(), 500);
    }

    #[test]
    fn test_consume_trims_overlapping_head_entry() {
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

        // an out-of-order segment stored ahead of ack
        tcb.add_unordered_packet(SeqNum(1200), vec![2; 300]);
        // the gap-filler that a retransmission re-segmented to overlap the stored one
        tcb.add_unordered_packet(SeqNum(1000), vec![1; 400]);

        // consuming pulls [1000..1400), advancing ack into the stored entry keyed at 1200
        let data = tcb.consume_unordered_packets(10_000).unwrap();
        assert_eq!(data.len(), 500); // 400 + the 100 bytes of the stored entry past ack
        assert_eq!(tcb.ack, SeqNum(1500));
        assert_eq!(tcb.unordered_packets.len(), 0);
    }

    #[test]
    fn test_update_inflight_packet_queue() {
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
        tcb.seq = SeqNum(100); // setting the initial seq

        // insert 3 consecutive packets
        tcb.add_inflight_packet(vec![1; 500]).unwrap(); // seq=100, len=500
        tcb.add_inflight_packet(vec![2; 500]).unwrap(); // seq=600, len=500
        tcb.add_inflight_packet(vec![3; 500]).unwrap(); // seq=1100, len=500

        // test 1: confirm partial packets (ack=800)
        tcb.update_inflight_packet_queue(SeqNum(800));
        assert_eq!(tcb.inflight_packets.len(), 2); // remaining two packets
        let first_packet = tcb.inflight_packets.first_key_value().unwrap().1;
        assert_eq!(first_packet.seq, SeqNum(800)); // the remaining part of the first packet
        assert_eq!(first_packet.payload.len(), 300); // remaining 300 bytes in the first packet
        let second_packet = tcb.inflight_packets.last_key_value().unwrap().1;
        assert_eq!(second_packet.seq, SeqNum(1100)); // no change in the second packet

        // test 2: confirm all packets (ack=2000)
        tcb.update_inflight_packet_queue(SeqNum(2000));
        assert_eq!(tcb.inflight_packets.len(), 0); // all packets are acknowledged
    }

    #[test]
    fn test_update_inflight_packet_queue_cumulative_ack() {
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
        tcb.seq = SeqNum(1000);

        // Insert 3 consecutive packets
        tcb.add_inflight_packet(vec![1; 500]).unwrap(); // seq=1000, len=500
        tcb.add_inflight_packet(vec![2; 500]).unwrap(); // seq=1500, len=500
        tcb.add_inflight_packet(vec![3; 500]).unwrap(); // seq=2000, len=500

        // Emulate cumulative ACK: ack=2500
        tcb.update_inflight_packet_queue(SeqNum(2500));
        assert_eq!(tcb.inflight_packets.len(), 0); // all packets should be removed
    }

    /// RFC 6298 §5's note: the backed-off timeout collapses once a segment sent exactly once is acknowledged
    #[tokio::test(start_paused = true)]
    async fn test_backoff_collapses_on_an_unretransmitted_segment() {
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

        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        tokio::time::advance(RTO).await;
        assert_eq!(tcb.collect_timed_out_inflight_packets().0.len(), 1);
        assert_eq!(tcb.current_rto, RTO * 2);

        // the retransmitted segment cannot say which transmission the acknowledgement answers
        tcb.update_inflight_packet_queue(tcb.get_seq());
        assert!(tcb.is_inflight_queue_empty());
        assert_eq!(tcb.current_rto, RTO * 2);

        // a segment sent exactly once, whose acknowledgement is the measurement
        tcb.add_inflight_packet(vec![2; 500]).unwrap();
        tcb.update_inflight_packet_queue(tcb.get_seq());
        assert!(tcb.is_inflight_queue_empty());
        assert_eq!(tcb.current_rto, RTO);
    }

    /// RFC 6298 §2.4: a configured timeout below one second is raised to one second.
    #[tokio::test(start_paused = true)]
    async fn test_timeout_below_one_second_is_raised() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            u16::MAX,
            None,
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            Duration::from_millis(100),
            MAX_RETRANSMIT_COUNT,
        );

        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        assert_eq!(
            tcb.get_retransmission_deadline(),
            Some(tokio::time::Instant::now() + Duration::from_secs(1))
        );
    }

    /// A configured timeout beyond the clock's range gives a deadline of `None`.
    #[tokio::test(start_paused = true)]
    async fn test_timeout_too_large_for_the_clock_has_no_deadline() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            u16::MAX,
            None,
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            Duration::MAX,
            MAX_RETRANSMIT_COUNT,
        );

        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        assert!(tcb.get_retransmission_deadline().is_none());
    }

    /// RFC 6298 §5.6: an expiry restarts the timer for every outstanding segment, so none is
    /// retransmitted before the backed-off timeout has run from that expiry.
    #[tokio::test(start_paused = true)]
    async fn test_expiry_restarts_the_timer_for_every_segment() {
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

        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        tokio::time::advance(Duration::from_millis(900)).await;
        tcb.add_inflight_packet(vec![2; 500]).unwrap();

        // the first segment expires, doubling the timeout to two seconds
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(tcb.collect_timed_out_inflight_packets().0.len(), 1);

        // nothing expires until two seconds after that expiry, and then both segments do
        tokio::time::advance(Duration::from_millis(1900)).await;
        assert!(tcb.collect_timed_out_inflight_packets().0.is_empty());
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(tcb.collect_timed_out_inflight_packets().0.len(), 2);
    }

    /// RFC 6298 §5.5: an expiry doubles the timeout, bounded above by the ceiling, so a configured
    /// timeout larger than `MAX_RTO` is never shortened.
    #[tokio::test(start_paused = true)]
    async fn test_backoff_never_shortens_a_large_configured_timeout() {
        let rto = Duration::from_secs(120);
        let mut tcb = Tcb::new(
            SeqNum(1000),
            u16::MAX,
            None,
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            rto,
            MAX_RETRANSMIT_COUNT,
        );

        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        tokio::time::advance(rto).await;
        assert_eq!(tcb.collect_timed_out_inflight_packets().0.len(), 1);
        assert!(tcb.current_rto >= rto, "the backoff shortened the timeout to {:?}", tcb.current_rto);
    }

    /// RFC 6298 §5.5: every expiry backs the connection's timer off, so the segment is retransmitted
    /// after a longer wait each time, and it stays outstanding once R2 reports the connection closed.
    #[tokio::test(start_paused = true)]
    async fn test_retransmit_with_exponential_backoff() {
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

        tcb.add_inflight_packet(vec![1; 500]).unwrap();

        // Simulate retransmission timeouts
        let mut previous_wait = Duration::ZERO;
        for i in 0..MAX_RETRANSMIT_COUNT {
            // Wait exactly as long as the connection asks, which is longer on every round
            let wait = tcb.get_retransmission_deadline().unwrap() - tokio::time::Instant::now();
            println!("timeout: {wait:?}");
            assert!(wait >= previous_wait); // doubling, until the ceiling flattens it
            previous_wait = wait;
            tokio::time::advance(wait).await;

            let (packets, exhausted) = tcb.collect_timed_out_inflight_packets();
            if i + 1 < MAX_RETRANSMIT_COUNT {
                assert_eq!(packets.len(), 1);
                assert_eq!(packets[0].retransmit_count, i + 1);
                assert!(!exhausted);
            } else {
                assert!(packets.is_empty());
                assert!(exhausted);
            }
            assert!(tcb.current_rto > RTO);
        }

        // the segment stays outstanding at R2; the connection closes rather than the queue losing it
        assert!(!tcb.is_inflight_queue_empty());
    }

    /// A peer shift of 7 is applied to every window the peer advertises after the handshake.
    #[test]
    fn test_peer_window_shift_is_taken_from_the_syn() {
        let mut tcb = window_tcb(4000, Some(7), READ_BUFFER_SIZE);
        assert_eq!(tcb.get_send_window(), 4000); // the SYN's own window is unscaled

        tcb.update_send_window(&TcpHeader::new(1, 2, 1000, 40_000));
        assert_eq!(tcb.get_send_window(), 40_000 << 7);
    }

    /// A peer that offers no window scale option has its windows honoured as they stand.
    #[test]
    fn test_no_window_scale_option_leaves_the_window_unshifted() {
        let mut tcb = window_tcb(4000, None, READ_BUFFER_SIZE);
        assert_eq!(tcb.get_send_window(), 4000);

        tcb.update_send_window(&TcpHeader::new(1, 2, 1000, 40_000));
        assert_eq!(tcb.get_send_window(), 40_000);
        assert_eq!(tcb.get_recv_window_shift(), None);
    }

    /// RFC 7323 §2.3 limits the shift count to 14, so a larger one is used as 14.
    #[test]
    fn test_peer_window_shift_above_the_maximum_is_clamped() {
        let mut tcb = window_tcb(4000, Some(15), READ_BUFFER_SIZE);

        tcb.update_send_window(&TcpHeader::new(1, 2, 1000, 40_000));
        assert_eq!(tcb.get_send_window(), 40_000 << MAX_WINDOW_SHIFT);
    }

    /// A peer opening with a closed window is held to it, whatever shift the same SYN offers.
    #[test]
    fn test_zero_peer_window_is_honoured() {
        assert_eq!(window_tcb(0, None, READ_BUFFER_SIZE).get_send_window(), 0);
        assert_eq!(window_tcb(0, Some(7), READ_BUFFER_SIZE).get_send_window(), 0);
    }

    /// The announced shift is the smallest expressing the read buffer in 16 bits, the advertised
    /// window is the free space shifted down by it, and a peer shift of 0 still enables scaling.
    #[test]
    fn test_advertised_window_is_derived_from_the_read_buffer() {
        assert_eq!(window_tcb(4000, Some(0), 16 * 1024).get_recv_window_shift(), Some(0));
        assert_eq!(window_tcb(4000, Some(0), 64 * 1024).get_recv_window_shift(), Some(1));

        // 1.2 MiB needs a shift of 5, which expresses the window only in multiples of 32, so the
        // advertised value rounds down and withholds the remainder rather than overstating the room
        let buffer = 1_258_291;
        let mut tcb = window_tcb(4000, Some(0), buffer);
        assert_eq!(tcb.get_recv_window_shift(), Some(5));
        assert_eq!(usize::from(tcb.get_scaled_recv_window()), buffer >> 5);
        assert!(usize::from(tcb.get_scaled_recv_window()) << 5 < buffer);

        // the advertised window shrinks as the buffer fills
        tcb.add_unordered_packet(SeqNum(1000), vec![0; buffer - 1000]);
        assert_eq!(usize::from(tcb.get_scaled_recv_window()), 1000 >> 5);
    }

    // A `Tcb` opened by a SYN advertising `peer_window` under `peer_window_shift`.
    fn window_tcb(peer_window: u16, peer_window_shift: Option<u8>, read_buffer_size: usize) -> Tcb {
        Tcb::new(
            SeqNum(1000),
            peer_window,
            peer_window_shift,
            1500,
            MAX_UNACK,
            read_buffer_size,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        )
    }
}
