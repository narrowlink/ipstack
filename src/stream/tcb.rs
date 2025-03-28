use super::seqnum::SeqNum;
use etherparse::TcpHeader;
use std::collections::{BTreeMap, VecDeque};

const MAX_UNACK: u32 = 1024 * 16; // 16KB
const READ_BUFFER_SIZE: usize = 1024 * 16; // 16KB

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
pub(super) enum PacketStatus {
    WindowUpdate,
    Invalid,
    RetransmissionRequest,
    NewPacket,
    Ack,
    KeepAlive,
}

#[derive(Debug)]
pub(super) struct Tcb {
    seq: SeqNum,
    ack: SeqNum,
    last_received_ack: SeqNum,
    send_window: u16,
    state: TcpState,
    avg_send_window: Average,
    inflight_packets: VecDeque<InflightPacket>,
    unordered_packets: BTreeMap<SeqNum, UnorderedPacket>,
}

impl Tcb {
    pub(super) fn new(ack: SeqNum) -> Tcb {
        #[cfg(debug_assertions)]
        let seq = 100;
        #[cfg(not(debug_assertions))]
        let seq = rand::Rng::random::<u32>(&mut rand::rng());
        Tcb {
            seq: seq.into(),
            ack,
            last_received_ack: seq.into(),
            send_window: u16::MAX,
            state: TcpState::Listen,
            avg_send_window: Average::default(),
            inflight_packets: VecDeque::new(),
            unordered_packets: BTreeMap::new(),
        }
    }

    pub(super) fn add_unordered_packet(&mut self, seq: SeqNum, buf: Vec<u8>) {
        if seq < self.ack {
            log::warn!("Received packet seq < ack: seq = {}, ack = {}, len = {}", seq, self.ack, buf.len());
            return;
        }
        self.unordered_packets.insert(seq, UnorderedPacket::new(buf));
    }
    pub(super) fn get_available_read_buffer_size(&self) -> usize {
        READ_BUFFER_SIZE.saturating_sub(self.unordered_packets.values().map(|p| p.payload.len()).sum())
    }

    pub(super) fn get_unordered_packets(&mut self) -> Option<Vec<u8>> {
        // dbg!(self.ack);
        // for (seq,_) in self.unordered_packets.iter() {
        //     dbg!(seq);
        // }
        self.unordered_packets.remove(&self.ack).map(|p| {
            self.ack += p.payload.len() as u32;
            p.payload
        })
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
    pub(super) fn get_last_received_ack(&self) -> SeqNum {
        self.last_received_ack
    }
    pub(super) fn change_state(&mut self, state: TcpState) {
        self.state = state;
    }
    pub(super) fn get_state(&self) -> TcpState {
        self.state
    }
    pub(super) fn update_send_window(&mut self, window: u16) {
        self.avg_send_window.update(window as u64);
        self.send_window = window;
    }
    pub(super) fn get_send_window(&self) -> u16 {
        self.send_window
    }
    pub(super) fn get_avg_send_window(&self) -> u64 {
        self.avg_send_window.get()
    }
    pub(super) fn get_recv_window(&self) -> u16 {
        self.get_available_read_buffer_size() as u16
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

    pub(super) fn check_pkt_type(&self, tcp_header: &TcpHeader, payload: &[u8]) -> PacketStatus {
        let rcvd_ack = SeqNum(tcp_header.acknowledgment_number);
        let rcvd_seq = SeqNum(tcp_header.sequence_number);
        let rcvd_window = tcp_header.window_size;
        let res = if rcvd_ack > self.seq {
            PacketStatus::Invalid
        } else {
            match rcvd_ack.cmp(&self.last_received_ack) {
                std::cmp::Ordering::Less => PacketStatus::Invalid,
                std::cmp::Ordering::Equal => {
                    if !payload.is_empty() {
                        PacketStatus::NewPacket
                    } else if self.send_window == rcvd_window && self.seq != self.last_received_ack {
                        PacketStatus::RetransmissionRequest
                    } else if self.ack - 1 == rcvd_seq {
                        PacketStatus::KeepAlive
                    } else {
                        PacketStatus::WindowUpdate
                    }
                }
                std::cmp::Ordering::Greater => {
                    if !payload.is_empty() {
                        PacketStatus::NewPacket
                    } else {
                        PacketStatus::Ack
                    }
                }
            }
        };
        #[rustfmt::skip]
        log::trace!("recieved {{ ack = {rcvd_ack}, seq = {rcvd_seq}, window = {rcvd_window} }}, self {{ ack = {}, seq = {}, send_window = {} }}, {res:?}", self.ack, self.seq, self.send_window);
        res
    }

    pub(super) fn add_inflight_packet(&mut self, buf: Vec<u8>) -> std::io::Result<()> {
        let buf_len = buf.len() as u32;
        self.inflight_packets.push_back(InflightPacket::new(self.seq, buf));
        self.seq += buf_len;
        Ok(())
    }

    pub(super) fn update_last_received_ack(&mut self, ack: SeqNum) {
        self.last_received_ack = ack;

        if self.state == TcpState::Established {
            if let Some(index) = self.inflight_packets.iter().position(|p| p.contains_seq_num(ack - 1)) {
                let Some(mut inflight_packet) = self.inflight_packets.remove(index) else {
                    log::warn!("Failed to find inflight packet with seq = {}", ack - 1);
                    return;
                };
                let distance = ack.distance(inflight_packet.seq) as usize;
                if distance < inflight_packet.payload.len() {
                    inflight_packet.payload.drain(0..distance);
                    inflight_packet.seq = ack;
                    self.inflight_packets.push_back(inflight_packet);
                }
            }
            self.inflight_packets.retain(|p| {
                let last_byte = p.seq + (p.payload.len() as u32);
                last_byte > self.last_received_ack
            });
        }
    }

    pub(crate) fn find_inflight_packet(&self, seq: SeqNum) -> Option<&InflightPacket> {
        self.inflight_packets.iter().find(|p| p.seq == seq)
    }

    #[allow(dead_code)]
    pub(crate) fn get_all_inflight_packets(&self) -> &VecDeque<InflightPacket> {
        &self.inflight_packets
    }

    pub fn is_send_buffer_full(&self) -> bool {
        (self.seq - self.last_received_ack).0 >= MAX_UNACK
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Average {
    pub(crate) avg: u64,
    pub(crate) count: u64,
}
impl Average {
    fn update(&mut self, value: u64) {
        self.avg = ((self.avg * self.count) + value) / (self.count + 1);
        self.count += 1;
    }
    fn get(&self) -> u64 {
        self.avg
    }
}

#[derive(Debug)]
pub struct InflightPacket {
    pub seq: SeqNum,
    pub payload: Vec<u8>,
    // pub send_time: SystemTime, // todo
}

impl InflightPacket {
    fn new(seq: SeqNum, payload: Vec<u8>) -> Self {
        Self {
            seq,
            payload,
            // send_time: SystemTime::now(), // todo
        }
    }
    pub(crate) fn contains_seq_num(&self, seq: SeqNum) -> bool {
        self.seq <= seq && seq < self.seq + self.payload.len() as u32
    }
}

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

#[derive(Debug)]
struct UnorderedPacket {
    payload: Vec<u8>,
    // pub recv_time: SystemTime, // todo
}

impl UnorderedPacket {
    pub(crate) fn new(payload: Vec<u8>) -> Self {
        Self {
            payload,
            // recv_time: SystemTime::now(), // todo
        }
    }
}
