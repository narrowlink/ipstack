use super::seqnum::SeqNum;
use etherparse::TcpHeader;
use std::collections::BTreeMap;

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
    last_ack: SeqNum,
    recv_window: u16,
    send_window: u16,
    state: TcpState,
    avg_send_window: (u64, u64), // (avg, count)
    inflight_packets: Vec<InflightPacket>,
    unordered_packets: BTreeMap<SeqNum, UnorderedPacket>,
}

impl Tcb {
    pub(super) fn new(ack: SeqNum) -> Tcb {
        #[cfg(debug_assertions)]
        let seq = 100;
        #[cfg(not(debug_assertions))]
        let seq = rand::random::<u32>();
        Tcb {
            seq: seq.into(),
            ack,
            last_ack: seq.into(),
            send_window: u16::MAX,
            recv_window: 0,
            state: TcpState::Listen,
            avg_send_window: (1, 1),
            inflight_packets: Vec::new(),
            unordered_packets: BTreeMap::new(),
        }
    }

    pub(super) fn add_unordered_packet(&mut self, seq: SeqNum, buf: Vec<u8>) {
        if seq < self.ack {
            log::debug!("Received packet with seq < ack: seq = {}, ack = {}", seq, self.ack);
            return;
        }
        self.unordered_packets.insert(seq, UnorderedPacket::new(buf));
    }
    pub(super) fn get_available_read_buffer_size(&self) -> usize {
        READ_BUFFER_SIZE.saturating_sub(self.unordered_packets.iter().fold(0, |acc, (_, p)| acc + p.payload.len()))
    }
    pub(super) fn get_unordered_packets(&mut self) -> Option<Vec<u8>> {
        // dbg!(self.ack);
        // for (seq,_) in self.unordered_packets.iter() {
        //     dbg!(seq);
        // }
        self.unordered_packets.remove(&self.ack).map(|p| p.payload)
    }
    pub(super) fn add_seq_one(&mut self) {
        self.seq += 1;
    }
    pub(super) fn get_seq(&self) -> SeqNum {
        self.seq
    }
    pub(super) fn add_ack(&mut self, add: SeqNum) {
        self.ack += add;
    }
    pub(super) fn get_ack(&self) -> SeqNum {
        self.ack
    }
    pub(super) fn get_last_ack(&self) -> SeqNum {
        self.last_ack
    }
    pub(super) fn change_state(&mut self, state: TcpState) {
        self.state = state;
    }
    pub(super) fn get_state(&self) -> TcpState {
        self.state
    }
    pub(super) fn change_send_window(&mut self, window: u16) {
        let avg_send_window = ((self.avg_send_window.0 * self.avg_send_window.1) + window as u64) / (self.avg_send_window.1 + 1);
        self.avg_send_window.0 = avg_send_window;
        self.avg_send_window.1 += 1;
        self.send_window = window;
    }
    pub(super) fn get_send_window(&self) -> u16 {
        self.send_window
    }
    pub(super) fn get_avg_send_window(&self) -> u64 {
        self.avg_send_window.0
    }
    pub(super) fn change_recv_window(&mut self, window: u16) {
        self.recv_window = window;
    }
    pub(super) fn get_recv_window(&self) -> u16 {
        self.recv_window
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

    pub(super) fn check_pkt_type(&self, tcp_header: &TcpHeader, p: &[u8]) -> PacketStatus {
        let received_ack = SeqNum(tcp_header.acknowledgment_number);
        let received_ack_distance = self.seq - received_ack;

        let current_ack_distance = self.seq - self.last_ack;
        if received_ack_distance > current_ack_distance || (self.seq != received_ack && self.seq.0.saturating_sub(received_ack.0) == 0) {
            PacketStatus::Invalid
        } else if self.last_ack == received_ack {
            if !p.is_empty() {
                PacketStatus::NewPacket
            } else if self.send_window == tcp_header.window_size && self.seq != self.last_ack {
                PacketStatus::RetransmissionRequest
            } else if self.ack - 1 == tcp_header.sequence_number {
                PacketStatus::KeepAlive
            } else {
                PacketStatus::WindowUpdate
            }
        } else if self.last_ack < received_ack {
            if !p.is_empty() {
                PacketStatus::NewPacket
            } else {
                PacketStatus::Ack
            }
        } else {
            PacketStatus::Invalid
        }
    }

    pub(super) fn add_inflight_packet(&mut self, seq: SeqNum, buf: Vec<u8>) {
        let buf_len = buf.len() as u32;
        self.inflight_packets.push(InflightPacket::new(seq, buf));
        self.seq += buf_len;
    }

    pub(super) fn change_last_ack(&mut self, ack: SeqNum) {
        self.last_ack = ack;

        if self.state == TcpState::Established {
            if let Some(i) = self.inflight_packets.iter().position(|p| p.contains_seq_num(ack - 1)) {
                let mut inflight_packet = self.inflight_packets.remove(i);
                let distance = ack.distance(inflight_packet.seq) as usize;
                if distance < inflight_packet.payload.len() {
                    inflight_packet.payload.drain(0..distance);
                    inflight_packet.seq = ack;
                    self.inflight_packets.push(inflight_packet);
                }
            }
            self.inflight_packets.retain(|p| {
                let last_byte = p.seq + (p.payload.len() as u32);
                last_byte > self.last_ack
            });
        }
    }

    pub(crate) fn find_inflight_packet(&self, seq: SeqNum) -> Option<&InflightPacket> {
        self.inflight_packets.iter().find(|p| p.seq == seq)
    }

    #[allow(dead_code)]
    pub(crate) fn get_all_inflight_packets(&self) -> &Vec<InflightPacket> {
        &self.inflight_packets
    }

    pub fn is_send_buffer_full(&self) -> bool {
        (self.seq - self.last_ack).0 >= MAX_UNACK
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
