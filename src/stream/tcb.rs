use std::{pin::Pin, time::Duration};

use tokio::time::Sleep;

use crate::packet::TcpPacket;

const MAX_UNACK: u32 = 1024 * 64; // 64KB
const TCP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub enum TcpState {
    SynReceived(bool), // bool means if syn/ack is sent
    Established,
    FinWait1,
    FinWait2,
    Closed,
}

pub(super) enum PacketStatus {
    WindowUpdate,
    Invalid,
    RetransmissionRequest,
    NewPacket,
    Ack,
}

pub(super) struct Tcb {
    pub(super) seq: u32,
    pub(super) retransmission: Option<u32>,
    ack: u32,
    pub(super) last_ack: u32,
    pub(super) timeout: Pin<Box<Sleep>>,
    recv_window: u16,
    send_window: u16,
    state: TcpState,
    pub(super) send_buffer: Vec<u8>,
}

impl Tcb {
    pub(super) fn new(ack: u32) -> Tcb {
        let seq = 100;
        Tcb {
            seq,
            retransmission: None,
            ack,
            last_ack: seq,
            timeout: Box::pin(tokio::time::sleep_until(
                tokio::time::Instant::now() + TCP_TIMEOUT,
            )),
            send_window: u16::MAX,
            recv_window: 0,
            state: TcpState::SynReceived(false),
            send_buffer: Vec::new(),
        }
    }
    pub(super) fn add_send_buffer(&mut self, buf: &[u8]) {
        self.send_buffer.extend(buf);
        self.seq = self.seq.wrapping_add(buf.len() as u32);
    }
    pub(super) fn add_seq_one(&mut self) {
        self.seq = self.seq.wrapping_add(1);
    }
    pub(super) fn get_seq(&self) -> u32 {
        self.seq
    }
    pub(super) fn add_ack(&mut self, add: u32) {
        self.ack = self.ack.wrapping_add(add);
    }
    pub(super) fn get_ack(&self) -> u32 {
        self.ack
    }
    pub(super) fn change_state(&mut self, state: TcpState) {
        self.state = state;
    }
    pub(super) fn get_state(&self) -> &TcpState {
        &self.state
    }
    pub(super) fn change_send_window(&mut self, window: u16) {
        self.send_window = window;
    }
    pub(super) fn get_send_window(&self) -> u16 {
        self.send_window
    }
    pub(super) fn change_recv_window(&mut self, window: u16) {
        self.recv_window = window;
    }
    pub(super) fn get_recv_window(&self) -> u16 {
        self.recv_window
    }
    #[inline(always)]
    pub(super) fn buffer_size(&self, payload_len: u16) -> u16 {
        match MAX_UNACK - self.send_buffer.len() as u32 {
            // b if b.saturating_sub(payload_len as u32 + 64) != 0 => payload_len,
            // b if b < 128 && b >= 4 => (b / 2) as u16,
            // b if b < 4 => b as u16,
            // b => (b - 64) as u16,
            b if b >= payload_len as u32 * 2 && b > 0 => payload_len,
            b if b < 4 => b as u16,
            b => (b / 2) as u16,
        }
    }

    pub(super) fn check_pkt_type(&self, incoming_packet: &TcpPacket, p: &[u8]) -> PacketStatus {
        let received_ack_distance = self
            .seq
            .wrapping_sub(incoming_packet.inner().acknowledgment_number);
        let current_ack_distance = self.seq.wrapping_sub(self.last_ack);
        if received_ack_distance > current_ack_distance {
            PacketStatus::Invalid
        } else if self.last_ack == incoming_packet.inner().acknowledgment_number {
            if !p.is_empty() {
                PacketStatus::NewPacket
            } else if self.send_window == incoming_packet.inner().window_size {
                PacketStatus::RetransmissionRequest
            } else {
                PacketStatus::WindowUpdate
            }
        } else if self.last_ack < incoming_packet.inner().acknowledgment_number {
            if !p.is_empty() {
                PacketStatus::NewPacket
            } else {
                PacketStatus::Ack
            }
        } else {
            PacketStatus::Invalid
        }
    }
    pub(super) fn change_last_ack(&mut self, ack: u32) {
        self.timeout
            .as_mut()
            .reset(tokio::time::Instant::now() + TCP_TIMEOUT);
        let distnace = ack.wrapping_sub(self.last_ack);

        if matches!(self.state, TcpState::Established) {
            self.send_buffer.drain(0..distnace as usize);
        }

        self.last_ack = self.last_ack.wrapping_add(distnace);
    }
    pub(super) fn is_send_buffer_full(&self) -> bool {
        self.send_buffer.len() >= MAX_UNACK as usize
    }
}
