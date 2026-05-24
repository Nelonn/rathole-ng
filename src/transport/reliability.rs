use std::collections::{BTreeMap, HashMap};
use std::task::Waker;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Data = 0,
    Syn = 1,
    SynAck = 2,
    Fin = 3,
    Ack = 4,
    Ping = 5,
    Pong = 6,
}

impl From<u8> for PacketType {
    fn from(v: u8) -> Self {
        match v {
            1 => PacketType::Syn,
            2 => PacketType::SynAck,
            3 => PacketType::Fin,
            4 => PacketType::Ack,
            5 => PacketType::Ping,
            6 => PacketType::Pong,
            _ => PacketType::Data,
        }
    }
}

pub struct UdpHeader {
    pub stream_id: u32,
    pub packet_type: PacketType,
    pub seq: u64,
    pub ack: u64,
    pub ack_bits: u64,
}

impl UdpHeader {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.push(self.packet_type as u8);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.ack.to_be_bytes());
        buf.extend_from_slice(&self.ack_bits.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 29 { return None; }
        Some((Self {
            stream_id: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            packet_type: PacketType::from(buf[4]),
            seq: u64::from_be_bytes(buf[5..13].try_into().unwrap()),
            ack: u64::from_be_bytes(buf[13..21].try_into().unwrap()),
            ack_bits: u64::from_be_bytes(buf[21..29].try_into().unwrap()),
        }, &buf[29..]))
    }
}

pub struct SentPacket {
    pub data: Vec<u8>,
    pub sent_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamMode {
    Tcp, // SACK
    Udp, // NACK
}

pub struct StreamState {
    pub mode: StreamMode,
    pub next_write_seq: u64,
    pub next_read_seq: u64,
    pub write_queue: BTreeMap<u64, SentPacket>,
    pub read_buffer: BTreeMap<u64, Vec<u8>>,
    pub read_buf_bytes: Vec<u8>,
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
}

impl StreamState {
    pub fn new(mode: StreamMode) -> Self {
        Self {
            mode,
            next_write_seq: 0,
            next_read_seq: 0,
            write_queue: BTreeMap::new(),
            read_buffer: BTreeMap::new(),
            read_buf_bytes: Vec::new(),
            read_waker: None,
            write_waker: None,
        }
    }

    pub fn build_ack(&self) -> (u64, u64) {
        let ack = self.next_read_seq.saturating_sub(1);
        let mut bits = 0u64;
        for i in 0..64 {
            if self.read_buffer.contains_key(&(ack + 1 + i)) {
                bits |= 1 << i;
            }
        }
        (ack, bits)
    }

    pub fn handle_ack(&mut self, ack: u64, ack_bits: u64) -> Vec<u64> {
        let mut retransmit = Vec::new();
        let mut highest_acked = ack;

        self.write_queue.retain(|&seq, _| {
            if seq <= ack { return false; }
            let offset = seq.saturating_sub(ack + 1);
            if offset < 64 && ((ack_bits >> offset) & 1) == 1 {
                if seq > highest_acked { highest_acked = seq; }
                return false;
            }
            true
        });

        // SACK: Retransmit everything below highest_acked that wasn't acked
        if self.mode == StreamMode::Tcp && highest_acked > ack {
            for (&seq, _) in self.write_queue.range(..highest_acked) {
                retransmit.push(seq);
            }
        }
        retransmit
    }

    pub fn handle_nack(&mut self, start: u64, end: u64) -> Vec<u64> {
        let mut retransmit = Vec::new();
        if self.mode == StreamMode::Udp {
            for seq in start..=end {
                if self.write_queue.contains_key(&seq) {
                    retransmit.push(seq);
                }
            }
        }
        retransmit
    }

    pub fn push_data(&mut self, seq: u64, data: Vec<u8>) -> Option<(u64, u64)> {
        if seq < self.next_read_seq || self.read_buffer.contains_key(&seq) { return None; }
        
        let mut nack = None;
        if self.mode == StreamMode::Udp && seq > self.next_read_seq {
            nack = Some((self.next_read_seq, seq - 1));
        }

        self.read_buffer.insert(seq, data);
        while let Some(data) = self.read_buffer.remove(&self.next_read_seq) {
            self.read_buf_bytes.extend_from_slice(&data);
            self.next_read_seq += 1;
        }

        if let Some(w) = self.read_waker.take() { w.wake(); }
        nack
    }
}

pub struct Reliability {
    pub streams: HashMap<u32, StreamState>,
}

impl Reliability {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub fn get_retransmissions(&mut self, now: Instant) -> Vec<(u32, u64, Vec<u8>)> {
        let mut res = Vec::new();
        for (&stream_id, state) in &mut self.streams {
            let is_udp = state.mode == StreamMode::Udp;
            for (&seq, p) in &mut state.write_queue {
                let timeout = if is_udp { Duration::from_secs(3) } else { Duration::from_millis(200) };
                if now.duration_since(p.sent_at) > timeout {
                    if is_udp { continue; } // NACK mode retransmits only on NACK
                    p.sent_at = now;
                    res.push((stream_id, seq, p.data.clone()));
                }
            }
            if is_udp {
                state.write_queue.retain(|_, p| now.duration_since(p.sent_at) < Duration::from_secs(3));
            }
        }
        res
    }
}
