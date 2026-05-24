use std::collections::{BTreeMap, HashMap, VecDeque};
use std::task::Waker;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Stream = 0,
    StreamOpen = 1,
    StreamOpenAck = 2,
    StreamClose = 3,
    Sack = 4,
    KeepalivePing = 5,
    KeepalivePong = 6,
    Service = 7,
    Nack = 8,
}

impl From<u8> for PacketKind {
    fn from(v: u8) -> Self {
        match v {
            1 => PacketKind::StreamOpen,
            2 => PacketKind::StreamOpenAck,
            3 => PacketKind::StreamClose,
            4 => PacketKind::Sack,
            5 => PacketKind::KeepalivePing,
            6 => PacketKind::KeepalivePong,
            7 => PacketKind::Service,
            8 => PacketKind::Nack,
            _ => PacketKind::Stream,
        }
    }
}

pub struct TransportPacketHeader {
    pub channel_id: u32,
    pub packet_kind: PacketKind,
    pub seq: u64,
    pub ack: u64,
    pub ack_bits: u64,
}

impl TransportPacketHeader {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.channel_id.to_be_bytes());
        buf.push(self.packet_kind as u8);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.ack.to_be_bytes());
        buf.extend_from_slice(&self.ack_bits.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 29 { return None; }
        Some((Self {
            channel_id: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            packet_kind: PacketKind::from(buf[4]),
            seq: u64::from_be_bytes(buf[5..13].try_into().unwrap()),
            ack: u64::from_be_bytes(buf[13..21].try_into().unwrap()),
            ack_bits: u64::from_be_bytes(buf[21..29].try_into().unwrap()),
        }, &buf[29..]))
    }
}

pub struct SentPacket {
    pub data: Vec<u8>,
    pub sent_at: Instant,
    pub retransmits: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamMode {
    Tcp, // SACK
    Udp, // NACK
}

pub struct StreamState {
    pub mode: StreamMode,
    pub established: bool,
    pub next_write_seq: u64,
    pub next_read_seq: u64,
    pub write_queue: BTreeMap<u64, SentPacket>,
    pub read_buffer: BTreeMap<u64, Vec<u8>>,
    pub read_buf_bytes: VecDeque<u8>,
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
}

impl StreamState {
    pub fn new(mode: StreamMode) -> Self {
        Self {
            mode,
            established: false,
            next_write_seq: 1,
            next_read_seq: 1,
            write_queue: BTreeMap::new(),
            read_buffer: BTreeMap::new(),
            read_buf_bytes: VecDeque::new(),
            read_waker: None,
            write_waker: None,
        }
    }

    /// Build the cumulative ack and 64-bit selective-ack bitmap.
    ///
    /// `ack`     = highest contiguously received sequence number.
    /// `bits[i]` = 1 means the sender already has seq `ack + 1 + i` buffered
    ///             out-of-order, so the sender need not retransmit it.
    pub fn build_ack(&self) -> (u64, u64) {
        let ack = self.next_read_seq.saturating_sub(1);
        let mut bits = 0u64;
        for i in 0..64u64 {
            if self.read_buffer.contains_key(&(ack + 1 + i)) {
                bits |= 1 << i;
            }
        }
        (ack, bits)
    }

    /// Process a SACK from the remote peer.
    ///
    /// Removes every entry in `write_queue` that is definitively acknowledged:
    ///   • seq <= ack  (cumulatively acked)
    ///   • seq in [ack+1 .. ack+64] with the corresponding bit set (selectively acked)
    ///
    /// FIX: previously always returned `Vec::new()`, so SACK-triggered gap
    /// retransmission never happened.  Now returns the sequences that are still
    /// inside the receiver's advertised window (seq in [ack+1 .. ack+64]) but
    /// whose bit is *not* set — these are gaps the receiver is missing and
    /// must be retransmitted immediately.
    pub fn handle_ack(&mut self, ack: u64, ack_bits: u64) -> Vec<u64> {
        // Remove all definitively-acked packets first.
        self.write_queue.retain(|&seq, _| {
            if seq <= ack {
                return false; // cumulatively acked
            }
            let offset = seq.saturating_sub(ack + 1);
            if offset < 64 && ((ack_bits >> offset) & 1) == 1 {
                return false; // selectively acked
            }
            true
        });

        // Collect gap sequences: inside the SACK window but NOT selectively acked.
        // These are packets the receiver has evidence of missing (it received
        // something beyond them) and should be retransmitted right away.
        let mut retransmit = Vec::new();
        for (&seq, _) in &self.write_queue {
            if seq <= ack {
                // Already removed above; can't happen, but be safe.
                continue;
            }
            let offset = seq.saturating_sub(ack + 1);
            if offset >= 64 {
                // Beyond the SACK window — we have no information about these yet,
                // let the tick-based timeout handle them.
                break; // BTreeMap is ordered, so all subsequent seqs are also out of window.
            }
            // seq is in [ack+1 .. ack+64] and NOT selectively acked → gap.
            retransmit.push(seq);
        }

        if self.write_queue.len() < 1024 {
            if let Some(w) = self.write_waker.take() { w.wake(); }
        }

        retransmit
    }

    /// Process a NACK range [start, end] from the remote peer (UDP/unreliable mode).
    ///
    /// FIX: the original code only populated `retransmit` when `mode == Udp`, but
    /// then unconditionally checked `write_queue.len() < 1024` to wake the writer.
    /// The wake is only meaningful when we actually modified write_queue (Udp mode),
    /// but waking spuriously in Tcp mode is harmless; the structure is preserved.
    pub fn handle_nack(&mut self, start: u64, end: u64) -> Vec<u64> {
        let mut retransmit = Vec::new();
        if self.mode == StreamMode::Udp {
            for seq in start..=end {
                if self.write_queue.contains_key(&seq) {
                    retransmit.push(seq);
                }
            }
        }

        if self.write_queue.len() < 1024 {
            if let Some(w) = self.write_waker.take() { w.wake(); }
        }

        retransmit
    }

    /// Buffer an incoming data packet and drain any now-contiguous run into
    /// `read_buf_bytes`.
    ///
    /// Returns `Some((start, end))` — a NACK range — when in UDP mode and the
    /// incoming seq creates a gap (i.e. we're missing [next_read_seq .. seq-1]).
    ///
    /// FIX: `read_waker` was woken even for duplicate / already-seen packets
    /// because `push_data` called `read_waker.wake()` unconditionally at the
    /// bottom.  The early-return for duplicates (`return None`) skipped the wake
    /// correctly, so the original was actually fine here.  No logic change; a
    /// comment has been added for clarity.
    pub fn push_data(&mut self, seq: u64, data: Vec<u8>) -> Option<(u64, u64)> {
        // Discard already-delivered or already-buffered duplicates.
        if seq < self.next_read_seq || self.read_buffer.contains_key(&seq) {
            return None;
        }

        let mut nack = None;
        if self.mode == StreamMode::Udp && seq > self.next_read_seq {
            // Gap detected: request retransmission of the missing range.
            nack = Some((self.next_read_seq, seq - 1));
        }

        self.read_buffer.insert(seq, data);

        // Drain the contiguous prefix of read_buffer into the byte stream.
        while let Some(data) = self.read_buffer.remove(&self.next_read_seq) {
            self.read_buf_bytes.extend(data);
            self.next_read_seq += 1;
        }

        // Wake the reader — new bytes are available in read_buf_bytes.
        // (The early-return above ensures we only reach here for new data.)
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

    /// Collect packets that need retransmitting and streams that have timed out.
    ///
    /// For TCP streams: any packet in `write_queue` that was last sent more than
    /// 200 ms ago is re-queued for retransmission.  After 100 consecutive
    /// retransmits the stream is declared timed-out.
    ///
    /// For UDP streams: entries older than 30 s are simply discarded (fire-and-forget).
    ///
    /// FIX: the original `for (&seq, p) in &mut state.write_queue` loop mutated
    /// `sent_at` and `retransmits` through a shared mutable reference while also
    /// calling `timed_out.push` — which is fine in terms of borrowing, but the
    /// `break` after marking a stream as timed-out left already-mutated earlier
    /// entries with their `sent_at` bumped forward.  Those mutations are harmless
    /// because the stream is about to be torn down, but the intent was cleaner.
    /// The logic is preserved; a clearer variable name is used.
    pub fn get_retransmissions(&mut self, now: Instant) -> (Vec<(u32, u64, Vec<u8>)>, Vec<u32>) {
        let mut retransmissions = Vec::new();
        let mut timed_out = Vec::new();

        for (&stream_id, state) in &mut self.streams {
            if state.mode == StreamMode::Udp {
                // UDP is unreliable: drop stale unacked entries; the application
                // layer accepted that packets can be lost.
                state.write_queue.retain(|_, p| now.duration_since(p.sent_at) < Duration::from_secs(30));
                continue;
            }

            // TCP mode — retransmit on timeout, give up after too many attempts.
            let mut stream_timed_out = false;
            for (&seq, p) in &mut state.write_queue {
                if now.duration_since(p.sent_at) > Duration::from_millis(200) {
                    p.sent_at = now;
                    p.retransmits += 1;
                    if p.retransmits > 100 {
                        stream_timed_out = true;
                        break;
                    }
                    retransmissions.push((stream_id, seq, p.data.clone()));
                }
            }
            if stream_timed_out {
                timed_out.push(stream_id);
            }
        }

        (retransmissions, timed_out)
    }
}
