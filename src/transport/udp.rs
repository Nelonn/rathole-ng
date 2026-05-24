use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use rand::{random, RngCore};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::config::{TransportConfig, UdpTransportConfig};
use super::{AddrMaybeCached, SocketOpts, Transport};

pub struct UdpTransport {
    _config: UdpTransportConfig,
    cipher: ChaCha20Poly1305,
}

impl Debug for UdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpTransport").finish()
    }
}

pub struct UdpAcceptor {
    _socket: Arc<UdpSocket>,
    incoming_rx: tokio::sync::Mutex<mpsc::Receiver<UdpStream>>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for UdpAcceptor {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[derive(Clone, Copy)]
struct UdpHeader {
    stream_id: u32,
    packet_type: u8,
    seq: u64,
    ack: u64,
    ack_bits: u64,
}

struct IncomingPacket {
    header: UdpHeader,
    payload: Vec<u8>,
    src_addr: SocketAddr,
}

struct SentPacket {
    _seq: u64,
    data: Vec<u8>,
    sent_at: Instant,
}

struct UdpStreamInner {
    peer_addr: SocketAddr,
    next_write_seq: u64,
    next_read_seq: u64,
    read_buffer: BTreeMap<u64, Vec<u8>>,
    read_buf_bytes: Vec<u8>,
    write_queue: BTreeMap<u64, SentPacket>,
    established: bool,
    closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    last_sent_at: Instant,
    last_received_at: Instant,
    shutdown_tx1: Option<tokio::sync::oneshot::Sender<()>>,
    shutdown_tx2: Option<tokio::sync::oneshot::Sender<()>>,
    active_streams: Option<(Arc<Mutex<std::collections::HashMap<u32, mpsc::Sender<IncomingPacket>>>>, u32)>,
    nack_mode: bool,
    is_client: bool,
}

pub struct UdpStream {
    stream_id: u32,
    inner: Arc<Mutex<UdpStreamInner>>,
    socket: Arc<UdpSocket>,
    cipher: ChaCha20Poly1305,
}

impl Debug for UdpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpStream")
            .field("stream_id", &self.stream_id)
            .finish()
    }
}

fn encode_header(h: &UdpHeader, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&h.stream_id.to_be_bytes());
    buf.push(h.packet_type);
    buf.extend_from_slice(&h.seq.to_be_bytes());
    buf.extend_from_slice(&h.ack.to_be_bytes());
    buf.extend_from_slice(&h.ack_bits.to_be_bytes());
}

fn decode_header(buf: &[u8]) -> Option<(UdpHeader, &[u8])> {
    if buf.len() < 29 {
        return None;
    }
    let stream_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    let packet_type = buf[4];
    let seq = u64::from_be_bytes(buf[5..13].try_into().unwrap());
    let ack = u64::from_be_bytes(buf[13..21].try_into().unwrap());
    let ack_bits = u64::from_be_bytes(buf[21..29].try_into().unwrap());
    Some((
        UdpHeader {
            stream_id,
            packet_type,
            seq,
            ack,
            ack_bits,
        },
        &buf[29..],
    ))
}

fn start_timer_task(
    inner: Arc<Mutex<UdpStreamInner>>,
    socket: Arc<UdpSocket>,
    stream_id: u32,
    cipher: ChaCha20Poly1305,
) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_millis(50));
        loop {
            ticker.tick().await;

            let mut to_send = Vec::new();
            let mut send_ping = false;
            let peer_addr = {
                let mut lock = inner.lock().unwrap();
                if lock.closed {
                    break;
                }
                let now = Instant::now();
                if lock.established && now.duration_since(lock.last_received_at) >= Duration::from_millis(10000) {
                    lock.closed = true;
                    tracing::info!("udp stream {} closed due to inactivity timeout", stream_id);
                    if let Some(w) = lock.read_waker.take() {
                        w.wake();
                    }
                    if let Some(w) = lock.write_waker.take() {
                        w.wake();
                    }
                    break;
                }

                if lock.established && now.duration_since(lock.last_sent_at) >= Duration::from_millis(2000) {
                    send_ping = true;
                    lock.last_sent_at = now;
                }

                if lock.nack_mode {
                    let mut expired = Vec::new();
                    for (&seq, sent) in &lock.write_queue {
                        if now.duration_since(sent.sent_at) >= Duration::from_millis(3000) {
                            expired.push(seq);
                        }
                    }
                    for seq in expired {
                        lock.write_queue.remove(&seq);
                    }
                } else {
                    let mut retransmitted = false;
                    for (&seq, sent) in &mut lock.write_queue {
                        if now.duration_since(sent.sent_at) >= Duration::from_millis(200) {
                            sent.sent_at = now;
                            to_send.push((seq, sent.data.clone()));
                            retransmitted = true;
                        }
                    }
                    if retransmitted {
                        lock.last_sent_at = now;
                    }
                }

                lock.peer_addr
            };

            for (seq, data) in to_send {
                let ack = {
                    let lock = inner.lock().unwrap();
                    lock.next_read_seq.saturating_sub(1)
                };
                let ack_bits = {
                    let lock = inner.lock().unwrap();
                    let mut bits = 0u64;
                    for i in 0..64 {
                        if lock.read_buffer.contains_key(&(ack + 1 + i)) {
                            bits |= 1 << i;
                        }
                    }
                    bits
                };
                let h = UdpHeader {
                    stream_id,
                    packet_type: 0,
                    seq,
                    ack,
                    ack_bits,
                };
                let mut payload = Vec::new();
                encode_header(&h, &mut payload);
                payload.extend_from_slice(&data);

                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                if let Ok(encrypted) = cipher.encrypt(nonce, payload.as_slice()) {
                    let mut pkt = nonce_bytes.to_vec();
                    pkt.extend_from_slice(&encrypted);
                    if let Err(_) = socket.try_send_to(&pkt, peer_addr) {
                        let socket_c = socket.clone();
                        tokio::spawn(async move {
                            let _ = socket_c.send_to(&pkt, peer_addr).await;
                        });
                    }
                }
            }

            if send_ping {
                let h = UdpHeader {
                    stream_id,
                    packet_type: 5,
                    seq: 0,
                    ack: 0,
                    ack_bits: 0,
                };
                let mut payload = Vec::new();
                encode_header(&h, &mut payload);
                let garbage_len = (random::<usize>() % 224) + 32;
                let mut garbage = vec![0u8; garbage_len];
                rand::thread_rng().fill_bytes(&mut garbage);
                payload.extend_from_slice(&garbage);

                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                if let Ok(encrypted) = cipher.encrypt(nonce, payload.as_slice()) {
                    let mut pkt = nonce_bytes.to_vec();
                    pkt.extend_from_slice(&encrypted);
                    if let Err(_) = socket.try_send_to(&pkt, peer_addr) {
                        let socket_c = socket.clone();
                        tokio::spawn(async move {
                            let _ = socket_c.send_to(&pkt, peer_addr).await;
                        });
                    }
                }
            }
        }
    });
}

fn send_nack(
    stream_id: u32,
    start: u64,
    end: u64,
    cipher: &ChaCha20Poly1305,
    socket: &Arc<UdpSocket>,
    peer_addr: SocketAddr,
    _is_client: bool,
) {
    let resp_h = UdpHeader {
        stream_id,
        packet_type: 4,
        seq: start,
        ack: end,
        ack_bits: 0,
    };
    let mut resp_payload = Vec::new();
    encode_header(&resp_h, &mut resp_payload);
    let garbage_len = (random::<usize>() % 224) + 32;
    let mut garbage = vec![0u8; garbage_len];
    rand::thread_rng().fill_bytes(&mut garbage);
    resp_payload.extend_from_slice(&garbage);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    if let Ok(encrypted) = cipher.encrypt(nonce, resp_payload.as_slice()) {
        let mut pkt = nonce_bytes.to_vec();
        pkt.extend_from_slice(&encrypted);
        if let Err(_) = socket.try_send_to(&pkt, peer_addr) {
            let socket_c = socket.clone();
            tokio::spawn(async move {
                let _ = socket_c.send_to(&pkt, peer_addr).await;
            });
        }
    }
}

fn start_reader_task(
    inner: Arc<Mutex<UdpStreamInner>>,
    mut rx: mpsc::Receiver<IncomingPacket>,
    socket: Arc<UdpSocket>,
    stream_id: u32,
    cipher: ChaCha20Poly1305,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    tracing::info!("start_reader_task spawned for stream_id={}", stream_id);
    tokio::spawn(async move {
        tracing::info!("start_reader_task running loop for stream_id={}", stream_id);
        loop {
            tokio::select! {
                packet_opt = rx.recv() => {
                    tracing::info!("start_reader_task rx.recv for stream_id={}: {:?}", stream_id, packet_opt.is_some());
                    let Some(packet) = packet_opt else { break; };
                    let mut to_fast_retransmit = Vec::new();
                    let peer_addr;
                    let is_client;

                    {
                        let mut lock = inner.lock().unwrap();
                        if lock.closed {
                            break;
                        }

                        is_client = lock.is_client;
                        lock.last_received_at = Instant::now();

                        if lock.peer_addr != packet.src_addr {
                            lock.peer_addr = packet.src_addr;
                        }
                        peer_addr = lock.peer_addr;

                        let h = packet.header;

                        if h.packet_type == 4 {
                            if lock.nack_mode {
                                let nack_start = h.seq;
                                let nack_end = h.ack;
                                for seq in nack_start..=nack_end {
                                    if let Some(sent) = lock.write_queue.get_mut(&seq) {
                                        sent.sent_at = Instant::now();
                                        to_fast_retransmit.push((seq, sent.data.clone()));
                                    }
                                }
                                lock.last_sent_at = Instant::now();
                            } else {
                                let acked_seqs: Vec<u64> = lock.write_queue.keys().cloned().collect();
                                let mut highest_acked = h.ack;
                                for seq in acked_seqs {
                                    if seq <= h.ack {
                                        lock.write_queue.remove(&seq);
                                    } else {
                                        let offset = seq.saturating_sub(h.ack + 1);
                                        if offset < 64 && ((h.ack_bits >> offset) & 1) == 1 {
                                            lock.write_queue.remove(&seq);
                                            if seq > highest_acked {
                                                highest_acked = seq;
                                            }
                                        }
                                    }
                                }

                                if highest_acked > h.ack {
                                    for (&seq, sent) in &mut lock.write_queue {
                                        if seq < highest_acked {
                                            sent.sent_at = Instant::now();
                                            to_fast_retransmit.push((seq, sent.data.clone()));
                                        }
                                    }
                                }
                            }
                        } else if h.packet_type == 1 {
                            lock.established = true;
                            tracing::info!("udp stream {} established (received Syn)", stream_id);
                            lock.last_sent_at = Instant::now();
                            let resp_h = UdpHeader {
                                stream_id,
                                packet_type: 2,
                                seq: 0,
                                ack: 0,
                                ack_bits: 0,
                            };
                            let mut resp_payload = Vec::new();
                            encode_header(&resp_h, &mut resp_payload);
                            let garbage_len = (random::<usize>() % 224) + 32;
                            let mut garbage = vec![0u8; garbage_len];
                            rand::thread_rng().fill_bytes(&mut garbage);
                            resp_payload.extend_from_slice(&garbage);

                            let mut nonce_bytes = [0u8; 12];
                            rand::thread_rng().fill_bytes(&mut nonce_bytes);
                            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                            if let Ok(encrypted) = cipher.encrypt(nonce, resp_payload.as_slice()) {
                                let mut pkt = nonce_bytes.to_vec();
                                pkt.extend_from_slice(&encrypted);
                            if let Err(_) = socket.try_send_to(&pkt, peer_addr) {
                                let socket_c = socket.clone();
                                tokio::spawn(async move {
                                    let _ = socket_c.send_to(&pkt, peer_addr).await;
                                });
                            }
                            }
                        } else if h.packet_type == 2 {
                            lock.established = true;
                            tracing::info!("udp stream {} established (received Syn-Ack)", stream_id);
                        } else if h.packet_type == 3 {
                            lock.closed = true;
                            tracing::info!("udp stream {} closed via Fin packet", stream_id);
                            if let Some(w) = lock.read_waker.take() {
                                w.wake();
                            }
                            if let Some(w) = lock.write_waker.take() {
                                w.wake();
                            }
                        } else if h.packet_type == 5 {
                            let resp_h = UdpHeader {
                                stream_id,
                                packet_type: 6,
                                seq: 0,
                                ack: 0,
                                ack_bits: 0,
                            };
                            let mut resp_payload = Vec::new();
                            encode_header(&resp_h, &mut resp_payload);
                            let garbage_len = (random::<usize>() % 224) + 32;
                            let mut garbage = vec![0u8; garbage_len];
                            rand::thread_rng().fill_bytes(&mut garbage);
                            resp_payload.extend_from_slice(&garbage);

                            let mut nonce_bytes = [0u8; 12];
                            rand::thread_rng().fill_bytes(&mut nonce_bytes);
                            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                            if let Ok(encrypted) = cipher.encrypt(nonce, resp_payload.as_slice()) {
                                let mut pkt = nonce_bytes.to_vec();
                                pkt.extend_from_slice(&encrypted);
                            if let Err(_) = socket.try_send_to(&pkt, peer_addr) {
                                let socket_c = socket.clone();
                                tokio::spawn(async move {
                                    let _ = socket_c.send_to(&pkt, peer_addr).await;
                                });
                            }
                            }
                        } else if h.packet_type == 0 {
                            if lock.nack_mode {
                                if h.seq >= lock.next_read_seq {
                                    lock.read_buffer.insert(h.seq, packet.payload);
                                    if h.seq > lock.next_read_seq {
                                        let mut nack_start = None;
                                        for s in lock.next_read_seq..h.seq {
                                            if !lock.read_buffer.contains_key(&s) {
                                                if nack_start.is_none() {
                                                    nack_start = Some(s);
                                                }
                                            } else {
                                                if let Some(start) = nack_start {
                                                    let end = s - 1;
                                                    send_nack(stream_id, start, end, &cipher, &socket, peer_addr, is_client);
                                                    nack_start = None;
                                                }
                                            }
                                        }
                                        if let Some(start) = nack_start {
                                            let end = h.seq - 1;
                                            send_nack(stream_id, start, end, &cipher, &socket, peer_addr, is_client);
                                        }
                                    }
                                    loop {
                                        let next_seq = lock.next_read_seq;
                                        if let Some(data) = lock.read_buffer.remove(&next_seq) {
                                            lock.read_buf_bytes.extend_from_slice(&data);
                                            lock.next_read_seq += 1;
                                        } else {
                                            break;
                                        }
                                    }
                                    if let Some(w) = lock.read_waker.take() {
                                        w.wake();
                                    }
                                }
                            } else {
                                if h.seq >= lock.next_read_seq {
                                    lock.read_buffer.insert(h.seq, packet.payload);
                                    loop {
                                        let next_seq = lock.next_read_seq;
                                        if let Some(data) = lock.read_buffer.remove(&next_seq) {
                                            lock.read_buf_bytes.extend_from_slice(&data);
                                            lock.next_read_seq += 1;
                                        } else {
                                            break;
                                        }
                                    }
                                    if let Some(w) = lock.read_waker.take() {
                                        w.wake();
                                    }
                                }

                                let ack = lock.next_read_seq.saturating_sub(1);
                                let mut ack_bits = 0u64;
                                for i in 0..64 {
                                    if lock.read_buffer.contains_key(&(ack + 1 + i)) {
                                        ack_bits |= 1 << i;
                                    }
                                }
                                lock.last_sent_at = Instant::now();
                                let resp_h = UdpHeader {
                                    stream_id,
                                    packet_type: 4,
                                    seq: 0,
                                    ack,
                                    ack_bits,
                                };
                                let mut resp_payload = Vec::new();
                                encode_header(&resp_h, &mut resp_payload);
                                let garbage_len = (random::<usize>() % 224) + 32;
                                let mut garbage = vec![0u8; garbage_len];
                                rand::thread_rng().fill_bytes(&mut garbage);
                                resp_payload.extend_from_slice(&garbage);

                                let mut nonce_bytes = [0u8; 12];
                                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                                if let Ok(encrypted) = cipher.encrypt(nonce, resp_payload.as_slice()) {
                                    let mut pkt = nonce_bytes.to_vec();
                                    pkt.extend_from_slice(&encrypted);
                                    if let Err(_) = socket.try_send_to(&pkt, lock.peer_addr) {
                                        let socket_c = socket.clone();
                                        let dest = lock.peer_addr;
                                        tokio::spawn(async move {
                                            let _ = socket_c.send_to(&pkt, dest).await;
                                        });
                                    }
                                }
                            }
                        }

                        if lock.write_queue.is_empty() {
                            if let Some(w) = lock.write_waker.take() {
                                w.wake();
                            }
                        }
                    }

                    for (seq, data) in to_fast_retransmit {
                        let ack = {
                            let lock = inner.lock().unwrap();
                            lock.next_read_seq.saturating_sub(1)
                        };
                        let ack_bits = {
                            let lock = inner.lock().unwrap();
                            let mut bits = 0u64;
                            for i in 0..64 {
                                if lock.read_buffer.contains_key(&(ack + 1 + i)) {
                                    bits |= 1 << i;
                                }
                            }
                            bits
                        };
                        let h = UdpHeader {
                            stream_id,
                            packet_type: 0,
                            seq,
                            ack,
                            ack_bits,
                        };
                        let mut payload = Vec::new();
                        encode_header(&h, &mut payload);
                        payload.extend_from_slice(&data);

                        let mut nonce_bytes = [0u8; 12];
                        rand::thread_rng().fill_bytes(&mut nonce_bytes);
                        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                        if let Ok(encrypted) = cipher.encrypt(nonce, payload.as_slice()) {
                            let mut pkt = nonce_bytes.to_vec();
                            pkt.extend_from_slice(&encrypted);
                            if let Err(_) = socket.try_send_to(&pkt, peer_addr) {
                                let socket_c = socket.clone();
                                tokio::spawn(async move {
                                    let _ = socket_c.send_to(&pkt, peer_addr).await;
                                });
                            }
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("start_reader_task shutdown_rx triggered for stream_id={}", stream_id);
                    break;
                }
            }
        }
    });
}

impl UdpStream {
    fn new(
        stream_id: u32,
        peer_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        rx: mpsc::Receiver<IncomingPacket>,
        cipher: ChaCha20Poly1305,
        is_client: bool,
        shutdown_tx2: Option<tokio::sync::oneshot::Sender<()>>,
        active_streams: Option<Arc<Mutex<std::collections::HashMap<u32, mpsc::Sender<IncomingPacket>>>>>,
    ) -> Self {
        let (shutdown_tx1, shutdown_rx) = tokio::sync::oneshot::channel();
        let inner = Arc::new(Mutex::new(UdpStreamInner {
            peer_addr,
            next_write_seq: 0,
            next_read_seq: 0,
            read_buffer: BTreeMap::new(),
            read_buf_bytes: Vec::new(),
            write_queue: BTreeMap::new(),
            established: !is_client,
            closed: false,
            read_waker: None,
            write_waker: None,
            last_sent_at: Instant::now(),
            last_received_at: Instant::now(),
            shutdown_tx1: Some(shutdown_tx1),
            shutdown_tx2,
            active_streams: active_streams.map(|as_set| (as_set, stream_id)),
            nack_mode: false,
            is_client,
        }));

        start_reader_task(inner.clone(), rx, socket.clone(), stream_id, cipher.clone(), shutdown_rx);
        start_timer_task(inner.clone(), socket.clone(), stream_id, cipher.clone());

        UdpStream {
            stream_id,
            inner,
            socket,
            cipher,
        }
    }

    async fn connect(&mut self) -> Result<()> {
        let mut ticker = interval(Duration::from_millis(100));
        let start = Instant::now();
        tracing::info!("udp connect: stream_id={} remote={:?}", self.stream_id, self.peer_addr());
        loop {
            if start.elapsed() > Duration::from_secs(15) {
                tracing::info!("udp connect handshake timeout: stream_id={}", self.stream_id);
                return Err(anyhow!("Handshake timed out"));
            }

            {
                let lock = self.inner.lock().unwrap();
                if lock.established {
                    break;
                }
                if lock.closed {
                    return Err(anyhow!("Connection closed during handshake"));
                }
            }

            let h = UdpHeader {
                stream_id: self.stream_id,
                packet_type: 1,
                seq: 0,
                ack: 0,
                ack_bits: 0,
            };
            let mut payload = Vec::new();
            encode_header(&h, &mut payload);
            let garbage_len = (random::<usize>() % 224) + 32;
            let mut garbage = vec![0u8; garbage_len];
            rand::thread_rng().fill_bytes(&mut garbage);
            payload.extend_from_slice(&garbage);

            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            if let Ok(encrypted) = self.cipher.encrypt(nonce, payload.as_slice()) {
                let mut pkt = nonce_bytes.to_vec();
                pkt.extend_from_slice(&encrypted);
                let peer_addr = {
                    let lock = self.inner.lock().unwrap();
                    lock.peer_addr
                };
                if let Err(e) = self.socket.try_send_to(&pkt, peer_addr) {
                    tracing::info!("try_send_to failed for stream_id={}: {:?}", self.stream_id, e);
                    let socket_c = self.socket.clone();
                    let stream_id = self.stream_id;
                    tokio::spawn(async move {
                        if let Err(e) = socket_c.send_to(&pkt, peer_addr).await {
                            tracing::info!("send_to failed for stream_id={}: {:?}", stream_id, e);
                        }
                    });
                }
            }

            ticker.tick().await;
        }
        Ok(())
    }

    fn peer_addr(&self) -> SocketAddr {
        let lock = self.inner.lock().unwrap();
        lock.peer_addr
    }
}

impl Drop for UdpStream {
    fn drop(&mut self) {
        let mut lock = self.inner.lock().unwrap();
        if let Some((active, sid)) = lock.active_streams.take() {
            let mut active_lock = active.lock().unwrap();
            active_lock.remove(&sid);
        }
        if let Some(tx) = lock.shutdown_tx1.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = lock.shutdown_tx2.take() {
            let _ = tx.send(());
        }
        if !lock.closed {
            lock.closed = true;
            if let Some(w) = lock.read_waker.take() {
                w.wake();
            }
            if let Some(w) = lock.write_waker.take() {
                w.wake();
            }

            let h = UdpHeader {
                stream_id: self.stream_id,
                packet_type: 3,
                seq: 0,
                ack: 0,
                ack_bits: 0,
            };
            let mut payload = Vec::new();
            encode_header(&h, &mut payload);
            let garbage_len = (random::<usize>() % 224) + 32;
            let mut garbage = vec![0u8; garbage_len];
            rand::thread_rng().fill_bytes(&mut garbage);
            payload.extend_from_slice(&garbage);

            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            if let Ok(encrypted) = self.cipher.encrypt(nonce, payload.as_slice()) {
                let mut pkt = nonce_bytes.to_vec();
                pkt.extend_from_slice(&encrypted);
                let socket = self.socket.clone();
                let peer_addr = lock.peer_addr;
                if let Err(_) = socket.try_send_to(&pkt, peer_addr) {
                    tokio::spawn(async move {
                        let _ = socket.send_to(&pkt, peer_addr).await;
                    });
                }
            }
        }
    }
}

impl AsyncRead for UdpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut lock = self.inner.lock().unwrap();
        if lock.closed && lock.read_buf_bytes.is_empty() {
            return Poll::Ready(Ok(()));
        }

        if !lock.read_buf_bytes.is_empty() {
            let len = std::cmp::min(buf.remaining(), lock.read_buf_bytes.len());
            let data: Vec<u8> = lock.read_buf_bytes.drain(0..len).collect();
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }

        lock.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for UdpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut lock = self.inner.lock().unwrap();
        if lock.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "Stream closed",
            )));
        }

        if lock.write_queue.len() > 512 {
            lock.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let chunk_size = 1200;
        let mut sent = 0;
        let peer_addr = lock.peer_addr;

        while sent < buf.len() {
            let end = std::cmp::min(sent + chunk_size, buf.len());
            let chunk = &buf[sent..end];

            let seq = lock.next_write_seq;
            lock.next_write_seq += 1;

            let sent_packet = SentPacket {
                _seq: seq,
                data: chunk.to_vec(),
                sent_at: Instant::now(),
            };
            lock.write_queue.insert(seq, sent_packet);

            let h = if lock.nack_mode {
                UdpHeader {
                    stream_id: self.stream_id,
                    packet_type: 0,
                    seq,
                    ack: 0,
                    ack_bits: 0,
                }
            } else {
                let ack = lock.next_read_seq.saturating_sub(1);
                let mut ack_bits = 0u64;
                for i in 0..64 {
                    if lock.read_buffer.contains_key(&(ack + 1 + i)) {
                        ack_bits |= 1 << i;
                    }
                }
                UdpHeader {
                    stream_id: self.stream_id,
                    packet_type: 0,
                    seq,
                    ack,
                    ack_bits,
                }
            };
            let mut payload = Vec::new();
            encode_header(&h, &mut payload);
            payload.extend_from_slice(chunk);

            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            if let Ok(encrypted) = self.cipher.encrypt(nonce, payload.as_slice()) {
                let mut pkt = nonce_bytes.to_vec();
                pkt.extend_from_slice(&encrypted);
                let socket = self.socket.clone();
                lock.last_sent_at = Instant::now();
                if let Err(_) = socket.try_send_to(&pkt, peer_addr) {
                    tokio::spawn(async move {
                        let _ = socket.send_to(&pkt, peer_addr).await;
                    });
                }
            }

            sent = end;
        }

        Poll::Ready(Ok(sent))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut lock = self.inner.lock().unwrap();
        if !lock.closed {
            lock.closed = true;
            let h = UdpHeader {
                stream_id: self.stream_id,
                packet_type: 3,
                seq: 0,
                ack: 0,
                ack_bits: 0,
            };
            let mut payload = Vec::new();
            encode_header(&h, &mut payload);
            let garbage_len = (random::<usize>() % 224) + 32;
            let mut garbage = vec![0u8; garbage_len];
            rand::thread_rng().fill_bytes(&mut garbage);
            payload.extend_from_slice(&garbage);

            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            if let Ok(encrypted) = self.cipher.encrypt(nonce, payload.as_slice()) {
                let mut pkt = nonce_bytes.to_vec();
                pkt.extend_from_slice(&encrypted);
                let socket = self.socket.clone();
                let peer_addr = lock.peer_addr;
                if let Err(_) = socket.try_send_to(&pkt, peer_addr) {
                    tokio::spawn(async move {
                        let _ = socket.send_to(&pkt, peer_addr).await;
                    });
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl Transport for UdpTransport {
    type Acceptor = UdpAcceptor;
    type RawStream = UdpStream;
    type Stream = UdpStream;

    fn new(config: &TransportConfig) -> Result<Self> {
        let config = match &config.udp {
            Some(v) => v.clone(),
            None => return Err(anyhow!("Missing UDP config")),
        };
        let mut hasher = Sha256::new();
        hasher.update(config.psk.as_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(&key);
        Ok(UdpTransport { _config: config, cipher })
    }

    fn hint(_conn: &Self::Stream, _opts: SocketOpts) {}

    fn set_udp_nack_mode(conn: &Self::Stream) {
        let mut inner = conn.inner.lock().unwrap();
        inner.nack_mode = true;
    }

    async fn bind<T: ToSocketAddrs + Send + Sync>(&self, addr: T) -> Result<Self::Acceptor> {
        let socket_addr = crate::helper::to_socket_addr(addr).await?;
        let socket2 = socket2::Socket::new(
            socket2::Domain::for_address(socket_addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket2.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket2.set_reuse_port(true)?;
        socket2.bind(&socket_addr.into())?;
        let socket = std::net::UdpSocket::from(socket2);
        crate::helper::disable_udp_connreset(&socket)?;
        let socket = UdpSocket::from_std(socket)?;
        let socket = Arc::new(socket);
        let (incoming_tx, incoming_rx) = mpsc::channel(1024);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

        let cipher = self.cipher.clone();
        let socket_clone = socket.clone();
        let active_streams: Arc<Mutex<std::collections::HashMap<u32, mpsc::Sender<IncomingPacket>>>> = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let active_streams_clone = active_streams.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    recv_res = socket_clone.recv_from(&mut buf) => {
                        let (len, src_addr) = match recv_res {
                            Ok(x) => x,
                            Err(e) => {
                                tracing::error!("acceptor recv_from error: {:?}", e);
                                continue;
                            }
                        };
                        tracing::info!("acceptor received {} bytes from {:?}", len, src_addr);

                        if len < 41 {
                            tracing::info!("acceptor packet too short");
                            continue;
                        }

                        let nonce = chacha20poly1305::Nonce::from_slice(&buf[..12]);
                        let decrypted = match cipher.decrypt(nonce, &buf[12..len]) {
                            Ok(x) => x,
                            Err(e) => {
                                tracing::info!("acceptor decrypt failed: {:?}", e);
                                continue;
                            }
                        };

                        let Some((header, payload)) = decode_header(&decrypted) else {
                            tracing::info!("acceptor decode header failed");
                            continue;
                        };

                        tracing::info!("acceptor header: stream_id={}, type={}", header.stream_id, header.packet_type);

                        let stream_id = header.stream_id;
                        let incoming = IncomingPacket {
                            header,
                            payload: payload.to_vec(),
                            src_addr,
                        };

                        {
                            let active = active_streams_clone.lock().unwrap();
                            if let Some(tx) = active.get(&stream_id) {
                                let _ = tx.try_send(incoming);
                                continue;
                            }
                        }

                        if header.packet_type != 1 {
                            tracing::info!("acceptor ignoring packet with type != 1: {}", header.packet_type);
                            continue;
                        }

                        let (tx, rx) = mpsc::channel(1024);
                        
                        {
                            let mut active = active_streams_clone.lock().unwrap();
                            active.insert(stream_id, tx.clone());
                        }

                        let (shutdown_tx2, _) = tokio::sync::oneshot::channel();

                        let stream = UdpStream::new(
                            stream_id,
                            src_addr,
                            socket_clone.clone(),
                            rx,
                            cipher.clone(),
                            false,
                            Some(shutdown_tx2),
                            Some(active_streams_clone.clone()),
                        );

                        let _ = tx.try_send(incoming);

                        tracing::info!("acceptor sending stream to incoming_tx for stream_id={}", stream_id);
                        if incoming_tx.send(stream).await.is_err() {
                            tracing::info!("acceptor failed sending stream to incoming_tx for stream_id={}", stream_id);
                            break;
                        }
                        tracing::info!("acceptor sent stream to incoming_tx for stream_id={}", stream_id);
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });

        Ok(UdpAcceptor {
            _socket: socket,
            incoming_rx: tokio::sync::Mutex::new(incoming_rx),
            shutdown_tx: Some(shutdown_tx),
        })
    }

    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)> {
        let mut rx = a.incoming_rx.lock().await;
        if let Some(stream) = rx.recv().await {
            let addr = stream.peer_addr();
            Ok((stream, addr))
        } else {
            Err(anyhow!("Acceptor closed"))
        }
    }

    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> {
        Ok(conn)
    }

    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream> {
        let socket_addr = addr
            .socket_addr
            .ok_or_else(|| anyhow!("Address not resolved"))?;
        let socket = UdpSocket::bind(if socket_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .await?;
        crate::helper::disable_udp_connreset(&socket)?;
        
        let socket = Arc::new(socket);

        let stream_id = random::<u32>();
        let (tx, rx) = mpsc::channel(1024);
        let (shutdown_tx2, mut shutdown_rx2) = tokio::sync::oneshot::channel();

        let cipher = self.cipher.clone();
        let socket_clone = socket.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    recv_res = socket_clone.recv_from(&mut buf) => {
                        let (len, src_addr) = match recv_res {
                            Ok(x) => x,
                            Err(e) => {
                                tracing::error!("client recv_from error: {:?}", e);
                                continue;
                            }
                        };
                        tracing::info!("client received {} bytes from {:?}", len, src_addr);

                        if src_addr != socket_addr {
                            tracing::info!("client packet from wrong addr: {:?}", src_addr);
                            continue;
                        }

                        if len < 41 {
                            tracing::info!("client packet too short");
                            continue;
                        }

                        let nonce = chacha20poly1305::Nonce::from_slice(&buf[..12]);
                        let decrypted = match cipher.decrypt(nonce, &buf[12..len]) {
                            Ok(x) => x,
                            Err(e) => {
                                tracing::info!("client decrypt failed: {:?}", e);
                                continue;
                            }
                        };

                        let Some((header, payload)) = decode_header(&decrypted) else {
                            tracing::info!("client decode header failed");
                            continue;
                        };

                        tracing::info!("client header: stream_id={}, type={}", header.stream_id, header.packet_type);

                        if header.stream_id != stream_id {
                            tracing::info!("client stream_id mismatch: expected={}, got={}", stream_id, header.stream_id);
                            continue;
                        }

                        let incoming = IncomingPacket {
                            header,
                            payload: payload.to_vec(),
                            src_addr,
                        };

                        if tx_clone.send(incoming).await.is_err() {
                            break;
                        }
                    }
                    _ = &mut shutdown_rx2 => {
                        break;
                    }
                }
            }
        });

        let mut stream = UdpStream::new(
            stream_id,
            socket_addr,
            socket,
            rx,
            self.cipher.clone(),
            true,
            Some(shutdown_tx2),
            None,
        );

        stream.connect().await?;

        Ok(stream)
    }
}
