use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::{random, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;
use tracing::trace;

use crate::config::TransportConfig;
use super::{AddrMaybeCached, SocketOpts, Transport};
use super::reliability::{
    PacketKind, Reliability, SentPacket, StreamMode, StreamState, TransportPacketHeader,
};

struct UdpStreamInner {
    peer_addr: SocketAddr,
    reliability: Reliability,
    last_received: Instant,
    last_sent: Instant,
    closed: bool,
}

pub struct UdpStream {
    stream_id: u32,
    inner: Arc<Mutex<UdpStreamInner>>,
    socket: Arc<UdpSocket>,
    cipher: Arc<ChaCha20Poly1305>,
    _shutdown_tx: oneshot::Sender<()>,
    _recv_shutdown_tx: Option<oneshot::Sender<()>>,
    write_tx: mpsc::Sender<(u64, Vec<u8>)>,
}

impl Debug for UdpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpStream").field("stream_id", &self.stream_id).finish()
    }
}

pub struct IncomingPacket {
    pub header: TransportPacketHeader,
    pub payload: Vec<u8>,
    pub src: SocketAddr,
}

struct ListenerPacketRuntime {
    active_streams: Arc<Mutex<HashMap<u32, mpsc::Sender<IncomingPacket>>>>,
    incoming_tx: mpsc::Sender<UdpStream>,
    socket: Arc<UdpSocket>,
    cipher: Arc<ChaCha20Poly1305>,
}

impl ListenerPacketRuntime {
    fn new(socket: Arc<UdpSocket>, incoming_tx: mpsc::Sender<UdpStream>, cipher: Arc<ChaCha20Poly1305>) -> Self {
        Self {
            active_streams: Arc::new(Mutex::new(HashMap::new())),
            incoming_tx,
            socket,
            cipher,
        }
    }

    async fn on_packet(&self, src: SocketAddr, header: TransportPacketHeader, payload: Vec<u8>) {
        let tx = {
            let mut active = self.active_streams.lock().unwrap();
            if let Some(tx) = active.get(&header.channel_id) {
                tx.clone()
            } else if header.packet_kind == PacketKind::StreamOpen {
                let (stream, tx) = UdpStream::new(
                    header.channel_id,
                    src,
                    self.socket.clone(),
                    self.cipher.clone(),
                    Some(self.active_streams.clone()),
                );
                active.insert(header.channel_id, tx.clone());
                let incoming_tx = self.incoming_tx.clone();
                tokio::spawn(async move {
                    let _ = incoming_tx.send(stream).await;
                });
                tx
            } else {
                // Unknown stream: send back a StreamClose to let the peer clean up.
                let close_header = TransportPacketHeader {
                    channel_id: header.channel_id,
                    packet_kind: PacketKind::StreamClose,
                    seq: 0,
                    ack: 0,
                    ack_bits: 0,
                };
                let mut buf = Vec::new();
                close_header.encode(&mut buf);
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                if let Ok(encrypted) = self.cipher.encrypt(nonce, buf.as_slice()) {
                    let mut pkt = nonce_bytes.to_vec();
                    pkt.extend_from_slice(&encrypted);
                    let socket = self.socket.clone();
                    tokio::spawn(async move {
                        let _ = socket.send_to(&pkt, src).await;
                    });
                }
                return;
            }
        };

        let _ = tx.try_send(IncomingPacket { header, payload, src });
    }
}

struct ConnectedPacketRuntime {
    stream_id: u32,
    dest: SocketAddr,
    packet_tx: mpsc::Sender<IncomingPacket>,
}

impl ConnectedPacketRuntime {
    fn new(stream_id: u32, dest: SocketAddr, packet_tx: mpsc::Sender<IncomingPacket>) -> Self {
        Self { stream_id, dest, packet_tx }
    }

    async fn on_packet(&self, src: SocketAddr, header: TransportPacketHeader, payload: Vec<u8>) {
        if src != self.dest || header.channel_id != self.stream_id {
            return;
        }

        let _ = self.packet_tx.try_send(IncomingPacket { header, payload, src });
    }
}

impl UdpStream {
    fn new(
        stream_id: u32,
        peer_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        cipher: Arc<ChaCha20Poly1305>,
        active_streams: Option<Arc<Mutex<HashMap<u32, mpsc::Sender<IncomingPacket>>>>>,
    ) -> (Self, mpsc::Sender<IncomingPacket>) {
        let (packet_tx, packet_rx) = mpsc::channel(1024);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (write_tx, write_rx) = mpsc::channel::<(u64, Vec<u8>)>(1024);
        let mut reliability = Reliability::new();
        reliability.streams.insert(stream_id, StreamState::new(StreamMode::Tcp));

        let inner = Arc::new(Mutex::new(UdpStreamInner {
            peer_addr,
            reliability,
            last_received: Instant::now(),
            last_sent: Instant::now(),
            closed: false,
        }));

        let cipher_clone = cipher.clone();
        let inner_clone = inner.clone();
        let socket_clone = socket.clone();
        let stream = Self {
            stream_id,
            inner: inner.clone(),
            socket: socket.clone(),
            cipher,
            _shutdown_tx: shutdown_tx,
            _recv_shutdown_tx: None,
            write_tx,
        };

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(50));
            let mut packet_rx = packet_rx;
            let mut write_rx = write_rx;
            let mut shutdown_rx = shutdown_rx;
            let cipher = cipher_clone;
            let inner = inner_clone;
            let socket = socket_clone;

            loop {
                tokio::select! {
                    pkt = packet_rx.recv() => {
                        let Some(pkt) = pkt else { break; };
                        if let Err(e) = handle_incoming(&inner, &socket, &cipher, pkt).await {
                            trace!("UdpStream task: handle_incoming error: {}", e);
                            break;
                        }
                    }
                    write_pkt = write_rx.recv() => {
                        let Some((seq, data)) = write_pkt else { break; };
                        if seq == 0 {
                            // seq == 0 is the sentinel for StreamClose
                            let _ = send_packet(&inner, &socket, &cipher, stream_id, PacketKind::StreamClose, 0, &[]).await;
                        } else {
                            if let Err(e) = send_packet(&inner, &socket, &cipher, stream_id, PacketKind::Stream, seq, &data).await {
                                trace!("UdpStream task: send_packet error: {}", e);
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if let Err(e) = handle_tick(&inner, &socket, &cipher).await {
                            trace!("UdpStream task: handle_tick error: {}", e);
                            break;
                        }
                    }
                    _ = &mut shutdown_rx => break,
                }
            }

            // Wake any pending readers/writers so they see the closed state.
            if let Ok(mut lock) = inner.lock() {
                lock.closed = true;
                if let Some(state) = lock.reliability.streams.get_mut(&stream_id) {
                    if let Some(w) = state.read_waker.take() { w.wake(); }
                    if let Some(w) = state.write_waker.take() { w.wake(); }
                }
            }

            if let Some(active) = active_streams {
                if let Ok(mut active_lock) = active.lock() {
                    active_lock.remove(&stream_id);
                }
            }
        });

        (stream, packet_tx)
    }

    async fn connect(&mut self) -> Result<()> {
        let mut ticker = interval(Duration::from_millis(200));
        let start = Instant::now();

        loop {
            if start.elapsed() > Duration::from_secs(10) {
                return Err(anyhow!("handshake timeout"));
            }

            {
                let lock = self.inner.lock().unwrap();
                if lock.closed {
                    return Err(anyhow!("stream closed"));
                }
                if let Some(state) = lock.reliability.streams.get(&self.stream_id) {
                    if state.established { break; }
                }
            }

            // FIX: send StreamOpen immediately on each iteration, then wait for the
            // next tick, rather than waiting first and then sending. This ensures the
            // first SYN goes out right away instead of after a 200 ms delay.
            send_packet(&self.inner, &self.socket, &self.cipher, self.stream_id, PacketKind::StreamOpen, 0, &[]).await?;
            ticker.tick().await;
        }
        Ok(())
    }
}

async fn handle_incoming(
    inner: &Arc<Mutex<UdpStreamInner>>,
    socket: &Arc<UdpSocket>,
    cipher: &ChaCha20Poly1305,
    pkt: IncomingPacket,
) -> Result<()> {
    trace!(
        "handle_incoming: stream_id={}, kind={:?}, seq={}, ack={}, bits={:x}",
        pkt.header.channel_id, pkt.header.packet_kind,
        pkt.header.seq, pkt.header.ack, pkt.header.ack_bits
    );

    let mut to_send = Vec::new();
    // Wakers that must be notified after the lock is dropped.
    let mut read_waker = None;
    let mut write_waker = None;
    let stream_id = pkt.header.channel_id;

    {
        let mut lock = inner.lock().map_err(|e| anyhow!(e.to_string()))?;
        if lock.closed {
            trace!("handle_incoming: stream {} is closed", stream_id);
            return Ok(());
        }
        lock.last_received = Instant::now();
        lock.peer_addr = pkt.src;

        let state = lock.reliability.streams.entry(stream_id).or_insert_with(|| StreamState::new(StreamMode::Tcp));

        match pkt.header.packet_kind {
            PacketKind::StreamOpen => {
                trace!("handle_incoming: stream {} open", stream_id);
                state.established = true;
                to_send.push((PacketKind::StreamOpenAck, 0u64, 0u64, 0u64, vec![]));
            }
            PacketKind::StreamOpenAck => {
                trace!("handle_incoming: stream {} open ack", stream_id);
                state.established = true;
            }
            PacketKind::StreamClose => {
                trace!("handle_incoming: stream {} close", stream_id);
                lock.closed = true;
                // FIX: wake both wakers so poll_read returns EOF and poll_write
                // returns an error immediately instead of hanging forever.
                if let Some(state) = lock.reliability.streams.get_mut(&stream_id) {
                    read_waker = state.read_waker.take();
                    write_waker = state.write_waker.take();
                }
            }
            PacketKind::Stream => {
                trace!("handle_incoming: stream {} data seq={}", stream_id, pkt.header.seq);
                let nack = state.push_data(pkt.header.seq, pkt.payload);
                if let Some((start, end)) = nack {
                    trace!("handle_incoming: stream {} nack {} to {}", stream_id, start, end);
                    to_send.push((PacketKind::Nack, start, end, 0, vec![]));
                } else if state.mode == StreamMode::Tcp {
                    let (ack, bits) = state.build_ack();
                    to_send.push((PacketKind::Sack, 0, ack, bits, vec![]));
                }
                // FIX: wake the reader so poll_read sees the newly arrived data.
                read_waker = state.read_waker.take();
            }
            PacketKind::Sack | PacketKind::Nack => {
                let retransmit = if pkt.header.packet_kind == PacketKind::Nack {
                    trace!("handle_incoming: stream {} nack received {} to {}", stream_id, pkt.header.seq, pkt.header.ack);
                    state.handle_nack(pkt.header.seq, pkt.header.ack)
                } else {
                    trace!("handle_incoming: stream {} sack received ack={}, bits={:x}", stream_id, pkt.header.ack, pkt.header.ack_bits);
                    state.handle_ack(pkt.header.ack, pkt.header.ack_bits)
                };
                for seq in retransmit {
                    if let Some(p) = state.write_queue.get_mut(&seq) {
                        trace!("handle_incoming: stream {} retransmit seq={}", stream_id, seq);
                        p.sent_at = Instant::now();
                        to_send.push((PacketKind::Stream, seq, 0, 0, p.data.clone()));
                    }
                }
                if state.write_queue.is_empty() {
                    write_waker = state.write_waker.take();
                }
            }
            PacketKind::KeepalivePing => {
                trace!("handle_incoming: stream {} ping", stream_id);
                to_send.push((PacketKind::KeepalivePong, 0, 0, 0, vec![]));
            }
            _ => {}
        }
    }

    // Wake outside the lock to avoid priority inversion.
    if let Some(w) = read_waker { w.wake(); }
    if let Some(w) = write_waker { w.wake(); }

    for (pt, seq, ack, bits, data) in to_send {
        send_packet_raw(inner, socket, cipher, stream_id, pt, seq, Some(ack), Some(bits), &data).await?;
    }
    Ok(())
}

async fn handle_tick(inner: &Arc<Mutex<UdpStreamInner>>, socket: &Arc<UdpSocket>, cipher: &ChaCha20Poly1305) -> Result<()> {
    let mut to_send = Vec::new();
    {
        let mut lock = inner.lock().map_err(|e| anyhow!(e.to_string()))?;
        if lock.closed {
            return Err(anyhow!("closed"));
        }

        let now = Instant::now();
        let has_pending_writes = lock.reliability.streams.values().any(|s| !s.write_queue.is_empty());

        if !has_pending_writes && now.duration_since(lock.last_received) > Duration::from_secs(300) {
            trace!("handle_tick: timeout after 300s");
            return Err(anyhow!("timeout"));
        }

        if now.duration_since(lock.last_sent) > Duration::from_secs(5) {
            for &stream_id in lock.reliability.streams.keys() {
                trace!("handle_tick: sending keepalive ping for stream {}", stream_id);
                to_send.push((stream_id, PacketKind::KeepalivePing, 0u64, 0u64, 0u64, vec![]));
            }
        }

        let (retransmissions, timed_out) = lock.reliability.get_retransmissions(now);
        if !timed_out.is_empty() {
            trace!("handle_tick: streams timed out: {:?}", timed_out);
            return Err(anyhow!("retransmission timeout"));
        }
        for (sid, seq, data) in retransmissions {
            trace!("handle_tick: retransmitting stream {} seq={}", sid, seq);
            to_send.push((sid, PacketKind::Stream, seq, 0, 0, data));
        }
    }

    for (sid, pt, seq, ack, bits, data) in to_send {
        send_packet_raw(inner, socket, cipher, sid, pt, seq, Some(ack), Some(bits), &data).await?;
    }
    Ok(())
}

async fn send_packet(
    inner: &Arc<Mutex<UdpStreamInner>>,
    socket: &Arc<UdpSocket>,
    cipher: &ChaCha20Poly1305,
    stream_id: u32,
    pt: PacketKind,
    seq: u64,
    data: &[u8],
) -> Result<()> {
    send_packet_raw(inner, socket, cipher, stream_id, pt, seq, None, None, data).await
}

async fn send_packet_raw(
    inner: &Arc<Mutex<UdpStreamInner>>,
    socket: &Arc<UdpSocket>,
    cipher: &ChaCha20Poly1305,
    stream_id: u32,
    pt: PacketKind,
    seq: u64,
    ack_override: Option<u64>,
    bits_override: Option<u64>,
    data: &[u8],
) -> Result<()> {
    let (peer_addr, ack, bits) = {
        let lock = inner.lock().map_err(|e| anyhow!(e.to_string()))?;

        // FIX: the original logic applied overrides only when pt was Nack/Sack,
        // silently ignoring them for every other packet kind. The correct rule is:
        //   • Nack/Sack carry explicit ack+bits in their header fields → use overrides.
        //   • All other packets piggyback the current receive state → use build_ack().
        // Callers that pass None/None always fall through to build_ack(), so this is
        // backward-compatible with the send_packet() helper.
        let (ack, bits) = match lock.reliability.streams.get(&stream_id) {
            Some(state) => {
                if (pt == PacketKind::Nack || pt == PacketKind::Sack) {
                    match (ack_override, bits_override) {
                        (Some(a), Some(b)) => (a, b),
                        _ => state.build_ack(),
                    }
                } else {
                    state.build_ack()
                }
            }
            None => (0, 0),
        };

        (lock.peer_addr, ack, bits)
    };

    trace!(
        "send_packet_raw: stream_id={}, kind={:?}, seq={}, ack={}, bits={:x}, payload_len={}, dest={}",
        stream_id, pt, seq, ack, bits, data.len(), peer_addr
    );

    let header = TransportPacketHeader {
        channel_id: stream_id,
        packet_kind: pt,
        seq,
        ack,
        ack_bits: bits,
    };
    let mut buf = Vec::new();
    header.encode(&mut buf);
    buf.extend_from_slice(data);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher.encrypt(nonce, buf.as_slice()).map_err(|e| anyhow!(e.to_string()))?;
    let mut pkt = nonce_bytes.to_vec();
    pkt.extend_from_slice(&encrypted);

    let _ = socket.send_to(&pkt, peer_addr).await;
    if let Ok(mut lock) = inner.lock() {
        lock.last_sent = Instant::now();
    }
    Ok(())
}

impl AsyncRead for UdpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let mut lock = self.inner.lock().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let sid = self.stream_id;
        let closed = lock.closed;
        let state = lock.reliability.streams.get_mut(&sid).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Stream not found"))?;

        if !state.read_buf_bytes.is_empty() {
            let len = std::cmp::min(buf.remaining(), state.read_buf_bytes.len());
            let data: Vec<u8> = state.read_buf_bytes.drain(..len).collect();
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }
        // Return EOF (empty read) when closed and the buffer is drained.
        if closed { return Poll::Ready(Ok(())); }
        state.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for UdpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let mut lock = self.inner.lock().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        if lock.closed { return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into())); }

        let sid = self.stream_id;
        let state = lock.reliability.streams.get_mut(&sid).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Stream not found"))?;

        if state.write_queue.len() >= 1024 {
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let chunk_len = std::cmp::min(buf.len(), 1100);
        let chunk = &buf[..chunk_len];
        let seq = state.next_write_seq;
        state.next_write_seq += 1;
        state.write_queue.insert(seq, SentPacket { data: chunk.to_vec(), sent_at: Instant::now(), retransmits: 0 });

        // The background task will retransmit via handle_tick if this try_send
        // fails (e.g. because the write channel is momentarily full).
        let _ = self.write_tx.try_send((seq, chunk.to_vec()));

        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut lock = self.inner.lock().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        lock.closed = true;
        // seq == 0 is the sentinel that triggers a StreamClose packet in the task.
        let _ = self.write_tx.try_send((0, vec![]));
        Poll::Ready(Ok(()))
    }
}

pub struct UdpTransport {
    cipher: Arc<ChaCha20Poly1305>,
}

impl Debug for UdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpTransport").finish()
    }
}

pub struct UdpAcceptor {
    incoming_rx: tokio::sync::Mutex<mpsc::Receiver<UdpStream>>,
    _shutdown_tx: oneshot::Sender<()>,
}

#[async_trait]
impl Transport for UdpTransport {
    type Acceptor = UdpAcceptor;
    type RawStream = UdpStream;
    type Stream = UdpStream;

    fn new(config: &TransportConfig) -> Result<Self> {
        let udp_config = config.udp.as_ref().ok_or_else(|| anyhow!("Missing UDP config"))?;
        let mut hasher = Sha256::new();
        hasher.update(udp_config.psk.as_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(&key);
        Ok(Self { cipher: Arc::new(cipher) })
    }

    fn hint(_: &Self::Stream, _: SocketOpts) {}

    fn set_udp_nack_mode(conn: &Self::Stream) {
        let mut inner = conn.inner.lock().unwrap();
        if let Some(state) = inner.reliability.streams.get_mut(&conn.stream_id) {
            state.mode = StreamMode::Udp;
        }
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
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let cipher = self.cipher.clone();
        let runtime = ListenerPacketRuntime::new(socket.clone(), incoming_tx.clone(), cipher.clone());

        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    res = socket.recv_from(&mut buf) => {
                        match res {
                            Ok((len, src)) => {
                                if len < 28 { continue; }
                                let nonce = chacha20poly1305::Nonce::from_slice(&buf[..12]);
                                let Ok(decrypted) = cipher.decrypt(nonce, &buf[12..len]) else { continue; };
                                let Some((header, payload)) = TransportPacketHeader::decode(&decrypted) else { continue; };
                                runtime.on_packet(src, header, payload.to_vec()).await;
                            }
                            Err(_) => {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                continue;
                            }
                        }
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });

        Ok(UdpAcceptor { incoming_rx: tokio::sync::Mutex::new(incoming_rx), _shutdown_tx: shutdown_tx })
    }

    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)> {
        let s = a.incoming_rx.lock().await.recv().await.ok_or(anyhow!("closed"))?;
        let addr = s.inner.lock().unwrap().peer_addr;
        Ok((s, addr))
    }

    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> { Ok(conn) }

    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream> {
        let dest = addr.socket_addr.ok_or(anyhow!("unresolved"))?;
        let socket = UdpSocket::bind(if dest.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await?;
        let std_socket = socket.into_std()?;
        let socket = UdpSocket::from_std(std_socket)?;
        let socket = Arc::new(socket);
        let stream_id: u32 = random();
        let cipher = self.cipher.clone();
        let (mut stream, tx) = UdpStream::new(stream_id, dest, socket.clone(), cipher.clone(), None);
        let (recv_shutdown_tx, recv_shutdown_rx) = oneshot::channel();
        stream._recv_shutdown_tx = Some(recv_shutdown_tx);

        let runtime = ConnectedPacketRuntime::new(stream_id, dest, tx.clone());
        let inner = stream.inner.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut recv_shutdown_rx = recv_shutdown_rx;
            loop {
                tokio::select! {
                    res = socket.recv_from(&mut buf) => {
                        match res {
                            Ok((len, src)) => {
                                if len < 28 { continue; }
                                let nonce = chacha20poly1305::Nonce::from_slice(&buf[..12]);
                                let Ok(decrypted) = cipher.decrypt(nonce, &buf[12..len]) else { continue; };
                                let Some((header, payload)) = TransportPacketHeader::decode(&decrypted) else { continue; };
                                runtime.on_packet(src, header, payload.to_vec()).await;
                            }
                            Err(_) => {
                                if let Ok(mut lock) = inner.lock() {
                                    lock.closed = true;
                                    if let Some(state) = lock.reliability.streams.get_mut(&stream_id) {
                                        if let Some(w) = state.read_waker.take() { w.wake(); }
                                        if let Some(w) = state.write_waker.take() { w.wake(); }
                                    }
                                }
                                break;
                            }
                        }
                    }
                    _ = &mut recv_shutdown_rx => break,
                }
            }
        });

        stream.connect().await?;
        Ok(stream)
    }
}
