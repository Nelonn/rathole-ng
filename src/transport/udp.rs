use anyhow::{anyhow, Result};
use async_trait::async_trait;
use rand::random;
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

use crate::config::TransportConfig;
use super::{AddrMaybeCached, SocketOpts, Transport};
use super::reliability::{Reliability, StreamState, StreamMode, PacketType, UdpHeader, SentPacket};

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
    _shutdown_tx: oneshot::Sender<()>,
}

impl Debug for UdpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpStream").field("stream_id", &self.stream_id).finish()
    }
}

pub struct IncomingPacket {
    pub header: UdpHeader,
    pub payload: Vec<u8>,
    pub src: SocketAddr,
}

impl UdpStream {
    fn new(
        stream_id: u32,
        peer_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        active_streams: Option<Arc<Mutex<HashMap<u32, mpsc::Sender<IncomingPacket>>>>>,
    ) -> (Self, mpsc::Sender<IncomingPacket>) {
        let (packet_tx, packet_rx) = mpsc::channel(1024);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let mut reliability = Reliability::new();
        reliability.streams.insert(stream_id, StreamState::new(StreamMode::Tcp)); // Default to TCP mode (SACK)
        
        let inner = Arc::new(Mutex::new(UdpStreamInner {
            peer_addr,
            reliability,
            last_received: Instant::now(),
            last_sent: Instant::now(),
            closed: false,
        }));

        let stream = Self {
            stream_id,
            inner: inner.clone(),
            socket: socket.clone(),
            _shutdown_tx: shutdown_tx,
        };

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(50));
            let mut packet_rx = packet_rx;
            let mut shutdown_rx = shutdown_rx;

            loop {
                tokio::select! {
                    pkt = packet_rx.recv() => {
                        let Some(pkt) = pkt else { break; };
                        if let Err(_) = handle_incoming(&inner, &socket, pkt).await { break; }
                    }
                    _ = ticker.tick() => {
                        if let Err(_) = handle_tick(&inner, &socket).await { break; }
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
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
            if start.elapsed() > Duration::from_secs(10) { return Err(anyhow!("timeout")); }
            
            {
                let lock = self.inner.lock().unwrap();
                if let Some(state) = lock.reliability.streams.get(&self.stream_id) {
                    if state.next_read_seq > 0 || state.next_write_seq > 0 { break; } // Rudimentary establishment check
                }
            }
            
            send_packet(&self.inner, &self.socket, self.stream_id, PacketType::Syn, 0, &[]).await?;
            ticker.tick().await;
        }
        Ok(())
    }
}

async fn handle_incoming(inner: &Arc<Mutex<UdpStreamInner>>, socket: &Arc<UdpSocket>, pkt: IncomingPacket) -> Result<()> {
    let mut to_send = Vec::new();
    let mut retransmit_pkts = Vec::new();
    let peer_addr;
    let stream_id = pkt.header.stream_id;

    {
        let mut lock = inner.lock().map_err(|e| anyhow!(e.to_string()))?;
        if lock.closed { return Ok(()); }
        lock.last_received = Instant::now();
        lock.peer_addr = pkt.src;
        peer_addr = lock.peer_addr;

        let state = lock.reliability.streams.entry(stream_id).or_insert_with(|| StreamState::new(StreamMode::Tcp));

        match pkt.header.packet_type {
            PacketType::Syn => {
                to_send.push((stream_id, PacketType::SynAck, 0, vec![]));
            }
            PacketType::SynAck => {}, // Handled by simple existence in connect()
            PacketType::Fin => lock.closed = true,
            PacketType::Data => {
                let nack = state.push_data(pkt.header.seq, pkt.payload);
                if let Some((start, end)) = nack {
                    retransmit_pkts.push((stream_id, PacketType::Ack, start, end, 0, vec![]));
                } else if state.mode == StreamMode::Tcp {
                    let (ack, bits) = state.build_ack();
                    retransmit_pkts.push((stream_id, PacketType::Ack, 0, ack, bits, vec![]));
                }
            }
            PacketType::Ack => {
                let retransmit = if state.mode == StreamMode::Udp {
                    state.handle_nack(pkt.header.seq, pkt.header.ack)
                } else {
                    state.handle_ack(pkt.header.ack, pkt.header.ack_bits)
                };
                for seq in retransmit {
                    if let Some(p) = state.write_queue.get_mut(&seq) {
                        p.sent_at = Instant::now();
                        to_send.push((stream_id, PacketType::Data, seq, p.data.clone()));
                    }
                }
                if state.write_queue.is_empty() {
                    if let Some(w) = state.write_waker.take() { w.wake(); }
                }
            }
            PacketType::Ping => to_send.push((stream_id, PacketType::Pong, 0, vec![])),
            _ => {}
        }
    }

    for (sid, pt, seq, data) in to_send {
        send_packet(inner, socket, sid, pt, seq, &data).await?;
    }
    for (sid, pt, seq, ack, bits, data) in retransmit_pkts {
        let (ack_val, bits_val) = {
            let lock = inner.lock().map_err(|e| anyhow!(e.to_string()))?;
            if let Some(state) = lock.reliability.streams.get(&sid) {
                 if pt == PacketType::Ack && seq == 0 && bits != 0 { (ack, bits) } else { state.build_ack() }
            } else { (0, 0) }
        };
        let header = UdpHeader { stream_id: sid, packet_type: pt, seq, ack: ack_val, ack_bits: bits_val };
        let mut buf = Vec::new();
        header.encode(&mut buf);
        buf.extend_from_slice(&data);
        let _ = socket.send_to(&buf, peer_addr).await;
    }
    Ok(())
}

async fn handle_tick(inner: &Arc<Mutex<UdpStreamInner>>, socket: &Arc<UdpSocket>) -> Result<()> {
    let mut to_send = Vec::new();
    {
        let mut lock = inner.lock().map_err(|e| anyhow!(e.to_string()))?;
        if lock.closed { return Err(anyhow!("closed")); }
        if Instant::now().duration_since(lock.last_received) > Duration::from_secs(30) { return Err(anyhow!("timeout")); }
        
        let now = Instant::now();
        
        // Multiplexed keepalive (per connection, not per stream for now)
        if now.duration_since(lock.last_sent) > Duration::from_secs(5) {
            to_send.push((0, PacketType::Ping, 0, vec![]));
        }

        let retransmissions = lock.reliability.get_retransmissions(now);
        for (sid, seq, data) in retransmissions {
            to_send.push((sid, PacketType::Data, seq, data));
        }
    }

    for (sid, pt, seq, data) in to_send {
        send_packet(inner, socket, sid, pt, seq, &data).await?;
    }
    Ok(())
}

async fn send_packet(inner: &Arc<Mutex<UdpStreamInner>>, socket: &Arc<UdpSocket>, stream_id: u32, pt: PacketType, seq: u64, data: &[u8]) -> Result<()> {
    let (peer_addr, ack, bits) = {
        let lock = inner.lock().map_err(|e| anyhow!(e.to_string()))?;
        let (ack, bits) = if let Some(state) = lock.reliability.streams.get(&stream_id) {
            state.build_ack()
        } else {
            (0, 0)
        };
        (lock.peer_addr, ack, bits)
    };

    let header = UdpHeader { stream_id, packet_type: pt, seq, ack, ack_bits: bits };
    let mut buf = Vec::new();
    header.encode(&mut buf);
    buf.extend_from_slice(data);
    let _ = socket.send_to(&buf, peer_addr).await;
    if let Ok(mut lock) = inner.lock() {
        lock.last_sent = Instant::now();
    }
    Ok(())
}

impl AsyncRead for UdpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let mut lock = self.inner.lock().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let closed = lock.closed;
        let state = lock.reliability.streams.get_mut(&self.stream_id).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Stream not found"))?;
        
        if !state.read_buf_bytes.is_empty() {
            let len = std::cmp::min(buf.remaining(), state.read_buf_bytes.len());
            buf.put_slice(&state.read_buf_bytes.drain(..len).collect::<Vec<_>>());
            return Poll::Ready(Ok(()));
        }
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
        
        if state.write_queue.len() > 1024 {
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let chunk_len = std::cmp::min(buf.len(), 1200);
        let chunk = &buf[..chunk_len];
        let seq = state.next_write_seq;
        state.next_write_seq += 1;
        state.write_queue.insert(seq, SentPacket { data: chunk.to_vec(), sent_at: Instant::now() });
        
        let inner = self.inner.clone();
        let socket = self.socket.clone();
        let data = chunk.to_vec();
        tokio::spawn(async move { let _ = send_packet(&inner, &socket, sid, PacketType::Data, seq, &data).await; });
        
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut lock = self.inner.lock().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        lock.closed = true;
        let sid = self.stream_id;
        let inner = self.inner.clone();
        let socket = self.socket.clone();
        tokio::spawn(async move { let _ = send_packet(&inner, &socket, sid, PacketType::Fin, 0, &[]).await; });
        Poll::Ready(Ok(()))
    }
}

pub struct UdpTransport {}
impl Debug for UdpTransport { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("UdpTransport").finish() } }

pub struct UdpAcceptor {
    incoming_rx: tokio::sync::Mutex<mpsc::Receiver<UdpStream>>,
    _shutdown_tx: oneshot::Sender<()>,
}

#[async_trait]
impl Transport for UdpTransport {
    type Acceptor = UdpAcceptor;
    type RawStream = UdpStream;
    type Stream = UdpStream;

    fn new(_config: &TransportConfig) -> Result<Self> {
        Ok(Self {})
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
        let active_streams: Arc<Mutex<HashMap<u32, mpsc::Sender<IncomingPacket>>>> = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    res = socket.recv_from(&mut buf) => {
                        let Ok((len, src)) = res else { continue; };
                        let Some((header, payload)) = UdpHeader::decode(&buf[..len]) else { continue; };
                        
                        let tx = {
                            let mut active = active_streams.lock().unwrap();
                            if let Some(tx) = active.get(&header.stream_id) { tx.clone() }
                            else if header.packet_type == PacketType::Syn {
                                let (stream, tx) = UdpStream::new(header.stream_id, src, socket.clone(), Some(active_streams.clone()));
                                active.insert(header.stream_id, tx.clone());
                                let tx_clone = tx.clone();
                                let incoming_tx = incoming_tx.clone();
                                tokio::spawn(async move { let _ = incoming_tx.send(stream).await; });
                                tx_clone
                            } else { continue; }
                        };
                        let _ = tx.try_send(IncomingPacket { header, payload: payload.to_vec(), src });
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
        crate::helper::disable_udp_connreset(&std_socket)?;
        let socket = UdpSocket::from_std(std_socket)?;
        let socket = Arc::new(socket);
        let stream_id = random();
        let (mut stream, tx) = UdpStream::new(stream_id, dest, socket.clone(), None);
        
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, src)) = socket.recv_from(&mut buf).await {
                if src != dest { continue; }
                let Some((header, payload)) = UdpHeader::decode(&buf[..len]) else { continue; };
                if header.stream_id != stream_id { continue; }
                let _ = tx.send(IncomingPacket { header, payload: payload.to_vec(), src }).await;
            }
        });

        stream.connect().await?;
        Ok(stream)
    }
}
