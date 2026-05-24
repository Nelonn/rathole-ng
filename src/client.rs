use crate::config::{
    ClientConfig, ClientServiceConfig, Config, ProxyProtocol, ServiceType, TransportType,
};
use crate::config_watcher::{ClientServiceChange, ConfigChange};
use crate::helper::udp_connect;
use crate::protocol::Hello::{self, *};
use crate::protocol::{
    self, read_ack, read_control_cmd, read_data_cmd, read_hello, read_visitor_ack,
    write_packet_message, write_visitor_auth, Ack, Auth, ControlChannelCmd, DataChannelCmd,
    PacketMessage, UdpTraffic, VisitorAck, VisitorAuth,
    CURRENT_PROTO_VERSION, HASH_WIDTH_IN_BYTES,
};
use crate::transport::{AddrMaybeCached, SocketOpts, TcpTransport, UdpTransport, Transport};
use anyhow::{anyhow, bail, Context, Result};
use backoff::backoff::Backoff;
use backoff::future::retry_notify;
use backoff::ExponentialBackoff;
use bytes::{Bytes, BytesMut};
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio::time::{self, Duration, Instant};
use tracing::{debug, error, info, instrument, trace, warn, Instrument, Span};

#[cfg(feature = "noise")]
use crate::transport::NoiseTransport;

use crate::constants::{run_control_chan_backoff, UDP_BUFFER_SIZE, UDP_SENDQ_SIZE, UDP_TIMEOUT};

// The entrypoint of running a client
pub async fn run_client(
    config: Config,
    shutdown_rx: broadcast::Receiver<bool>,
    update_rx: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    let config = config.client.ok_or_else(|| {
        anyhow!(
        "Try to run as a client, but the configuration is missing. Please add the `[client]` block"
    )
    })?;

    match config.transport.transport_type {
        TransportType::Tcp => {
            if config.transport.noise.is_some() {
                #[cfg(feature = "noise")]
                {
                    let mut transport = NoiseTransport::<TcpTransport>::new(&config.transport)?;
                    if let Some(noise) = &config.transport.noise {
                        if let Some(psk) = &noise.psk {
                            if let Ok(psk_bytes) = base64::decode(psk.as_bytes()) {
                                if psk_bytes.len() == 32 {
                                    let mut res = [0u8; 32];
                                    res.copy_from_slice(&psk_bytes);
                                    transport.set_psk(res);
                                }
                            }
                        }
                    }
                    let mut client = Client::from_config_and_transport(config, Arc::new(transport)).await?;
                    client.run(shutdown_rx, update_rx).await
                }
                #[cfg(not(feature = "noise"))]
                crate::helper::feature_not_compile("noise")
            } else {
                let mut client = Client::<TcpTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
        }
        TransportType::Udp => {
            if config.transport.noise.is_some() {
                #[cfg(feature = "noise")]
                {
                    let mut transport = NoiseTransport::<UdpTransport>::new(&config.transport)?;
                    if let Some(noise) = &config.transport.noise {
                        if let Some(psk) = &noise.psk {
                            if let Ok(psk_bytes) = base64::decode(psk.as_bytes()) {
                                if psk_bytes.len() == 32 {
                                    let mut res = [0u8; 32];
                                    res.copy_from_slice(&psk_bytes);
                                    transport.set_psk(res);
                                }
                            }
                        }
                    }
                    let mut client = Client::from_config_and_transport(config, Arc::new(transport)).await?;
                    client.run(shutdown_rx, update_rx).await
                }
                #[cfg(not(feature = "noise"))]
                crate::helper::feature_not_compile("noise")
            } else {
                let mut client = Client::<UdpTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
        }
    }
}

type ServiceDigest = protocol::Digest;
type Nonce = protocol::Digest;

// Holds the state of a client
struct Client<T: Transport> {
    config: ClientConfig,
    service_handles: HashMap<String, ControlChannelHandle>,
    transport: Arc<T>,
}

impl<T: 'static + Transport> Client<T> {
    pub async fn from_config_and_transport(config: ClientConfig, transport: Arc<T>) -> Result<Client<T>> {
        Ok(Client {
            config,
            service_handles: HashMap::new(),
            transport,
        })
    }

    // Create a Client from `[client]` config block
    async fn from(config: ClientConfig) -> Result<Client<T>> {
        let transport =
            Arc::new(T::new(&config.transport).with_context(|| "Failed to create the transport")?);
        Self::from_config_and_transport(config, transport).await
    }

    // The entrypoint of Client
    async fn run(
        &mut self,
        mut shutdown_rx: broadcast::Receiver<bool>,
        mut update_rx: mpsc::Receiver<ConfigChange>,
    ) -> Result<()> {
        for (name, config) in &self.config.services {
            // Create a control channel for each service defined
            let handle = ControlChannelHandle::new(
                (*config).clone(),
                self.config.remote_addr.clone(),
                self.transport.clone(),
                self.config.heartbeat_timeout,
            );
            self.service_handles.insert(name.clone(), handle);
        }

        // Wait for the shutdown signal
        loop {
            tokio::select! {
                val = shutdown_rx.recv() => {
                    match val {
                        Ok(_) => {}
                        Err(err) => {
                            error!("Unable to listen for shutdown signal: {}", err);
                        }
                    }
                    break;
                },
                e = update_rx.recv() => {
                    if let Some(e) = e {
                        self.handle_hot_reload(e).await;
                    }
                }
            }
        }

        // Shutdown all services
        for (_, handle) in self.service_handles.drain() {
            handle.shutdown();
        }

        Ok(())
    }

    async fn handle_hot_reload(&mut self, e: ConfigChange) {
        match e {
            ConfigChange::ClientChange(client_change) => match client_change {
                ClientServiceChange::Add(cfg) => {
                    let name = cfg.name.clone();
                    let handle = ControlChannelHandle::new(
                        cfg,
                        self.config.remote_addr.clone(),
                        self.transport.clone(),
                        self.config.heartbeat_timeout,
                    );
                    let _ = self.service_handles.insert(name, handle);
                }
                ClientServiceChange::Delete(s) => {
                    let _ = self.service_handles.remove(&s);
                }
            },
            ignored => warn!("Ignored {:?} since running as a client", ignored),
        }
    }
}

struct RunDataChannelArgs<T: Transport> {
    session_key: Nonce,
    remote_addr: AddrMaybeCached,
    connector: Arc<T>,
    socket_opts: SocketOpts,
    service: ClientServiceConfig,
}

async fn do_data_channel_handshake<T: Transport>(
    args: Arc<RunDataChannelArgs<T>>,
) -> Result<T::Stream> {
    // Retry at least every 100ms, at most for 10 seconds
    let backoff = ExponentialBackoff {
        max_interval: Duration::from_millis(100),
        max_elapsed_time: Some(Duration::from_secs(10)),
        ..Default::default()
    };

    // Connect to remote_addr
    let mut conn: T::Stream = retry_notify(
        backoff,
        || async {
            args.connector
                .connect(&args.remote_addr)
                .await
                .with_context(|| format!("Failed to connect to {}", &args.remote_addr))
                .map_err(backoff::Error::transient)
        },
        |e, duration| {
            warn!("{:#}. Retry in {:?}", e, duration);
        },
    )
    .await?;

    T::hint(&conn, args.socket_opts);

    // Send nonce
    let v: &[u8; HASH_WIDTH_IN_BYTES] = args.session_key[..].try_into().unwrap();
    let hello = Hello::DataChannelHello(CURRENT_PROTO_VERSION, v.to_owned());
    write_packet_message(&mut conn, &PacketMessage::Hello(hello)).await?;

    Ok(conn)
}

async fn run_data_channel<T: Transport>(args: Arc<RunDataChannelArgs<T>>) -> Result<()> {
    // Do the handshake
    let mut conn = do_data_channel_handshake(args.clone()).await?;

    if args.service.service_type == ServiceType::Udp {
        T::set_udp_nack_mode(&conn);
    }

    // Forward
    let data_cmd = match read_data_cmd(&mut conn).await {
        Ok(cmd) => cmd,
        Err(err) if is_unexpected_eof(&err) => return Ok(()),
        Err(err) => return Err(err),
    };

    match data_cmd {
        DataChannelCmd::StartForwardTcp(real_ip) => {
            if args.service.service_type != ServiceType::Tcp {
                bail!("Expect TCP traffic. Please check the configuration.")
            }
            run_data_channel_for_tcp::<T>(
                conn,
                &args.service.local_addr,
                real_ip,
                args.service.proxy_protocol,
            )
            .await?;
        }
        DataChannelCmd::StartForwardUdp(_real_ip) => {
            if args.service.service_type != ServiceType::Udp {
                bail!("Expect UDP traffic. Please check the configuration.")
            }
            run_data_channel_for_udp::<T>(conn, &args.service.local_addr, args.service.prefer_ipv6).await?;
        }
    }
    Ok(())
}

fn is_unexpected_eof(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::UnexpectedEof)
    })
}

// Simply copying back and forth for TCP
#[instrument(skip(conn))]
async fn run_data_channel_for_tcp<T: Transport>(
    mut conn: T::Stream,
    local_addr: &str,
    real_ip: protocol::ForwardAddr,
    proxy_protocol: Option<ProxyProtocol>,
) -> Result<()> {
    debug!("New data channel starts forwarding");

    let mut local = TcpStream::connect(local_addr)
        .await
        .with_context(|| format!("Failed to connect to {}", local_addr))?;

    if let Some(pp) = proxy_protocol {
        let src_addr: SocketAddr = real_ip.into();
        let dst_addr = local.local_addr().unwrap_or(src_addr);

        match pp {
            ProxyProtocol::V1 => {
                let family = if src_addr.is_ipv4() { "TCP4" } else { "TCP6" };
                let header = format!(
                    "PROXY {} {} {} {} {}\r\n",
                    family,
                    src_addr.ip(),
                    dst_addr.ip(),
                    src_addr.port(),
                    dst_addr.port()
                );
                local.write_all(header.as_bytes()).await?;
            }
            ProxyProtocol::V2 => {
                let mut header = Vec::new();
                header.extend_from_slice(b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A");
                header.push(0x21); // Version 2, Command Proxy

                match (src_addr, dst_addr) {
                    (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                        header.push(0x11); // AF_INET, STREAM
                        header.extend_from_slice(&12u16.to_be_bytes());
                        header.extend_from_slice(&src.ip().octets());
                        header.extend_from_slice(&dst.ip().octets());
                        header.extend_from_slice(&src.port().to_be_bytes());
                        header.extend_from_slice(&dst.port().to_be_bytes());
                    }
                    (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                        header.push(0x21); // AF_INET6, STREAM
                        header.extend_from_slice(&36u16.to_be_bytes());
                        header.extend_from_slice(&src.ip().octets());
                        header.extend_from_slice(&dst.ip().octets());
                        header.extend_from_slice(&src.port().to_be_bytes());
                        header.extend_from_slice(&dst.port().to_be_bytes());
                    }
                    _ => {
                        warn!("Mixed AF in PROXY v2, skipping header");
                        header.clear();
                    }
                }
                if !header.is_empty() {
                    local.write_all(&header).await?;
                }
            }
        }
    }

    let _ = copy_bidirectional(&mut conn, &mut local).await;
    Ok(())
}

// Things get a little tricker when it gets to UDP because it's connection-less.
// A UdpPortMap must be maintained for recent seen incoming address, giving them
// each a local port, which is associated with a socket. So just the sender
// to the socket will work fine for the map's value.
type UdpPortMap = Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>;

#[instrument(skip(conn))]
async fn run_data_channel_for_udp<T: Transport>(conn: T::Stream, local_addr: &str, prefer_ipv6: bool) -> Result<()> {
    debug!("New data channel starts forwarding");

    let port_map: UdpPortMap = Arc::new(RwLock::new(HashMap::new()));

    // The channel stores UdpTraffic that needs to be sent to the server
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<UdpTraffic>(UDP_SENDQ_SIZE);

    // FIXME: https://github.com/tokio-rs/tls/issues/40
    // Maybe this is our concern
    let (mut rd, mut wr) = io::split(conn);

    // Keep sending items from the outbound channel to the server
    tokio::spawn(async move {
        while let Some(t) = outbound_rx.recv().await {
            trace!("outbound {:?}", t);
            if let Err(e) = t
                .write(&mut wr)
                .await
                .with_context(|| "Failed to forward UDP traffic to the server")
            {
                debug!("{:?}", e);
                break;
            }
        }
    });

    loop {
        // Read a packet from the server
        let hdr_len = rd.read_u8().await?;
        let packet = UdpTraffic::read(&mut rd, hdr_len)
            .await
            .with_context(|| "Failed to read UDPTraffic from the server")?;
        let m = port_map.read().await;

        if m.get(&packet.from).is_none() {
            // This packet is from a address we don't see for a while,
            // which is not in the UdpPortMap.
            // So set up a mapping (and a forwarder) for it

            // Drop the reader lock
            drop(m);

            // Grab the writer lock
            // This is the only thread that will try to grab the writer lock
            // So no need to worry about some other thread has already set up
            // the mapping between the gap of dropping the reader lock and
            // grabbing the writer lock
            let mut m = port_map.write().await;

            match udp_connect(local_addr, prefer_ipv6).await {
                Ok(s) => {
                    let (inbound_tx, inbound_rx) = mpsc::channel(UDP_SENDQ_SIZE);
                    m.insert(packet.from, inbound_tx);
                    tokio::spawn(run_udp_forwarder(
                        s,
                        inbound_rx,
                        outbound_tx.clone(),
                        packet.from,
                        port_map.clone(),
                    ));
                }
                Err(e) => {
                    error!("{:#}", e);
                }
            }
        }

        // Now there should be a udp forwarder that can receive the packet
        let m = port_map.read().await;
        if let Some(tx) = m.get(&packet.from) {
            let _ = tx.send(packet.data).await;
        }
    }
}

// Run a UdpSocket for the visitor `from`
#[instrument(skip_all, fields(from))]
async fn run_udp_forwarder(
    s: UdpSocket,
    mut inbound_rx: mpsc::Receiver<Bytes>,
    outbount_tx: mpsc::Sender<UdpTraffic>,
    from: SocketAddr,
    port_map: UdpPortMap,
) -> Result<()> {
    debug!("Forwarder created");
    let mut buf = BytesMut::new();
    buf.resize(UDP_BUFFER_SIZE, 0);

    loop {
        tokio::select! {
            // Receive from the server
            data = inbound_rx.recv() => {
                if let Some(data) = data {
                    s.send(&data).await?;
                } else {
                    break;
                }
            },

            // Receive from the service
            val = s.recv(&mut buf) => {
                let len = match val {
                    Ok(v) => v,
                    Err(_) => break
                };

                let t = UdpTraffic{
                    from,
                    data: Bytes::copy_from_slice(&buf[..len])
                };

                outbount_tx.send(t).await?;
            },

            // No traffic for the duration of UDP_TIMEOUT, clean up the state
            _ = time::sleep(Duration::from_secs(UDP_TIMEOUT)) => {
                break;
            }
        }
    }

    let mut port_map = port_map.write().await;
    port_map.remove(&from);

    debug!("Forwarder dropped");
    Ok(())
}

// Control channel, using T as the transport layer
struct ControlChannel<T: Transport> {
    digest: ServiceDigest,              // SHA256 of the service name
    service: ClientServiceConfig,       // `[client.services.foo]` config block
    shutdown_rx: oneshot::Receiver<u8>, // Receives the shutdown signal
    remote_addr: String,                // `client.remote_addr`
    transport: Arc<T>,                  // Wrapper around the transport layer
    heartbeat_timeout: u64,             // Application layer heartbeat timeout in secs
}

// Handle of a control channel
// Dropping it will also drop the actual control channel
struct ControlChannelHandle {
    shutdown_tx: oneshot::Sender<u8>,
}

impl<T: 'static + Transport> ControlChannel<T> {
    #[instrument(skip_all)]
    async fn run(&mut self) -> Result<()> {
        let mut remote_addr = AddrMaybeCached::new(&self.remote_addr);
        remote_addr.resolve().await?;

        let mut conn = self
            .transport
            .connect(&remote_addr)
            .await
            .with_context(|| format!("Failed to connect to {}", &self.remote_addr))?;
        T::hint(&conn, SocketOpts::for_control_channel());

        debug!("Sending hello");
        let hello_send =
            Hello::ControlChannelHello(CURRENT_PROTO_VERSION, self.digest[..].try_into().unwrap());
        write_packet_message(&mut conn, &PacketMessage::Hello(hello_send)).await?;

        debug!("Reading hello");
        let nonce = match read_hello(&mut conn).await? {
            ControlChannelHello(_, d) => d,
            _ => {
                bail!("Unexpected type of hello");
            }
        };

        debug!("Sending auth");
        let token = self.service.token.as_ref().map(|s| s.as_bytes()).unwrap_or(b"");
        let mut concat = Vec::from(token);
        concat.extend_from_slice(&nonce);

        let session_key = protocol::digest(&concat);
        let auth = Auth(session_key);
        write_packet_message(&mut conn, &PacketMessage::Auth(auth)).await?;

        debug!("Reading ack");
        match read_ack(&mut conn).await? {
            Ack::Ok => {}
            v => {
                return Err(anyhow!("{}", v))
                    .with_context(|| format!("Authentication failed: {}", self.service.name));
            }
        }

        info!("Control channel established");

        let socket_opts = SocketOpts::from_client_cfg(&self.service);
        let data_ch_args = Arc::new(RunDataChannelArgs {
            session_key,
            remote_addr,
            connector: self.transport.clone(),
            socket_opts,
            service: self.service.clone(),
        });

        let (cancel_tx, _cancel_rx) = broadcast::channel::<()>(1);

        let run_result: Result<()> = loop {
            tokio::select! {
                val = read_control_cmd(&mut conn) => {
                    let val = match val {
                        Ok(val) => val,
                        Err(err) => break Err(err),
                    };
                    debug!( "Received {:?}", val);
                    match val {
                        ControlChannelCmd::CreateDataChannel => {
                            let args = data_ch_args.clone();
                            let mut cancel_rx = cancel_tx.subscribe();
                            tokio::spawn(async move {
                                tokio::select! {
                                    _ = cancel_rx.recv() => {}
                                    res = run_data_channel(args) => {
                                        if let Err(e) = res.with_context(|| "Failed to run the data channel") {
                                            if !is_unexpected_eof(&e) {
                                                warn!("{:#}", e);
                                            }
                                        }
                                    }
                                }
                            }.instrument(Span::current()));
                        },
                        ControlChannelCmd::HeartBeat => ()
                    }
                },
                _ = time::sleep(Duration::from_secs(self.heartbeat_timeout)), if self.heartbeat_timeout != 0 => {
                    break Err(anyhow!("Heartbeat timed out"))
                }
                _ = &mut self.shutdown_rx => {
                    break Ok(());
                }
            }
        };

        let _ = cancel_tx.send(());

        run_result?;

        info!("Control channel shutdown");
        Ok(())
    }
}

struct VisitorControlChannel<T: Transport> {
    service: ClientServiceConfig,
    shutdown_rx: oneshot::Receiver<u8>,
    remote_addr: String,
    transport: Arc<T>,
    heartbeat_timeout: u64,
}

impl<T: 'static + Transport> VisitorControlChannel<T> {
    #[instrument(skip_all)]
    async fn run(&mut self) -> Result<()> {
        let mut remote_addr = AddrMaybeCached::new(&self.remote_addr);
        remote_addr.resolve().await?;

        let mut conn = self
            .transport
            .connect(&remote_addr)
            .await
            .with_context(|| format!("Failed to connect to {}", &self.remote_addr))?;
        T::hint(&conn, SocketOpts::for_control_channel());

        let mut pad = [0u8; HASH_WIDTH_IN_BYTES];
        rand::thread_rng().fill_bytes(&mut pad);
        let hello = Hello::VisitorHello(CURRENT_PROTO_VERSION, pad);
        write_packet_message(&mut conn, &PacketMessage::Hello(hello)).await?;

        let mut challenge_nonce = [0u8; HASH_WIDTH_IN_BYTES];
        conn.read_exact(&mut challenge_nonce)
            .await
            .with_context(|| "Failed to read challenge nonce")?;

        let token = self.service.token.as_ref().map(|s| s.as_bytes()).unwrap_or(b"");
        let mut concat = Vec::from(token);
        concat.extend_from_slice(&challenge_nonce);
        let token_digest = protocol::digest(&concat);

        let auth = VisitorAuth {
            token_digest,
            bind_addr: self.service.remote_bind_addr.clone().unwrap(),
            service_type: self.service.service_type,
        };
        write_visitor_auth(&mut conn, &auth).await?;

        match read_visitor_ack(&mut conn).await? {
            VisitorAck::Ok => {}
            VisitorAck::AuthFailed => {
                return Err(anyhow!("Visitor authentication failed for service {}", self.service.name));
            }
            VisitorAck::PortDenied => {
                return Err(anyhow!(
                    "Server denied port for service {}: {}",
                    self.service.name,
                    auth.bind_addr
                ));
            }
            VisitorAck::BindError => {
                return Err(anyhow!(
                    "Server failed to bind address for service {}: {}",
                    self.service.name,
                    auth.bind_addr
                ));
            }
        }

        let session_key = match protocol::read_auth(&mut conn).await {
            Ok(protocol::Auth(session_key)) => session_key,
            Err(err) => return Err(err).with_context(|| "Failed to read session key"),
        };

        info!("Visitor channel established");

        let socket_opts = SocketOpts::from_client_cfg(&self.service);
        let data_ch_args = Arc::new(RunDataChannelArgs {
            session_key,
            remote_addr,
            connector: self.transport.clone(),
            socket_opts,
            service: self.service.clone(),
        });

        let (cancel_tx, _cancel_rx) = broadcast::channel::<()>(1);

        let run_result: Result<()> = loop {
            tokio::select! {
                val = read_control_cmd(&mut conn) => {
                    let val = match val {
                        Ok(val) => val,
                        Err(err) => break Err(err),
                    };
                    debug!("Received {:?}", val);
                    match val {
                        ControlChannelCmd::CreateDataChannel => {
                            let args = data_ch_args.clone();
                            let mut cancel_rx = cancel_tx.subscribe();
                            tokio::spawn(async move {
                                tokio::select! {
                                    _ = cancel_rx.recv() => {}
                                    res = run_data_channel(args) => {
                                        if let Err(e) = res.with_context(|| "Failed to run the data channel") {
                                            if !is_unexpected_eof(&e) {
                                                warn!("{:#}", e);
                                            }
                                        }
                                    }
                                }
                            }.instrument(Span::current()));
                        }
                        ControlChannelCmd::HeartBeat => ()
                    }
                }
                _ = time::sleep(Duration::from_secs(self.heartbeat_timeout)), if self.heartbeat_timeout != 0 => {
                    break Err(anyhow!("Heartbeat timed out"));
                }
                _ = &mut self.shutdown_rx => {
                    break Ok(());
                }
            }
        };

        let _ = cancel_tx.send(());

        run_result?;

        info!("Visitor channel shutdown");
        Ok(())
    }
}

impl ControlChannelHandle {
    #[instrument(name="handle", skip_all, fields(service = %service.name))]
    fn new<T: 'static + Transport>(
        service: ClientServiceConfig,
        remote_addr: String,
        transport: Arc<T>,
        heartbeat_timeout: u64,
    ) -> ControlChannelHandle {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let mut retry_backoff = run_control_chan_backoff(service.retry_interval.unwrap());

        if service.is_visitor_mode() {
            let mut s = VisitorControlChannel {
                service,
                shutdown_rx,
                remote_addr,
                transport,
                heartbeat_timeout,
            };

            tokio::spawn(
                async move {
                    let mut start = Instant::now();

                    while let Err(err) = s
                        .run()
                        .await
                        .with_context(|| "Failed to run the visitor channel")
                    {
                        if s.shutdown_rx.try_recv() != Err(oneshot::error::TryRecvError::Empty) {
                            break;
                        }

                        if start.elapsed() > Duration::from_secs(3) {
                            retry_backoff.reset();
                        }

                        if let Some(duration) = retry_backoff.next_backoff() {
                            if !is_unexpected_eof(&err) {
                                error!("{:#}. Retry in {:?}...", err, duration);
                            }
                            time::sleep(duration).await;
                        } else {
                            panic!("{:#}. Break", err);
                        }

                        start = Instant::now();
                    }
                }
                .instrument(Span::current()),
            );
        } else {
            let user = service.user.as_ref().map(|s| s.as_str()).unwrap_or("default");
            let id = format!("{}:{}", user, service.name);
            let digest = protocol::digest(id.as_bytes());

            info!("Starting {} (identity: {})", hex::encode(digest), id);

            let mut s = ControlChannel {
                digest,
                service,
                shutdown_rx,
                remote_addr,
                transport,
                heartbeat_timeout,
            };

            tokio::spawn(
                async move {
                    let mut start = Instant::now();

                    while let Err(err) = s
                        .run()
                        .await
                        .with_context(|| "Failed to run the control channel")
                    {
                        if s.shutdown_rx.try_recv() != Err(oneshot::error::TryRecvError::Empty) {
                            break;
                        }

                        if start.elapsed() > Duration::from_secs(3) {
                            retry_backoff.reset();
                        }

                        if let Some(duration) = retry_backoff.next_backoff() {
                            if !is_unexpected_eof(&err) {
                                error!("{:#}. Retry in {:?}...", err, duration);
                            }
                            time::sleep(duration).await;
                        } else {
                            panic!("{:#}. Break", err);
                        }

                        start = Instant::now();
                    }
                }
                .instrument(Span::current()),
            );
        }

        ControlChannelHandle { shutdown_tx }
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(0u8);
    }
}
