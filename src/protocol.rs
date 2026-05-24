pub const HASH_WIDTH_IN_BYTES: usize = 32;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

use crate::config::ServiceType;

type ProtocolVersion = u8;
const _PROTO_V0: u8 = 0u8;
const PROTO_V1: u8 = 1u8;

pub const CURRENT_PROTO_VERSION: ProtocolVersion = PROTO_V1;

pub type Digest = [u8; HASH_WIDTH_IN_BYTES];

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Hello {
    ControlChannelHello(ProtocolVersion, Digest),
    DataChannelHello(ProtocolVersion, Digest),
    VisitorHello(ProtocolVersion, Digest),
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VisitorAuth {
    pub token_digest: Digest,
    pub bind_addr: String,
    pub service_type: ServiceType,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum VisitorAck {
    Ok,
    AuthFailed,
    PortDenied,
    BindError,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Auth(pub Digest);

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Ack {
    Ok,
    ServiceNotExist,
    AuthFailed,
}

impl std::fmt::Display for Ack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Ack::Ok => "Ok",
                Ack::ServiceNotExist => "Service not exist",
                Ack::AuthFailed => "Incorrect token",
            }
        )
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ControlChannelCmd {
    CreateDataChannel,
    HeartBeat,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardAddr {
    pub ip: [u8; 16],
    pub port: u16,
    pub is_ipv6: bool,
}

impl Default for ForwardAddr {
    fn default() -> Self {
        ForwardAddr {
            ip: [0u8; 16],
            port: 0,
            is_ipv6: false,
        }
    }
}

impl From<SocketAddr> for ForwardAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(a) => {
                let mut ip = [0u8; 16];
                ip[..4].copy_from_slice(&a.ip().octets());
                ForwardAddr {
                    ip,
                    port: a.port(),
                    is_ipv6: false,
                }
            }
            SocketAddr::V6(a) => ForwardAddr {
                ip: a.ip().octets(),
                port: a.port(),
                is_ipv6: true,
            },
        }
    }
}

impl From<ForwardAddr> for SocketAddr {
    fn from(addr: ForwardAddr) -> Self {
        if addr.is_ipv6 {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr.ip)), addr.port)
        } else {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&addr.ip[0..4]);
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)), addr.port)
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum DataChannelCmd {
    StartForwardTcp(ForwardAddr),
    StartForwardUdp(ForwardAddr),
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum PacketMessage {
    Hello(Hello),
    VisitorAuth(VisitorAuth),
    VisitorAck(VisitorAck),
    Auth(Auth),
    Ack(Ack),
    Control(ControlChannelCmd),
    DataCommand(DataChannelCmd),
    TcpChunk(Vec<u8>),
    UdpPacket {
        from: SocketAddr,
        data: Vec<u8>,
    },
}

pub fn encode_packet_message(message: &PacketMessage) -> Vec<u8> {
    bincode::serialize(message).unwrap()
}

pub fn decode_packet_message(bytes: &[u8]) -> Result<PacketMessage> {
    bincode::deserialize(bytes).with_context(|| "Failed to decode packet message")
}

pub async fn read_framed_packet<T: AsyncRead + Unpin>(conn: &mut T) -> Result<Vec<u8>> {
    let len = conn
        .read_u32()
        .await
        .with_context(|| "Failed to read packet length")? as usize;
    let mut buf = vec![0u8; len];
    conn.read_exact(&mut buf)
        .await
        .with_context(|| "Failed to read packet body")?;
    Ok(buf)
}

pub async fn write_framed_packet<T: AsyncWrite + Unpin>(conn: &mut T, bytes: &[u8]) -> Result<()> {
    conn.write_u32(bytes.len() as u32)
        .await
        .with_context(|| "Failed to write packet length")?;
    conn.write_all(bytes)
        .await
        .with_context(|| "Failed to write packet body")?;
    conn.flush().await.with_context(|| "Failed to flush packet")?;
    Ok(())
}

pub async fn read_packet_message<T: AsyncRead + Unpin>(conn: &mut T) -> Result<PacketMessage> {
    let bytes = read_framed_packet(conn).await?;
    decode_packet_message(&bytes)
}

pub async fn write_packet_message<T: AsyncWrite + Unpin>(conn: &mut T, message: &PacketMessage) -> Result<()> {
    let bytes = encode_packet_message(message);
    write_framed_packet(conn, &bytes).await
}

type UdpPacketLen = u16; // `u16` should be enough for any practical UDP traffic on the Internet
#[derive(Deserialize, Serialize, Debug)]
struct UdpHeader {
    from: SocketAddr,
    len: UdpPacketLen,
}

#[derive(Debug)]
pub struct UdpTraffic {
    pub from: SocketAddr,
    pub data: Bytes,
}

impl UdpTraffic {
    pub async fn write<T: AsyncWrite + Unpin>(&self, writer: &mut T) -> Result<()> {
        let hdr = UdpHeader {
            from: self.from,
            len: self.data.len() as UdpPacketLen,
        };

        let v = bincode::serialize(&hdr).unwrap();

        trace!("Write {:?} of length {}", hdr, v.len());
        writer.write_u8(v.len() as u8).await?;
        writer.write_all(&v).await?;

        writer.write_all(&self.data).await?;

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn write_slice<T: AsyncWrite + Unpin>(
        writer: &mut T,
        from: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        let hdr = UdpHeader {
            from,
            len: data.len() as UdpPacketLen,
        };

        let v = bincode::serialize(&hdr).unwrap();

        trace!("Write {:?} of length {}", hdr, v.len());
        writer.write_u8(v.len() as u8).await?;
        writer.write_all(&v).await?;

        writer.write_all(data).await?;

        Ok(())
    }

    pub async fn read<T: AsyncRead + Unpin>(reader: &mut T, hdr_len: u8) -> Result<UdpTraffic> {
        let mut buf = vec![0; hdr_len as usize];
        reader
            .read_exact(&mut buf)
            .await
            .with_context(|| "Failed to read udp header")?;

        let hdr: UdpHeader =
            bincode::deserialize(&buf).with_context(|| "Failed to deserialize UdpHeader")?;

        trace!("hdr {:?}", hdr);

        let mut data = BytesMut::new();
        data.resize(hdr.len as usize, 0);
        reader.read_exact(&mut data).await?;

        Ok(UdpTraffic {
            from: hdr.from,
            data: data.freeze(),
        })
    }
}

pub fn digest(data: &[u8]) -> Digest {
    use sha2::{Digest, Sha256};
    let d = Sha256::new().chain_update(data).finalize();
    d.into()
}

struct PacketLength {
    hello: usize,
    ack: usize,
    auth: usize,
    c_cmd: usize,
    d_cmd: usize,
    visitor_ack: usize,
}

impl PacketLength {
    pub fn new() -> PacketLength {
        let username = "default";
        let d = digest(username.as_bytes());
        let hello = bincode::serialized_size(&Hello::ControlChannelHello(CURRENT_PROTO_VERSION, d))
            .unwrap() as usize;
        let c_cmd =
            bincode::serialized_size(&ControlChannelCmd::CreateDataChannel).unwrap() as usize;
        let d_cmd = bincode::serialized_size(&DataChannelCmd::StartForwardTcp(ForwardAddr::default())).unwrap() as usize;
        let ack = Ack::Ok;
        let ack = bincode::serialized_size(&ack).unwrap() as usize;
        let visitor_ack = bincode::serialized_size(&VisitorAck::Ok).unwrap() as usize;

        let auth = bincode::serialized_size(&Auth(d)).unwrap() as usize;
        PacketLength {
            hello,
            ack,
            auth,
            c_cmd,
            d_cmd,
            visitor_ack,
        }
    }
}

lazy_static! {
    static ref PACKET_LEN: PacketLength = PacketLength::new();
}

pub async fn read_hello<T: AsyncRead + Unpin>(conn: &mut T) -> Result<Hello> {
    let hello = match read_packet_message(conn).await? {
        PacketMessage::Hello(hello) => hello,
        _ => bail!("Unexpected packet message for hello"),
    };

    match hello {
        Hello::ControlChannelHello(v, _) => {
            if v != CURRENT_PROTO_VERSION {
                bail!(
                    "Protocol version mismatched. Expected {}, got {}. Please update `rathole`.",
                    CURRENT_PROTO_VERSION,
                    v
                );
            }
        }
        Hello::DataChannelHello(v, _) => {
            if v != CURRENT_PROTO_VERSION {
                bail!(
                    "Protocol version mismatched. Expected {}, got {}. Please update `rathole`.",
                    CURRENT_PROTO_VERSION,
                    v
                );
            }
        }
        Hello::VisitorHello(v, _) => {
            if v != CURRENT_PROTO_VERSION {
                bail!(
                    "Protocol version mismatched. Expected {}, got {}. Please update `rathole`.",
                    CURRENT_PROTO_VERSION,
                    v
                );
            }
        }
    }

    Ok(hello)
}

pub async fn read_auth<T: AsyncRead + Unpin>(conn: &mut T) -> Result<Auth> {
    match read_packet_message(conn).await? {
        PacketMessage::Auth(auth) => Ok(auth),
        _ => bail!("Unexpected packet message for auth"),
    }
}

pub async fn read_ack<T: AsyncRead + Unpin>(conn: &mut T) -> Result<Ack> {
    match read_packet_message(conn).await? {
        PacketMessage::Ack(ack) => Ok(ack),
        _ => bail!("Unexpected packet message for ack"),
    }
}

pub async fn read_control_cmd<T: AsyncRead + Unpin>(conn: &mut T) -> Result<ControlChannelCmd> {
    match read_packet_message(conn).await? {
        PacketMessage::Control(cmd) => Ok(cmd),
        _ => bail!("Unexpected packet message for control cmd"),
    }
}

pub async fn read_data_cmd<T: AsyncRead + Unpin>(conn: &mut T) -> Result<DataChannelCmd> {
    match read_packet_message(conn).await? {
        PacketMessage::DataCommand(cmd) => Ok(cmd),
        _ => bail!("Unexpected packet message for data cmd"),
    }
}

pub async fn write_visitor_auth<T: AsyncWrite + Unpin>(conn: &mut T, auth: &VisitorAuth) -> Result<()> {
    write_packet_message(conn, &PacketMessage::VisitorAuth(auth.clone())).await
}

pub async fn read_visitor_auth<T: AsyncRead + Unpin>(conn: &mut T) -> Result<VisitorAuth> {
    match read_packet_message(conn).await? {
        PacketMessage::VisitorAuth(auth) => Ok(auth),
        _ => bail!("Unexpected packet message for visitor auth"),
    }
}

pub async fn read_visitor_ack<T: AsyncRead + Unpin>(conn: &mut T) -> Result<VisitorAck> {
    match read_packet_message(conn).await? {
        PacketMessage::VisitorAck(ack) => Ok(ack),
        _ => bail!("Unexpected packet message for visitor ack"),
    }
}
