use std::path::PathBuf;

use anyhow::Result;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::broadcast,
};

pub const PING: &str = "ping";
pub const PONG: &str = "pong";

pub async fn run_rathole_server(
    config_path: &str,
    shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    let cli = rathole::Cli {
        config_path: Some(PathBuf::from(config_path)),
        server: true,
        client: false,
        ..Default::default()
    };
    rathole::run(cli, shutdown_rx).await
}

pub async fn run_rathole_client(
    config_path: &str,
    shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    let cli = rathole::Cli {
        config_path: Some(PathBuf::from(config_path)),
        server: false,
        client: true,
        ..Default::default()
    };
    rathole::run(cli, shutdown_rx).await
}

pub mod tcp {
    use super::*;

    pub async fn echo_server<A: ToSocketAddrs>(addr: A) -> Result<()> {
        let l = TcpListener::bind(addr).await?;

        loop {
            let (conn, _addr) = l.accept().await?;
            tokio::spawn(async move {
                let _ = echo(conn).await;
            });
        }
    }

    pub async fn proxy_echo_server<A: ToSocketAddrs>(addr: A) -> Result<()> {
        let l = TcpListener::bind(addr).await?;

        loop {
            let (mut conn, _addr) = l.accept().await?;
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = conn.read(&mut buf).await.unwrap();
                let s = String::from_utf8_lossy(&buf[..n]);
                let offset = if s.starts_with("PROXY ") {
                    s.find("\r\n").unwrap() + 2
                } else if s.starts_with("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A") {
                    // v2 signature is 12 bytes
                    // then 1 byte version/cmd, 1 byte family, 2 bytes length
                    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
                    16 + len
                } else {
                    0
                };
                if offset > 0 {
                    conn.write_all(&buf[offset..n]).await.unwrap();
                } else {
                    conn.write_all(&buf[..n]).await.unwrap();
                }
                let (mut rd, mut wr) = conn.into_split();
                let _ = io::copy(&mut rd, &mut wr).await;
            });
        }
    }

    pub async fn pingpong_server<A: ToSocketAddrs>(addr: A) -> Result<()> {
        let l = TcpListener::bind(addr).await?;

        loop {
            let (conn, _addr) = l.accept().await?;
            tokio::spawn(async move {
                let _ = pingpong(conn).await;
            });
        }
    }

    async fn echo(conn: TcpStream) -> Result<()> {
        let (mut rd, mut wr) = conn.into_split();
        io::copy(&mut rd, &mut wr).await?;

        Ok(())
    }

    async fn pingpong(mut conn: TcpStream) -> Result<()> {
        let mut buf = [0u8; PING.len()];

        while conn.read_exact(&mut buf).await? != 0 {
            assert_eq!(buf, PING.as_bytes());
            conn.write_all(PONG.as_bytes()).await?;
        }

        Ok(())
    }
}

pub mod udp {
    use rathole::UDP_BUFFER_SIZE;
    use tokio::net::UdpSocket;
    use tracing::debug;

    use super::*;

    pub async fn echo_server<A: ToSocketAddrs>(addr: A) -> Result<()> {
        let l = UdpSocket::bind(addr).await?;
        debug!("UDP echo server listening");

        let mut buf = [0u8; UDP_BUFFER_SIZE];
        loop {
            let (n, addr) = l.recv_from(&mut buf).await?;
            debug!("Get {:?} from {}", &buf[..n], addr);
            l.send_to(&buf[..n], addr).await?;
        }
    }

    pub async fn pingpong_server<A: ToSocketAddrs>(addr: A) -> Result<()> {
        let l = UdpSocket::bind(addr).await?;

        let mut buf = [0u8; UDP_BUFFER_SIZE];
        loop {
            let (n, addr) = l.recv_from(&mut buf).await?;
            assert_eq!(&buf[..n], PING.as_bytes());
            l.send_to(PONG.as_bytes(), addr).await?;
        }
    }
}
