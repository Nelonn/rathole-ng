use super::{AddrMaybeCached, SocketOpts, TcpTransport, Transport};
use crate::config::{NoiseConfig, TransportConfig};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use snowstorm::{Builder, NoiseParams, NoiseStream};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::ToSocketAddrs;

pub struct NoiseTransport<T: Transport = TcpTransport> {
    underlying: T,
    config: NoiseConfig,
    params: NoiseParams,
    remote_public_key: Option<Vec<u8>>,
    psk: Option<[u8; 32]>,
}

impl<T: Transport> std::fmt::Debug for NoiseTransport<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self.config)
    }
}

impl<T: Transport> NoiseTransport<T> {
    pub fn set_psk(&mut self, psk: [u8; 32]) {
        self.psk = Some(psk);
    }

    async fn do_handshake<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        stream: S,
        initiator: bool,
    ) -> Result<snowstorm::stream::NoiseStream<S>> {
        let mut builder = Builder::new(self.params.clone());
        let keypair = builder.generate_keypair()?;
        builder = builder.local_private_key(&keypair.private);

        if let Some(x) = &self.remote_public_key {
            builder = builder.remote_public_key(x);
        }

        if let Some(psk) = &self.psk {
            builder = builder.psk(0, psk);
        }

        if initiator {
            Ok(NoiseStream::handshake(stream, builder.build_initiator()?).await?)
        } else {
            Ok(NoiseStream::handshake(stream, builder.build_responder()?).await?)
        }
    }
}

#[async_trait]
impl<T: Transport> Transport for NoiseTransport<T> {
    type Acceptor = T::Acceptor;
    type RawStream = T::RawStream;
    type Stream = snowstorm::stream::NoiseStream<T::Stream>;

    fn new(config: &TransportConfig) -> Result<Self> {
        let underlying = T::new(config)?;

        let config = match &config.noise {
            Some(v) => v.clone(),
            None => return Err(anyhow!("Missing noise config")),
        };

        let remote_public_key = match &config.remote_public_key {
            Some(x) => {
                Some(base64::decode(x).with_context(|| "Failed to decode remote_public_key")?)
            }
            None => None,
        };

        let params: NoiseParams = config.pattern.parse()?;

        Ok(NoiseTransport {
            underlying,
            config,
            params,
            remote_public_key,
            psk: None,
        })
    }

    fn hint(conn: &Self::Stream, opt: SocketOpts) {
        T::hint(conn.get_inner(), opt);
    }

    fn set_udp_nack_mode(conn: &Self::Stream) {
        T::set_udp_nack_mode(conn.get_inner());
    }

    async fn bind<U: ToSocketAddrs + Send + Sync>(&self, addr: U) -> Result<Self::Acceptor> {
        self.underlying.bind(addr).await
    }

    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)> {
        self.underlying.accept(a).await
    }

    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> {
        let conn = self.underlying.handshake(conn).await?;
        let conn = self.do_handshake(conn, false)
            .await
            .with_context(|| "Failed to do noise handshake")?;
        Ok(conn)
    }

    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream> {
        let conn = self.underlying.connect(addr).await?;

        let conn = self.do_handshake(conn, true)
            .await
            .with_context(|| "Failed to do noise handshake")?;
        return Ok(conn);
    }
}
