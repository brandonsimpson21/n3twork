use super::error::N3tworkError;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::{fmt::Debug, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};
use tracing::{error, trace};

pub mod tcp;

#[derive(Debug, Clone, Copy)]
pub struct SocketOpts {
    nodelay: Option<bool>,
    keepalive: Option<Duration>,
}

impl Default for SocketOpts {
    fn default() -> Self {
        SocketOpts {
            nodelay: Some(false),
            keepalive: None,
        }
    }
}

impl SocketOpts {
    pub fn new(nodelay: Option<bool>, keepalive: Option<Duration>) -> Self {
        SocketOpts { nodelay, keepalive }
    }

    pub fn apply(&self, conn: &TcpStream) {
        if let Some(v) = self.keepalive {
            todo!();
        }

        if let Some(nodelay) = self.nodelay {
            trace!("Set nodelay {}", nodelay);
            if let Err(e) = conn.set_nodelay(nodelay) {
                error!("{:#}", e);
            }
        }
    }
}

#[async_trait]
pub trait Transport: Debug + Send + Sync {
    type Acceptor: Send + Sync;
    type RawStream: Send + Sync;
    type Stream: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug;

    fn new() -> Result<Self, N3tworkError>
    where
        Self: Sized;
    async fn bind<T: ToSocketAddrs + Send + Sync>(
        &self,
        addr: T,
    ) -> Result<Self::Acceptor, N3tworkError>;
    async fn accept(
        &self,
        a: &Self::Acceptor,
    ) -> Result<(Self::RawStream, SocketAddr), N3tworkError>;
    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream, N3tworkError>;
    async fn connect<T: ToSocketAddrs + Send + Sync>(
        &self,
        addr: &T,
    ) -> Result<Self::Stream, N3tworkError>;
}
