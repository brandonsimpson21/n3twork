use std::net::SocketAddr;

use crate::error::N3tworkError;

use super::Transport;
use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};





#[derive(Debug)]
pub struct TcpTransport {}

impl Default for TcpTransport{
    fn default()-> TcpTransport{
        TcpTransport {}
    }
}



#[async_trait]
impl Transport for TcpTransport {
    type Acceptor = TcpListener;
    type Stream = TcpStream;
    type RawStream = TcpStream;

    fn new()->Result<Self, N3tworkError>{
        Ok(TcpTransport::default())
    }

    async fn bind<T: ToSocketAddrs + Send + Sync>(&self, addr: T)-> Result<Self::Acceptor, N3tworkError>{
        Ok(TcpListener::bind(addr).await?)
    }

    async fn accept(&self, acceptor: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr), N3tworkError> {
        Ok(acceptor.accept().await?)
    }

    async fn handshake(&self, conn: Self::RawStream)-> Result<Self::Stream, N3tworkError>{
        Ok(conn)
    }

    async fn connect<T: ToSocketAddrs + Send + Sync>(&self, addr: &T) -> Result<Self::Stream, N3tworkError> {
        TcpStream::connect(addr).await.map_err(|e| N3tworkError::IOError(e))
    }
}