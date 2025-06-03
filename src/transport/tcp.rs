use std::net::SocketAddr;

use crate::error::N3tworkError;

use super::Transport;
use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

#[derive(Debug, Clone, Copy)]
pub struct TcpTransport {}

impl Default for TcpTransport {
    fn default() -> TcpTransport {
        TcpTransport {}
    }
}

#[async_trait]
impl Transport for TcpTransport {
    type Acceptor = TcpListener;
    type Stream = TcpStream;
    type RawStream = TcpStream;

    fn new() -> Result<Self, N3tworkError> {
        Ok(TcpTransport::default())
    }

    async fn bind<T: ToSocketAddrs + Send + Sync>(
        &self,
        addr: T,
    ) -> Result<Self::Acceptor, N3tworkError> {
        Ok(TcpListener::bind(addr).await?)
    }

    async fn accept(
        &self,
        acceptor: &Self::Acceptor,
    ) -> Result<(Self::RawStream, SocketAddr), N3tworkError> {
        Ok(acceptor.accept().await?)
    }

    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream, N3tworkError> {
        Ok(conn)
    }

    async fn connect<T: ToSocketAddrs + Send + Sync>(
        &self,
        addr: &T,
    ) -> Result<Self::Stream, N3tworkError> {
        TcpStream::connect(addr)
            .await
            .map_err(|e| N3tworkError::IOError(e))
    }
}




mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn test_tcp_transport() {
        let transport = TcpTransport::new().unwrap();
        let addr = "127.0.0.1:9876";
        let listener = transport.bind(addr).await.unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0; 1024];
            let (stream, _) = transport.accept(&listener).await.unwrap();
            let mut stream = transport.handshake(stream).await.unwrap();
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            assert_eq!(&buf[..n], b"Hello, World!");
            stream.write_all(&buf[..n]).await.unwrap();
        });
        let  client_stream = transport.connect(&addr).await.unwrap();
        let mut client_stream = transport.handshake(client_stream).await.unwrap();
        client_stream.write(b"Hello, World!").await.unwrap();
        let mut client_buf = [0; 1024];
        let n = client_stream.read(&mut client_buf).await.unwrap();
        assert!(n > 0);
        assert_eq!(&client_buf[..n], b"Hello, World!");
        handle.await.unwrap();
    }
}
