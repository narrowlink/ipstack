use super::tcp::IpStackTcpStream as IpStackTcpStreamInner;
use crate::{
    packet::{NetworkPacket, TcpHeaderWrapper},
    IpStackError,
};
use std::{net::SocketAddr, pin::Pin, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    sync::mpsc::{self, UnboundedSender},
    time::timeout,
};

pub struct IpStackTcpStream {
    inner: Option<Box<IpStackTcpStreamInner>>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    stream_sender: mpsc::UnboundedSender<NetworkPacket>,
}

impl IpStackTcpStream {
    pub(crate) fn new(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        tcp: TcpHeaderWrapper,
        pkt_sender: UnboundedSender<NetworkPacket>,
        mtu: u16,
        tcp_timeout: Duration,
    ) -> Result<IpStackTcpStream, IpStackError> {
        let (stream_sender, stream_receiver) = mpsc::unbounded_channel::<NetworkPacket>();
        IpStackTcpStreamInner::new(
            local_addr,
            peer_addr,
            tcp,
            pkt_sender,
            stream_receiver,
            mtu,
            tcp_timeout,
        )
        .map(Box::new)
        .map(|inner| IpStackTcpStream {
            inner: Some(inner),
            peer_addr,
            local_addr,
            stream_sender,
        })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
    pub fn stream_sender(&self) -> UnboundedSender<NetworkPacket> {
        self.stream_sender.clone()
    }
}

impl tokio::io::AsyncRead for IpStackTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.inner.as_mut() {
            Some(mut inner) => Pin::new(&mut inner).poll_read(cx, buf),
            None => {
                std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
            }
        }
    }
}

impl tokio::io::AsyncWrite for IpStackTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.inner.as_mut() {
            Some(mut inner) => Pin::new(&mut inner).poll_write(cx, buf),
            None => {
                std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
            }
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.inner.as_mut() {
            Some(mut inner) => Pin::new(&mut inner).poll_flush(cx),
            None => {
                std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
            }
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.inner.as_mut() {
            Some(mut inner) => Pin::new(&mut inner).poll_shutdown(cx),
            None => {
                std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
            }
        }
    }
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            tokio::spawn(async move {
                _ = timeout(Duration::from_secs(2), inner.shutdown()).await;
            });
        }
    }
}
