//! Connection close, end to end: a peer speaking TCP over a packet device, and the application
//! on the other side of an `IpStackTcpStream`.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, TcpConfig};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    time::timeout,
};

const PEER: [u8; 4] = [10, 0, 0, 2];
const LOCAL: [u8; 4] = [10, 0, 0, 1];
const PEER_PORT: u16 = 40000;
const LOCAL_PORT: u16 = 80;
/// Bounds each wait. It is shorter than the 2 MSL TIME-WAIT, so nothing here can pass by waiting it out.
const WAIT: Duration = Duration::from_millis(1000);

/// A TUN device that keeps packet boundaries.
struct Device {
    rx: UnboundedReceiver<Vec<u8>>,
    tx: UnboundedSender<Vec<u8>>,
}

impl AsyncRead for Device {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.rx.poll_recv(cx).map(|packet| {
            if let Some(packet) = packet {
                buf.put_slice(&packet);
            }
            Ok(())
        })
    }
}

impl AsyncWrite for Device {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        _ = self.tx.send(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
struct Segment {
    seq: u32,
    ack: u32,
    syn: bool,
    fin: bool,
    rst: bool,
    payload: Vec<u8>,
}

/// The TCP peer on the device side of the stack.
struct Peer {
    tx: UnboundedSender<Vec<u8>>,
    rx: UnboundedReceiver<Vec<u8>>,
    /// Our next sequence number.
    seq: u32,
    /// The next sequence number we expect from the stack.
    ack: u32,
}

impl Peer {
    fn send_raw(&self, seq: u32, ack: Option<u32>, flags: &str, payload: &[u8]) {
        let mut b = PacketBuilder::ipv4(PEER, LOCAL, 64).tcp(PEER_PORT, LOCAL_PORT, seq, u16::MAX);
        if let Some(ack) = ack {
            b = b.ack(ack);
        }
        for flag in flags.chars() {
            b = match flag {
                'S' => b.syn(),
                'P' => b.psh(),
                'F' => b.fin(),
                'R' => b.rst(),
                _ => unreachable!(),
            };
        }
        let mut packet = Vec::new();
        b.write(&mut packet, payload).unwrap();
        self.tx.send(packet).unwrap();
    }

    /// Sends a segment at our next sequence number, acknowledging everything received so far.
    fn send(&mut self, flags: &str, payload: &[u8]) {
        self.send_raw(self.seq, Some(self.ack), flags, payload);
        self.seq = self.seq.wrapping_add(payload.len() as u32 + flags.contains('F') as u32);
    }

    fn try_recv(&mut self) -> Option<Segment> {
        self.rx.try_recv().ok().map(|packet| parse(&packet))
    }

    async fn recv(&mut self) -> Segment {
        let packet = timeout(WAIT, self.rx.recv()).await.expect("the stack sent nothing").unwrap();
        parse(&packet)
    }

    /// Takes in-order data from the stack until its FIN, acknowledging the data as it goes, and the
    /// FIN when `ack_fin`; returns the data.
    async fn read_to_fin(&mut self, ack_fin: bool) -> Vec<u8> {
        let mut data = Vec::new();
        loop {
            let s = self.recv().await;
            assert!(!s.rst, "the stack reset the connection");
            if s.seq == self.ack {
                data.extend_from_slice(&s.payload);
                self.ack = self.ack.wrapping_add(s.payload.len() as u32);
            }
            if s.fin && s.seq.wrapping_add(s.payload.len() as u32) == self.ack {
                if ack_fin {
                    self.ack = self.ack.wrapping_add(1);
                    self.send("", b"");
                }
                return data;
            }
            if !s.payload.is_empty() {
                self.send("", b"");
            }
        }
    }

    /// Sends `data` in 1000-byte segments, the last one carrying FIN when `fin_with_data`.
    fn upload(&mut self, data: &[u8], fin_with_data: bool) {
        let chunks = data.chunks(1000);
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.enumerate() {
            self.send(if fin_with_data && i == last { "PF" } else { "P" }, chunk);
        }
        if !fin_with_data {
            self.send("F", b"");
        }
    }
}

fn parse(packet: &[u8]) -> Segment {
    let sliced = SlicedPacket::from_ip(packet).unwrap();
    let Some(TransportSlice::Tcp(t)) = sliced.transport else {
        panic!("the stack sent a packet that is not TCP");
    };
    Segment {
        seq: t.sequence_number(),
        ack: t.acknowledgment_number(),
        syn: t.syn(),
        fin: t.fin(),
        rst: t.rst(),
        payload: t.payload().to_vec(),
    }
}

/// Starts a stack, opens a connection from the peer, and returns the peer and the accepted stream.
async fn connect() -> (IpStack, Peer, IpStackTcpStream) {
    let (to_stack, device_rx) = unbounded_channel();
    let (device_tx, from_stack) = unbounded_channel();
    let mut config = IpStackConfig::default();
    config.mtu_unchecked(1500);
    let mut stack = IpStack::new(
        config,
        Device {
            rx: device_rx,
            tx: device_tx,
        },
    );
    let mut peer = Peer {
        tx: to_stack,
        rx: from_stack,
        seq: 1000,
        ack: 0,
    };
    peer.send_raw(peer.seq, None, "S", b"");
    peer.seq += 1;
    let IpStackStream::Tcp(stream) = timeout(WAIT, stack.accept()).await.unwrap().unwrap() else {
        panic!("expected a TCP stream");
    };
    let syn_ack = peer.recv().await;
    assert!(syn_ack.syn);
    peer.ack = syn_ack.seq.wrapping_add(1);
    peer.send("", b"");
    (stack, peer, stream)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

async fn read_to_end(stream: &mut IpStackTcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut data))
        .await
        .unwrap_or_else(|_| panic!("no end of stream; {} bytes read", data.len()))
        .unwrap();
    data
}

/// Drops the stream and waits for the stack to forget the session: only `probe` holds its sender then.
async fn session_is_removed(stream: IpStackTcpStream) {
    session_is_removed_within(stream, WAIT).await;
}

/// Drops a stream in TIME-WAIT and waits for the stack to forget it after 2 MSL expires.
async fn session_is_removed_after_time_wait(stream: IpStackTcpStream) {
    session_is_removed_within(stream, TcpConfig::default().two_msl + WAIT).await;
}

async fn session_is_removed_within(stream: IpStackTcpStream, limit: Duration) {
    let probe = stream.stream_sender();
    drop(stream);
    timeout(limit, async {
        while probe.strong_count() > 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the stack still holds the session");
}

/// An upload ends with a FIN on its own: the application reads every byte, then end of stream.
#[tokio::test(flavor = "multi_thread")]
async fn upload_then_separate_fin_arrives_whole() {
    let (_stack, mut peer, mut stream) = connect().await;
    let data = pattern(4321);
    peer.upload(&data, false);
    assert_eq!(read_to_end(&mut stream).await, data);
}

/// The last segment of an upload carries the FIN: its payload reaches the application.
#[tokio::test(flavor = "multi_thread")]
async fn upload_with_fin_on_the_last_segment_arrives_whole() {
    let (_stack, mut peer, mut stream) = connect().await;
    let data = pattern(4321);
    peer.upload(&data, true);
    assert_eq!(read_to_end(&mut stream).await, data);
    while peer.recv().await.ack != peer.seq {}
}

async fn both<A: std::future::Future, B: std::future::Future>(app: A, peer: B) -> (A::Output, B::Output) {
    timeout(WAIT, async { tokio::join!(app, peer) })
        .await
        .expect("the exchange did not finish")
}

/// The application shuts its side down first, as `shutdown(SHUT_WR)` does, and then reads the reply.
/// `fin_with_reply` sends the reply and the peer's FIN in one segment; `before_ack` sends them
/// before acknowledging our FIN.
async fn shutdown_then_reply(fin_with_reply: bool, before_ack: bool) {
    let (_stack, mut peer, mut stream) = connect().await;
    let reply = pattern(3000);
    let app = async {
        stream.write_all(b"request").await.unwrap();
        stream.shutdown().await.unwrap();
        read_to_end(&mut stream).await
    };
    let remote = async {
        // The reply acknowledges the request, and our FIN only when it is not `before_ack`.
        assert_eq!(peer.read_to_fin(!before_ack).await, b"request");
        peer.upload(&reply, fin_with_reply);
        if before_ack {
            peer.ack = peer.ack.wrapping_add(1);
            peer.send("", b"");
        }
    };
    let (received, ()) = both(app, remote).await;
    assert_eq!(received, reply);
    session_is_removed_after_time_wait(stream).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_then_reply_then_separate_fin() {
    shutdown_then_reply(false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_then_reply_with_fin() {
    shutdown_then_reply(true, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_then_reply_with_fin_before_our_fin_is_acknowledged() {
    shutdown_then_reply(true, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_then_one_segment_acks_our_fin_and_carries_reply_and_fin() {
    let (_stack, mut peer, mut stream) = connect().await;
    let app = async {
        stream.write_all(b"request").await.unwrap();
        stream.shutdown().await.unwrap();
        read_to_end(&mut stream).await
    };
    let remote = async {
        assert_eq!(peer.read_to_fin(false).await, b"request");
        peer.ack = peer.ack.wrapping_add(1);
        peer.send("PF", b"reply");
    };
    let (received, ()) = both(app, remote).await;
    assert_eq!(received, b"reply");
    session_is_removed_after_time_wait(stream).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_closes_first() {
    let (_stack, mut peer, mut stream) = connect().await;
    peer.upload(b"request", true);
    let reply = pattern(3000);
    let app = async {
        assert_eq!(read_to_end(&mut stream).await, b"request");
        stream.write_all(&reply).await.unwrap();
        stream.shutdown().await.unwrap();
    };
    let (_, received) = both(app, peer.read_to_fin(true)).await;
    assert_eq!(received, reply);
    session_is_removed(stream).await;
}

/// Both sides send FIN before seeing the other's.
#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_close() {
    let (_stack, mut peer, mut stream) = connect().await;
    let app = async {
        stream.shutdown().await.unwrap();
        read_to_end(&mut stream).await
    };
    let remote = async {
        let fin = peer.recv().await;
        assert!(fin.fin);
        // The peer's FIN crosses ours: it does not acknowledge the stack's FIN.
        peer.send("F", b"");
        let ack = peer.recv().await;
        assert_eq!(ack.ack, peer.seq, "the stack did not acknowledge the peer's FIN");
        peer.ack = fin.seq.wrapping_add(1);
        peer.send("", b"");
    };
    let (received, ()) = both(app, remote).await;
    assert_eq!(received, b"");
    session_is_removed_after_time_wait(stream).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_reset_ends_the_connection() {
    let (_stack, mut peer, mut stream) = connect().await;
    peer.send("P", b"partial");
    peer.send("R", b"");
    assert_eq!(read_to_end(&mut stream).await, b"partial");
    assert!(stream.write_all(b"late").await.is_err());
    session_is_removed(stream).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn segment_after_close_is_reset() {
    let (_stack, mut peer, mut stream) = connect().await;
    peer.send("F", b"");
    let app = async {
        assert_eq!(read_to_end(&mut stream).await, b"");
        stream.shutdown().await.unwrap();
    };
    both(app, peer.read_to_fin(true)).await;
    session_is_removed(stream).await;
    while peer.try_recv().is_some() {}
    peer.send("P", b"late");
    let reset = peer.recv().await;
    assert!(reset.rst, "{reset:?}");
}
