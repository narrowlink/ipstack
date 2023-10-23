use std::collections::{
    hash_map::Entry::{Occupied, Vacant},
    HashMap,
};

use packet::{NetworkPacket, NetworkTuple};
use stream::IpStackStream;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};

use crate::{
    packet::IpStackPacketProtocol,
    stream::{IpStackTcpStream, IpStackUdpStream},
};
mod error;
mod packet;
pub mod stream;

const TUN_FLAGS: [u8; 2] = [0x00, 0x00];
#[cfg(target_os = "linux")]
const TUN_PROTO_IP6: [u8; 2] = [0x86, 0xdd];
#[cfg(target_os = "linux")]
const TUN_PROTO_IP4: [u8; 2] = [0x08, 0x00];

#[cfg(target_os = "macos")]
const TUN_PROTO_IP6: [u8; 2] = [0x00, 0x02];
#[cfg(target_os = "macos")]
const TUN_PROTO_IP4: [u8; 2] = [0x00, 0x02];

pub struct IpStack {
    accept_receiver: UnboundedReceiver<IpStackStream>,
}

impl IpStack {
    pub fn new<D>(mut device: D, mtu: u16, packet_info: bool) -> IpStack
    where
        D: AsyncRead + AsyncWrite + std::marker::Unpin + std::marker::Send + 'static,
    {
        let (accept_sender, accept_receiver) = mpsc::unbounded_channel::<IpStackStream>();

        tokio::spawn(async move {
            let mut streams: HashMap<NetworkTuple, UnboundedSender<NetworkPacket>> = HashMap::new();
            let mut buffer = [0u8; u16::MAX as usize];

            let (pkt_sender, mut pkt_receiver) = mpsc::unbounded_channel::<NetworkPacket>();
            loop {
                select! {
                    Ok(n) = device.read(&mut buffer) => {
                        let Ok(packet) = NetworkPacket::parse(&buffer[4..n])else{
                            dbg!("parse error");
                            continue;
                        };
                        match streams.entry(packet.network_tuple()){
                            Occupied(entry) =>{
                                let t = packet.transport_protocol();
                                if let Err(_x) = entry.get().send(packet){
                                    match t{
                                        IpStackPacketProtocol::Tcp(_t) => {
                                            // dbg!(t.flags());
                                        }
                                        IpStackPacketProtocol::Udp => {
                                            // dbg!("udp");
                                        }
                                    }

                                }
                            }
                            Vacant(entry) => {
                                match packet.transport_protocol(){
                                    IpStackPacketProtocol::Tcp(h) => {
                                        match IpStackTcpStream::new(packet.src_addr(),packet.dst_addr(),h, pkt_sender.clone(),mtu).await{
                                            Ok(stream) => {
                                                entry.insert(stream.stream_sender());
                                                accept_sender.send(IpStackStream::Tcp(stream)).unwrap();
                                            }
                                            Err(e) => {
                                                dbg!(e);
                                            }
                                        }
                                    }
                                    IpStackPacketProtocol::Udp => {
                                        let stream = IpStackUdpStream::new(packet.src_addr(),packet.dst_addr(),packet.payload, pkt_sender.clone(),mtu);
                                        entry.insert(stream.stream_sender());
                                        accept_sender.send(IpStackStream::Udp(stream)).unwrap();
                                    }
                                }
                            }
                        }
                    }
                    Some(packet) = pkt_receiver.recv() => {
                        if packet.ttl() == 0{
                            streams.remove(&packet.network_tuple());
                            continue;
                        }
                        let Ok(mut packet_byte) = packet.to_bytes() else{
                            dbg!("to_bytes error");
                            continue;
                        };
                        if packet_info {
                            if packet.src_addr().is_ipv4(){
                                packet_byte.splice(0..0, [TUN_FLAGS, TUN_PROTO_IP4].concat());
                            } else{
                                packet_byte.splice(0..0, [TUN_FLAGS, TUN_PROTO_IP6].concat());
                            }
                        }
                        device.write_all(&packet_byte).await.unwrap();
                        // device.flush().await.unwrap();
                    }
                }
            }
        });

        IpStack { accept_receiver }
    }
    pub async fn accept(&mut self) -> IpStackStream {
        self.accept_receiver.recv().await.unwrap()
    }
}
