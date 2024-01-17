//
// tokio = { version = "1.33", features = ["full"] }
//
use std::{env, error::Error, io};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

const TCP_TIMEOUT: u64 = 10 * 1000; // 10sec

async fn tcp_main(addr: &str) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("[TCP] listening on: {}", addr);
    loop {
        let (mut socket, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let block = async move {
                let mut buf = vec![0; 1024];
                println!("[TCP] incoming peer {}", peer);
                loop {
                    let duration = std::time::Duration::from_millis(TCP_TIMEOUT);
                    let n = tokio::time::timeout(duration, socket.read(&mut buf)).await??;
                    if n == 0 {
                        println!("[TCP] {} exit", peer);
                        break;
                    }
                    let amt = socket.write(&buf[0..n]).await?;
                    println!("[TCP] Echoed {}/{} bytes to {}", amt, n, peer);
                }
                Ok::<(), io::Error>(())
            };
            if let Err(err) = block.await {
                println!("[TCP] {}", err);
            }
        });
    }
}

async fn udp_main(addr: &str) -> io::Result<()> {
    let socket = UdpSocket::bind(&addr).await?;
    println!("[UDP] Listening on: {}", socket.local_addr()?);

    let mut buf = vec![0; 1024];
    let mut to_send = None;

    loop {
        if let Some((size, peer)) = to_send {
            let amt = socket.send_to(&buf[..size], &peer).await?;
            println!("[UDP] Echoed {}/{} bytes to {}", amt, size, peer);
        }

        to_send = Some(socket.recv_from(&mut buf).await?);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = env::args().nth(1).unwrap_or("127.0.0.1:8080".to_string());

    let addr1 = addr.clone();
    let tcp = tokio::spawn(async move {
        tcp_main(&addr1).await?;
        Ok::<(), io::Error>(())
    });

    let udp = tokio::spawn(async move {
        udp_main(&addr).await?;
        Ok::<(), io::Error>(())
    });

    tcp.await??;
    udp.await??;

    Ok(())
}
