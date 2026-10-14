//! Minimal fast HTTP destination for benchmarking the tunnel.
//!
//! `cargo run --release --example bench_upstream -- 127.0.0.1:7000 1024`
//! answers every request with a body of the given size (default 1 KiB).

use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let addr: SocketAddr = args.next().as_deref().unwrap_or("127.0.0.1:7000").parse().expect("listen address");
    let size: usize = args.next().as_deref().unwrap_or("1024").parse().expect("body size");
    let body = Bytes::from(vec![b'x'; size]);
    let listener = TcpListener::bind(addr).await?;
    println!("bench upstream on {addr}, body {size} bytes");
    loop {
        let (tcp, _) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        let body = body.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |_req: Request<Incoming>| {
                let body = body.clone();
                async move { Ok::<_, Infallible>(Response::new(Full::new(body))) }
            });
            let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tcp), svc).await;
        });
    }
}
