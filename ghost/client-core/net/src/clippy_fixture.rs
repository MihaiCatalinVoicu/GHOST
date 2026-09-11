//! Negative fixture for `clippy.toml` (compiled only with the `clippy-fixture` feature, which no
//! build enables): every call below must be reported by clippy as a disallowed method or type.
//! `scripts/gates/clippy-clearnet-fixture.sh` checks that each ban in `clippy.toml` fires here,
//! so a mistyped or unresolvable path cannot silently disable a ban. Never called.
#![allow(dead_code, unused_must_use, clippy::let_underscore_future)]

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

async fn std_and_tokio(addr: SocketAddr) {
    let _ = std::net::TcpStream::connect(addr);
    let _ = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1));
    let _ = std::net::UdpSocket::bind(addr);
    let _ = ("example.invalid", 80).to_socket_addrs();
    let _ = tokio::net::TcpStream::connect(addr).await;
    if let Ok(s) = tokio::net::TcpSocket::new_v4() {
        let _ = s.connect(addr).await;
    }
    let _ = tokio::net::TcpSocket::new_v6();
    let _ = tokio::net::UdpSocket::bind(addr).await;
    let _ = tokio::net::lookup_host("example.invalid:80").await;
}

fn hyper_clearnet() {
    let _ = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http::<tonic::body::Body>();
    let _ = hyper_util::client::legacy::connect::HttpConnector::new();
    let _ = hyper_util::client::legacy::connect::dns::GaiResolver::new();
}

fn named_types(
    _c: Option<hyper_util::client::legacy::connect::HttpConnector>,
    _r: Option<hyper_util::client::legacy::connect::dns::GaiResolver>,
) {
}

async fn runtime_sockets<R>(rt: &R, addr: SocketAddr)
where
    R: tor_rtcompat::NetStreamProvider + tor_rtcompat::UdpProvider,
{
    let _ = tor_rtcompat::NetStreamProvider::connect(rt, &addr, &Default::default()).await;
    let _ = tor_rtcompat::UdpProvider::bind(rt, &addr).await;
}

async fn arti_dials(c: &arti_client::TorClient<tor_rtcompat::PreferredRuntime>) {
    let prefs = arti_client::StreamPrefs::new();
    let _ = c.connect(("example.invalid", 80)).await;
    let _ = c.connect_with_prefs(("example.invalid", 80), &prefs).await;
    let _ = c.resolve("example.invalid").await;
    let _ = c.resolve_with_prefs("example.invalid", &prefs).await;
    let ip: std::net::IpAddr = [192, 0, 2, 1].into();
    let _ = c.resolve_ptr(ip).await;
    let _ = c.resolve_ptr_with_prefs(ip, &prefs).await;
}
