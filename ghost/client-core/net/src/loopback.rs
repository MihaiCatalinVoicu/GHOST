//! Test-only loopback connector: plain TCP to an in-process gRPC server, in place of the onion
//! connector, so the relay clients run without Tor. It counts dials, which lets tests prove that a
//! call refused before any I/O never opened a connection. Compiled only under `cfg(test)`.

// Loopback sockets are the point of this module; the clearnet bans apply to the library.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::relay_client::{BoxError, Io, StreamType};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::TcpStream;

#[derive(Clone)]
pub(crate) struct TcpConnector {
    addr: SocketAddr,
    dials: Arc<AtomicUsize>,
}

impl TcpConnector {
    pub(crate) fn new(addr: SocketAddr) -> Self {
        TcpConnector {
            addr,
            dials: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Connections attempted through this connector and its clones.
    pub(crate) fn dials(&self) -> usize {
        self.dials.load(Ordering::SeqCst)
    }
}

impl StreamType for TcpConnector {
    type Stream = TcpStream;
}

impl tower::Service<http::Uri> for TcpConnector {
    type Response = Io<TcpStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: http::Uri) -> Self::Future {
        self.dials.fetch_add(1, Ordering::SeqCst);
        let addr = self.addr;
        Box::pin(async move { Ok(Io::new(TcpStream::connect(addr).await?)) })
    }
}
