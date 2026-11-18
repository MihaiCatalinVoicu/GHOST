//! `wire_transcript`: G-D11's wire-transcript generator (a dev-only example of `ghost-client-net`,
//! never part of the shipped library). It drives every client RPC — the six relay RPCs (StoreBlob,
//! GetBlob, ListNamespace, CheckBlobs, RedeemToken, RegisterKey), the six issuer RPCs
//! (RequestInvoice, BlindSign, InvoiceStatus, RedeemInvite, ClaimPayout, RefreshCredit) and the
//! mirror fetch — against in-process tonic/h2 servers over loopback TCP with fixed inputs, tees
//! the byte stream off the connector, and renders the canonical text transcript
//! `protocol/test-vectors/wire_transcript.txt`:
//!
//! ```text
//! cargo run -p ghost-client-net --example wire_transcript --locked
//! ```
//!
//! The transcript records, per RPC, the HTTP/2 preface, the SETTINGS values of both directions,
//! WINDOW_UPDATE presence, HEADERS frame shapes (the request metadata as recorded at the mock
//! service, sorted) and DATA frame lengths only. No payload byte is ever rendered: every secret
//! lives in the protobuf bodies, which appear only as lengths. The generator self-checks that
//! rule — it greps every rendered line for the lowercase hex (or the verbatim string) of each
//! fixed secret constant and aborts if one appears.
//!
//! The run is deterministic: fixed inputs, one fresh server, connection and capture per RPC, and
//! nothing rendered depends on the clock, randomness or the ephemeral port. The committed file is
//! therefore a golden artifact: `scripts/gates/wire-transcript.sh` regenerates it and diffs
//! (G-D11, the wire half of NI-U5's two-release comparison harness). The file's SHA-256 is printed
//! on stdout as the last line. `GHOST_WIRE_TRANSCRIPT_OUT` redirects where the file is written
//! (the gate regenerates into scratch space and diffs, never touching the committed copy).

// Loopback servers and plain TCP connectors are the point of this generator.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::io::IoSlice;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ghost_client_net::mirror::{fetch_with, MirrorSet};
use ghost_client_net::namespace_client::{RedeemRpc, RegisterRpc};
use ghost_client_net::relay_client::{Io, RelayClient, StreamType};
use ghost_client_net::{IssuerClient, IssuerRpc};
use ghost_issuer_api::proto::issuer_service_server::{IssuerService, IssuerServiceServer};
use ghost_issuer_api::proto::{
    BlindSignRequest, BlindSignResponse, ClaimPayoutRequest, ClaimPayoutResponse,
    InvoiceStatusRequest, InvoiceStatusResponse, RedeemInviteRequest, RedeemInviteResponse,
    RefreshCreditRequest, RefreshCreditResponse, RequestInvoiceRequest, RequestInvoiceResponse,
};
use ghost_relay_api::proto::relay_service_server::{RelayService, RelayServiceServer};
use ghost_relay_api::proto::{
    Capability, CheckBlobsRequest, CheckBlobsResponse, GetBlobRequest, GetBlobResponse, GossipAck,
    GossipInventoryBatch, ListNamespaceRequest, ListNamespaceResponse, RedeemResult,
    RedeemTokenRequest, RedeemTokenResponse, RegisterKeyRequest, RegisterKeyResponse,
    RegisterResult, StoreBlobRequest, StoreBlobResponse,
};
use ghost_relay_api::PROTOCOL_VERSION;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;

/// The fixed namespace every relay request binds to. A redaction-checked secret.
const NAMESPACE: [u8; 32] = {
    let mut b = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        b[i] = i as u8;
        i += 1;
    }
    b
};

/// A v1 capability (82 bytes) for NAMESPACE: version 1, kind Write (2), a fixed quota and expiry,
/// an arbitrary MAC. No client-side check verifies the MAC before the wire (the guards read the
/// header only), and the relay answers are fixed bytes. A redaction-checked secret.
fn capability() -> Vec<u8> {
    let mut cap = vec![1, 2];
    cap.extend_from_slice(&NAMESPACE);
    cap.extend_from_slice(&1_048_576u64.to_be_bytes());
    cap.extend_from_slice(&1_800_000_000u64.to_be_bytes());
    cap.extend_from_slice(&[0x5A; 32]);
    cap
}

/// A fixed 354-byte token shape (the ACCESS-token length). The bytes ride in DATA and are never
/// rendered. A redaction-checked secret.
fn token() -> Vec<u8> {
    (0..354u16)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
        .collect()
}

/// The tee: a TCP stream that appends every written byte to `c2s` and every read byte to `s2c`.
struct CaptureStream {
    inner: TcpStream,
    c2s: Arc<Mutex<Vec<u8>>>,
    s2c: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for CaptureStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        this.s2c
            .lock()
            .unwrap()
            .extend_from_slice(&buf.filled()[before..]);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CaptureStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let n = std::task::ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        this.c2s.lock().unwrap().extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let n = std::task::ready!(Pin::new(&mut this.inner).poll_write_vectored(cx, bufs))?;
        let mut remaining = n;
        for buf in bufs {
            if remaining == 0 {
                break;
            }
            let take = remaining.min(buf.len());
            this.c2s.lock().unwrap().extend_from_slice(&buf[..take]);
            remaining -= take;
        }
        Poll::Ready(Ok(n))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The connector every client here builds against: dials the loopback server, tees the stream.
/// Ignores the request URI exactly like the onion connector does.
#[derive(Clone)]
struct CaptureConnector {
    addr: SocketAddr,
    c2s: Arc<Mutex<Vec<u8>>>,
    s2c: Arc<Mutex<Vec<u8>>>,
}

impl CaptureConnector {
    fn new(addr: SocketAddr) -> (Self, Arc<Mutex<Vec<u8>>>, Arc<Mutex<Vec<u8>>>) {
        let c2s = Arc::new(Mutex::new(Vec::new()));
        let s2c = Arc::new(Mutex::new(Vec::new()));
        (
            CaptureConnector {
                addr,
                c2s: c2s.clone(),
                s2c: s2c.clone(),
            },
            c2s,
            s2c,
        )
    }
}

impl StreamType for CaptureConnector {
    type Stream = CaptureStream;
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl tower::Service<http::Uri> for CaptureConnector {
    type Response = Io<CaptureStream>;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: http::Uri) -> Self::Future {
        let addr = self.addr;
        let c2s = self.c2s.clone();
        let s2c = self.s2c.clone();
        Box::pin(async move {
            let inner = TcpStream::connect(addr).await?;
            Ok(Io::new(CaptureStream { inner, c2s, s2c }))
        })
    }
}

/// One HTTP/2 frame of a captured byte stream. The payload is kept only to decode SETTINGS and
/// WINDOW_UPDATE values; it is never rendered.
#[derive(Clone)]
struct Frame {
    kind: &'static str,
    stream: u32,
    len: usize,
    end_stream: bool,
    payload: Vec<u8>,
}

const KINDS: [(u8, &str); 10] = [
    (0, "data"),
    (1, "headers"),
    (2, "priority"),
    (3, "rst_stream"),
    (4, "settings"),
    (5, "push_promise"),
    (6, "ping"),
    (7, "goaway"),
    (8, "window_update"),
    (9, "continuation"),
];

/// Walks a captured byte stream into frames. The 24-byte client preface is skipped when present
/// (it is: the clients speak h2 with prior knowledge). A truncated tail is ignored: the clients
/// close the connection without GOAWAY when the call is done.
fn parse_frames(bytes: &[u8]) -> Vec<Frame> {
    let mut off = 0;
    if bytes.len() >= 24 && &bytes[..24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        off = 24;
    }
    let mut out = Vec::new();
    while off + 9 <= bytes.len() {
        let len = ((bytes[off] as usize) << 16)
            | ((bytes[off + 1] as usize) << 8)
            | bytes[off + 2] as usize;
        let typ = bytes[off + 3];
        let flags = bytes[off + 4];
        let stream = u32::from_be_bytes([
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
            bytes[off + 8],
        ]) & 0x7fff_ffff;
        off += 9;
        if off + len > bytes.len() {
            break;
        }
        let payload = bytes[off..off + len].to_vec();
        off += len;
        let kind = KINDS
            .iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, k)| *k)
            .unwrap_or("unknown");
        out.push(Frame {
            kind,
            stream,
            len,
            end_stream: flags & 0x1 != 0,
            payload,
        });
    }
    out
}

/// Canonicalizes a parsed direction's frame list against h2's emission-timing race: the
/// SETTINGS ACK (a connection-level frame carrying no HPACK state) is flushed by h2 either
/// with the peer-settings response or with the next write, so its byte position relative to
/// WINDOW_UPDATE and the first stream frames varies run to run with no wire semantics in the
/// difference. Every `settings: ack` is pinned immediately after the direction's first
/// non-ACK SETTINGS frame (its semantic anchor); every other frame keeps its exact wire
/// order, so HEADERS/DATA sequences per stream are untouched.
fn canonicalize(frames: &mut Vec<Frame>) {
    let anchor = frames
        .iter()
        .position(|f| f.kind == "settings" && !f.end_stream);
    let Some(anchor) = anchor else { return };
    let acks: Vec<Frame> = frames
        .iter()
        .filter(|f| f.kind == "settings" && f.end_stream)
        .cloned()
        .collect();
    if acks.is_empty() {
        return;
    }
    frames.retain(|f| !(f.kind == "settings" && f.end_stream));
    let anchor = anchor.min(frames.len());
    for (i, ack) in acks.into_iter().enumerate() {
        frames.insert(anchor + 1 + i, ack);
    }
}

/// Renders one captured frame as a line: lengths only, never payload bytes. SETTINGS renders its
/// values (window sizes and frame bounds, the NI-U5 pin surface); WINDOW_UPDATE renders its
/// increment; both are settings, not secrets.
fn render_frame(f: &Frame) -> String {
    match f.kind {
        "settings" if f.end_stream => "settings: ack".to_owned(),
        "settings" => {
            let mut parts = Vec::new();
            for entry in f.payload.chunks_exact(6) {
                let id = u16::from_be_bytes([entry[0], entry[1]]);
                let value = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
                let named = match id {
                    1 => Some("header_table_size"),
                    2 => Some("enable_push"),
                    3 => Some("max_concurrent_streams"),
                    4 => Some("initial_window_size"),
                    5 => Some("max_frame_size"),
                    6 => Some("max_header_list_size"),
                    _ => None,
                };
                match named {
                    Some(name) => parts.push(format!("{name}={value}")),
                    None => parts.push(format!("id{id}={value}")),
                }
            }
            format!("settings: {}", parts.join(" "))
        }
        "window_update" => {
            let increment = f
                .payload
                .get(..4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x7fff_ffff)
                .unwrap_or(0);
            format!("window_update: stream={} +{increment}", f.stream)
        }
        _ => {
            let end = if f.end_stream { " end_stream" } else { "" };
            format!("{}: stream={} len={}{end}", f.kind, f.stream, f.len)
        }
    }
}

/// The request metadata one mock service recorded, sorted for a canonical rendering.
struct Seen {
    name: String,
    headers: Vec<(String, String)>,
}

fn record(seen: &Arc<Mutex<Option<Seen>>>, name: &str, md: &tonic::metadata::MetadataMap) {
    let mut headers: Vec<(String, String)> = md
        .iter()
        .map(|kv| match kv {
            tonic::metadata::KeyAndValueRef::Ascii(k, v) => {
                let value = v
                    .to_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|_| format!("{} bytes", v.len()));
                (k.as_str().to_owned(), value)
            }
            tonic::metadata::KeyAndValueRef::Binary(k, v) => (
                k.as_str().to_owned(),
                format!("{} bytes", v.to_bytes().map_or(0, |b| b.len())),
            ),
        })
        .collect();
    headers.sort();
    *seen.lock().unwrap() = Some(Seen {
        name: name.to_owned(),
        headers,
    });
}

/// One section of the transcript.
struct Section {
    title: String,
    method: &'static str,
    authority: String,
    path: String,
    note: &'static str,
    seen: Option<Seen>,
    c2s: Vec<Frame>,
    s2c: Vec<Frame>,
}

impl Section {
    fn render(&self, out: &mut String) {
        out.push_str(&format!("## {}\n", self.title));
        out.push_str(&format!(":authority: {}\n", self.authority));
        out.push_str(&format!(":method: {}\n", self.method));
        out.push_str(&format!(":path: {}\n", self.path));
        for line in self.note.lines() {
            out.push_str(&format!("# {line}\n"));
        }
        match &self.seen {
            Some(seen) => {
                out.push_str(&format!(
                    "request headers (recorded at the mock service `{}`, sorted):\n",
                    seen.name
                ));
                for (k, v) in &seen.headers {
                    out.push_str(&format!("  {k}: {v}\n"));
                }
            }
            None => out.push_str(
                "request headers: not recorded (no service on this route; the request shape is in\n# the captured c2s HEADERS frame and rendered from the client's builder)\n",
            ),
        }
        out.push_str(&format!("c2s DATA: {}\n", data_total(&self.c2s)));
        out.push_str("c2s frames:\n");
        for f in &self.c2s {
            out.push_str(&format!("  {}\n", render_frame(f)));
        }
        out.push_str(&format!("s2c DATA: {}\n", data_total(&self.s2c)));
        out.push_str("s2c frames:\n");
        for f in &self.s2c {
            out.push_str(&format!("  {}\n", render_frame(f)));
        }
        out.push('\n');
    }
}

/// Sums the DATA frames of one direction: `<n> bytes in <m> frame(s)`.
fn data_total(frames: &[Frame]) -> String {
    let data: Vec<&Frame> = frames.iter().filter(|f| f.kind == "data").collect();
    let bytes: usize = data.iter().map(|f| f.len).sum();
    format!("{bytes} bytes in {} frame(s)", data.len())
}

/// The mock relay: records the request metadata of the one RPC it serves and answers fixed bytes.
/// The client's response validation is irrelevant to the transcript — a request is complete on
/// the wire the moment the client sends it — and fixed answers keep every rendered length stable
/// across runs and machines.
#[derive(Clone, Default)]
struct TranscriptRelay {
    seen: Arc<Mutex<Option<Seen>>>,
}

#[tonic::async_trait]
impl RelayService for TranscriptRelay {
    async fn store_blob(
        &self,
        r: tonic::Request<StoreBlobRequest>,
    ) -> Result<tonic::Response<StoreBlobResponse>, tonic::Status> {
        record(&self.seen, "store_blob", r.metadata());
        let r = r.into_inner();
        Ok(tonic::Response::new(StoreBlobResponse {
            success: true,
            stored_hash: r.blob_hash,
            expiry_unix_seconds: 1_800_000_000,
        }))
    }

    async fn get_blob(
        &self,
        r: tonic::Request<GetBlobRequest>,
    ) -> Result<tonic::Response<GetBlobResponse>, tonic::Status> {
        record(&self.seen, "get_blob", r.metadata());
        Ok(tonic::Response::new(GetBlobResponse {
            data: vec![0x6B; 1024],
            ..Default::default()
        }))
    }

    async fn check_blobs(
        &self,
        r: tonic::Request<CheckBlobsRequest>,
    ) -> Result<tonic::Response<CheckBlobsResponse>, tonic::Status> {
        record(&self.seen, "check_blobs", r.metadata());
        Ok(tonic::Response::new(CheckBlobsResponse {
            available_hashes: r.into_inner().blob_hashes,
        }))
    }

    async fn list_namespace(
        &self,
        r: tonic::Request<ListNamespaceRequest>,
    ) -> Result<tonic::Response<ListNamespaceResponse>, tonic::Status> {
        record(&self.seen, "list_namespace", r.metadata());
        Ok(tonic::Response::new(ListNamespaceResponse {
            blob_hashes: vec![vec![0x11; 32]],
            next_cursor: Vec::new(),
        }))
    }

    type GossipSyncStream = tokio_stream::Empty<Result<GossipAck, tonic::Status>>;

    async fn gossip_sync(
        &self,
        _r: tonic::Request<tonic::Streaming<GossipInventoryBatch>>,
    ) -> Result<tonic::Response<Self::GossipSyncStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("relay-to-relay only"))
    }

    async fn redeem_token(
        &self,
        r: tonic::Request<RedeemTokenRequest>,
    ) -> Result<tonic::Response<RedeemTokenResponse>, tonic::Status> {
        record(&self.seen, "redeem_token", r.metadata());
        Ok(tonic::Response::new(RedeemTokenResponse {
            result: RedeemResult::Replayed as i32,
            capability: None,
            relay_period_id: 2959,
            relay_minute: 29_812_345,
        }))
    }

    async fn register_key(
        &self,
        r: tonic::Request<RegisterKeyRequest>,
    ) -> Result<tonic::Response<RegisterKeyResponse>, tonic::Status> {
        record(&self.seen, "register_key", r.metadata());
        Ok(tonic::Response::new(RegisterKeyResponse {
            result: RegisterResult::WrongPeriod as i32,
            relay_period_id: 2959,
            relay_minute: 29_812_345,
            valid_until_unix: 0,
        }))
    }
}

/// The mock issuer: same recording contract as the mock relay.
#[derive(Clone, Default)]
struct TranscriptIssuer {
    seen: Arc<Mutex<Option<Seen>>>,
}

#[tonic::async_trait]
impl IssuerService for TranscriptIssuer {
    async fn request_invoice(
        &self,
        r: tonic::Request<RequestInvoiceRequest>,
    ) -> Result<tonic::Response<RequestInvoiceResponse>, tonic::Status> {
        record(&self.seen, "request_invoice", r.metadata());
        Ok(tonic::Response::new(RequestInvoiceResponse {
            result: 2, // WRONG_PERIOD, nothing recorded
            ..Default::default()
        }))
    }

    async fn blind_sign(
        &self,
        r: tonic::Request<BlindSignRequest>,
    ) -> Result<tonic::Response<BlindSignResponse>, tonic::Status> {
        record(&self.seen, "blind_sign", r.metadata());
        Ok(tonic::Response::new(BlindSignResponse {
            state: 2, // AWAITING_PAYMENT
            ..Default::default()
        }))
    }

    async fn invoice_status(
        &self,
        r: tonic::Request<InvoiceStatusRequest>,
    ) -> Result<tonic::Response<InvoiceStatusResponse>, tonic::Status> {
        record(&self.seen, "invoice_status", r.metadata());
        Ok(tonic::Response::new(InvoiceStatusResponse {
            state: 2,
            ..Default::default()
        }))
    }

    async fn redeem_invite(
        &self,
        r: tonic::Request<RedeemInviteRequest>,
    ) -> Result<tonic::Response<RedeemInviteResponse>, tonic::Status> {
        record(&self.seen, "redeem_invite", r.metadata());
        Ok(tonic::Response::new(RedeemInviteResponse {
            result: 3, // WRONG_PERIOD
            ..Default::default()
        }))
    }

    async fn claim_payout(
        &self,
        r: tonic::Request<ClaimPayoutRequest>,
    ) -> Result<tonic::Response<ClaimPayoutResponse>, tonic::Status> {
        record(&self.seen, "claim_payout", r.metadata());
        Ok(tonic::Response::new(ClaimPayoutResponse {
            result: 2, // CREDITS_SPENT
            ..Default::default()
        }))
    }

    async fn refresh_credit(
        &self,
        r: tonic::Request<RefreshCreditRequest>,
    ) -> Result<tonic::Response<RefreshCreditResponse>, tonic::Status> {
        record(&self.seen, "refresh_credit", r.metadata());
        Ok(tonic::Response::new(RefreshCreditResponse {
            result: 2, // REPLAYED
            ..Default::default()
        }))
    }
}

/// Binds a listener and serves one mock relay on it (the caller keeps the service handle for its
/// recording; the server task runs until the process exits).
async fn relay_server() -> (TranscriptRelay, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = TranscriptRelay::default();
    let svc = RelayServiceServer::new(relay.clone());
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (relay, addr)
}

async fn issuer_server() -> (TranscriptIssuer, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = TranscriptIssuer::default();
    let svc = IssuerServiceServer::new(issuer.clone());
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (issuer, addr)
}

/// Runs one relay-RPC section: a fresh mock relay, capture and client, one call whose result is
/// ignored, then the two captured directions parsed into frames.
async fn relay_section<F, Fut>(title: &str, path: &str, note: &'static str, call: F) -> Section
where
    F: FnOnce(RelayClient<CaptureConnector>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (relay, addr) = relay_server().await;
    let (connector, c2s, s2c) = CaptureConnector::new(addr);
    let client = RelayClient::with_connector(connector);
    call(client).await;
    let seen = relay.seen.lock().unwrap().take();
    let mut c2s = parse_frames(&c2s.lock().unwrap());
    let mut s2c = parse_frames(&s2c.lock().unwrap());
    canonicalize(&mut c2s);
    canonicalize(&mut s2c);
    Section {
        title: title.to_owned(),
        method: "POST",
        authority: "relay.invalid".to_owned(),
        path: path.to_owned(),
        note,
        seen,
        c2s,
        s2c,
    }
}

/// Runs one issuer-RPC section: same contract as `relay_section`.
async fn issuer_section<F, Fut>(title: &str, path: &str, note: &'static str, call: F) -> Section
where
    F: FnOnce(IssuerClient<CaptureConnector>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (issuer, addr) = issuer_server().await;
    let (connector, c2s, s2c) = CaptureConnector::new(addr);
    let client = IssuerClient::with_connector(connector);
    call(client).await;
    let seen = issuer.seen.lock().unwrap().take();
    let mut c2s = parse_frames(&c2s.lock().unwrap());
    let mut s2c = parse_frames(&s2c.lock().unwrap());
    canonicalize(&mut c2s);
    canonicalize(&mut s2c);
    Section {
        title: title.to_owned(),
        method: "POST",
        authority: "issuer.invalid".to_owned(),
        path: path.to_owned(),
        note,
        seen,
        c2s,
        s2c,
    }
}

/// Runs one mirror-fetch section: the tonic router serves no route for the mirror's GET path and
/// answers 404, which the client refuses at status — the request is complete on the wire either
/// way, and no mock handler ever sees it.
async fn mirror_section(
    title: &str,
    authority: &str,
    path: String,
    note: &'static str,
    set: &MirrorSet,
    slot: u8,
    kind: u8,
    chunk_index: u64,
) -> Section {
    let (_router, addr) = relay_server().await;
    let (connector, c2s, s2c) = CaptureConnector::new(addr);
    let _ = fetch_with(
        connector,
        set,
        slot,
        kind,
        chunk_index,
        Duration::from_secs(5),
    )
    .await;
    // The refused fetch returns at the status check without draining the 404 body; the
    // connection task keeps reading while a fixed settle beat lets those frames land, so the
    // captured s2c frame list is the same on every run.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c2s = parse_frames(&c2s.lock().unwrap());
    let mut s2c = parse_frames(&s2c.lock().unwrap());
    canonicalize(&mut c2s);
    canonicalize(&mut s2c);
    Section {
        title: title.to_owned(),
        method: "GET",
        authority: authority.to_owned(),
        path,
        note,
        seen: None,
        c2s,
        s2c,
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The transcript's documented header.
const HEADER: &str = "\
# GHOST wire transcript — protocol/test-vectors/wire_transcript.txt
# Generator: client-core/net/examples/wire_transcript.rs
#   cargo run -p ghost-client-net --example wire_transcript --locked
# Gate: scripts/gates/wire-transcript.sh regenerates this file and diffs it against the committed
#   copy (G-D11; the wire half of NI-U5's two-release comparison harness).
# Determinism: fixed inputs only; each RPC runs against its own in-process tonic/h2 server over
#   loopback TCP through a tee'd connector; nothing rendered depends on the clock, randomness or
#   the ephemeral port. Re-running the generator reproduces this file byte for byte.
# Redaction: DATA payloads (the grpc/protobuf bodies, where every secret lives) render as frame
#   lengths only; HEADERS render as the request metadata recorded at the mock service (sorted)
#   plus frame shapes. The generator self-checks: the lowercase hex of every fixed secret constant
#   must appear in no rendered line, or the run aborts. The APK SHA-256 is the one deliberate
#   exclusion: it names the mirror path by design, a public identifier like the path itself.
# The SHA-256 of this file is the generator's last stdout line.

";

const NOTE_STORE: &str = "RelayClient::store with the smallest ciphertext bucket (1024 bytes), the
86400-second TTL bucket and one fixed capability. The request id is random but always 16 bytes,
so every rendered length is fixed.";

const NOTE_GET: &str = "RelayClient::get of the SHA-256 of the fixed 1024-byte ciphertext.";

const NOTE_LIST: &str = "RelayClient::list, first page (empty cursor), limit 16.";

const NOTE_CHECK: &str = "RelayClient::check over two fixed hashes.";

const NOTE_REDEEM: &str = "Driven at the RedeemRpc seam with the exact request redeem_with
(NamespaceClient::redeem) builds and sends. NamespaceClient::redeem itself is not driveable
in-process: its pre-I/O binding check needs an issuer-minted token, and that check never changes
the bytes sent (tests/redeem.rs pins the guarded path).";

const NOTE_REGISTER: &str = "Driven at the RegisterRpc seam with the exact request register_with
(NamespaceClient::register_key) builds and sends after its capability guard; the guard reads the
capability header only and never changes the bytes sent (tests/register.rs pins the guarded
path).";

const NOTE_ISSUER: &str = "IssuerClient's IssuerRpc impl sends the request unvalidated — the
issuer_flow checks run above the wire — so a Default-extended fixed request reaches the wire as
the client builds it.";

const NOTE_MIRROR_BUNDLE: &str = "Rendered from mirror.rs's request builder: the GET path routes
to no service on the tonic server, which answers 404 and the client refuses at status — the
request is complete on the wire. No mock handler sees it.";

const NOTE_MIRROR_CHUNK: &str = "The chunk fetch (kind 1, chunk 0 of a 6000-byte APK): the path
names the APK by its SHA-256, a public path component, and the range header carries
`bytes 0-4194303/6000` (the length renders in the RANGE value, not in DATA).";

const NOTES: &str = "\
## coverage notes
# GossipSync is a relay-to-relay streaming RPC, not a client RPC: no client ever sends it, and it
# is not driven here.
# The six relay RPCs and the six issuer RPCs are all driven. RedeemToken and RegisterKey run at
# the RedeemRpc/RegisterRpc seams with the exact requests the NamespaceClient paths send; their
# pre-I/O guards (the ES binding, the capability header check) never change the bytes on the wire.
# No mock answer is built to pass client-side validation: every answer is fixed bytes and the
# result of every call is ignored. A request is complete on the wire the moment the client sends
# it; the transcript records shapes, not outcomes.
# The mirror fetch's request shape is rendered from mirror.rs's builder rather than from a mock
# handler: the bare router answers 404 before any handler runs. The c2s HEADERS frame in the
# capture carries exactly this :method, :path and :authority.
";

#[tokio::main]
async fn main() {
    let cap = capability();
    let tok = token();
    let ciphertext = vec![0xE5; 1024];
    let blob_hash = sha256(&ciphertext);
    let other_hash = sha256(&[0x5D; 4096]);
    let request_id: Vec<u8> = (0..16u8)
        .map(|i| i.wrapping_mul(11).wrapping_add(1))
        .collect();
    let verifier: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(3).wrapping_add(9))
        .collect();
    let claim_hash = sha256(b"ghost/v1/issuer-claim || claim_key");
    let claim_key: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(13).wrapping_add(5))
        .collect();
    let blinded = vec![0xB1u8; 256];
    let invoice_id: Vec<u8> = (0..16u8)
        .map(|i| i.wrapping_mul(5).wrapping_add(7))
        .collect();
    let claim_id: Vec<u8> = (0..16u8)
        .map(|i| i.wrapping_mul(9).wrapping_add(2))
        .collect();
    let payout_address = format!("4{}", "A".repeat(94));
    let mut apk_sha256 = [0u8; 32];
    for (i, b) in apk_sha256.iter_mut().enumerate() {
        // Offset so its hex cannot contain any shorter sequential secret's hex
        // (the redaction self-check greps substrings; request_id is 0..16).
        *b = (i as u8).wrapping_add(0x80);
    }
    let mirror_first = "pdp7otysol5453kpyinghqcbcok64pshyuxn5ht4flxx3imxfuy7erqd.onion:443";
    let mirror_second = "cu7sle2hf44gz72vwtpck66he42dzyfdfgxsgacwyhb4wlktwwrualyd.onion:443";
    let set = MirrorSet {
        first: mirror_first.as_bytes().to_vec(),
        second: mirror_second.as_bytes().to_vec(),
        network: 2,
        apk_sha256: Some(apk_sha256),
        apk_length: 6000,
    };

    let mut sections: Vec<Section> = Vec::new();

    {
        let cap = cap.clone();
        sections.push(
            relay_section(
                "relay StoreBlob",
                "/ghost.relay.v1.RelayService/StoreBlob",
                NOTE_STORE,
                move |mut client| async move {
                    let _ = client.store(NAMESPACE, cap, vec![0xE5; 1024], 86_400).await;
                },
            )
            .await,
        );
    }
    {
        let cap = cap.clone();
        sections.push(
            relay_section(
                "relay GetBlob",
                "/ghost.relay.v1.RelayService/GetBlob",
                NOTE_GET,
                move |mut client| async move {
                    let _ = client.get(blob_hash, cap).await;
                },
            )
            .await,
        );
    }
    {
        let cap = cap.clone();
        sections.push(
            relay_section(
                "relay ListNamespace",
                "/ghost.relay.v1.RelayService/ListNamespace",
                NOTE_LIST,
                move |mut client| async move {
                    let _ = client.list(NAMESPACE, cap, Vec::new(), 16).await;
                },
            )
            .await,
        );
    }
    {
        let cap = cap.clone();
        sections.push(
            relay_section(
                "relay CheckBlobs",
                "/ghost.relay.v1.RelayService/CheckBlobs",
                NOTE_CHECK,
                move |mut client| async move {
                    let _ = client.check(cap, vec![blob_hash, other_hash]).await;
                },
            )
            .await,
        );
    }
    {
        let tok = tok.clone();
        let request_id = request_id.clone();
        sections.push(
            relay_section(
                "relay RedeemToken",
                "/ghost.relay.v1.RelayService/RedeemToken",
                NOTE_REDEEM,
                move |mut client| async move {
                    let _ = client
                        .redeem_token(RedeemTokenRequest {
                            version: PROTOCOL_VERSION,
                            token: tok,
                            namespace_id: NAMESPACE.to_vec(),
                            request_id,
                        })
                        .await;
                },
            )
            .await,
        );
    }
    {
        let cap = cap.clone();
        let request_id = request_id.clone();
        let verifier = verifier.clone();
        sections.push(
            relay_section(
                "relay RegisterKey",
                "/ghost.relay.v1.RelayService/RegisterKey",
                NOTE_REGISTER,
                move |mut client| async move {
                    let _ = client
                        .register_key(RegisterKeyRequest {
                            version: PROTOCOL_VERSION,
                            namespace_id: NAMESPACE.to_vec(),
                            period_id: 2959,
                            kind: 1, // a bearer kind; the value rides in DATA, never rendered
                            verifier,
                            capability: Some(Capability { token: cap }),
                            request_id,
                        })
                        .await;
                },
            )
            .await,
        );
    }

    {
        let tok = tok.clone();
        sections.push(
            issuer_section(
                "issuer RequestInvoice",
                "/ghost.issuer.v1.IssuerService/RequestInvoice",
                NOTE_ISSUER,
                move |mut client| async move {
                    let _ = client
                        .request_invoice(RequestInvoiceRequest {
                            version: 1,
                            rail: 1,    // RAIL_MONERO
                            product: 1, // PRODUCT_PACK
                            claim_hash: claim_hash.to_vec(),
                            credits: vec![tok],
                            base_week: 2959,
                        })
                        .await;
                },
            )
            .await,
        );
    }
    {
        let invoice_id = invoice_id.clone();
        let claim_key = claim_key.clone();
        let blinded = blinded.clone();
        sections.push(
            issuer_section(
                "issuer BlindSign",
                "/ghost.issuer.v1.IssuerService/BlindSign",
                NOTE_ISSUER,
                move |mut client| async move {
                    let _ = client
                        .blind_sign(BlindSignRequest {
                            version: 1,
                            invoice_id,
                            claim_key,
                            blinded,
                        })
                        .await;
                },
            )
            .await,
        );
    }
    {
        let invoice_id = invoice_id.clone();
        let claim_key = claim_key.clone();
        sections.push(
            issuer_section(
                "issuer InvoiceStatus",
                "/ghost.issuer.v1.IssuerService/InvoiceStatus",
                NOTE_ISSUER,
                move |mut client| async move {
                    let _ = client
                        .invoice_status(InvoiceStatusRequest {
                            version: 1,
                            invoice_id,
                            claim_key,
                        })
                        .await;
                },
            )
            .await,
        );
    }
    {
        let tok = tok.clone();
        let blinded = blinded.clone();
        sections.push(
            issuer_section(
                "issuer RedeemInvite",
                "/ghost.issuer.v1.IssuerService/RedeemInvite",
                NOTE_ISSUER,
                move |mut client| async move {
                    let _ = client
                        .redeem_invite(RedeemInviteRequest {
                            version: 1,
                            invite_token: tok,
                            base_week: 2959,
                            blinded,
                            drop_slots: vec![],
                        })
                        .await;
                },
            )
            .await,
        );
    }
    {
        let tok = tok.clone();
        let claim_id = claim_id.clone();
        let payout_address = payout_address.clone();
        sections.push(
            issuer_section(
                "issuer ClaimPayout",
                "/ghost.issuer.v1.IssuerService/ClaimPayout",
                NOTE_ISSUER,
                move |mut client| async move {
                    let _ = client
                        .claim_payout(ClaimPayoutRequest {
                            version: 1,
                            claim_id,
                            credits: vec![tok.clone(), tok],
                            payout_address,
                        })
                        .await;
                },
            )
            .await,
        );
    }
    {
        let tok = tok.clone();
        let blinded = blinded.clone();
        sections.push(
            issuer_section(
                "issuer RefreshCredit",
                "/ghost.issuer.v1.IssuerService/RefreshCredit",
                NOTE_ISSUER,
                move |mut client| async move {
                    let _ = client
                        .refresh_credit(RefreshCreditRequest {
                            version: 1,
                            credit: tok,
                            blinded,
                        })
                        .await;
                },
            )
            .await,
        );
    }

    sections.push(
        mirror_section(
            "mirror bundle fetch",
            mirror_first,
            "/ghost/v1/stagenet/current.ghrb".to_owned(),
            NOTE_MIRROR_BUNDLE,
            &set,
            0,
            0,
            0,
        )
        .await,
    );
    let apk_path = format!("/ghost/v1/stagenet/apk/{}", hex::encode(apk_sha256));
    sections.push(
        mirror_section(
            "mirror APK chunk 0",
            mirror_first,
            apk_path,
            NOTE_MIRROR_CHUNK,
            &set,
            0,
            1,
            0,
        )
        .await,
    );

    // Assemble the transcript: documented header, one section per RPC, coverage notes.
    let mut text = String::from(HEADER);
    for s in &sections {
        s.render(&mut text);
    }
    text.push_str(NOTES);

    // The redaction self-check: no fixed secret may appear in any rendered line. The APK
    // SHA-256 is deliberately excluded (it names the mirror path; see the header).
    let secrets: Vec<String> = [
        NAMESPACE.to_vec(),
        cap,
        tok,
        ciphertext,
        blob_hash.to_vec(),
        other_hash.to_vec(),
        request_id,
        verifier,
        claim_hash.to_vec(),
        claim_key,
        blinded,
        invoice_id,
        claim_id,
        payout_address.into_bytes(),
    ]
    .into_iter()
    .map(|s| hex::encode(s))
    .collect();
    for (n, line) in text.lines().enumerate() {
        for secret in &secrets {
            if line.contains(secret) {
                panic!(
                    "wire transcript redaction breach at line {}: a fixed secret appears in `{line}`",
                    n + 1
                );
            }
        }
    }

    // GHOST_WIRE_TRANSCRIPT_OUT is the gate's regeneration seam: scripts/gates/wire-transcript.sh
    // points it at a scratch file so the committed transcript is never touched by a gate run.
    let path = std::env::var_os("GHOST_WIRE_TRANSCRIPT_OUT").map_or_else(
        || {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../protocol/test-vectors/wire_transcript.txt")
        },
        PathBuf::from,
    );
    std::fs::write(&path, &text).unwrap();
    println!(
        "wire_transcript.txt sha256={} ({} lines)",
        hex::encode(sha256(text.as_bytes())),
        text.lines().count()
    );
}
