//! The production payment rail (Phase 8 design §7.1, §7.2, §7.5, §7.6; RM §3, §4, §5, §8):
//! JSON-RPC 2.0 to the view-only `monero-wallet-rpc` and to its `monerod`, both on loopback in the
//! issuer's network namespace.
//!
//! - **Transport.** Plain HTTP/1.1 on one kept-alive connection per server, through hyper's
//!   connection API over `hyper-util`'s tokio adapter, bodies through `http-body-util`: no
//!   connection pool, no name resolution, no TLS, and [`Endpoint`] refuses every address but a
//!   loopback one. [`PaymentRail`] is synchronous: every [`RpcClient`] owns a current-thread tokio
//!   runtime and blocks on it, so the rail is called from blocking threads (the periodic jobs run
//!   on `spawn_blocking`), never from an async task.
//! - **Authentication.** RFC 2617 digest, `qop=auth`, MD5 ([`super::digest`]), kept per connection
//!   as the epee server keeps it. A 401 answering credentials computed from a challenge that
//!   arrived on the same connection in the same call means wrong credentials ([`RailError::Auth`]).
//! - **Resending.** Only a request the connection never took (a kept-alive connection the server
//!   closed while idle) is sent again, once, on a new connection. Nothing that may have reached
//!   the server is repeated: a lost `create_address` answer is the pool's in-process
//!   reconciliation (§19.6 rule 4), never a second address created here.
//! - **Timeouts.** Connecting, and every call as a whole; `refresh` and `rescan_blockchain` have a
//!   long one (after downtime the wallet may need minutes to catch up, RM §8). A call cut short
//!   drops its connection.
//! - **Strict decoding.** The JSON-RPC envelope must be version 2.0, echo the request id and carry
//!   exactly one of `result` (an object) and `error`. Every field the issuer reads must be present
//!   with its JSON type: amounts, heights and times are unsigned integers (serde refuses a float,
//!   a negative number or a string for `u64`; the module denies float arithmetic), txids are 64
//!   lowercase hex digits, `subaddr_index.major` is 0 (account 0 was asked for), a pool entry has
//!   height and confirmations 0 and type `pool`, a mined entry a positive height and type `in`
//!   (`block` for a coinbase, whose unlock time never lets it count). Bodies are bounded. Fields
//!   the issuer does not read are ignored: [`TRANSFER_FIELDS`] lists the ones it reads, the
//!   `ChainPort` field set plus `type` (RP §6.8; regtest step 18).
//! - **Subaddress count.** Probed one index at a time (`get_address` with `address_index`, −15
//!   beyond the count), galloping from the last count then bisecting: never the whole list, which
//!   outgrows any body bound as minors are used up and costs wallet-rpc a scan of every transfer
//!   per row (review finding S5-MON-2).
//! - **Network.** At startup the daemon must run the configured network (`get_info` `nettype`,
//!   review finding S5-MON-5).
//! - **Errors.** Typed, no catch-all: `Transport` (unreachable, timed out, an HTTP status other
//!   than 200 and 401, a broken body), `Auth`, `Rpc { code }` (the server's JSON-RPC error),
//!   `Decode`, `ReorgDepth` (the wallet refused a reorganisation deeper than its window). The
//!   scanner treats every one as "no progress this tick", never as "unpaid" (RM §8). Nothing is
//!   printed or recorded, and no error carries text of the server.
#![deny(clippy::float_arithmetic)]

use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use ghost_entitlement::monero::MoneroNetwork;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1::{self, SendRequest};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, WWW_AUTHENTICATE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

use super::digest::{self, Challenge, Credentials};
use super::{hex_decode_32, hex_encode, IncomingEntry, PaymentRail, RailError, RailHeight};

/// The JSON-RPC endpoint of both servers.
pub const JSON_RPC_PATH: &str = "/json_rpc";
/// Bound of an answer body.
pub const MAX_BODY_BYTES: usize = 1 << 20;
/// Bound of the list answers (`get_transfers`, the addresses of one `create_address` replay chunk).
pub const MAX_LIST_BODY_BYTES: usize = 64 << 20;
/// Most subaddresses one `create_address` call creates (RM §3.3).
pub const MAX_CREATE_COUNT: u32 = 65_536;
/// wallet-rpc error codes the rail tells apart (`wallet_rpc_server_error_codes.h`).
pub const ERROR_WRONG_TXID: i64 = -8;
pub const ERROR_ADDRESS_INDEX_OUT_OF_BOUNDS: i64 = -15;
pub const ERROR_WATCH_ONLY: i64 = -29;
/// The text of wallet2's `reorg_depth_error`, which wallet-rpc reports under a generic code.
const REORG_DEPTH_TEXT: &str = "reorg exceeds maximum allowed depth";
/// Round trips of one call: a resend on a new connection and one fresh challenge fit.
const MAX_ROUND_TRIPS: usize = 4;
/// Bound of a 401 body (read so the connection stays usable).
const CHALLENGE_BODY_BYTES: usize = 64 << 10;

/// The `get_transfers` fields the issuer reads (`IncomingEntry`, RP §6.8); every other field of
/// an entry is ignored.
pub const TRANSFER_FIELDS: [&str; 9] = [
    "amount",
    "confirmations",
    "double_spend_seen",
    "height",
    "subaddr_index",
    "timestamp",
    "txid",
    "type",
    "unlock_time",
];

/// Why an RPC address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointError {
    /// Not `http://<IP address>:<port>` (a host name, another scheme, a path, port 0).
    Format,
    /// An IP address other than a loopback one.
    NotLoopback,
}

impl std::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            EndpointError::Format => "rpc address is not http://<ip>:<port>",
            EndpointError::NotLoopback => "rpc address is not a loopback address",
        })
    }
}

impl std::error::Error for EndpointError {}

/// A loopback RPC server: the wallet and the daemon share the issuer's network namespace
/// (design §6.7, RM §2.1); nothing is ever resolved by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint(SocketAddr);

impl Endpoint {
    /// `http://<loopback IP>:<port>`, with an optional trailing `/`.
    pub fn parse_url(url: &str) -> Result<Self, EndpointError> {
        let rest = url.strip_prefix("http://").ok_or(EndpointError::Format)?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let addr: SocketAddr = rest.parse().map_err(|_| EndpointError::Format)?;
        Self::new(addr)
    }

    pub fn new(addr: SocketAddr) -> Result<Self, EndpointError> {
        if addr.port() == 0 {
            return Err(EndpointError::Format);
        }
        if !addr.ip().is_loopback() {
            return Err(EndpointError::NotLoopback);
        }
        Ok(Self(addr))
    }

    pub fn addr(&self) -> SocketAddr {
        self.0
    }
}

/// Time limits of one server client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Timeouts {
    pub connect: Duration,
    /// Every call but the long ones, as a whole.
    pub call: Duration,
    /// `refresh` and `rescan_blockchain`.
    pub long: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            call: Duration::from_secs(30),
            long: Duration::from_secs(600),
        }
    }
}

struct Connection {
    sender: SendRequest<Full<Bytes>>,
    challenge: Option<Challenge>,
    nc: u32,
    /// The challenge arrived in the current call.
    fresh: bool,
}

#[derive(Default)]
struct ClientState {
    connection: Option<Connection>,
    next_id: u64,
}

/// A JSON-RPC client of one epee server (`monero-wallet-rpc` or `monerod`). Calls are serialized:
/// one connection, one request at a time.
pub struct RpcClient {
    endpoint: Endpoint,
    credentials: Credentials,
    timeouts: Timeouts,
    /// Always `Some` until the client is dropped.
    runtime: Option<Runtime>,
    random: SystemRandom,
    state: Mutex<ClientState>,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClient")
            .field("endpoint", &self.endpoint)
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl RpcClient {
    pub fn new(
        endpoint: Endpoint,
        credentials: Credentials,
        timeouts: Timeouts,
    ) -> Result<Self, RailError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| RailError::Transport)?;
        Ok(Self {
            endpoint,
            credentials,
            timeouts,
            runtime: Some(runtime),
            random: SystemRandom::new(),
            state: Mutex::new(ClientState::default()),
        })
    }

    pub fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    pub fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// `POST /json_rpc` `{"jsonrpc":"2.0","id":…,"method":…,"params":…}` within the call timeout:
    /// the `result` object, or the typed error.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, RailError> {
        self.call_with(method, params, self.timeouts.call, MAX_BODY_BYTES)
    }

    /// [`RpcClient::call`] with its own time limit and body bound.
    pub fn call_with(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
        max_body: usize,
    ) -> Result<Value, RailError> {
        let mut state = self.lock();
        state.next_id = state.next_id.wrapping_add(1);
        let id = state.next_id.to_string();
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|_| RailError::Decode)?;
        let raw = self.exchange(&mut state, JSON_RPC_PATH, body, timeout, max_body)?;
        decode_envelope(&raw, &id)
    }

    /// `POST <path>` with a JSON body, for the daemon's endpoints outside JSON-RPC
    /// (`/pop_blocks`, …): the answer as JSON.
    pub fn post(&self, path: &str, body: &Value) -> Result<Value, RailError> {
        if !path.starts_with('/') || !path.bytes().all(|b| b.is_ascii_graphic() && b != b'"') {
            return Err(RailError::Decode);
        }
        let mut state = self.lock();
        let bytes = serde_json::to_vec(body).map_err(|_| RailError::Decode)?;
        let raw = self.exchange(&mut state, path, bytes, self.timeouts.call, MAX_BODY_BYTES)?;
        serde_json::from_slice(&raw).map_err(|_| RailError::Decode)
    }

    fn lock(&self) -> MutexGuard<'_, ClientState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn exchange(
        &self,
        state: &mut ClientState,
        path: &str,
        body: Vec<u8>,
        timeout: Duration,
        max_body: usize,
    ) -> Result<Vec<u8>, RailError> {
        let runtime = self.runtime.as_ref().ok_or(RailError::Transport)?;
        let body = Bytes::from(body);
        let outcome = runtime.block_on(async {
            tokio::time::timeout(timeout, self.round_trips(state, path, body, max_body)).await
        });
        outcome.unwrap_or_else(|_| {
            // Cut short: the connection may be anywhere in a request.
            state.connection = None;
            Err(RailError::Transport)
        })
    }

    async fn round_trips(
        &self,
        state: &mut ClientState,
        path: &str,
        body: Bytes,
        max_body: usize,
    ) -> Result<Vec<u8>, RailError> {
        if let Some(c) = state.connection.as_mut() {
            c.fresh = false;
        }
        let mut resent = false;
        for _ in 0..MAX_ROUND_TRIPS {
            let reused = state.connection.is_some();
            if !reused {
                state.connection = Some(self.connect().await?);
            }
            let Some(conn) = state.connection.as_mut() else {
                return Err(RailError::Transport);
            };
            let authorization = match &conn.challenge {
                Some(challenge) => {
                    conn.nc = conn.nc.checked_add(1).ok_or(RailError::Auth)?;
                    let cnonce = self.cnonce()?;
                    Some(digest::authorization(
                        &self.credentials,
                        challenge,
                        "POST",
                        path,
                        conn.nc,
                        &cnonce,
                    ))
                }
                None => None,
            };
            let answers_fresh = authorization.is_some() && conn.fresh;
            let request = self.request(path, body.clone(), authorization.as_deref())?;
            // Err(true): the request may have reached the server; Err(false): it never left.
            let sent = match conn.sender.ready().await {
                Ok(()) => conn
                    .sender
                    .try_send_request(request)
                    .await
                    .map_err(|mut e| e.take_message().is_none()),
                Err(_) => Err(false),
            };
            let response = match sent {
                Ok(response) => response,
                Err(may_have_reached) => {
                    state.connection = None;
                    if reused && !may_have_reached && !resent {
                        resent = true;
                        continue;
                    }
                    return Err(RailError::Transport);
                }
            };
            match response.status() {
                StatusCode::OK => {
                    let body = read_body(response, max_body).await;
                    if body.is_err() {
                        state.connection = None;
                    }
                    return body;
                }
                StatusCode::UNAUTHORIZED => {
                    let challenge = digest::select_challenge(
                        response
                            .headers()
                            .get_all(WWW_AUTHENTICATE)
                            .iter()
                            .filter_map(|v| v.to_str().ok()),
                    );
                    let drained = read_body(response, CHALLENGE_BODY_BYTES).await.is_ok();
                    if answers_fresh {
                        return Err(RailError::Auth);
                    }
                    let challenge = challenge.ok_or(RailError::Auth)?;
                    match state.connection.as_mut() {
                        Some(c) if drained => {
                            c.challenge = Some(challenge);
                            c.nc = 0;
                            c.fresh = true;
                        }
                        // A challenge belongs to its connection: a new one gets its own.
                        _ => state.connection = None,
                    }
                }
                _ => {
                    state.connection = None;
                    return Err(RailError::Transport);
                }
            }
        }
        Err(RailError::Auth)
    }

    async fn connect(&self) -> Result<Connection, RailError> {
        let stream = tokio::time::timeout(
            self.timeouts.connect,
            TcpStream::connect(self.endpoint.addr()),
        )
        .await
        .map_err(|_| RailError::Transport)?
        .map_err(|_| RailError::Transport)?;
        // Small request and answer pairs on loopback: no Nagle delay.
        stream.set_nodelay(true).map_err(|_| RailError::Transport)?;
        let (sender, driver) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| RailError::Transport)?;
        tokio::spawn(async move {
            // Ends when the server closes the connection or its sender is dropped; a failure
            // shows at the next request on it.
            let _ = driver.await;
        });
        Ok(Connection {
            sender,
            challenge: None,
            nc: 0,
            fresh: false,
        })
    }

    fn request(
        &self,
        path: &str,
        body: Bytes,
        authorization: Option<&str>,
    ) -> Result<Request<Full<Bytes>>, RailError> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(HOST, self.endpoint.addr().to_string())
            .header(CONTENT_TYPE, "application/json");
        if let Some(value) = authorization {
            builder = builder.header(AUTHORIZATION, value);
        }
        builder
            .body(Full::new(body))
            .map_err(|_| RailError::Transport)
    }

    fn cnonce(&self) -> Result<String, RailError> {
        let mut bytes = [0u8; 16];
        self.random
            .fill(&mut bytes)
            .map_err(|_| RailError::Transport)?;
        Ok(hex_encode(&bytes))
    }
}

impl Drop for RpcClient {
    fn drop(&mut self) {
        // Never blocks, also when the last owner is dropped on an async worker thread.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

async fn read_body(response: Response<Incoming>, max: usize) -> Result<Vec<u8>, RailError> {
    match Limited::new(response.into_body(), max).collect().await {
        Ok(collected) => Ok(collected.to_bytes().to_vec()),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => Err(RailError::Decode),
        Err(_) => Err(RailError::Transport),
    }
}

#[derive(Deserialize)]
struct Envelope {
    jsonrpc: String,
    id: Value,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<ErrorBody>,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: i64,
    message: String,
}

fn decode_envelope(raw: &[u8], id: &str) -> Result<Value, RailError> {
    let envelope: Envelope = serde_json::from_slice(raw).map_err(|_| RailError::Decode)?;
    if envelope.jsonrpc != "2.0" || envelope.id != Value::String(id.to_string()) {
        return Err(RailError::Decode);
    }
    match (envelope.result, envelope.error) {
        (Some(result), None) if result.is_object() => Ok(result),
        (None, Some(error)) if error.message.contains(REORG_DEPTH_TEXT) => {
            Err(RailError::ReorgDepth)
        }
        (None, Some(error)) => Err(RailError::Rpc { code: error.code }),
        _ => Err(RailError::Decode),
    }
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T, RailError> {
    serde_json::from_value(value).map_err(|_| RailError::Decode)
}

// ---------------------------------------------------------------------------------------------
// Answers (the fields the rail reads; serde ignores the others).
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreatedAddress {
    address: String,
    address_index: u32,
    #[serde(default)]
    address_indices: Option<Vec<u32>>,
    #[serde(default)]
    addresses: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct AccountAddresses {
    address: String,
    addresses: Vec<AddressRow>,
}

#[derive(Deserialize)]
struct AddressRow {
    #[serde(rename = "address")]
    _address: String,
    address_index: u32,
}

#[derive(Deserialize)]
struct Refreshed {
    #[serde(rename = "blocks_fetched")]
    _blocks_fetched: u64,
    #[serde(rename = "received_money")]
    _received_money: bool,
}

#[derive(Deserialize)]
struct WalletHeight {
    height: u64,
}

#[derive(Deserialize)]
struct DaemonInfo {
    height: u64,
    synchronized: bool,
    busy_syncing: bool,
    status: String,
}

#[derive(Deserialize)]
struct DaemonNetwork {
    nettype: String,
    status: String,
}

#[derive(Deserialize)]
struct Transfers {
    // wallet-rpc leaves an empty list out.
    #[serde(default, rename = "in")]
    incoming: Vec<TransferRow>,
    #[serde(default)]
    pool: Vec<TransferRow>,
}

#[derive(Deserialize)]
struct TransfersByTxid {
    transfers: Vec<TransferRow>,
}

/// One `get_transfers` entry: exactly [`TRANSFER_FIELDS`].
#[derive(Deserialize)]
struct TransferRow {
    amount: u64,
    confirmations: u64,
    double_spend_seen: bool,
    height: u64,
    subaddr_index: SubaddrIndex,
    timestamp: u64,
    txid: String,
    #[serde(rename = "type")]
    kind: String,
    unlock_time: u64,
}

#[derive(Deserialize)]
struct SubaddrIndex {
    major: u32,
    minor: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lane {
    Mined,
    Pool,
}

fn entry(row: TransferRow, lane: Lane) -> Result<IncomingEntry, RailError> {
    let txid = hex_decode_32(&row.txid).ok_or(RailError::Decode)?;
    if row.subaddr_index.major != 0 {
        return Err(RailError::Decode);
    }
    let height = match (lane, row.kind.as_str()) {
        (Lane::Mined, "in" | "block") if row.height > 0 => Some(row.height),
        (Lane::Pool, "pool") if row.height == 0 && row.confirmations == 0 => None,
        _ => return Err(RailError::Decode),
    };
    Ok(IncomingEntry {
        minor: row.subaddr_index.minor,
        amount_atomic: row.amount,
        height,
        confirmations: row.confirmations,
        unlock_time: row.unlock_time,
        double_spend_seen: row.double_spend_seen,
        txid,
        timestamp: row.timestamp,
    })
}

/// Why a startup check of the wallet failed (§6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletCheckError {
    /// `query_key spend_key` answered: the wallet holds the spend key.
    NotWatchOnly,
    /// The wallet's primary address is not the configured treasury.
    TreasuryMismatch,
    /// The daemon runs another network than the configured one.
    NetworkMismatch,
    Rail(RailError),
}

impl std::fmt::Display for WalletCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletCheckError::NotWatchOnly => f.write_str("the wallet is not watch-only"),
            WalletCheckError::TreasuryMismatch => {
                f.write_str("the wallet's primary address is not the treasury")
            }
            WalletCheckError::NetworkMismatch => {
                f.write_str("the daemon runs another network than the configured one")
            }
            WalletCheckError::Rail(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WalletCheckError {}

/// The view-only treasury wallet (account 0) and its daemon.
#[derive(Debug)]
pub struct MoneroWalletRpc {
    wallet: RpcClient,
    daemon: RpcClient,
    /// The last subaddress count: where the next count's search starts (a hint only).
    known_count: Mutex<u32>,
}

impl MoneroWalletRpc {
    pub fn new(wallet: RpcClient, daemon: RpcClient) -> Self {
        Self {
            wallet,
            daemon,
            known_count: Mutex::new(1),
        }
    }

    pub fn wallet(&self) -> &RpcClient {
        &self.wallet
    }

    pub fn daemon(&self) -> &RpcClient {
        &self.daemon
    }

    /// §6.6, RM §3.1: `query_key {"key_type":"spend_key"}` must fail with −29 (watch-only).
    pub fn check_watch_only(&self) -> Result<(), WalletCheckError> {
        match self
            .wallet
            .call("query_key", json!({"key_type": "spend_key"}))
        {
            Err(RailError::Rpc {
                code: ERROR_WATCH_ONLY,
            }) => Ok(()),
            // The answer (a spend key) is dropped unread.
            Ok(_) => Err(WalletCheckError::NotWatchOnly),
            Err(e) => Err(WalletCheckError::Rail(e)),
        }
    }

    /// The primary address of account 0 (minor 0).
    pub fn primary_address(&self) -> Result<String, RailError> {
        let answer: AccountAddresses = decode(self.wallet.call(
            "get_address",
            json!({"account_index": 0, "address_index": [0]}),
        )?)?;
        Ok(answer.address)
    }

    /// §6.6: the wallet's primary address is the configured treasury address.
    pub fn check_treasury(&self, treasury: &str) -> Result<(), WalletCheckError> {
        let primary = self.primary_address().map_err(WalletCheckError::Rail)?;
        if primary == treasury {
            Ok(())
        } else {
            Err(WalletCheckError::TreasuryMismatch)
        }
    }

    /// The daemon runs the configured network: `get_info` `nettype` is `mainnet`, `stagenet`, or
    /// `fakechain` for regtest (review finding S5-MON-5). With [`RailHeight::synced_view`], which
    /// refuses a daemon behind the wallet, this is what the issuer can check of "the synced view
    /// is the wallet's own daemon" (§5.4): wallet-rpc does not name its daemon.
    pub fn check_daemon_network(&self, network: MoneroNetwork) -> Result<(), WalletCheckError> {
        let answer = self
            .daemon
            .call("get_info", json!({}))
            .map_err(WalletCheckError::Rail)?;
        let info: DaemonNetwork = decode(answer).map_err(WalletCheckError::Rail)?;
        if info.status != "OK" {
            return Err(WalletCheckError::Rail(RailError::Decode));
        }
        let expected = match network {
            MoneroNetwork::Mainnet => "mainnet",
            MoneroNetwork::Stagenet => "stagenet",
            MoneroNetwork::Regtest => "fakechain",
        };
        if info.nettype == expected {
            Ok(())
        } else {
            Err(WalletCheckError::NetworkMismatch)
        }
    }

    /// Runbook R5 step 2 (§7.5, RM §3.3): `create_address` in chunks of at most
    /// [`MAX_CREATE_COUNT`] until the restored wallet holds every minor through `highest_minor`,
    /// so its scan covers every invoice ever handed out. Returns the subaddress count.
    pub fn replay_subaddresses(&self, highest_minor: u32) -> Result<u32, RailError> {
        let mut count = self.address_count()?;
        while count <= highest_minor {
            let missing = u64::from(highest_minor) + 1 - u64::from(count);
            let n = missing.min(u64::from(MAX_CREATE_COUNT));
            // The answer lists every address created: a list body.
            let _: CreatedAddress = decode(self.wallet.call_with(
                "create_address",
                json!({"account_index": 0, "count": n}),
                self.wallet.timeouts().long,
                MAX_LIST_BODY_BYTES,
            )?)?;
            let next = self.address_count()?;
            if next <= count {
                return Err(RailError::Decode);
            }
            count = next;
        }
        Ok(count)
    }

    /// Runbook R5 step 3: `rescan_blockchain` within `timeout` (a restored wallet scans the chain
    /// from its restore height: it may take longer than the long timeout of `refresh`).
    pub fn rescan(&self, timeout: Duration) -> Result<(), RailError> {
        self.wallet
            .call_with(
                "rescan_blockchain",
                json!({"hard": false}),
                timeout,
                MAX_BODY_BYTES,
            )
            .map(|_| ())
    }

    /// `get_address {"account_index":0,"address_index":[k]}`: true when minor `k` exists, false
    /// for wallet-rpc's −15 (an index at or beyond the count).
    fn has_minor(&self, k: u32) -> Result<bool, RailError> {
        match self.wallet.call(
            "get_address",
            json!({"account_index": 0, "address_index": [k]}),
        ) {
            Ok(answer) => {
                let answer: AccountAddresses = decode(answer)?;
                match answer.addresses.as_slice() {
                    [row] if row.address_index == k => Ok(true),
                    _ => Err(RailError::Decode),
                }
            }
            Err(RailError::Rpc {
                code: ERROR_ADDRESS_INDEX_OUT_OF_BOUNDS,
            }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn known_count(&self) -> MutexGuard<'_, u32> {
        self.known_count.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl PaymentRail for MoneroWalletRpc {
    fn new_address(&self) -> Result<(u32, String), RailError> {
        let answer: CreatedAddress = decode(
            self.wallet
                .call("create_address", json!({"account_index": 0, "count": 1}))?,
        )?;
        let indices_agree = answer
            .address_indices
            .as_ref()
            .is_none_or(|i| i.as_slice() == [answer.address_index]);
        let addresses_agree = answer
            .addresses
            .as_ref()
            .is_none_or(|a| a.len() == 1 && a[0] == answer.address);
        if !indices_agree || !addresses_agree {
            return Err(RailError::Decode);
        }
        Ok((answer.address_index, answer.address))
    }

    fn address_count(&self) -> Result<u32, RailError> {
        // The subaddresses of an account are the minors 0..count, so "minor k exists" holds below
        // the count and fails from it on: the count is the first missing minor. The search starts
        // at the last count (two probes when nothing changed), gallops up or down, then bisects.
        // An index beyond u32 does not exist; a count of 2^32 does not decode.
        let exists = |k: u64| match u32::try_from(k) {
            Ok(k) => self.has_minor(k),
            Err(_) => Ok(false),
        };
        let hint = u64::from(*self.known_count()).max(1);
        // From here on minor `lo` exists and minor `hi` does not.
        let (mut lo, mut hi);
        if exists(hint - 1)? {
            lo = hint - 1;
            let mut step = 1u64;
            loop {
                let probe = lo + step;
                if !exists(probe)? {
                    hi = probe;
                    break;
                }
                lo = probe;
                step = step.saturating_mul(2);
            }
        } else {
            hi = hint - 1;
            let mut step = 1u64;
            loop {
                // Minor 0 is the primary address: a wallet without it does not decode.
                if hi == 0 {
                    return Err(RailError::Decode);
                }
                let probe = hi.saturating_sub(step);
                if exists(probe)? {
                    lo = probe;
                    break;
                }
                hi = probe;
                step = step.saturating_mul(2);
            }
        }
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if exists(mid)? {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let count = u32::try_from(hi).map_err(|_| RailError::Decode)?;
        *self.known_count() = count;
        Ok(count)
    }

    fn height(&self) -> Result<RailHeight, RailError> {
        let _: Refreshed = decode(self.wallet.call_with(
            "refresh",
            json!({}),
            self.wallet.timeouts().long,
            MAX_BODY_BYTES,
        )?)?;
        let wallet: WalletHeight = decode(self.wallet.call("get_height", json!({}))?)?;
        let info: DaemonInfo = decode(self.daemon.call("get_info", json!({}))?)?;
        if info.status != "OK" {
            return Err(RailError::Decode);
        }
        Ok(RailHeight {
            wallet: wallet.height,
            daemon: info.height,
            synced: info.synchronized && !info.busy_syncing,
        })
    }

    fn transfers(&self, from: u64, to: u64) -> Result<Vec<IncomingEntry>, RailError> {
        // wallet2 selects mined payments with min_height < height <= max_height.
        let params = json!({
            "in": true,
            "pool": true,
            "account_index": 0,
            "filter_by_height": true,
            "min_height": from.saturating_sub(1),
            "max_height": to,
        });
        let answer: Transfers = decode(self.wallet.call_with(
            "get_transfers",
            params,
            self.wallet.timeouts().call,
            MAX_LIST_BODY_BYTES,
        )?)?;
        let mut out = Vec::with_capacity(answer.incoming.len() + answer.pool.len());
        for row in answer.incoming {
            let e = entry(row, Lane::Mined)?;
            // Exactly the heights asked for, however a wallet version reads its bounds.
            if e.height.is_some_and(|h| from <= h && h <= to) {
                out.push(e);
            }
        }
        for row in answer.pool {
            out.push(entry(row, Lane::Pool)?);
        }
        Ok(out)
    }

    fn transfer_by_txid(&self, txid: &[u8; 32]) -> Result<Option<IncomingEntry>, RailError> {
        let answer = match self.wallet.call(
            "get_transfer_by_txid",
            json!({"txid": hex_encode(txid), "account_index": 0}),
        ) {
            Err(RailError::Rpc {
                code: ERROR_WRONG_TXID,
            }) => return Ok(None),
            other => other?,
        };
        let answer: TransfersByTxid = decode(answer)?;
        for row in answer.transfers {
            let lane = match row.kind.as_str() {
                "in" | "block" => Lane::Mined,
                "pool" => Lane::Pool,
                // Outgoing entries (a wallet that imported key images) are not incoming ones.
                _ => continue,
            };
            let e = entry(row, lane)?;
            if e.txid != *txid {
                return Err(RailError::Decode);
            }
            return Ok(Some(e));
        }
        Ok(None)
    }
}
