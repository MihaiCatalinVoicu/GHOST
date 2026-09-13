//! An emulated epee JSON-RPC server, the HTTP server of `monero-wallet-rpc` and `monerod`
//! v0.18.5.1 (Phase 8 design §7.1; `contrib/epee/src/http_auth.cpp`), for the production rail:
//! RFC 2617 digest authentication with the nonce and the request counter kept per connection (a
//! fresh nonce and a reset counter with every 401, the counter raised by every request carrying
//! credentials and compared with `nc`, `stale=true` for a nonce the connection does not hold), the
//! two challenges of a 401 in epee's order and wording (recorded from a v0.18.5.1 daemon),
//! keep-alive, and scripted answers. Test-only.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ghost_issuer::rail::monero::Endpoint;
use md5::{Digest, Md5};
use serde_json::{json, Value};

pub const USER: &str = "ci";
pub const PASSWORD: &str = "emulated-password";
const REALM: &str = "monero-rpc";
/// A 95-character subaddress as wallet-rpc writes it.
pub const SUBADDRESS: &str =
    "8BnERTpvL5MbCLtj5n9No7J5oE5hHiB3tVCK5cjSvCsYWD2WRJLFuWeKTLiXo5QJqt2ZwUaLy2Vh1Ad51K7FNgqcHgjW85o";

/// wallet-rpc's `get_address` of account 0 over `count` subaddresses (`on_get_address`): the rows
/// `address_index` asks for, error −15 (`ADDRESS_INDEX_OUT_OF_BOUNDS`) for an index at or beyond
/// the count, and without `address_index` every row (about 150 bytes each, so a large wallet's
/// list exceeds any body bound).
pub fn get_address_reply(call: &Call, count: u64) -> Reply {
    let row = |i: u64| {
        format!(r#"{{"address":"{SUBADDRESS}","address_index":{i},"label":"","used":false}}"#)
    };
    let rows: Vec<String> = match call.params.get("address_index").and_then(Value::as_array) {
        Some(indices) => {
            let mut rows = Vec::new();
            for i in indices {
                let i = i.as_u64().unwrap();
                if i >= count {
                    return Reply::Error(-15, "address index is out of bound");
                }
                rows.push(row(i));
            }
            rows
        }
        None => (0..count).map(row).collect(),
    };
    Reply::Body(
        format!(
            r#"{{"id":{},"jsonrpc":"2.0","result":{{"address":"{SUBADDRESS}","addresses":[{}]}}}}"#,
            call.id,
            rows.join(",")
        )
        .into_bytes(),
    )
}

/// An incoming `transfer_entry` of `get_transfers` and `get_transfer_by_txid` (`kind` `in`,
/// `block` or `pool`) as wallet-rpc v0.18.5.1 writes it (`wallet_rpc_server_commands_defs.h`;
/// `fill_transfer_entry` and `set_confirmations` in `wallet_rpc_server.cpp`): every `KV_SERIALIZE`
/// field, `confirmations` only when it is not 0 (`KV_SERIALIZE_OPT(confirmations, 0)`: epee's
/// `KV_SERIALIZE_OPT_N` stores nothing for the default value, so a pool entry, whose
/// confirmations are always 0, never has the key), and `destinations`, empty for an incoming
/// transfer, left out (epee stores nothing for an empty list). A pool entry has height 0 and is
/// locked; a coinbase (`block`) unlocks 60 blocks after its height.
pub fn transfer_entry(
    kind: &str,
    minor: u32,
    amount: u64,
    height: u64,
    confirmations: u64,
    txid: &str,
) -> Value {
    let unlock_time = if kind == "block" { height + 60 } else { 0 };
    let mut v = json!({
        "address": SUBADDRESS,
        "amount": amount,
        "amounts": [amount],
        "double_spend_seen": false,
        "fee": 30_660_000u64,
        "height": height,
        "locked": kind == "pool" || confirmations < 10,
        "note": "",
        "payment_id": "0000000000000000",
        "subaddr_index": {"major": 0, "minor": minor},
        "subaddr_indices": [{"major": 0, "minor": minor}],
        "suggested_confirmations_threshold": 1,
        "timestamp": 1_789_237_444u64,
        "txid": txid,
        "type": kind,
        "unlock_time": unlock_time
    });
    if confirmations != 0 {
        v["confirmations"] = json!(confirmations);
    }
    v
}

/// One authenticated request as the script sees it.
#[derive(Debug, Clone)]
pub struct Call {
    pub connection: u64,
    pub path: String,
    /// The JSON-RPC method (empty on another path).
    pub method: String,
    /// The JSON-RPC params, or the whole body on another path.
    pub params: Value,
    pub id: Value,
    pub nc: u32,
}

pub enum Reply {
    Result(Value),
    Error(i64, &'static str),
    /// The whole answer body, as it is.
    Body(Vec<u8>),
    /// This HTTP status and an empty body.
    Status(u16),
    /// A result after a delay.
    Slow(Duration, Value),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// `Connection: close` after every 200 answer.
    pub close_after_answer: bool,
    /// The connection forgets its nonce after every this many authenticated requests (as at a
    /// nonce expiry): the next request is answered `stale=true`.
    pub rotate_nonce_after: Option<u32>,
}

type Script = Arc<dyn Fn(&Call) -> Reply + Send + Sync>;

pub struct Emulator {
    addr: SocketAddr,
    calls: Arc<Mutex<Vec<Call>>>,
    challenges: Arc<AtomicU64>,
    /// The server side of every connection accepted and not dropped yet.
    streams: Arc<Mutex<Vec<TcpStream>>>,
}

impl Emulator {
    pub fn start(
        options: Options,
        script: impl Fn(&Call) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let challenges = Arc::new(AtomicU64::new(0));
        let streams = Arc::new(Mutex::new(Vec::new()));
        let script: Script = Arc::new(script);
        let (c, ch, st) = (
            Arc::clone(&calls),
            Arc::clone(&challenges),
            Arc::clone(&streams),
        );
        std::thread::spawn(move || {
            for (id, stream) in listener.incoming().enumerate() {
                let Ok(stream) = stream else { continue };
                if let Ok(server_side) = stream.try_clone() {
                    st.lock().unwrap().push(server_side);
                }
                let (c, ch, s) = (Arc::clone(&c), Arc::clone(&ch), Arc::clone(&script));
                std::thread::spawn(move || connection(id as u64, stream, options, &s, &c, &ch));
            }
        });
        Self {
            addr,
            calls,
            challenges,
            streams,
        }
    }

    /// Closes every open connection at once, as a restarted wallet-rpc (or one timing out idle
    /// connections) does: no `Connection: close`, the client learns it from the socket alone.
    pub fn drop_connections(&self) {
        for s in self.streams.lock().unwrap().drain(..) {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }

    pub fn endpoint(&self) -> Endpoint {
        Endpoint::new(self.addr).unwrap()
    }

    /// Every request that passed authentication, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    /// 401 answers sent.
    pub fn challenges(&self) -> u64 {
        self.challenges.load(Ordering::SeqCst)
    }
}

struct HttpRequest {
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_request(r: &mut BufReader<TcpStream>) -> Option<HttpRequest> {
    let mut line = String::new();
    if r.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let path = line.split_whitespace().nth(1)?.to_string();
    let mut headers = Vec::new();
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        r.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (k, v) = h.split_once(':')?;
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        if k == "content-length" {
            len = v.parse().ok()?;
        }
        headers.push((k, v));
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).ok()?;
    Some(HttpRequest {
        path,
        headers,
        body,
    })
}

enum Verdict {
    Pass,
    Stale,
    Fail,
}

fn md5_hex(s: &str) -> String {
    hex::encode(Md5::digest(s.as_bytes()))
}

/// The server side of RFC 2617 `qop=auth` with MD5, as epee checks it.
fn verify(header: &str, path: &str, nonce: Option<&str>, counter: u32) -> Verdict {
    let Some(rest) = header.strip_prefix("Digest ") else {
        return Verdict::Fail;
    };
    let fields: Vec<(&str, &str)> = rest
        .split(", ")
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim().trim_matches('"')))
        .collect();
    let get = |k: &str| {
        fields
            .iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| *v)
            .unwrap_or("")
    };
    if Some(get("nonce")) != nonce {
        return Verdict::Stale;
    }
    let nc = format!("{counter:08x}");
    if get("username") != USER
        || get("realm") != REALM
        || get("uri") != path
        || get("qop") != "auth"
        || get("algorithm") != "MD5"
        || get("nc") != nc
    {
        return Verdict::Fail;
    }
    let ha1 = md5_hex(&format!("{USER}:{REALM}:{PASSWORD}"));
    let ha2 = md5_hex(&format!("POST:{path}"));
    let expected = md5_hex(&format!(
        "{ha1}:{}:{nc}:{}:auth:{ha2}",
        get("nonce"),
        get("cnonce")
    ));
    if get("response") == expected {
        Verdict::Pass
    } else {
        Verdict::Fail
    }
}

fn envelope(rpc: bool, id: &Value, fields: Value) -> Vec<u8> {
    let value = if rpc {
        let mut v = fields;
        v["id"] = id.clone();
        v["jsonrpc"] = json!("2.0");
        v
    } else {
        fields.get("result").cloned().unwrap_or(fields)
    };
    serde_json::to_vec(&value).unwrap()
}

fn connection(
    id: u64,
    stream: TcpStream,
    options: Options,
    script: &Script,
    calls: &Mutex<Vec<Call>>,
    challenges: &AtomicU64,
) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    let mut nonce: Option<String> = None;
    let mut counter = 0u32;
    let mut passed = 0u32;
    while let Some(req) = read_request(&mut reader) {
        let verdict = match req.headers.iter().find(|(k, _)| k == "authorization") {
            Some((_, value)) => {
                counter += 1;
                verify(value, &req.path, nonce.as_deref(), counter)
            }
            None => Verdict::Fail,
        };
        if !matches!(verdict, Verdict::Pass) {
            let stale = matches!(verdict, Verdict::Stale);
            counter = 0;
            let n = format!(
                "emulated-nonce-{}",
                challenges.fetch_add(1, Ordering::SeqCst)
            );
            nonce = Some(n.clone());
            let body = "<html><head><title>Unauthorized Access</title></head><body><h1>401 Unauthorized</h1></body></html>";
            let mut head = format!(
                "HTTP/1.1 401 Unauthorized\r\nServer: Epee-based\r\nContent-Length: {}\r\nContent-Type: text/html\r\n",
                body.len()
            );
            for alg in ["MD5", "MD5-sess"] {
                head.push_str(&format!(
                    "WWW-authenticate: Digest qop=\"auth\",algorithm={alg},realm=\"{REALM}\",nonce=\"{n}\",stale={stale}\r\n"
                ));
            }
            head.push_str("\r\n");
            if writer
                .write_all(head.as_bytes())
                .and_then(|()| writer.write_all(body.as_bytes()))
                .is_err()
            {
                return;
            }
            continue;
        }
        passed += 1;
        let json: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let rpc = req.path == "/json_rpc";
        let call = Call {
            connection: id,
            path: req.path.clone(),
            method: if rpc {
                json["method"].as_str().unwrap_or_default().to_string()
            } else {
                String::new()
            },
            params: if rpc {
                json["params"].clone()
            } else {
                json.clone()
            },
            id: json["id"].clone(),
            nc: counter,
        };
        calls.lock().unwrap().push(call.clone());
        let (status, body) = match script(&call) {
            Reply::Result(v) => (200, envelope(rpc, &call.id, json!({ "result": v }))),
            Reply::Error(code, message) => (
                200,
                envelope(
                    rpc,
                    &call.id,
                    json!({"error": {"code": code, "message": message}}),
                ),
            ),
            Reply::Body(b) => (200, b),
            Reply::Status(s) => (s, Vec::new()),
            Reply::Slow(d, v) => {
                std::thread::sleep(d);
                (200, envelope(rpc, &call.id, json!({ "result": v })))
            }
        };
        if options
            .rotate_nonce_after
            .is_some_and(|k| passed.is_multiple_of(k))
        {
            nonce = Some(format!("emulated-nonce-forgotten-{passed}"));
        }
        let close = options.close_after_answer && status == 200;
        let head = format!(
            "HTTP/1.1 {status} {}\r\nServer: Epee-based\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\r\n",
            if status == 200 { "Ok" } else { "Error" },
            body.len(),
            if close { "Connection: close\r\n" } else { "" }
        );
        if writer
            .write_all(head.as_bytes())
            .and_then(|()| writer.write_all(&body))
            .is_err()
            || close
        {
            return;
        }
    }
}
