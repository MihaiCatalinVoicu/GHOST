//! The production Monero rail against an emulated epee server (Phase 8 design §7.1, §7.6; RM §8):
//! digest authentication kept per connection, resending only a request that never left, typed
//! errors, time limits, and the strict decoding of wallet-rpc and monerod answers. The live
//! counterpart, on the pinned binaries, is `monero_regtest.rs`.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::epee::{self, Call, Emulator, Options, Reply};
use ghost_issuer::rail::digest::Credentials;
use ghost_issuer::rail::monero::{
    Endpoint, EndpointError, MoneroWalletRpc, RpcClient, Timeouts, WalletCheckError,
    TRANSFER_FIELDS,
};
use ghost_issuer::rail::{IncomingEntry, PaymentRail, RailError, RailHeight};
use serde_json::{json, Value};

fn creds(password: &str) -> Credentials {
    Credentials::new(epee::USER, password).unwrap()
}

fn client(e: &Emulator) -> RpcClient {
    RpcClient::new(e.endpoint(), creds(epee::PASSWORD), Timeouts::default()).unwrap()
}

fn quick(e: &Emulator) -> RpcClient {
    let t = Timeouts {
        connect: Duration::from_secs(2),
        call: Duration::from_secs(1),
        long: Duration::from_secs(1),
    };
    RpcClient::new(e.endpoint(), creds(epee::PASSWORD), t).unwrap()
}

/// A server answering from `answers`; any other method is epee's "Method not found".
fn emulator(
    options: Options,
    answers: impl Fn(&Call) -> Option<Reply> + Send + Sync + 'static,
) -> Emulator {
    Emulator::start(options, move |c| {
        answers(c).unwrap_or(Reply::Error(-32601, "Method not found"))
    })
}

fn rail(wallet: &Emulator, daemon: &Emulator) -> MoneroWalletRpc {
    MoneroWalletRpc::new(client(wallet), client(daemon))
}

fn txid(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

/// A `get_transfers` entry with every field wallet-rpc v0.18.5.1 writes.
fn row(kind: &str, minor: u32, amount: u64, height: u64, confirmations: u64, id: &str) -> Value {
    json!({
        "address": "8BnERTpvL5MbCLtj5n9No7J5oE5hHiB3tVCK5cjSvCsYWD2WRJLFuWeKTLiXo5QJqt2ZwUaLy2Vh1Ad51K7FNgqcHgjW85o",
        "amount": amount,
        "amounts": [amount],
        "confirmations": confirmations,
        "double_spend_seen": false,
        "fee": 30_660_000u64,
        "height": height,
        "locked": false,
        "note": "",
        "payment_id": "0000000000000000",
        "subaddr_index": {"major": 0, "minor": minor},
        "subaddr_indices": [{"major": 0, "minor": minor}],
        "suggested_confirmations_threshold": 1,
        "timestamp": 1_789_237_444u64,
        "txid": id,
        "type": kind,
        "unlock_time": 0
    })
}

fn height_answer(c: &Call) -> Option<Reply> {
    (c.method == "get_height").then(|| Reply::Result(json!({"height": 77})))
}

#[test]
fn digest_is_kept_per_connection_and_nc_counts_on_it() {
    let e = emulator(Options::default(), height_answer);
    let c = client(&e);
    for _ in 0..5 {
        assert_eq!(c.call("get_height", json!({})), Ok(json!({"height": 77})));
    }
    let calls = e.calls();
    assert_eq!(
        calls.iter().map(|c| c.nc).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5]
    );
    assert!(calls.iter().all(|x| x.connection == calls[0].connection));
    assert_eq!(e.challenges(), 1, "one challenge for the one connection");
}

#[test]
fn a_forgotten_nonce_is_answered_once_more() {
    let options = Options {
        rotate_nonce_after: Some(2),
        ..Options::default()
    };
    let e = emulator(options, height_answer);
    let c = client(&e);
    for _ in 0..6 {
        assert_eq!(c.call("get_height", json!({})), Ok(json!({"height": 77})));
    }
    assert_eq!(
        e.calls().iter().map(|c| c.nc).collect::<Vec<_>>(),
        [1, 2, 1, 2, 1, 2]
    );
    assert_eq!(e.challenges(), 3);
}

#[test]
fn a_connection_the_server_closed_is_replaced() {
    let options = Options {
        close_after_answer: true,
        ..Options::default()
    };
    let e = emulator(options, height_answer);
    let c = client(&e);
    for _ in 0..3 {
        assert_eq!(c.call("get_height", json!({})), Ok(json!({"height": 77})));
    }
    let calls = e.calls();
    assert_eq!(calls.len(), 3);
    assert!(calls.windows(2).all(|w| w[0].connection != w[1].connection));
    assert!(calls.iter().all(|x| x.nc == 1));
}

#[test]
fn wrong_credentials_are_an_auth_error() {
    let e = emulator(Options::default(), |_| Some(Reply::Result(json!({}))));
    let wrong =
        RpcClient::new(e.endpoint(), creds("not-the-password"), Timeouts::default()).unwrap();
    assert_eq!(wrong.call("get_height", json!({})), Err(RailError::Auth));
    assert_eq!(wrong.post("/get_height", &json!({})), Err(RailError::Auth));
    assert!(e.calls().is_empty(), "nothing reached the server's methods");
    // Per call: the challenge, then the refusal of the answer computed from it.
    assert_eq!(e.challenges(), 4);
}

#[test]
fn rpc_errors_are_typed() {
    let wallet = emulator(Options::default(), |c| {
        match c.method.as_str() {
        "get_height" => Some(Reply::Error(-13, "No wallet file")),
        "refresh" => Some(Reply::Error(
            -1,
            "reorg exceeds maximum allowed depth, use 'set max-reorg-depth N' to allow it, reorg depth: 150",
        )),
        "get_transfer_by_txid" => Some(Reply::Error(-8, "Transaction not found.")),
        _ => None,
    }
    });
    let daemon = emulator(Options::default(), |_| None);
    let c = client(&wallet);
    assert_eq!(
        c.call("get_height", json!({})),
        Err(RailError::Rpc { code: -13 })
    );
    assert_eq!(
        c.call("no_such_method", json!({})),
        Err(RailError::Rpc { code: -32601 })
    );
    let r = rail(&wallet, &daemon);
    assert_eq!(r.height(), Err(RailError::ReorgDepth));
    assert_eq!(r.transfer_by_txid(&[7; 32]), Ok(None));
}

#[test]
fn envelopes_decode_strictly() {
    let body = Arc::new(Mutex::new(String::new()));
    let b = Arc::clone(&body);
    let e = Emulator::start(Options::default(), move |call| {
        Reply::Body(
            b.lock()
                .unwrap()
                .replace("$ID", &call.id.to_string())
                .into_bytes(),
        )
    });
    let c = client(&e);
    let set = |t: &str| *body.lock().unwrap() = t.to_string();
    set(r#"{"id":$ID,"jsonrpc":"2.0","result":{"height":5}}"#);
    assert_eq!(c.call("get_height", json!({})), Ok(json!({"height": 5})));
    for bad in [
        r#"{"id":$ID,"jsonrpc":"1.0","result":{}}"#,
        r#"{"id":"another","jsonrpc":"2.0","result":{}}"#,
        r#"{"id":$ID,"jsonrpc":"2.0","result":{},"error":{"code":-1,"message":"x"}}"#,
        r#"{"id":$ID,"jsonrpc":"2.0","result":5}"#,
        r#"{"id":$ID,"jsonrpc":"2.0","result":null}"#,
        r#"{"id":$ID,"jsonrpc":"2.0"}"#,
        r#"{"id":$ID,"jsonrpc":"2.0","error":{"code":"-1","message":"x"}}"#,
        r#"{"id":$ID,"jsonrpc":"2.0","error":{"code":-1}}"#,
        "not json",
    ] {
        set(bad);
        assert_eq!(
            c.call("get_height", json!({})),
            Err(RailError::Decode),
            "{bad}"
        );
    }
}

#[test]
fn transport_failures_and_limits() {
    // Nobody listens.
    let addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let c = RpcClient::new(
        Endpoint::new(addr).unwrap(),
        creds(epee::PASSWORD),
        Timeouts::default(),
    )
    .unwrap();
    assert_eq!(c.call("get_height", json!({})), Err(RailError::Transport));
    // A status other than 200 and 401; an answer after the time limit (the next call works, on a
    // new connection); an answer beyond the body bound.
    let e = emulator(Options::default(), |c| match c.method.as_str() {
        "broken" => Some(Reply::Status(500)),
        "slow" => Some(Reply::Slow(Duration::from_millis(2_500), json!({}))),
        "huge" => Some(Reply::Result(json!({"blob": "x".repeat(2 << 20)}))),
        _ => height_answer(c),
    });
    let c = quick(&e);
    assert_eq!(c.call("broken", json!({})), Err(RailError::Transport));
    assert_eq!(c.call("slow", json!({})), Err(RailError::Transport));
    assert_eq!(c.call("get_height", json!({})), Ok(json!({"height": 77})));
    assert_eq!(c.call("huge", json!({})), Err(RailError::Decode));
    assert_eq!(c.call("get_height", json!({})), Ok(json!({"height": 77})));
}

#[test]
fn transfers_ask_for_the_exclusive_lower_bound_and_decode_strictly() {
    let answer = Arc::new(Mutex::new(json!({})));
    let a = Arc::clone(&answer);
    let wallet = emulator(Options::default(), move |c| {
        (c.method == "get_transfers").then(|| Reply::Result(a.lock().unwrap().clone()))
    });
    let daemon = emulator(Options::default(), |_| None);
    let r = rail(&wallet, &daemon);
    *answer.lock().unwrap() = json!({
        "in": [
            row("in", 3, 5, 100, 12, &txid(1)),
            row("in", 4, 6, 99, 13, &txid(2)),
            row("block", 0, 7, 101, 11, &txid(3)),
        ],
        "pool": [row("pool", 3, 8, 0, 0, &txid(4))]
    });
    let got = r.transfers(100, 110).unwrap();
    assert_eq!(got.len(), 3, "height 99 lies outside [100, 110]");
    assert_eq!(
        got[0],
        IncomingEntry {
            minor: 3,
            amount_atomic: 5,
            height: Some(100),
            confirmations: 12,
            unlock_time: 0,
            double_spend_seen: false,
            txid: [1; 32],
            timestamp: 1_789_237_444,
        }
    );
    assert_eq!((got[1].minor, got[1].height), (0, Some(101)));
    assert_eq!((got[2].amount_atomic, got[2].height), (8, None));
    // wallet2 selects mined payments with min_height < height <= max_height.
    assert_eq!(
        wallet.calls()[0].params,
        json!({"in": true, "pool": true, "account_index": 0, "filter_by_height": true,
               "min_height": 99, "max_height": 110})
    );
    // wallet-rpc leaves empty lists out.
    *answer.lock().unwrap() = json!({});
    assert_eq!(r.transfers(1, 2), Ok(Vec::new()));

    type Edit = fn(&mut Value);
    let mined = |edit: Edit| {
        let mut v = row("in", 3, 5, 100, 12, &txid(1));
        edit(&mut v);
        json!({ "in": [v] })
    };
    let cases: Vec<(&str, Value)> = vec![
        ("float amount", mined(|v| v["amount"] = json!(1.5))),
        ("negative amount", mined(|v| v["amount"] = json!(-1))),
        ("amount as text", mined(|v| v["amount"] = json!("5"))),
        (
            "amount beyond u64",
            mined(|v| v["amount"] = json!(18_446_744_073_709_551_616.0)),
        ),
        ("63-digit txid", mined(|v| v["txid"] = json!(txid(1)[..63]))),
        (
            "uppercase txid",
            mined(|v| v["txid"] = json!("AB".repeat(32))),
        ),
        (
            "account 1",
            mined(|v| v["subaddr_index"]["major"] = json!(1)),
        ),
        ("height 0", mined(|v| v["height"] = json!(0))),
        (
            "pool type in the mined list",
            mined(|v| v["type"] = json!("pool")),
        ),
        ("outgoing type", mined(|v| v["type"] = json!("out"))),
        (
            "no timestamp",
            mined(|v| {
                v.as_object_mut().unwrap().remove("timestamp");
            }),
        ),
        (
            "no unlock time",
            mined(|v| {
                v.as_object_mut().unwrap().remove("unlock_time");
            }),
        ),
        (
            "no double-spend flag",
            mined(|v| {
                v.as_object_mut().unwrap().remove("double_spend_seen");
            }),
        ),
        (
            "confirmations as float",
            mined(|v| v["confirmations"] = json!(12.0)),
        ),
        (
            "pool entry with a height",
            json!({"pool": [row("pool", 3, 8, 5, 0, &txid(4))]}),
        ),
        (
            "pool entry with confirmations",
            json!({"pool": [row("pool", 3, 8, 0, 1, &txid(4))]}),
        ),
        ("mined list not a list", json!({"in": {}})),
    ];
    for (what, value) in cases {
        *answer.lock().unwrap() = value;
        assert_eq!(r.transfers(100, 110), Err(RailError::Decode), "{what}");
    }
}

#[test]
fn addresses_decode_strictly() {
    let answer = Arc::new(Mutex::new(json!({})));
    let a = Arc::clone(&answer);
    let wallet = emulator(Options::default(), move |c| {
        matches!(c.method.as_str(), "create_address" | "get_address")
            .then(|| Reply::Result(a.lock().unwrap().clone()))
    });
    let daemon = emulator(Options::default(), |_| None);
    let r = rail(&wallet, &daemon);
    let set = |v: Value| *answer.lock().unwrap() = v;

    set(json!({"address": "8A", "address_index": 5, "address_indices": [5], "addresses": ["8A"]}));
    assert_eq!(r.new_address(), Ok((5, "8A".to_string())));
    assert_eq!(
        wallet.calls()[0].params,
        json!({"account_index": 0, "count": 1})
    );
    set(json!({"address": "8A", "address_index": 5}));
    assert_eq!(r.new_address(), Ok((5, "8A".to_string())));
    for bad in [
        json!({"address": "8A", "address_index": 5, "address_indices": [6], "addresses": ["8A"]}),
        json!({"address": "8A", "address_index": 5, "address_indices": [5], "addresses": ["8B"]}),
        json!({"address": "8A", "address_index": -1}),
        json!({"address_index": 5}),
    ] {
        set(bad.clone());
        assert_eq!(r.new_address(), Err(RailError::Decode), "{bad}");
    }

    let rows = |indices: &[u32]| {
        let rows: Vec<Value> = indices
            .iter()
            .map(|i| json!({"address": format!("8{i}"), "address_index": i, "label": "", "used": false}))
            .collect();
        json!({"address": "4Primary", "addresses": rows})
    };
    set(rows(&[0, 1, 2, 3]));
    assert_eq!(r.address_count(), Ok(4));
    for bad in [rows(&[0, 2]), rows(&[1]), rows(&[])] {
        set(bad.clone());
        assert_eq!(r.address_count(), Err(RailError::Decode), "{bad}");
    }
}

#[test]
fn height_refreshes_the_wallet_then_reads_both_heights() {
    let refresh = Arc::new(Mutex::new(
        json!({"blocks_fetched": 3, "received_money": false}),
    ));
    let info = Arc::new(Mutex::new(Value::Null));
    let (rf, inf) = (Arc::clone(&refresh), Arc::clone(&info));
    let wallet = emulator(Options::default(), move |c| match c.method.as_str() {
        "refresh" => Some(Reply::Result(rf.lock().unwrap().clone())),
        "get_height" => Some(Reply::Result(json!({"height": 120}))),
        _ => None,
    });
    let daemon = emulator(Options::default(), move |c| {
        (c.method == "get_info").then(|| Reply::Result(inf.lock().unwrap().clone()))
    });
    let r = rail(&wallet, &daemon);
    let daemon_info = |edit: fn(&mut Value)| {
        let mut v = json!({"height": 121, "synchronized": true, "busy_syncing": false,
                           "status": "OK", "offline": true, "nettype": "fakechain"});
        edit(&mut v);
        *info.lock().unwrap() = v;
    };
    daemon_info(|_| {});
    assert_eq!(
        r.height(),
        Ok(RailHeight {
            wallet: 120,
            daemon: 121,
            synced: true
        })
    );
    assert_eq!(
        wallet
            .calls()
            .iter()
            .map(|c| c.method.as_str())
            .collect::<Vec<_>>(),
        ["refresh", "get_height"]
    );
    daemon_info(|v| v["busy_syncing"] = json!(true));
    assert!(!r.height().unwrap().synced);
    daemon_info(|v| v["synchronized"] = json!(false));
    assert!(!r.height().unwrap().synced);
    daemon_info(|v| v["status"] = json!("BUSY"));
    assert_eq!(r.height(), Err(RailError::Decode));
    daemon_info(|v| {
        v.as_object_mut().unwrap().remove("synchronized");
    });
    assert_eq!(r.height(), Err(RailError::Decode));
    daemon_info(|_| {});
    *refresh.lock().unwrap() = json!({"received_money": false});
    assert_eq!(r.height(), Err(RailError::Decode));
}

#[test]
fn startup_checks_of_the_wallet() {
    let daemon = emulator(Options::default(), |_| None);
    let watch_only = emulator(Options::default(), |c| match c.method.as_str() {
        "query_key" => Some(Reply::Error(
            -29,
            "The wallet is watch-only. Cannot retrieve spend key.",
        )),
        "get_address" => Some(Reply::Result(json!({
            "address": "4Treasury",
            "addresses": [{"address": "4Treasury", "address_index": 0, "label": "Primary account", "used": true}]
        }))),
        _ => None,
    });
    let r = rail(&watch_only, &daemon);
    assert_eq!(r.check_watch_only(), Ok(()));
    assert_eq!(
        watch_only.calls()[0].params,
        json!({"key_type": "spend_key"})
    );
    assert_eq!(r.check_treasury("4Treasury"), Ok(()));
    assert_eq!(
        r.check_treasury("4Other"),
        Err(WalletCheckError::TreasuryMismatch)
    );
    let full = emulator(Options::default(), |c| {
        (c.method == "query_key").then(|| Reply::Result(json!({"key": "ab".repeat(32)})))
    });
    assert_eq!(
        rail(&full, &daemon).check_watch_only(),
        Err(WalletCheckError::NotWatchOnly)
    );
    let closed = emulator(Options::default(), |c| {
        (c.method == "query_key").then_some(Reply::Error(-13, "No wallet file"))
    });
    assert_eq!(
        rail(&closed, &daemon).check_watch_only(),
        Err(WalletCheckError::Rail(RailError::Rpc { code: -13 }))
    );
}

#[test]
fn replay_creates_subaddresses_through_the_highest_minor() {
    let count = Arc::new(Mutex::new(3u64));
    let c = Arc::clone(&count);
    let wallet = emulator(Options::default(), move |call| {
        let mut n = c.lock().unwrap();
        match call.method.as_str() {
            "get_address" => {
                let rows: Vec<Value> = (0..*n)
                    .map(|i| json!({"address": "8x", "address_index": i}))
                    .collect();
                Some(Reply::Result(
                    json!({"address": "4Primary", "addresses": rows}),
                ))
            }
            "create_address" => {
                let k = call.params["count"].as_u64().unwrap();
                let first = *n;
                *n += k;
                Some(Reply::Result(json!({
                    "address": "8x",
                    "address_index": first,
                    "address_indices": (first..first + k).collect::<Vec<u64>>(),
                    "addresses": vec!["8x"; k as usize],
                })))
            }
            _ => None,
        }
    });
    let daemon = emulator(Options::default(), |_| None);
    let r = rail(&wallet, &daemon);
    let created = || {
        wallet
            .calls()
            .iter()
            .filter(|c| c.method == "create_address")
            .map(|c| c.params["count"].as_u64().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(r.replay_subaddresses(10), Ok(11));
    assert_eq!(created(), [8]);
    assert_eq!(r.replay_subaddresses(5), Ok(11));
    assert_eq!(created(), [8], "nothing to replay");
    *count.lock().unwrap() = 3;
    assert_eq!(r.replay_subaddresses(65_540), Ok(65_541));
    assert_eq!(created(), [8, 65_536, 2], "chunks of at most 65 536");
}

#[test]
fn endpoints_are_loopback_addresses_only() {
    for ok in [
        "http://127.0.0.1:18083",
        "http://127.0.0.1:18083/",
        "http://[::1]:18083",
    ] {
        assert!(Endpoint::parse_url(ok).is_ok(), "{ok}");
    }
    for bad in [
        "https://127.0.0.1:18083",
        "http://localhost:18083",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "127.0.0.1:18083",
        "http://127.0.0.1:18083/json_rpc",
    ] {
        assert_eq!(
            Endpoint::parse_url(bad),
            Err(EndpointError::Format),
            "{bad}"
        );
    }
    for bad in [
        "http://10.0.0.1:18083",
        "http://0.0.0.0:18083",
        "http://[::]:18083",
    ] {
        assert_eq!(
            Endpoint::parse_url(bad),
            Err(EndpointError::NotLoopback),
            "{bad}"
        );
    }
}

#[test]
fn the_fields_read_are_the_chain_port_fields() {
    // IncomingEntry: minor <- subaddr_index, amount_atomic <- amount, height <- height and type,
    // confirmations, unlock_time, double_spend_seen, txid, timestamp (the T2 view only).
    assert_eq!(
        TRANSFER_FIELDS,
        [
            "amount",
            "confirmations",
            "double_spend_seen",
            "height",
            "subaddr_index",
            "timestamp",
            "txid",
            "type",
            "unlock_time"
        ]
    );
}
