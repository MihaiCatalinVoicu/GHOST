//! The production Monero rail against an emulated epee server (Phase 8 design §7.1, §7.6; RM §8):
//! digest authentication kept per connection, resending only a request that never left, typed
//! errors, time limits, and the strict decoding of wallet-rpc and monerod answers. The live
//! counterpart, on the pinned binaries, is `monero_regtest.rs`.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::epee::{self, Call, Emulator, Options, Reply};
use ghost_entitlement::monero::MoneroNetwork;
use ghost_issuer::rail::digest::Credentials;
use ghost_issuer::rail::monero::{
    incoming_from_dump, Endpoint, EndpointError, MoneroWalletRpc, RpcClient, Timeouts,
    WalletCheckError, TRANSFER_FIELDS, TRANSFER_FIELDS_OMITTED_AT_ZERO,
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

/// A `get_transfers` entry as wallet-rpc v0.18.5.1 writes it ([`epee::transfer_entry`]: no
/// `confirmations` key when it is 0).
fn row(kind: &str, minor: u32, amount: u64, height: u64, confirmations: u64, id: &str) -> Value {
    epee::transfer_entry(kind, minor, amount, height, confirmations, id)
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

/// Regression (CI run 34744508158, regtest step 17b): a kept-alive connection the server closed
/// while no call ran, without `Connection: close` (a restarted wallet-rpc), is known closed before
/// the next request, which goes out once, on a new connection.
#[test]
fn a_connection_the_server_dropped_while_idle_is_replaced() {
    let e = emulator(Options::default(), height_answer);
    let c = client(&e);
    for round in 0..3 {
        assert_eq!(
            c.call("get_height", json!({})),
            Ok(json!({"height": 77})),
            "round {round}"
        );
        e.drop_connections();
        // The server's close arrives while no call runs.
        std::thread::sleep(Duration::from_millis(100));
    }
    let calls = e.calls();
    assert_eq!(calls.len(), 3, "every request reached the server once");
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

/// A pool entry exactly as wallet-rpc v0.18.5.1 writes it (`fill_transfer_entry` for
/// `pool_payment_details`): height 0, locked, and no `confirmations` key: `set_confirmations`
/// gives a pool entry 0 and `KV_SERIALIZE_OPT(confirmations, 0)` stores nothing for 0. The first
/// regtest run on the real wallet (CI run 34727439185) failed its scanner tick on this entry.
fn real_pool_entry() -> Value {
    json!({
        "address": epee::SUBADDRESS,
        "amount": 8,
        "amounts": [8],
        "double_spend_seen": false,
        "fee": 30_660_000u64,
        "height": 0,
        "locked": true,
        "note": "",
        "payment_id": "0000000000000000",
        "subaddr_index": {"major": 0, "minor": 3},
        "subaddr_indices": [{"major": 0, "minor": 3}],
        "suggested_confirmations_threshold": 1,
        "timestamp": 1_789_237_444u64,
        "txid": txid(4),
        "type": "pool",
        "unlock_time": 0
    })
}

/// Regression (CI run 34727439185): wallet-rpc leaves `confirmations` out when it is 0, in every
/// pool entry and in a mined entry at or above the wallet's height; the rail reads it as 0, in
/// `transfers`, `transfer_by_txid` and an operator's view dump. A present value stays strictly
/// typed, and a pool entry still has 0.
#[test]
fn entries_without_confirmations_decode_as_wallet_rpc_writes_them() {
    let answer = Arc::new(Mutex::new(json!({})));
    let a = Arc::clone(&answer);
    let wallet = emulator(Options::default(), move |c| {
        matches!(c.method.as_str(), "get_transfers" | "get_transfer_by_txid")
            .then(|| Reply::Result(a.lock().unwrap().clone()))
    });
    let daemon = emulator(Options::default(), |_| None);
    let r = rail(&wallet, &daemon);
    let set = |v: Value| *answer.lock().unwrap() = v;

    let pool = real_pool_entry();
    assert!(pool.get("confirmations").is_none());
    // A mined entry at the wallet's height: `set_confirmations` gives it 0 as well.
    let mut tip = real_pool_entry();
    tip["type"] = json!("in");
    tip["height"] = json!(110);
    tip["txid"] = json!(txid(5));
    let expected_pool = IncomingEntry {
        minor: 3,
        amount_atomic: 8,
        height: None,
        confirmations: 0,
        unlock_time: 0,
        double_spend_seen: false,
        txid: [4; 32],
        timestamp: 1_789_237_444,
    };
    let expected_tip = IncomingEntry {
        height: Some(110),
        txid: [5; 32],
        ..expected_pool
    };

    set(json!({"in": [tip.clone()], "pool": [pool.clone()]}));
    assert_eq!(r.transfers(100, 110), Ok(vec![expected_tip, expected_pool]));
    set(json!({"transfer": pool.clone(), "transfers": [pool.clone()]}));
    assert_eq!(r.transfer_by_txid(&[4; 32]), Ok(Some(expected_pool)));
    let dump = json!({"id": "0", "jsonrpc": "2.0", "result": {"in": [tip], "pool": [pool]}});
    assert_eq!(incoming_from_dump(dump), Ok(vec![expected_tip]));

    for (what, value) in [
        ("float", json!(0.0)),
        ("text", json!("0")),
        ("null", Value::Null),
        ("negative", json!(-1)),
        ("a pool entry with 1", json!(1)),
    ] {
        let mut p = real_pool_entry();
        p["confirmations"] = value;
        set(json!({ "pool": [p] }));
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

    // A count probe asks for one index and must get exactly that row back.
    let rows = |indices: &[u32]| {
        let rows: Vec<Value> = indices
            .iter()
            .map(|i| json!({"address": format!("8{i}"), "address_index": i, "label": "", "used": false}))
            .collect();
        json!({"address": "4Primary", "addresses": rows})
    };
    for bad in [rows(&[7]), rows(&[0, 1]), rows(&[])] {
        set(bad.clone());
        assert_eq!(r.address_count(), Err(RailError::Decode), "{bad}");
    }
    let refusing = |code: i64| {
        let wallet = emulator(Options::default(), move |c| {
            (c.method == "get_address").then_some(Reply::Error(code, "refused"))
        });
        let count = rail(&wallet, &daemon).address_count();
        (wallet, count)
    };
    // Not even minor 0 (the primary address); another wallet error.
    assert_eq!(refusing(-15).1, Err(RailError::Decode));
    assert_eq!(refusing(-13).1, Err(RailError::Rpc { code: -13 }));
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
    // A daemon more than one block behind the wallet is not the wallet's own daemon, whose height
    // the refresh has just reached: no synced view (review finding S5-MON-5).
    *refresh.lock().unwrap() = json!({"blocks_fetched": 0, "received_money": false});
    daemon_info(|v| v["height"] = json!(118));
    let h = r.height().unwrap();
    assert!(h.synced && !h.synced_view(), "{h:?}");
    daemon_info(|v| v["height"] = json!(119));
    assert!(r.height().unwrap().synced_view());
}

#[test]
fn the_subaddress_count_is_probed_without_listing_every_subaddress() {
    // More subaddresses than one list answer may carry (review finding S5-MON-2).
    let count = Arc::new(AtomicU64::new(800_000));
    let n = Arc::clone(&count);
    let wallet = emulator(Options::default(), move |c| {
        (c.method == "get_address").then(|| epee::get_address_reply(c, n.load(Ordering::SeqCst)))
    });
    let daemon = emulator(Options::default(), |_| None);
    let r = rail(&wallet, &daemon);
    assert_eq!(r.address_count(), Ok(800_000));
    let calls = wallet.calls();
    assert!(
        calls.iter().all(|c| c.params["address_index"]
            .as_array()
            .is_some_and(|a| a.len() == 1)),
        "one index per probe, never the whole list"
    );
    assert!(calls.len() <= 44, "{} probes", calls.len());
    // The next count starts where the last one ended: two probes.
    let before = wallet.calls().len();
    assert_eq!(r.address_count(), Ok(800_000));
    assert_eq!(wallet.calls().len() - before, 2);
    // It follows the wallet up, and down (a restored wallet holds fewer).
    for n in [800_123, 800_124, 3, 1, 2] {
        count.store(n, Ordering::SeqCst);
        assert_eq!(r.address_count(), Ok(n as u32), "{n}");
    }
}

/// A `get_transfers` entry holding exactly [`TRANSFER_FIELDS`].
fn exact_row(kind: &str, height: u64, confirmations: u64) -> Value {
    let mut v = serde_json::Map::new();
    for f in TRANSFER_FIELDS {
        let value = match f {
            "amount" => json!(5),
            "confirmations" => json!(confirmations),
            "double_spend_seen" => json!(false),
            "height" => json!(height),
            "subaddr_index" => json!({"major": 0, "minor": 3}),
            "timestamp" => json!(1_789_237_444u64),
            "txid" => json!(txid(1)),
            "type" => json!(kind),
            "unlock_time" => json!(0),
            other => panic!("TRANSFER_FIELDS names {other}: give it a value here"),
        };
        v.insert(f.to_string(), value);
    }
    Value::Object(v)
}

/// RP §6.8, §13.3 step 18: the fields the decoder needs are exactly [`TRANSFER_FIELDS`]: an entry
/// holding only them decodes (mined, pool, by txid), and one without any of them does not
/// (review finding S5-MON-4), but for [`TRANSFER_FIELDS_OMITTED_AT_ZERO`], which wallet-rpc leaves
/// out at 0 and which then reads as 0. With `IncomingEntry` they are the `ChainPort` field set:
/// minor from `subaddr_index`, `amount_atomic` from `amount`, `height` from `height` and `type`,
/// `confirmations`, `unlock_time`, `double_spend_seen`, `txid`, and `timestamp` (T2 view only).
#[test]
fn the_decoder_reads_exactly_the_transfer_fields() {
    let answer = Arc::new(Mutex::new(json!({})));
    let a = Arc::clone(&answer);
    let wallet = emulator(Options::default(), move |c| {
        matches!(c.method.as_str(), "get_transfers" | "get_transfer_by_txid")
            .then(|| Reply::Result(a.lock().unwrap().clone()))
    });
    let daemon = emulator(Options::default(), |_| None);
    let r = rail(&wallet, &daemon);
    let set = |v: Value| *answer.lock().unwrap() = v;

    set(json!({"in": [exact_row("in", 100, 12)], "pool": [exact_row("pool", 0, 0)]}));
    let got = r.transfers(100, 110).unwrap();
    assert_eq!(
        (got.len(), got[0].height, got[1].height),
        (2, Some(100), None)
    );
    set(json!({"transfers": [exact_row("in", 100, 12)]}));
    assert!(r.transfer_by_txid(&[1; 32]).unwrap().is_some());

    for f in TRANSFER_FIELDS {
        let without = |kind: &str, height: u64, confirmations: u64| {
            let mut v = exact_row(kind, height, confirmations);
            v.as_object_mut().unwrap().remove(f);
            v
        };
        if TRANSFER_FIELDS_OMITTED_AT_ZERO.contains(&f) {
            // Absent reads as 0: a pool entry as the wallet writes it, a mined one not credited.
            set(json!({"in": [without("in", 100, 12)], "pool": [without("pool", 0, 0)]}));
            let got = r.transfers(100, 110).unwrap();
            assert_eq!((got[0].confirmations, got[1].confirmations), (0, 0), "{f}");
            set(json!({ "transfers": [without("in", 100, 12)] }));
            assert_eq!(
                r.transfer_by_txid(&[1; 32])
                    .map(|e| e.map(|e| e.confirmations)),
                Ok(Some(0)),
                "by txid: {f}"
            );
            continue;
        }
        set(json!({ "in": [without("in", 100, 12)] }));
        assert_eq!(r.transfers(100, 110), Err(RailError::Decode), "in: {f}");
        set(json!({ "pool": [without("pool", 0, 0)] }));
        assert_eq!(r.transfers(100, 110), Err(RailError::Decode), "pool: {f}");
        set(json!({ "transfers": [without("in", 100, 12)] }));
        assert_eq!(
            r.transfer_by_txid(&[1; 32]),
            Err(RailError::Decode),
            "by txid: {f}"
        );
    }
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
fn the_daemon_must_run_the_configured_network() {
    let info = Arc::new(Mutex::new(Value::Null));
    let i = Arc::clone(&info);
    let daemon = emulator(Options::default(), move |c| {
        (c.method == "get_info").then(|| Reply::Result(i.lock().unwrap().clone()))
    });
    let wallet = emulator(Options::default(), |_| None);
    let r = rail(&wallet, &daemon);
    let set = |nettype: Value, status: &str| {
        *info.lock().unwrap() = json!({"height": 5, "synchronized": true, "busy_syncing": false,
                                       "status": status, "nettype": nettype});
    };
    for (nettype, network) in [
        ("mainnet", MoneroNetwork::Mainnet),
        ("stagenet", MoneroNetwork::Stagenet),
        ("fakechain", MoneroNetwork::Regtest),
    ] {
        set(json!(nettype), "OK");
        assert_eq!(r.check_daemon_network(network), Ok(()), "{nettype}");
    }
    set(json!("stagenet"), "OK");
    assert_eq!(
        r.check_daemon_network(MoneroNetwork::Mainnet),
        Err(WalletCheckError::NetworkMismatch)
    );
    set(json!("testnet"), "OK");
    assert_eq!(
        r.check_daemon_network(MoneroNetwork::Stagenet),
        Err(WalletCheckError::NetworkMismatch)
    );
    set(json!("mainnet"), "BUSY");
    assert_eq!(
        r.check_daemon_network(MoneroNetwork::Mainnet),
        Err(WalletCheckError::Rail(RailError::Decode))
    );
    set(Value::Null, "OK");
    assert_eq!(
        r.check_daemon_network(MoneroNetwork::Mainnet),
        Err(WalletCheckError::Rail(RailError::Decode))
    );
}

#[test]
fn replay_creates_subaddresses_through_the_highest_minor() {
    let count = Arc::new(Mutex::new(3u64));
    let c = Arc::clone(&count);
    let wallet = emulator(Options::default(), move |call| {
        let mut n = c.lock().unwrap();
        match call.method.as_str() {
            "get_address" => Some(epee::get_address_reply(call, *n)),
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
