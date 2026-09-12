//! Replays `protocol/test-vectors/monero_addresses.txt` (Phase 8 design §7.7): published Monero
//! addresses (sources in the file header) and negative cases derived from them. The ignored test
//! `derive_negative_cases` prints the derived lines the file records (run it with --ignored
//! --nocapture only to regenerate them).

use curve25519_dalek::edwards::CompressedEdwardsY;
use ghost_entitlement::monero::{
    base58_decode, base58_encode, payment_uri, AddressError, AddressPurpose, AddressType,
    MoneroAddress, MoneroNetwork,
};
use sha3::{Digest, Keccak256, Sha3_256};

const VECTORS: &str = include_str!("../../../../protocol/test-vectors/monero_addresses.txt");

fn network(s: &str) -> MoneroNetwork {
    match s {
        "mainnet" => MoneroNetwork::Mainnet,
        "stagenet" => MoneroNetwork::Stagenet,
        "regtest" => MoneroNetwork::Regtest,
        other => panic!("unknown network {other}"),
    }
}

fn purpose(s: &str) -> AddressPurpose {
    match s {
        "invoice" => AddressPurpose::Invoice,
        "payout" => AddressPurpose::Payout,
        other => panic!("unknown purpose {other}"),
    }
}

fn error(s: &str) -> AddressError {
    match s {
        "length" => AddressError::Length,
        "integrated" => AddressError::Integrated,
        "alphabet" => AddressError::Alphabet,
        "encoding" => AddressError::Encoding,
        "wrong-network" => AddressError::WrongNetwork,
        "wrong-type" => AddressError::WrongType,
        "prefix" => AddressError::Prefix,
        "checksum" => AddressError::Checksum,
        "invalid-key" => AddressError::InvalidKey,
        other => panic!("unknown error {other}"),
    }
}

/// Address fields use `\s` for an ASCII space so leading and trailing spaces stay visible.
fn unescape(s: &str) -> String {
    s.replace("\\s", " ")
}

#[test]
fn every_vector_line_has_its_verdict() {
    let (mut valid, mut invalid) = (0, 0);
    for (n, line) in VECTORS.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('|').collect();
        assert!(f.len() == 6, "line {}: {line}", n + 1);
        let (net, purp, address) = (network(f[1]), purpose(f[2]), unescape(f[4]));
        let verdict = MoneroAddress::parse(&address, net, purp);
        match f[0] {
            "valid" => {
                let kind = match f[3] {
                    "standard" => AddressType::Standard,
                    "subaddress" => AddressType::Subaddress,
                    other => panic!("unknown type {other}"),
                };
                let parsed = verdict.unwrap_or_else(|e| panic!("line {}: {e:?}: {line}", n + 1));
                assert_eq!(parsed.kind(), kind, "line {}", n + 1);
                assert_eq!(parsed.network(), net);
                assert_eq!(parsed.as_str(), address);
                valid += 1;
            }
            "invalid" => {
                assert_eq!(verdict.err(), Some(error(f[3])), "line {}: {line}", n + 1);
                invalid += 1;
            }
            other => panic!("line {}: unknown verdict {other}", n + 1),
        }
    }
    assert!(
        valid >= 20 && invalid >= 40,
        "{valid} valid, {invalid} invalid"
    );
}

#[test]
fn documented_decoding_and_uri() {
    // monero-docs public-address/standard-address.md: address, decoding and checksum a57120a3.
    let doc = "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge";
    let parsed = MoneroAddress::parse(doc, MoneroNetwork::Mainnet, AddressPurpose::Payout).unwrap();
    assert_eq!(
        hex::encode(parsed.spend_key()),
        "eda9fe8dfcdd25d5430ea64229d04f6b41b2e5a1587c29cd499a63eb79d11711"
    );
    assert_eq!(
        hex::encode(parsed.view_key()),
        "3076a02b73d130fb904c9e91075fcd16f735c6850dfadb125eb826d96a113f09"
    );
    assert_eq!(hex::encode(&base58_decode(doc).unwrap()[65..]), "a57120a3");

    // getmonero.org General Fund subaddress: a valid invoice destination; the URI is built locally.
    let sub = "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H";
    let sub = MoneroAddress::parse(sub, MoneroNetwork::Mainnet, AddressPurpose::Invoice).unwrap();
    assert_eq!(
        payment_uri(&sub, 250_000_000_000).unwrap(),
        format!("monero:{}?tx_amount=0.250000000000", sub.as_str())
    );
    let standard =
        MoneroAddress::parse(doc, MoneroNetwork::Mainnet, AddressPurpose::Payout).unwrap();
    assert_eq!(payment_uri(&standard, 1), Err(AddressError::UriInput));
}

fn reencode(mut bytes: Vec<u8>, keccak: bool) -> String {
    let check: [u8; 4] = if keccak {
        Keccak256::digest(&bytes[..65])[..4].try_into().unwrap()
    } else {
        Sha3_256::digest(&bytes[..65])[..4].try_into().unwrap()
    };
    bytes[65..69].copy_from_slice(&check);
    base58_encode(&bytes)
}

fn not_a_point() -> [u8; 32] {
    (2u8..)
        .map(|i| {
            let mut y = [0u8; 32];
            y[0] = i;
            y
        })
        .find(|y| CompressedEdwardsY(*y).decompress().is_none())
        .unwrap()
}

#[test]
#[ignore = "prints the derived negative cases recorded in monero_addresses.txt"]
fn derive_negative_cases() {
    let sub = "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H";
    let std_addr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
    let stage_sub = "73LhUiix4DVFMcKhsPRG51QmCsv8dYYbL6GcQoLwEEFvPvkVvc7BhebfA4pnEFF9Lq66hwvLqBvpHjTcqvpJMHmmNjPPBqa";
    let raw = base58_decode(sub).unwrap();
    let with_prefix = |p: u8| {
        let mut b = raw.clone();
        b[0] = p;
        reencode(b, true)
    };
    let bad = not_a_point();
    let mut spend = raw.clone();
    spend[1..33].copy_from_slice(&bad);
    let mut view = raw.clone();
    view[33..65].copy_from_slice(&bad);
    let flipped: String = sub
        .char_indices()
        .map(|(i, c)| {
            if i == 40 {
                if c == 'x' {
                    'y'
                } else {
                    'x'
                }
            } else {
                c
            }
        })
        .collect();
    let lines = [
        (
            "invoice",
            "checksum",
            flipped.clone(),
            "888tNk subaddress with character 40 replaced",
        ),
        (
            "invoice",
            "checksum",
            reencode(raw.clone(), false),
            "888tNk bytes with a SHA3-256 (not Keccak-256) checksum",
        ),
        (
            "invoice",
            "wrong-type",
            with_prefix(18),
            "888tNk keys under the mainnet standard prefix 18, Keccak checksum recomputed",
        ),
        (
            "invoice",
            "wrong-network",
            with_prefix(36),
            "888tNk keys under the stagenet subaddress prefix 36, checksum recomputed",
        ),
        (
            "invoice",
            "wrong-network",
            with_prefix(63),
            "888tNk keys under the testnet subaddress prefix 63, checksum recomputed",
        ),
        (
            "invoice",
            "integrated",
            with_prefix(19),
            "888tNk keys under the integrated prefix 19 at 95 characters, checksum recomputed",
        ),
        (
            "invoice",
            "prefix",
            with_prefix(99),
            "888tNk keys under the unknown prefix 99, checksum recomputed",
        ),
        (
            "invoice",
            "invalid-key",
            reencode(spend, true),
            "888tNk with a spend key that is not an Ed25519 point, checksum recomputed",
        ),
        (
            "invoice",
            "invalid-key",
            reencode(view, true),
            "888tNk with a view key that is not an Ed25519 point, checksum recomputed",
        ),
        (
            "invoice",
            "encoding",
            format!("{}zzzzzzz", &sub[..88]),
            "888tNk with the final 7-character block zzzzzzz (58^7 - 1 > 2^40 - 1)",
        ),
        (
            "invoice",
            "encoding",
            format!("zzzzzzzzzzz{}", &sub[11..]),
            "888tNk with the first 11-character block zzzzzzzzzzz (> 2^64 - 1)",
        ),
        (
            "invoice",
            "length",
            sub[..94].to_string(),
            "888tNk truncated to 94 characters",
        ),
        (
            "invoice",
            "length",
            format!("{sub}1"),
            "888tNk with a character appended (96)",
        ),
        (
            "invoice",
            "length",
            format!("\\s{sub}"),
            "888tNk with a leading space",
        ),
        (
            "invoice",
            "length",
            format!("{sub}\\s"),
            "888tNk with a trailing space",
        ),
        ("invoice", "length", String::new(), "empty"),
        (
            "invoice",
            "alphabet",
            format!("0{}", &sub[1..]),
            "888tNk with '0' (not in the Base58 alphabet)",
        ),
        (
            "invoice",
            "alphabet",
            format!("{}O", &sub[..94]),
            "888tNk with 'O'",
        ),
        (
            "invoice",
            "alphabet",
            format!("{}I{}", &sub[..50], &sub[51..]),
            "888tNk with 'I'",
        ),
        (
            "invoice",
            "alphabet",
            format!("{}l{}", &sub[..60], &sub[61..]),
            "888tNk with 'l'",
        ),
        (
            "invoice",
            "checksum",
            format!("{}{}", &sub[..94], sub[94..].to_ascii_lowercase()),
            "888tNk with the last character lowercased",
        ),
        (
            "payout",
            "checksum",
            format!(
                "{}{}",
                &std_addr[..94],
                if std_addr.ends_with('A') { "B" } else { "A" }
            ),
            "44AFFq with the last character replaced",
        ),
        (
            "payout",
            "wrong-network",
            stage_sub.to_string(),
            "stagenet subaddress 73LhUi offered on mainnet",
        ),
    ];
    for (purpose, err, addr, why) in lines {
        let got = MoneroAddress::parse(
            &unescape(&addr),
            MoneroNetwork::Mainnet,
            self::purpose(purpose),
        )
        .err();
        assert_eq!(got, Some(error(err)), "{why}");
        println!("invalid|mainnet|{purpose}|{err}|{addr}|derived: {why}");
    }
}
