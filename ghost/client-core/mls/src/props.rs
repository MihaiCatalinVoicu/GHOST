//! Property tests of every GHOST parser (Phase 10 design §12.2: "property tests with 10⁶ seeded
//! inputs per CI run for every GHOST parser (never panics, never over-reads)"; slice S2a).
//!
//! Each parser gets `GHOST_PROP_CASES` inputs (default 10⁶) from a SplitMix64 stream seeded by
//! `GHOST_PROP_SEED` (default fixed; a CI run may pass its own and a failure prints it) and the
//! parser's name. Three inputs in four are mutations of a valid encoding (bit flips, boundary
//! bytes, a truncation, an extension, an insertion, a deletion, a duplicated range, a 2- or 4-byte
//! field set to a boundary, a varint prefix), one in four is random bytes of a random length.
//!
//! The properties: a parser never panics (in safe Rust an over-read is an index panic, so this is
//! also "never over-reads"); what a parser accepts re-encodes to its input byte for byte (one
//! encoding: nothing past the end was read and nothing was left unread); and an authenticated
//! format (the invite link's AEAD, the outer seal, the key envelope, a KeyPackage's signatures)
//! accepts nothing but an unmodified original. Two parsers run a tenth of the cases: the sealed
//! blob (4 KiB through HMAC and ChaCha20-Poly1305 per input) and the KeyPackage (two Ed25519
//! verifications per input that parses); their layouts are covered at full count by `seal_layout`
//! and by OpenMLS's own suite (§19.30).

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::canonical::parse_key_package;
use crate::codec::{base32_lower, base32_lower_decode, put_vec};
use crate::content::{
    Body, ChannelContent, InviteIssued, KIND_INVITE_ISSUED, KIND_LEAVE, KIND_POST, KIND_REACTION,
    KIND_REVEAL,
};
use crate::derive::{
    DepositBase, EpochExport, InvitePassword, InviteSeed, JoinKey, PseudonymSeed, ReadBase,
    StateKey,
};
use crate::ext::{
    AdmitEvidence, Bootstrap, ChannelContext, ChannelOrder, CommitAad, GhostLeaf, KpBind, Purpose,
    SwapEvidence,
};
use crate::group::{ChannelHandle, KeyClass, MlsContext};
use crate::invite::{build_v2, from_link, parse_v2, peek_header, to_link, InviteFields};
use crate::join::{JoinAuth, JoinRequest, RequestType, WelcomeBlob, KEY_PACKAGE_LEN};
use crate::seal::{
    check_epoch_body, open, open_plain, seal, EpochContent, Order, SealKeyInput, MODE_EPOCH,
    MODE_JOIN, MODE_WELCOME,
};
use crate::Code;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n + 8);
        while v.len() < n {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

fn cases() -> u64 {
    std::env::var("GHOST_PROP_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000)
}

fn base_seed() -> u64 {
    std::env::var("GHOST_PROP_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x6768_6f73_7431_3021)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One mutation round of 1 … 3 operations on a valid encoding.
fn mutate(r: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..=r.below(3) {
        match r.below(9) {
            0 if !v.is_empty() => {
                for _ in 0..=r.below(4) {
                    let i = r.below(v.len());
                    v[i] ^= 1 << r.below(8);
                }
            }
            1 if !v.is_empty() => {
                let i = r.below(v.len());
                v[i] = [0x00, 0x01, 0x3f, 0x40, 0x7f, 0x80, 0xc0, 0xff][r.below(8)];
            }
            2 => {
                let n = r.below(v.len() + 1);
                v.truncate(n);
            }
            3 => {
                let n = 1 + r.below(16);
                let tail = r.bytes(n);
                v.extend_from_slice(&tail);
            }
            4 => {
                let i = r.below(v.len() + 1);
                let b = r.next() as u8;
                v.insert(i, b);
            }
            5 if !v.is_empty() => {
                let i = r.below(v.len());
                let n = 1 + r.below((v.len() - i).min(8));
                v.drain(i..i + n);
            }
            6 if !v.is_empty() => {
                let i = r.below(v.len());
                let n = 1 + r.below((v.len() - i).min(32));
                let d = v[i..i + n].to_vec();
                let j = r.below(v.len() + 1);
                v.splice(j..j, d);
            }
            7 => {
                let w = if r.below(2) == 0 { 2 } else { 4 };
                if v.len() >= w {
                    let i = r.below(v.len() - w + 1);
                    let len = v.len() as u32;
                    let x = [
                        0,
                        1,
                        u32::MAX,
                        len,
                        len.wrapping_sub(i as u32),
                        0x7fff_ffff,
                        395,
                        64,
                    ][r.below(8)];
                    v[i..i + w].copy_from_slice(&x.to_be_bytes()[4 - w..]);
                }
            }
            8 if !v.is_empty() => {
                // A varint prefix: the two-byte form (0b01), the four-byte form (0b10) or the
                // reserved one (0b11).
                let i = r.below(v.len());
                v[i] = [0x40, 0x80, 0xc0][r.below(3)] | (r.next() as u8 & 0x3f);
            }
            _ => {}
        }
    }
    v
}

/// Runs `n` inputs through `check`, which returns whether the parser accepted and `Err` for a
/// broken property. The corpus itself must be accepted. Returns the number accepted.
fn run_n(
    name: &str,
    n: u64,
    corpus: &[Vec<u8>],
    mut check: impl FnMut(&[u8]) -> Result<bool, String>,
) -> u64 {
    assert!(!corpus.is_empty(), "{name}: empty corpus");
    for (i, c) in corpus.iter().enumerate() {
        assert_eq!(
            check(c),
            Ok(true),
            "{name}: corpus item {i} is not accepted"
        );
    }
    let seed = base_seed();
    let name_hash = name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    let mut r = Rng(seed ^ name_hash);
    let max = corpus.iter().map(Vec::len).max().unwrap_or(0);
    let mut accepted = 0;
    for i in 0..n {
        let input = if r.below(4) == 0 {
            let len = r.below(2 * max + 2);
            r.bytes(len)
        } else {
            let base = &corpus[r.below(corpus.len())];
            mutate(&mut r, base)
        };
        match catch_unwind(AssertUnwindSafe(|| check(&input))) {
            Ok(Ok(true)) => accepted += 1,
            Ok(Ok(false)) => {}
            Ok(Err(e)) => panic!(
                "{name}: case {i} (GHOST_PROP_SEED={seed}): {e}; input {}",
                hex(&input)
            ),
            Err(_) => panic!(
                "{name}: case {i} (GHOST_PROP_SEED={seed}) panicked; input {}",
                hex(&input)
            ),
        }
    }
    accepted
}

fn run(name: &str, corpus: &[Vec<u8>], check: impl FnMut(&[u8]) -> Result<bool, String>) {
    run_n(name, cases(), corpus, check);
}

/// Accepted ⇒ the value re-encodes to the input.
fn round_trip<T>(
    input: &[u8],
    decoded: Option<T>,
    encode: impl Fn(&T) -> Vec<u8>,
) -> Result<bool, String> {
    match decoded {
        None => Ok(false),
        Some(v) => {
            let again = encode(&v);
            if again == input {
                Ok(true)
            } else {
                Err(format!("accepted, but re-encodes to {}", hex(&again)))
            }
        }
    }
}

fn context(
    committers: usize,
    funders: usize,
    name: &[u8],
    flags: u8,
    pw_version: u16,
) -> ChannelContext {
    ChannelContext {
        channel_id: [9; 32],
        size_class: 0,
        timer_code: 4,
        timer_version: 1,
        history_policy: 0,
        flags,
        idle_evict_days: 30,
        pw_version,
        name: name.to_vec(),
        committers: (0..committers).map(|i| [i as u8 + 1; 32]).collect(),
        funders: (0..funders).map(|i| [i as u8 + 0x40; 32]).collect(),
    }
}

#[test]
fn prop_channel_context() {
    let corpus: Vec<Vec<u8>> = [
        context(1, 0, b"", 0, 0),
        context(3, 2, b"forum", 0, 0),
        context(8, 8, &[b'n'; 48], 0b100, 3),
        context(1, 1, "chan\u{e9}".as_bytes(), 0b1, 0),
    ]
    .iter()
    .map(ChannelContext::encode)
    .collect();
    run("channel_context", &corpus, |b| {
        round_trip(b, ChannelContext::decode(b), ChannelContext::encode)
    });
}

#[test]
fn prop_ghost_leaf_kp_bind_bootstrap_order() {
    let leaves = vec![
        GhostLeaf {
            box_pk: [5; 32],
            refresh_epoch: 0,
        }
        .encode(),
        GhostLeaf {
            box_pk: [0xff; 32],
            refresh_epoch: u64::MAX,
        }
        .encode(),
    ];
    run("ghost_leaf", &leaves, |b| {
        round_trip(b, GhostLeaf::decode(b), GhostLeaf::encode)
    });
    let binds: Vec<Vec<u8>> = [Purpose::Join, Purpose::Rejoin, Purpose::Restore]
        .iter()
        .map(|&purpose| {
            KpBind {
                channel_id: [3; 32],
                purpose,
                day: 20_725,
            }
            .encode()
        })
        .collect();
    run("kp_bind", &binds, |b| {
        round_trip(b, KpBind::decode(b), KpBind::encode)
    });
    let boots = vec![
        Bootstrap {
            generation: 1,
            open_epoch: 0,
            g: [0; 32],
        }
        .encode(),
        Bootstrap {
            generation: u32::MAX,
            open_epoch: 77,
            g: [0x11; 32],
        }
        .encode(),
    ];
    run("bootstrap", &boots, |b| {
        round_trip(b, Bootstrap::decode(b), Bootstrap::encode)
    });
    let orders = vec![
        ChannelOrder {
            sender_leaf: 0,
            seq: 0,
        }
        .encode(),
        ChannelOrder {
            sender_leaf: 31,
            seq: 1_000_000,
        }
        .encode(),
    ];
    run("channel_order", &orders, |b| {
        round_trip(b, ChannelOrder::decode(b), ChannelOrder::encode)
    });
}

fn admit(kp_ref_len: usize, seed: u8) -> AdmitEvidence {
    AdmitEvidence {
        kp_ref: vec![seed; kp_ref_len],
        invite_id: [seed ^ 1; 16],
        invite_pk: [seed ^ 2; 32],
        expiry_day: 20_730,
        sponsor: [seed ^ 3; 32],
        sponsor_sig: [seed ^ 4; 64],
        invite_sig: [seed ^ 5; 64],
    }
}

#[test]
fn prop_commit_aad() {
    let corpus: Vec<Vec<u8>> = [
        CommitAad::default(),
        CommitAad {
            commit_minute: 29_000_000,
            rotate: true,
            ..CommitAad::default()
        },
        CommitAad {
            commit_minute: 1,
            rotate: false,
            admits: vec![admit(32, 1), admit(1, 2), admit(64, 3)],
            swaps: vec![
                SwapEvidence::Rejoin {
                    kp_ref: vec![7; 32],
                    generation: 2,
                    day: 20_725,
                    last_epoch: 9,
                    last_hash: [8; 32],
                    rejoin_sig: [6; 64],
                },
                SwapEvidence::Restore(admit(32, 9)),
            ],
        },
    ]
    .iter()
    .map(CommitAad::encode)
    .collect();
    run("commit_aad", &corpus, |b| {
        round_trip(b, CommitAad::decode(b), CommitAad::encode)
    });
}

fn content(kind: u8, body: Body) -> ChannelContent {
    ChannelContent {
        kind,
        op_id: [1; 16],
        author_minute: 29_000_000,
        timer_code: 4,
        body,
    }
}

#[test]
fn prop_channel_content() {
    let issued = |pw_version| InviteIssued {
        invite_id: [2; 16],
        invite_pk: [3; 32],
        expiry_day: 20_730,
        sponsor_sig: [4; 64],
        committers_digest: [5; 32],
        pw_version,
    };
    let corpus: Vec<Vec<u8>> = [
        content(
            KIND_POST,
            Body::Post {
                text: "hello".into(),
                reply_to: None,
            },
        ),
        content(
            KIND_POST,
            Body::Post {
                text: "r\u{e9}ply".into(),
                reply_to: Some([9; 16]),
            },
        ),
        content(
            KIND_REACTION,
            Body::Reaction {
                target: [7; 16],
                grapheme: "\u{1f44d}".into(),
            },
        ),
        content(
            KIND_REACTION,
            Body::Reaction {
                target: [7; 16],
                grapheme: String::new(),
            },
        ),
        content(KIND_INVITE_ISSUED, Body::InviteIssued(issued(None))),
        content(KIND_INVITE_ISSUED, Body::InviteIssued(issued(Some(2)))),
        content(KIND_LEAVE, Body::Leave),
        content(
            KIND_REVEAL,
            Body::Reveal {
                hpke_enc: [6; 32],
                ciphertext: vec![0xaa; 100],
            },
        ),
    ]
    .iter()
    .map(|c| c.encode().unwrap())
    .collect();
    run("channel_content", &corpus, |b| {
        let decoded = ChannelContent::decode(b).ok();
        let again = match &decoded {
            None => return Ok(false),
            Some(c) => c
                .encode()
                .map_err(|e| format!("accepted, but encode refuses it: {e:?}"))?,
        };
        round_trip(b, decoded, |_| again.clone())
    });
}

fn fields(name: &[u8]) -> InviteFields {
    InviteFields {
        suite: 0x0003,
        size_class: 0,
        handshake_ttl_code: 2,
        channel_id: [1; 32],
        generation: 3,
        ns: [2; 32],
        read_base: ReadBase::from_bytes([3; 32]),
        deposit_base: DepositBase::from_bytes([4; 32]),
        join_key: JoinKey::from_bytes([5; 32]),
        invite_id: [6; 16],
        invite_seed: InviteSeed::from_bytes([7; 32]),
        committers_digest: [8; 32],
        expiry_day: 20_730,
        name: name.to_vec(),
    }
}

#[test]
fn prop_invite_fields_and_link() {
    let inner: Vec<Vec<u8>> = [
        fields(b""),
        fields(&[b'x'; 48]),
        fields("f\u{e9}".as_bytes()),
    ]
    .iter()
    .map(|f| f.encode().unwrap().to_vec())
    .collect();
    run("invite_fields", &inner, |b| {
        round_trip(b, InviteFields::decode(b).ok(), |f| {
            f.encode().unwrap().to_vec()
        })
    });
    // The sealed link: an open invite opens only unmodified; a password invite without a password
    // is PASSWORD_REQUIRED (no Argon2id runs), and nothing else is accepted.
    let open_links = [
        build_v2(&fields(b"open"), 0, None, [0x21; 16]).unwrap(),
        build_v2(&fields(b""), 0, None, [0x22; 16]).unwrap(),
    ];
    let pw = InvitePassword::from_bytes(b"correct horse".to_vec());
    let pw_link = build_v2(&fields(b"pw"), 1, Some(&pw), [0x23; 16]).unwrap();
    let mut corpus = open_links.to_vec();
    corpus.push(pw_link.clone());
    run("invite_v2", &corpus, |b| {
        let header = peek_header(b);
        match parse_v2(b, None) {
            Ok(_) if open_links.iter().any(|l| l == b) => Ok(true),
            Ok(_) => Err("a modified open invite opened".into()),
            Err(e) if e.code == Code::PasswordRequired => match header {
                Ok((1, _)) => Ok(b == pw_link.as_slice()),
                _ => Err(format!("PASSWORD_REQUIRED with header {header:?}")),
            },
            Err(_) => Ok(false),
        }
    });
    let links: Vec<Vec<u8>> = corpus.iter().map(|l| to_link(l).into_bytes()).collect();
    run("invite_link", &links, |b| {
        let Ok(s) = core::str::from_utf8(b) else {
            return Ok(false); // a link reaches the parser as a string
        };
        round_trip(b, from_link(s).ok(), |v| to_link(v).into_bytes())
    });
    let texts: Vec<Vec<u8>> = [&b""[..], b"a", b"ghost", &[0xa5; 335][..]]
        .iter()
        .map(|d| base32_lower(d).into_bytes())
        .collect();
    run("base32", &texts, |b| {
        let Ok(s) = core::str::from_utf8(b) else {
            return Ok(false);
        };
        round_trip(b, base32_lower_decode(s), |v| base32_lower(v).into_bytes())
    });
}

#[test]
fn prop_join_request_and_welcome_blob() {
    let kp = vec![0x5a; KEY_PACKAGE_LEN];
    let corpus: Vec<Vec<u8>> = [
        JoinRequest {
            request_type: RequestType::Join,
            key_package: kp.clone(),
            auth: JoinAuth::Invite {
                invite_id: [1; 16],
                invite_sig: [2; 64],
            },
        },
        JoinRequest {
            request_type: RequestType::Restore,
            key_package: kp.clone(),
            auth: JoinAuth::Invite {
                invite_id: [3; 16],
                invite_sig: [4; 64],
            },
        },
        JoinRequest {
            request_type: RequestType::Rejoin,
            key_package: kp,
            auth: JoinAuth::Rejoin {
                day: 20_725,
                last_epoch: 7,
                last_hash: [5; 32],
                rejoin_sig: [6; 64],
            },
        },
    ]
    .iter()
    .map(|j| j.encode().unwrap())
    .collect();
    run("join_request", &corpus, |b| {
        round_trip(b, JoinRequest::decode(b).ok(), |j| j.encode().unwrap())
    });
    let blobs: Vec<Vec<u8>> = [
        WelcomeBlob {
            kp_ref: vec![1; 32],
            welcome: vec![2; 700],
        },
        WelcomeBlob {
            kp_ref: vec![3; 1],
            welcome: vec![4; 1],
        },
    ]
    .iter()
    .map(|w| w.encode().unwrap())
    .collect();
    run("welcome_blob", &blobs, |b| {
        round_trip(b, WelcomeBlob::decode(b).ok(), |w| w.encode().unwrap())
    });
}

/// `MLSMessage { version = mls10, wire_format = mls_private_message, PrivateMessage }` with opaque
/// sender data and ciphertext: what `check_epoch_body` parses (it decrypts nothing).
fn private_message(epoch: u64, content_type: u8, aad: &[u8]) -> Vec<u8> {
    let mut m = vec![0, 1, 0, 2];
    put_vec(&mut m, &[9; 32]);
    m.extend_from_slice(&epoch.to_be_bytes());
    m.push(content_type);
    put_vec(&mut m, aad);
    put_vec(&mut m, &[0x33; 28]);
    put_vec(&mut m, &[0x44; 120]);
    m
}

/// P for bucket `bucket`: `mode ‖ u24(len) ‖ order ‖ body ‖ zeros`.
fn layout(bucket: usize, mode: u8, order: &Order, body: &[u8]) -> Vec<u8> {
    let mut p = vec![mode];
    p.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    p.extend_from_slice(&order.encode());
    p.extend_from_slice(body);
    p.resize(bucket - 48, 0);
    p
}

const APP: Order = Order {
    epoch: 12,
    sender_leaf: 3,
    seq: 40,
};
const HANDSHAKE: Order = Order {
    epoch: 12,
    sender_leaf: 0,
    seq: 0,
};

fn app_order() -> Vec<u8> {
    ChannelOrder {
        sender_leaf: APP.sender_leaf,
        seq: APP.seq,
    }
    .encode()
}

#[test]
fn prop_epoch_body() {
    let bodies = [
        (APP, private_message(12, 1, &app_order())),
        (HANDSHAKE, private_message(12, 3, &[1, 2, 3])),
        (HANDSHAKE, private_message(12, 2, &[])),
    ];
    for (order, body) in &bodies {
        check_epoch_body(order, body).expect("the corpus satisfies CS-S7");
    }
    let corpus: Vec<Vec<u8>> = bodies.iter().map(|(_, b)| b.clone()).collect();
    // Checked against both orders: an accepted body satisfies CS-S7 for the order it was checked
    // against.
    run("epoch_body", &corpus, |b| {
        let mut any = false;
        for order in [APP, HANDSHAKE] {
            if let Ok(h) = check_epoch_body(&order, b) {
                any = true;
                if h.epoch != order.epoch {
                    return Err(format!("epoch {} accepted for order {order:?}", h.epoch));
                }
                let ok = match h.content {
                    EpochContent::Application => {
                        h.channel_order
                            == Some(ChannelOrder {
                                sender_leaf: order.sender_leaf,
                                seq: order.seq,
                            })
                    }
                    _ => order.sender_leaf == 0 && order.seq == 0 && h.channel_order.is_none(),
                };
                if !ok {
                    return Err(format!("header {h:?} accepted for order {order:?}"));
                }
            }
        }
        Ok(any)
    });
}

#[test]
fn prop_seal_layout() {
    let corpus = vec![
        layout(
            4096,
            MODE_EPOCH,
            &APP,
            &private_message(12, 1, &app_order()),
        ),
        layout(16_384, MODE_EPOCH, &HANDSHAKE, &private_message(12, 3, &[])),
        layout(4096, MODE_JOIN, &Order::default(), &[0x77; 600]),
        layout(4096, MODE_WELCOME, &Order::default(), &[0x78; 4028]),
        layout(4096, MODE_WELCOME, &Order::default(), &[]),
    ];
    let mut r = Rng(base_seed() ^ 0x5eed);
    run("seal_layout", &corpus, |input| {
        // A P of a bucket's length (what the AEAD guarantees), and three in four of the others
        // cut or padded to one, is opened with the mode of its first byte, as the caller's key and
        // mode would match; the rest test the guards with a random bucket and mode.
        let mut p = input.to_vec();
        let exact = [4096, 16_384].contains(&(p.len() + 48));
        let (bucket, mode) = if exact || (!p.is_empty() && r.below(4) != 0) {
            let bucket = if p.len() > 4096 - 48 { 16_384 } else { 4096 };
            p.resize(bucket - 48, 0);
            (bucket, p[0])
        } else {
            (
                [4096, 16_384][r.below(2)],
                [MODE_EPOCH, MODE_JOIN, MODE_WELCOME][r.below(3)],
            )
        };
        match open_plain(bucket, mode, &p) {
            Ok(o) => {
                let again = layout(bucket, mode, &o.order, &o.body);
                if again != p {
                    return Err("accepted, but its order and body lay out differently".into());
                }
                if (mode == MODE_EPOCH) != o.header.is_some() {
                    return Err("mode 0x11 without a header, or a header outside it".into());
                }
                Ok(true)
            }
            Err(e) if e.code == Code::NonCanonical => Ok(false),
            Err(e) => Err(format!("unexpected refusal {e:?}")),
        }
    });
}

#[test]
fn prop_sealed_blobs_open_only_unmodified() {
    let k = EpochExport::from_bytes([0x61; 32]);
    let jk = JoinKey::from_bytes([0x62; 32]);
    let ns = [0x63; 32];
    let body = private_message(12, 1, &app_order());
    let epoch_blob = seal(
        &SealKeyInput::Epoch(&k),
        &ns,
        4096,
        MODE_EPOCH,
        &APP,
        &body,
        [1; 16],
    )
    .unwrap();
    let join_blob = seal(
        &SealKeyInput::Join(&jk),
        &ns,
        4096,
        MODE_JOIN,
        &Order::default(),
        &[5; 450],
        [2; 16],
    )
    .unwrap();
    let corpus = vec![epoch_blob.clone(), join_blob.clone()];
    run_n("sealed_blob", cases() / 10, &corpus, |b| {
        let e = open(&SealKeyInput::Epoch(&k), &ns, MODE_EPOCH, b);
        let j = open(&SealKeyInput::Join(&jk), &ns, MODE_JOIN, b);
        match (e, j) {
            (Ok(_), _) if b == epoch_blob.as_slice() => Ok(true),
            (_, Ok(_)) if b == join_blob.as_slice() => Ok(true),
            (Ok(_), _) | (_, Ok(_)) => Err("a modified blob opened".into()),
            (Err(x), Err(y)) if x.code == Code::NotOpen && y.code == Code::NotOpen => Ok(false),
            (Err(x), Err(y)) => Err(format!("unexpected refusals {x:?} {y:?}")),
        }
    });
}

#[test]
fn prop_key_envelope_and_key_package() {
    let ctx = MlsContext::open(StateKey::from_bytes([0x71; 32])).unwrap();
    let channel_id = [0x72; 32];
    let env = ctx
        .wrap_key(KeyClass::Epoch, &channel_id, &[0x73; 32])
        .unwrap();
    run("key_envelope", std::slice::from_ref(&env), |b| {
        match ctx.unwrap_key(KeyClass::Epoch, &channel_id, b) {
            Ok(_) if b == env.as_slice() => Ok(true),
            Ok(_) => Err("a modified envelope opened".into()),
            Err(e) if e.code == Code::StateCorrupt => Ok(false),
            Err(e) => Err(format!("unexpected refusal {e:?}")),
        }
    });
    let ch = ChannelHandle::open(channel_id, &PseudonymSeed::from_bytes([0x74; 32]));
    let kps: Vec<Vec<u8>> = [Purpose::Join, Purpose::Rejoin]
        .iter()
        .map(|&p| ctx.key_package(&ch, p, 20_725).unwrap().key_package)
        .collect();
    run_n(
        "key_package",
        cases() / 10,
        &kps,
        |b| match parse_key_package(ctx.crypto(), b, Some(&channel_id)) {
            Ok(_) if kps.iter().any(|k| k == b) => Ok(true),
            Ok(_) => Err("a modified KeyPackage was accepted".into()),
            Err(_) => Ok(false),
        },
    );
}
