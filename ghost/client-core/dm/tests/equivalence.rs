//! The host/Android equivalence case set (Phase 9 design §15.9 item 7, RG-2, V-16; slice S12).
//!
//! This test **generates** `protocol/test-vectors/dm_equivalence.txt` — `id ‖ kind ‖ hex input`,
//! one case per line — and checks the committed file against it, exactly as `vectors.rs` does for
//! the conformance vectors (`GHOST_DM_EQUIVALENCE_WRITE=1` rewrites it). It records **inputs
//! only**: the outputs are what the two builds are compared on, so they are recorded where each
//! build runs — the `android` job through JNI on `ghost-dm-host`, `dm-emulator.yml` on the
//! emulator's test library — and never here.
//!
//! What it does assert about the outputs is what makes the file worth replaying:
//!  - every case is **deterministic**: run twice in this process, byte-identical (a case that drew
//!    randomness would make the comparison fail for no reason — §15.9's "excluded, because they
//!    draw randomness" is enforced here, not trusted);
//!  - every case named `ok_*` succeeds and every `refuse_*` case answers a refusal code, so both
//!    halves of "result codes are outputs too" are in the file;
//!  - the control case is the only `CONTROL` case.
//!
//! Run with `cargo test -p ghost-client-dm --features test-vectors --test equivalence`.

use ghost_client_dm::card;
use ghost_client_dm::codec::{self, DmContent, Kind, Tlv};
use ghost_client_dm::derive::{self, MessagingBranch};
use ghost_client_dm::equivalence::{self, frame, kind};
use ghost_client_dm::pq;
use ghost_client_dm::seal;
use ghost_client_dm::wrap::WrapName;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("protocol")
        .join("test-vectors")
}

/// Deterministic bytes: SHA-256 expansion of a label. No case draws randomness.
fn bytes(label: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut block = 0u32;
    while out.len() < n {
        let digest = Sha256::new()
            .chain_update(label.as_bytes())
            .chain_update(block.to_be_bytes())
            .finalize();
        out.extend_from_slice(&digest);
        block += 1;
    }
    out.truncate(n);
    out
}

fn b32(label: &str) -> [u8; 32] {
    bytes(label, 32).try_into().unwrap()
}

struct Case {
    id: String,
    kind: u8,
    input: Vec<u8>,
}

fn golden() -> BTreeMap<String, String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(format!(
            "vodozemac-{}",
            ghost_client_dm::olm::VODOZEMAC_VERSION
        ))
        .join("olm-session.txt");
    let text = std::fs::read_to_string(&path).expect("the golden session of the pinned vodozemac");
    let mut map = BTreeMap::new();
    for line in text.replace("\r\n", "\n").lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').expect("key = value");
        map.insert(key.trim().to_string(), value.trim().to_string());
    }
    map
}

fn content(kind: Kind, id: u8, body: Vec<u8>, quote: Option<[u8; 16]>, ext: Vec<Tlv>) -> DmContent {
    DmContent {
        kind,
        message_id: [id; 16],
        author_minute: 29_000_000 + u32::from(id),
        minute_index: u16::from(id % 5),
        timer_code: id % 6,
        timer_version: u32::from(id),
        quote_ref: quote,
        body,
        ext,
    }
}

#[allow(clippy::too_many_lines)]
fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    let mut add = |id: String, kind: u8, input: Vec<u8>| out.push(Case { id, kind, input });

    // HKDF derivations and card-level values (§3.1, §3.2).
    for i in 0..8u8 {
        let m = b32(&format!("derive-{i}"));
        add(
            format!("ok_derive_{i}"),
            kind::DERIVE,
            frame(&[&m, &u16::from(i % 2 == 1).to_be_bytes(), &[i * 3]]),
        );
    }
    // Card v2 (§3.3): built, linked, re-parsed; then the parser's refusals.
    for i in 0..4u8 {
        add(
            format!("ok_card_build_{i}"),
            kind::CARD_BUILD,
            frame(&[
                &b32(&format!("card-seed-{i}")),
                &b32(&format!("card-m-{i}")),
                &0u16.to_be_bytes(),
            ]),
        );
    }
    let seed = b32("card-seed-0");
    let m = MessagingBranch::from_bytes(b32("card-m-0"));
    let good = card::build(&seed, 0, &derive::derive_card_secret(&m, 0))
        .encode()
        .to_vec();
    add("ok_card_parse".into(), kind::CARD_PARSE, frame(&[&good]));
    add(
        "refuse_card_parse_empty".into(),
        kind::CARD_PARSE,
        frame(&[&[]]),
    );
    add(
        "refuse_card_parse_short".into(),
        kind::CARD_PARSE,
        frame(&[&good[..good.len() - 1]]),
    );
    add(
        "refuse_card_parse_long".into(),
        kind::CARD_PARSE,
        frame(&[&[good.clone(), vec![0]].concat()]),
    );
    for (name, at) in [
        ("version", 0usize),
        ("index", 2),
        ("identity", 10),
        ("secret", 60),
        ("signature", 120),
    ] {
        let mut bad = good.clone();
        bad[at] ^= 0x01;
        add(
            format!("refuse_card_parse_flip_{name}"),
            kind::CARD_PARSE,
            frame(&[&bad]),
        );
    }
    // The MSC3814 encoder and the identity keys vodozemac reports for it (§2.2).
    for i in 0..4u8 {
        let fallback: Vec<u8> = if i % 2 == 0 {
            Vec::new()
        } else {
            b32(&format!("fallback-{i}")).to_vec()
        };
        add(
            format!("ok_account_{i}"),
            kind::ACCOUNT,
            frame(&[&b32(&format!("account-m-{i}")), &fallback]),
        );
    }
    // X-Wing: the draft-06 vectors' seeds and encapsulation seeds, then 32 seeded cases (§9.2).
    let draft: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("vectors")
                .join("xwing-draft06.json"),
        )
        .expect("the X-Wing draft-06 vectors"),
    )
    .expect("json");
    for (i, v) in draft.as_array().expect("an array").iter().enumerate() {
        let seed = hex::decode(v["seed"].as_str().unwrap()).unwrap();
        let eseed = hex::decode(v["eseed"].as_str().unwrap()).unwrap();
        add(
            format!("ok_xwing_draft06_{i}"),
            kind::XWING,
            frame(&[&seed, &eseed]),
        );
    }
    for i in 0..32u8 {
        add(
            format!("ok_xwing_seeded_{i:02}"),
            kind::XWING,
            frame(&[
                &b32(&format!("xwing-seed-{i}")),
                &bytes(&format!("xwing-eseed-{i}"), pq::ENCAPS_RANDOMNESS_BYTES),
            ]),
        );
    }
    add(
        "refuse_xwing_decaps_short".into(),
        kind::XWING_DECAPS,
        frame(&[
            &b32("xwing-seed-0"),
            &bytes("short-ct", pq::CIPHERTEXT_BYTES - 1),
        ]),
    );
    // A ciphertext whose X25519 half is the all-zero point: libcrux refuses it (§22.8.2 rule 4).
    let mut low = bytes("low-ct", pq::CIPHERTEXT_BYTES);
    for byte in &mut low[pq::ML_KEM_CIPHERTEXT_BYTES..] {
        *byte = 0;
    }
    add(
        "refuse_xwing_decaps_low_order".into(),
        kind::XWING_DECAPS,
        frame(&[&b32("xwing-seed-0"), &low]),
    );

    // Pair and provisional modes at every bucket, and the symmetric opener's refusals (§6.3, §6.7).
    let (oi_a, oi_b) = (b32("oi-a"), b32("oi-b"));
    for (mode, k) in [
        ("pair", kind::SEAL_PAIR),
        ("provisional", kind::SEAL_PROVISIONAL),
    ] {
        for (bucket, len) in [(4096u32, 120usize), (16384, 9000), (65536, 40000)] {
            add(
                format!("ok_seal_{mode}_{bucket}"),
                k,
                frame(&[
                    &b32(&format!("{mode}-key")),
                    &b32(&format!("{mode}-ns")),
                    &bucket.to_be_bytes(),
                    &oi_a,
                    &oi_b,
                    &bytes(&format!("{mode}-l1-{bucket}"), len),
                    &bytes(&format!("{mode}-salt-{bucket}"), seal::SALT_BYTES),
                ]),
            );
        }
    }
    add(
        "refuse_seal_pair_no_fit".into(),
        kind::SEAL_PAIR,
        frame(&[
            &b32("pair-key"),
            &b32("pair-ns"),
            &4096u32.to_be_bytes(),
            &oi_a,
            &oi_b,
            &bytes("big", 5000),
            &bytes("s", 16),
        ]),
    );
    let blob = equivalence_field(
        &equivalence::run(
            kind::SEAL_PAIR,
            &frame(&[
                &b32("pair-key"),
                &b32("pair-ns"),
                &4096u32.to_be_bytes(),
                &oi_a,
                &oi_b,
                &bytes("pair-l1-4096", 120),
                &bytes("pair-salt-4096", 16),
            ]),
        ),
        0,
    );
    let mut flipped = blob.clone();
    flipped[200] ^= 0x80;
    add(
        "refuse_open_pair_flipped".into(),
        kind::OPEN_SYMMETRIC,
        frame(&[
            &b32("pair-key"),
            &b32("pair-ns"),
            &[0x01],
            &oi_a,
            &oi_b,
            &flipped,
        ]),
    );
    add(
        "refuse_open_pair_as_provisional".into(),
        kind::OPEN_SYMMETRIC,
        frame(&[
            &b32("pair-key"),
            &b32("pair-ns"),
            &[0x04],
            &oi_a,
            &oi_b,
            &blob,
        ]),
    );
    add(
        "refuse_open_pair_other_namespace".into(),
        kind::OPEN_SYMMETRIC,
        frame(&[
            &b32("pair-key"),
            &b32("other-ns"),
            &[0x01],
            &oi_a,
            &oi_b,
            &blob,
        ]),
    );
    add(
        "refuse_open_pair_swapped_direction".into(),
        kind::OPEN_SYMMETRIC,
        frame(&[
            &b32("pair-key"),
            &b32("pair-ns"),
            &[0x01],
            &oi_b,
            &oi_a,
            &blob,
        ]),
    );
    // Bundle v2 built, sealed and opened (§5.3).
    for i in 0..2u8 {
        add(
            format!("ok_seal_bundle_{i}"),
            kind::SEAL_BUNDLE,
            frame(&[
                &b32(&format!("bundle-seed-{i}")),
                &0u16.to_be_bytes(),
                &(2_870u64 + u64::from(i)).to_be_bytes(),
                &u16::from(i).to_be_bytes(),
                &(0x1000_0000u32 + u32::from(i)).to_be_bytes(),
                &b32(&format!("bundle-oi-{i}")),
                &b32(&format!("bundle-fallback-{i}")),
                &b32(&format!("bundle-xwing-{i}")),
                &b32(&format!("bundle-key-{i}")),
                &b32(&format!("bundle-ns-{i}")),
                &bytes(&format!("bundle-salt-{i}"), seal::SALT_BYTES),
            ]),
        );
    }
    // The intro mode, both layers opened (§6.4), at the two smaller buckets.
    for (i, bucket) in [(0u8, 4096u32), (1, 16384)] {
        add(
            format!("ok_seal_intro_{bucket}"),
            kind::SEAL_INTRO,
            frame(&[
                &b32(&format!("intro-outer-{i}")),
                &b32(&format!("intro-ns-{i}")),
                &bucket.to_be_bytes(),
                &(0x2000_0000u32 + u32::from(i)).to_be_bytes(),
                &b32(&format!("intro-gen-{i}")),
                &b32(&format!("intro-roi-{i}")),
                &b32(&format!("intro-rpk-{i}")),
                &b32(&format!("intro-sender-seed-{i}")),
                &b32(&format!("intro-sender-m-{i}")),
                &b32(&format!("intro-base-{i}")),
                &(29_000_000u32 + u32::from(i)).to_be_bytes(),
                &b32(&format!("intro-reply-{i}")),
                &bytes(&format!("intro-l1-{i}"), 300),
                &bytes(&format!("intro-salt-{i}"), seal::SALT_BYTES),
                &bytes(&format!("intro-kem-{i}"), pq::ENCAPS_RANDOMNESS_BYTES),
            ]),
        );
    }
    // The L0 codec (§7.1): canonical records re-encode to themselves; the refusals are outputs.
    let records = [
        content(
            Kind::Text,
            0x41,
            "equivalence".as_bytes().to_vec(),
            None,
            Vec::new(),
        ),
        content(
            Kind::Text,
            0x42,
            "quoted".as_bytes().to_vec(),
            Some([0x43; 16]),
            Vec::new(),
        ),
        content(Kind::TimerSet, 0x44, Vec::new(), None, Vec::new()),
        content(
            Kind::Reaction,
            0x45,
            [vec![0x46u8; 16], "x".as_bytes().to_vec()].concat(),
            None,
            Vec::new(),
        ),
        content(
            Kind::Control,
            0x47,
            Vec::new(),
            None,
            vec![Tlv {
                tlv_type: codec::TLV_SEAL_ROOT,
                value: codec::SealRoot {
                    root: [0x48; 32],
                    base_week: 2_870,
                    root_gen: 1,
                }
                .encode(),
            }],
        ),
    ];
    for (i, record) in records.iter().enumerate() {
        let encoded = record.encode().expect("a canonical record");
        add(format!("ok_l0_{i}"), kind::L0_DECODE, frame(&[&encoded]));
        if i == 0 {
            let mut version = encoded.clone();
            version[0] ^= 0x02;
            add(
                "refuse_l0_version".into(),
                kind::L0_DECODE,
                frame(&[&version]),
            );
            add(
                "refuse_l0_truncated".into(),
                kind::L0_DECODE,
                frame(&[&encoded[..encoded.len() - 1]]),
            );
            add(
                "refuse_l0_trailing".into(),
                kind::L0_DECODE,
                frame(&[&[encoded.clone(), vec![0]].concat()]),
            );
        }
    }
    // Safety number v1 (§8.4), both orders.
    for i in 0..2u8 {
        let (a, b) = (
            (b32(&format!("sn-id-a-{i}")), b32(&format!("sn-oi-a-{i}"))),
            (b32(&format!("sn-id-b-{i}")), b32(&format!("sn-oi-b-{i}"))),
        );
        add(
            format!("ok_safety_{i}_ab"),
            kind::SAFETY,
            frame(&[&a.0, &a.1, &b.0, &b.1]),
        );
        add(
            format!("ok_safety_{i}_ba"),
            kind::SAFETY,
            frame(&[&b.0, &b.1, &a.0, &a.1]),
        );
    }
    // State wrapping under every name (§2.5, §22.8.3).
    for (i, _) in WrapName::ALL.iter().enumerate() {
        add(
            format!("ok_wrap_{i}"),
            kind::WRAP,
            frame(&[
                &b32("state-key"),
                &[i as u8],
                &bytes(&format!("binding-{i}"), 48),
                &bytes(&format!("plain-{i}"), 64),
                &bytes(&format!("nonce-{i}"), 12),
            ]),
        );
    }
    // Olm (§8.1) over the golden session of the pinned vodozemac: every held message decrypted
    // from the stored responder state, the initiator's held reply, normal-message encryption from
    // the initiator state (its sending ratchet is active: deterministic), and the V-15 prune.
    let g = golden();
    let today: u32 = g["today"].parse().unwrap();
    let state = |key: &str| hex::decode(&g[key]).unwrap();
    for i in 0..4 {
        let l1 = hex::decode(&g[&format!("held_for_responder.{i}.l1")]).unwrap();
        let pre: u8 = g[&format!("held_for_responder.{i}.prekey")]
            .parse()
            .unwrap();
        add(
            format!("ok_olm_decrypt_responder_{i}"),
            kind::OLM_DECRYPT,
            frame(&[&state("responder_state"), &l1, &[pre], &today.to_be_bytes()]),
        );
    }
    let l1 = hex::decode(&g["held_for_initiator.0.l1"]).unwrap();
    let pre: u8 = g["held_for_initiator.0.prekey"].parse().unwrap();
    add(
        "ok_olm_decrypt_initiator_0".into(),
        kind::OLM_DECRYPT,
        frame(&[&state("initiator_state"), &l1, &[pre], &today.to_be_bytes()]),
    );
    let held0 = hex::decode(&g["held_for_responder.0.l1"]).unwrap();
    let pre0: u8 = g["held_for_responder.0.prekey"].parse().unwrap();
    add(
        "refuse_olm_decrypt_wrong_session".into(),
        kind::OLM_DECRYPT,
        frame(&[
            &state("initiator_state"),
            &held0,
            &[pre0],
            &today.to_be_bytes(),
        ]),
    );
    for (i, len) in [(0usize, 16usize), (1, 700)] {
        add(
            format!("ok_olm_encrypt_initiator_{i}"),
            kind::OLM_ENCRYPT,
            frame(&[
                &state("initiator_state"),
                &bytes(&format!("olm-l0-{i}"), len),
                &today.to_be_bytes(),
            ]),
        );
    }
    let prune_day: u32 = g["prune_day"].parse().unwrap();
    add(
        "ok_olm_prune".into(),
        kind::OLM_PRUNE,
        frame(&[&state("responder_state"), &prune_day.to_be_bytes()]),
    );
    add(
        "ok_olm_prune_nothing_due".into(),
        kind::OLM_PRUNE,
        frame(&[&state("responder_state"), &today.to_be_bytes()]),
    );

    // The comparator's control: the replaying side flips one byte of this input (§15.9 item 7).
    add(
        "control".into(),
        kind::CONTROL,
        frame(&[&bytes("control", 64)]),
    );
    out
}

/// Field `index` of an OK answer (`code ‖ u32_be(len) ‖ bytes ‖ …`).
fn equivalence_field(answer: &[u8], index: usize) -> Vec<u8> {
    assert_eq!(answer[0], 0, "an OK answer");
    let mut at = 1;
    for i in 0.. {
        let len = u32::from_be_bytes(answer[at..at + 4].try_into().unwrap()) as usize;
        if i == index {
            return answer[at + 4..at + 4 + len].to_vec();
        }
        at += 4 + len;
    }
    unreachable!()
}

fn render(cases: &[Case]) -> String {
    let mut out = String::from(
        "# GHOST Phase 9 host/Android equivalence cases (design §15.9 item 7, RG-2, V-16; slice S12).\n\
# Generated by `GHOST_DM_EQUIVALENCE_WRITE=1 cargo test -p ghost-client-dm --features test-vectors\n\
# --test equivalence`, which also asserts every case is deterministic, every `ok_*` case succeeds\n\
# and every `refuse_*` case answers a refusal.\n\
#\n\
# One case per line: `id kind hex(input)`. `kind` is a `ghost_client_dm::equivalence::kind`\n\
# constant; the input is `u32_be(len) || bytes` fields. The file holds INPUTS only: the `android`\n\
# job records the outputs of `ghost-dm-host` through JNI (`DmEquivalence.run`) and `dm-emulator.yml`\n\
# replays this file on the emulator's x86_64 test library and compares byte for byte. Excluded,\n\
# because they draw randomness: PreKey creation and outbound session creation.\n",
    );
    for case in cases {
        writeln!(
            out,
            "{} {:02x} {}",
            case.id,
            case.kind,
            hex::encode(&case.input)
        )
        .unwrap();
    }
    out
}

#[test]
fn the_case_set_is_deterministic_and_covers_both_answers() {
    let cases = cases();
    let mut ids = std::collections::BTreeSet::new();
    for case in &cases {
        assert!(ids.insert(case.id.clone()), "duplicate id {}", case.id);
        let first = equivalence::run(case.kind, &case.input);
        let second = equivalence::run(case.kind, &case.input);
        assert_eq!(first, second, "{} is not deterministic", case.id);
        if case.id.starts_with("ok_") {
            assert_eq!(
                first[0], 0,
                "{} must succeed, answered code {:#04x}",
                case.id, first[0]
            );
        } else if case.id.starts_with("refuse_") {
            assert_ne!(first[0], 0, "{} must be refused", case.id);
            assert_eq!(first.len(), 1, "{}: a refusal is its code alone", case.id);
        }
    }
    assert_eq!(
        cases.iter().filter(|c| c.kind == kind::CONTROL).count(),
        1,
        "exactly one control case"
    );
    assert!(cases.len() >= 80, "the case set shrank to {}", cases.len());
}

#[test]
fn the_control_detects_one_flipped_byte() {
    let input = frame(&[&bytes("control", 64)]);
    let mut flipped = input.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_ne!(
        equivalence::run(kind::CONTROL, &input),
        equivalence::run(kind::CONTROL, &flipped)
    );
}

#[test]
fn an_unknown_kind_or_a_short_input_is_a_refusal_not_a_panic() {
    assert_eq!(equivalence::run(0x7e, &[]).len(), 1);
    assert_ne!(equivalence::run(kind::DERIVE, &[0, 0, 0, 5, 1])[0], 0);
    assert_ne!(
        equivalence::run(kind::SEAL_INTRO, &frame(&[&[1, 2, 3]]))[0],
        0
    );
}

#[test]
fn the_committed_case_file_is_the_generated_one() {
    let content = render(&cases());
    let path = vectors_dir().join("dm_equivalence.txt");
    if std::env::var("GHOST_DM_EQUIVALENCE_WRITE").as_deref() == Ok("1") {
        std::fs::write(&path, &content).expect("write the case file");
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| {
            panic!("dm_equivalence.txt is missing; run with GHOST_DM_EQUIVALENCE_WRITE=1")
        })
        .replace("\r\n", "\n");
    assert_eq!(committed, content, "dm_equivalence.txt differs from the generator; review, then rerun with GHOST_DM_EQUIVALENCE_WRITE=1");
}
