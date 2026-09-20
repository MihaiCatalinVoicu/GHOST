//! Golden pickles and transcripts per vodozemac pin (design §15.2 item 2, G-2 re-sourced, gate
//! G-R7), extended by S0′ (V-7, V-15) with the pruned pickles and the pinned `chainPosition` and
//! `sessionPrune` outputs.
//!
//! **Why these are loaded, not regenerated.** Olm draws random base and ratchet keys inside the
//! library, so a golden cannot be reproduced byte for byte from fixed inputs the way the `dm_*`
//! vectors are. The drill is the one §15.2 item 2 and §2.8 name: the committed pickles of the
//! **previous** pin are loaded with the **new** pin and both sides continue, which is exactly what
//! this file does with the current pin against the committed bytes. It catches a pickle-format
//! change, a receiver-chain or skipped-key layout change, and a session-config change at a bump,
//! none of which the library's own tests can see from GHOST's side.
//!
//! Regenerate deliberately, at a pin change only, with
//! `GHOST_DM_GOLDEN_WRITE=1 cargo test -p ghost-client-dm --test golden`, into the directory of
//! the **new** version, keeping the old one until the upgrade drill has run against it.

use ghost_client_dm::derive::{self, MessagingBranch, OlmSecret};
use ghost_client_dm::olm::pickle::ChainPosition;
use ghost_client_dm::olm::session::{self, Slot, StoredSession};
use ghost_client_dm::olm::state::SessionState;
use ghost_client_dm::olm::{pickle, VODOZEMAC_VERSION};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The day index every golden is generated at; the prune drill uses `GOLDEN_DAY + 51`.
const GOLDEN_DAY: u32 = 1_000;
/// How many of A's messages the responder skips before decrypting the newest one.
const SKIPPED: usize = 4;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(format!("vodozemac-{VODOZEMAC_VERSION}"))
}

fn golden_path() -> PathBuf {
    golden_dir().join("olm-session.txt")
}

/// Regenerates the file once per test binary when asked, so the three tests below read the same
/// bytes however the harness schedules them.
fn golden() -> Golden {
    static WRITTEN: std::sync::Once = std::sync::Once::new();
    WRITTEN.call_once(|| {
        if std::env::var("GHOST_DM_GOLDEN_WRITE").as_deref() == Ok("1") {
            write_golden();
        }
    });
    Golden::read()
}

/// A `key = value` file: hex values, one per line, with `#` comments.
struct Golden(BTreeMap<String, String>);

impl Golden {
    fn read() -> Self {
        let text = std::fs::read_to_string(golden_path()).unwrap_or_else(|_| {
            panic!(
                "{} is missing; regenerate with GHOST_DM_GOLDEN_WRITE=1",
                golden_path().display()
            )
        });
        let mut map = BTreeMap::new();
        for line in text.replace("\r\n", "\n").lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            // Split before trimming: an empty value (a chain with no skipped key) would otherwise
            // lose its separator and look like a malformed line.
            let (key, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("golden line is not `key = value`: {line}"));
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
        Self(map)
    }

    fn text(&self, key: &str) -> &str {
        self.0
            .get(key)
            .unwrap_or_else(|| panic!("golden key {key} is missing"))
    }

    fn bytes(&self, key: &str) -> Vec<u8> {
        hex::decode(self.text(key)).expect("hex")
    }

    fn number(&self, key: &str) -> u64 {
        self.text(key).parse().expect("number")
    }

    fn count(&self, prefix: &str) -> usize {
        self.0
            .keys()
            .filter(|key| key.starts_with(prefix) && key.ends_with(".l1"))
            .count()
    }
}

struct Party {
    identity: OlmSecret,
    signing: OlmSecret,
    public: [u8; 32],
}

fn party(tag: u8) -> Party {
    let branch = MessagingBranch::from_bytes([tag; 32]);
    let identity = derive::derive_olm_identity(&branch);
    let signing = derive::derive_olm_account_signing(&branch);
    let public = derive::olm_identity_public(&identity);
    Party {
        identity,
        signing,
        public,
    }
}

/// Builds the scenario the goldens record and writes the file.
///
/// A (initiator) and B (responder) exchange a first flight and a reply, then A sends
/// `SKIPPED + 1` messages of which B decrypts only the newest, so B's state holds `SKIPPED`
/// skipped keys on one receiver chain. The messages B skipped and one reply A never read are kept
/// as held transcripts, so the load drill has something to decrypt on both sides.
fn write_golden() {
    let a = party(0xa1);
    let b = party(0xb2);
    let fallback_secret = [0xf0u8; 32];
    let fallback_public = derive::olm_identity_public(&OlmSecret::from_bytes(fallback_secret));

    let outbound = session::session_outbound(
        &a.identity,
        &a.signing,
        &b.public,
        &fallback_public,
        GOLDEN_DAY,
    )
    .expect("outbound");
    let first = session::encrypt(&outbound.state, b"golden first flight", GOLDEN_DAY).expect("m0");
    let inbound = session::session_inbound(
        &b.identity,
        &b.signing,
        fallback_secret,
        &a.public,
        &first.l1,
        GOLDEN_DAY,
    )
    .expect("inbound");
    assert_eq!(inbound.plaintext, b"golden first flight");

    // B answers; A reads the answer, which opens a receiver chain on A's side.
    let reply = session::encrypt(&inbound.state, b"golden reply", GOLDEN_DAY).expect("r0");
    let a_state = session::decrypt(
        &[StoredSession {
            slot: Slot::Current,
            state: &first.state,
        }],
        &reply.l1,
        reply.is_pre_key,
        GOLDEN_DAY,
    )
    .expect("A reads the reply")
    .state;
    let mut b_state = reply.state;

    // A sends SKIPPED + 1 messages; B decrypts only the newest.
    let mut a_state = a_state;
    let mut held_for_responder = Vec::new();
    let mut newest = None;
    for index in 0..=SKIPPED {
        let plaintext = format!("golden a{index}");
        let out = session::encrypt(&a_state, plaintext.as_bytes(), GOLDEN_DAY).expect("encrypt");
        a_state = out.state.clone();
        if index == SKIPPED {
            newest = Some((out.l1, out.is_pre_key, plaintext));
        } else {
            held_for_responder.push((out.l1, out.is_pre_key, plaintext));
        }
    }
    let (newest_l1, newest_prekey, newest_text) = newest.expect("newest");
    let read = session::decrypt(
        &[StoredSession {
            slot: Slot::Current,
            state: &b_state,
        }],
        &newest_l1,
        newest_prekey,
        GOLDEN_DAY,
    )
    .expect("B reads the newest");
    assert_eq!(read.plaintext, newest_text.as_bytes());
    b_state = read.state;

    // One reply A never reads, so the load drill decrypts on both sides.
    let unread = session::encrypt(&b_state, b"golden unread reply", GOLDEN_DAY).expect("unread");
    b_state = unread.state;

    let stored = SessionState::decode(&b_state).expect("state");
    assert_eq!(
        stored.sidecar.len(),
        SKIPPED,
        "the responder holds exactly the skipped keys"
    );
    let (pruned_state, removed) =
        session::session_prune(&b_state, GOLDEN_DAY + session::SKIPPED_KEY_MAX_AGE_DAYS)
            .expect("prune");
    assert_eq!(removed, SKIPPED);

    let mut out = String::new();
    out.push_str(concat!(
        "# GHOST Phase 9 golden Olm session (design §15.2 item 2, gate G-R7).\n",
        "# Generated by `GHOST_DM_GOLDEN_WRITE=1 cargo test -p ghost-client-dm --test golden`.\n",
        "# `*_state` values are the plaintext of `olm_session.state_env`:\n",
        "#     u32_be(pickle_len) || vodozemac JSON pickle || first-seen sidecar.\n",
        "# `held_*` are Olm messages that side has not decrypted yet, with their plaintexts.\n",
        "# Loading these with a newer pin and continuing both ways is the §2.8 upgrade drill.\n",
    ));
    let mut line = |key: &str, value: String| {
        out.push_str(key);
        out.push_str(" = ");
        out.push_str(&value);
        out.push('\n');
    };
    line("version", VODOZEMAC_VERSION.to_string());
    line("today", GOLDEN_DAY.to_string());
    line("initiator_identity", hex::encode(a.public));
    line("responder_identity", hex::encode(b.public));
    line("initiator_state", hex::encode(&a_state));
    line("responder_state", hex::encode(&b_state));
    line("responder_state_pruned", hex::encode(&pruned_state));
    line(
        "prune_day",
        (GOLDEN_DAY + session::SKIPPED_KEY_MAX_AGE_DAYS).to_string(),
    );
    line("prune_removed", removed.to_string());
    for (index, view) in pickle::chain_views(&stored.pickle)
        .expect("views")
        .into_iter()
        .enumerate()
    {
        line(
            &format!("responder_chain.{index}.ratchet_key"),
            hex::encode(view.ratchet_key),
        );
        line(
            &format!("responder_chain.{index}.next_index"),
            view.next_index.to_string(),
        );
        line(
            &format!("responder_chain.{index}.skipped"),
            view.skipped
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    for (index, (l1, is_pre_key, plaintext)) in held_for_responder.iter().enumerate() {
        line(&format!("held_for_responder.{index}.l1"), hex::encode(l1));
        line(
            &format!("held_for_responder.{index}.prekey"),
            u8::from(*is_pre_key).to_string(),
        );
        line(
            &format!("held_for_responder.{index}.plaintext"),
            hex::encode(plaintext.as_bytes()),
        );
    }
    line("held_for_initiator.0.l1", hex::encode(&unread.l1));
    line(
        "held_for_initiator.0.prekey",
        u8::from(unread.is_pre_key).to_string(),
    );
    line(
        "held_for_initiator.0.plaintext",
        hex::encode(b"golden unread reply"),
    );

    std::fs::create_dir_all(golden_dir()).expect("golden dir");
    std::fs::write(golden_path(), out).expect("write golden");
}

/// The upgrade drill of §2.8 and §15.2 item 2: the committed pickles load with the pinned version
/// and both sides continue, held messages included.
#[test]
fn golden_pickles_load_and_both_sides_continue() {
    let golden = golden();
    assert_eq!(
        golden.text("version"),
        VODOZEMAC_VERSION,
        "the golden directory belongs to another pin"
    );
    let today = u32::try_from(golden.number("today")).expect("day");

    // The responder decrypts every message it had skipped, in any order.
    let mut responder = golden.bytes("responder_state");
    let held = golden.count("held_for_responder.");
    assert_eq!(held, SKIPPED);
    for index in (0..held).rev() {
        let l1 = golden.bytes(&format!("held_for_responder.{index}.l1"));
        let is_pre_key = golden.number(&format!("held_for_responder.{index}.prekey")) == 1;
        let expected = golden.bytes(&format!("held_for_responder.{index}.plaintext"));
        let read = session::decrypt(
            &[StoredSession {
                slot: Slot::Current,
                state: &responder,
            }],
            &l1,
            is_pre_key,
            today,
        )
        .unwrap_or_else(|code| panic!("held message {index} must decrypt, got {code:?}"));
        assert_eq!(read.plaintext, expected);
        responder = read.state;
    }

    // The initiator decrypts the reply it never read.
    let l1 = golden.bytes("held_for_initiator.0.l1");
    let is_pre_key = golden.number("held_for_initiator.0.prekey") == 1;
    let read = session::decrypt(
        &[StoredSession {
            slot: Slot::Current,
            state: &golden.bytes("initiator_state"),
        }],
        &l1,
        is_pre_key,
        today,
    )
    .expect("the held reply must decrypt");
    assert_eq!(
        read.plaintext,
        golden.bytes("held_for_initiator.0.plaintext")
    );
    let mut initiator = read.state;

    // Both sides continue: one more message each way, on the loaded state.
    let forward = session::encrypt(&initiator, b"after the upgrade, a", today).expect("encrypt");
    initiator = forward.state;
    let seen = session::decrypt(
        &[StoredSession {
            slot: Slot::Current,
            state: &responder,
        }],
        &forward.l1,
        forward.is_pre_key,
        today,
    )
    .expect("the responder continues");
    assert_eq!(seen.plaintext, b"after the upgrade, a");
    responder = seen.state;

    let back = session::encrypt(&responder, b"after the upgrade, b", today).expect("encrypt");
    let seen = session::decrypt(
        &[StoredSession {
            slot: Slot::Current,
            state: &initiator,
        }],
        &back.l1,
        back.is_pre_key,
        today,
    )
    .expect("the initiator continues");
    assert_eq!(seen.plaintext, b"after the upgrade, b");
}

/// G-R7 pins `chainPosition`'s outputs per pin: every recorded chain, and an unknown key.
#[test]
fn golden_chain_positions_are_pinned() {
    let golden = golden();
    let responder = golden.bytes("responder_state");
    let mut index = 0;
    while golden
        .0
        .contains_key(&format!("responder_chain.{index}.ratchet_key"))
    {
        let ratchet_key: [u8; 32] = golden
            .bytes(&format!("responder_chain.{index}.ratchet_key"))
            .try_into()
            .expect("32 bytes");
        let expected = golden.number(&format!("responder_chain.{index}.next_index"));
        assert_eq!(
            session::chain_position(&responder, &ratchet_key).expect("position"),
            ChainPosition::Index(expected),
            "chain {index}"
        );
        index += 1;
    }
    assert!(index > 0, "the golden records at least one receiver chain");
    assert_eq!(
        session::chain_position(&responder, &[0x5c; 32]).expect("position"),
        ChainPosition::NewChain
    );
}

/// G-R7 pins `sessionPrune`'s outputs per pin: the removed count and the resulting key set, and
/// the pruned pickle itself loads and continues (R-41's mitigation, drilled in V-15).
#[test]
fn golden_prune_outputs_are_pinned_and_the_pruned_state_continues() {
    let golden = golden();
    let responder = golden.bytes("responder_state");
    let prune_day = u32::try_from(golden.number("prune_day")).expect("day");

    let (kept, removed) = session::session_prune(&responder, prune_day - 1).expect("prune");
    assert_eq!(removed, 0, "nothing is pruned before the age bound");
    assert_eq!(
        SessionState::decode(&kept).expect("state").sidecar.len(),
        SKIPPED
    );

    let (pruned, removed) = session::session_prune(&responder, prune_day).expect("prune");
    assert_eq!(
        u64::try_from(removed).expect("count"),
        golden.number("prune_removed")
    );
    let state = SessionState::decode(&pruned).expect("state");
    assert!(state.sidecar.is_empty());
    assert!(pickle::skipped_keys(&state.pickle)
        .expect("keys")
        .is_empty());

    // The committed pruned state is the one an upgrade would load: it must still work.
    let committed = golden.bytes("responder_state_pruned");
    let out = session::encrypt(&committed, b"after the prune", prune_day).expect("encrypt");
    session::decrypt(
        &[StoredSession {
            slot: Slot::Current,
            state: &golden.bytes("initiator_state"),
        }],
        &out.l1,
        out.is_pre_key,
        prune_day,
    )
    .expect("the peer reads a message from a pruned session");
}
