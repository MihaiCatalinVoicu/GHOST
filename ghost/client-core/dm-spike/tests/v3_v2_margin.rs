//! V-3 margin: how much of O_MAX a move to vodozemac's experimental SessionConfig V2 (full 32-byte
//! MAC) would use. `cargo test --release --features v2-config --test v3_v2_margin -- --nocapture`.
//! The feature is forbidden in every shipped graph (G-R2); this only sizes the margin.
#![cfg(feature = "v2-config")]

use ghost_dm_spike::sizes::set_sending_index;
use vz11::olm::{Account, OlmMessage, Session, SessionConfig, SessionPickle};

fn overhead(config: SessionConfig, len: usize, index: u64) -> (usize, usize) {
    let a = Account::new();
    let mut b = Account::new();
    b.generate_fallback_key();
    let fallback = *b.fallback_key().values().next().expect("fallback key");
    let mut outbound = a
        .create_outbound_session(config, b.curve25519_key(), fallback)
        .expect("outbound");
    let OlmMessage::PreKey(first) = outbound.encrypt(b"x").expect("encrypt") else {
        panic!("prekey expected")
    };
    let created = b
        .create_inbound_session(config, a.curve25519_key(), &first)
        .expect("inbound");
    let reload = |s: &Session, index: u64| {
        let json = set_sending_index(&serde_json::to_vec(&s.pickle()).expect("pickle"), index)
            .expect("edit");
        Session::from_pickle(serde_json::from_slice::<SessionPickle>(&json).expect("load"))
    };
    let plaintext = vec![0u8; len];
    let prekey = reload(&outbound, index)
        .encrypt(&plaintext)
        .expect("encrypt")
        .to_parts()
        .1
        .len()
        - len;
    let mut responder = created.session;
    let _ = responder.encrypt(b"activate").expect("encrypt");
    let normal = reload(&responder, index)
        .encrypt(&plaintext)
        .expect("encrypt")
        .to_parts()
        .1
        .len()
        - len;
    (prekey, normal)
}

#[test]
fn v2_config_margin() {
    let len = 65_536 - 1_664;
    let index = u64::MAX - 1;
    let (p1, n1) = overhead(SessionConfig::version_1(), len, index);
    let (p2, n2) = overhead(SessionConfig::version_2(), len, index);
    println!(
        "V3-V2 64 KiB class, index 2^64-2: V1 prekey {p1} normal {n1}; V2 prekey {p2} normal {n2}"
    );
    let intro_v2 = 49 + 1_376 + p2;
    println!(
        "V3-V2 worst intro total with V2: {intro_v2} (O_MAX 1664, margin {})",
        1_664 - intro_v2
    );
    assert!(intro_v2 <= 1_664);
}
