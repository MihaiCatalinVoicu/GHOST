//! Replays `protocol/test-vectors/entitlement_schedule.txt`: every Entitlement Schedule rule has a
//! negative case (Phase 8 design §3.1, §19.2).

mod common;

use common::fixture::{self, FIRST_WEEK, FIXTURE, WEEKS};
use ghost_blind_rsa::{i2osp, BigUint, PublicKey, PROOF_BLOCK_LEN};
use ghost_entitlement::grid::{credit_epoch, invite_epoch, price_epoch, Kind};
use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::onion;
use ghost_entitlement::schedule::{KeyContent, ScheduleContent, ScheduleMemory, SlotEntry};
use ghost_entitlement::{Schedule, ScheduleError};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../../protocol/test-vectors/entitlement_schedule.txt");

fn verdict_name(r: &Result<(), ScheduleError>) -> String {
    match r {
        Ok(()) => "ok".to_string(),
        Err(e) => {
            let debug = format!("{e:?}");
            let mut out = String::new();
            for (i, c) in debug.chars().enumerate() {
                if c.is_ascii_uppercase() && i > 0 {
                    out.push('-');
                }
                out.push(c.to_ascii_lowercase());
            }
            out
        }
    }
}

fn verify(bytes: &[u8]) -> Result<Schedule, ScheduleError> {
    Schedule::verify_with_key(bytes, &fixture::schedule_key())
}

fn content() -> ScheduleContent {
    fixture::schedule().content().clone()
}

/// Re-signs an edited copy of the fixture content.
fn edited(edit: impl FnOnce(&mut ScheduleContent)) -> Vec<u8> {
    let mut c = content();
    edit(&mut c);
    fixture::resign(&c)
}

fn key_index(c: &ScheduleContent, kind: Kind, epoch: u64) -> usize {
    c.keys
        .iter()
        .position(|k| k.kind == kind && k.epoch == epoch)
        .unwrap()
}

fn fake_key(n: &[u8], e: &[u8], proof_from: &KeyContent, kind: Kind, epoch: u64) -> KeyContent {
    KeyContent {
        kind,
        epoch,
        spki: PublicKey::from_components(n, e).unwrap().to_spki(),
        proof: proof_from.proof,
    }
}

/// Replaces base32 character 10 of an onion's label with another base32 character: the decoded
/// bytes change, so the v3 checksum (or version byte) no longer matches.
fn corrupt_onion(onion: &str) -> String {
    let mut chars: Vec<char> = onion.chars().collect();
    chars[10] = if chars[10] == 'a' { 'b' } else { 'a' };
    chars.into_iter().collect()
}

/// An Ed25519 service key no fixture onion uses.
fn fresh_service_key() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&[9; 32])
        .verifying_key()
        .to_bytes()
}

/// The body offset of the kind byte of key entry 0.
fn first_key_kind_offset(body: &[u8], c: &ScheduleContent) -> usize {
    let spki = &c.keys[0].spki;
    let at = body
        .windows(spki.len())
        .position(|w| w == spki.as_slice())
        .unwrap();
    at - 2 - 8 - 1
}

fn raw_body() -> Vec<u8> {
    FIXTURE[..FIXTURE.len() - 64].to_vec()
}

/// Accepts `first` into a fresh memory, then checks `second` against it.
fn memory_case(first: &[u8], second: &[u8]) -> Result<(), ScheduleError> {
    let mut memory = ScheduleMemory::default();
    let a = verify(first).unwrap();
    a.check_memory(&memory).unwrap();
    a.remember(&mut memory);
    let b = verify(second)?;
    b.check_memory(&memory)
}

fn run(case: &str) -> Result<(), ScheduleError> {
    let c = content();
    let access0 = key_index(&c, Kind::Access, FIRST_WEEK);
    let check = |bytes: Vec<u8>| verify(&bytes).map(|_| ());
    match case {
        "as-is" => check(FIXTURE.to_vec()),
        "flip-body-byte" => {
            let mut b = FIXTURE.to_vec();
            b[200] ^= 0x01;
            check(b)
        }
        "flip-signature-byte" => {
            let mut b = FIXTURE.to_vec();
            let last = b.len() - 1;
            b[last] ^= 0x01;
            check(b)
        }
        "truncate-1" => check(FIXTURE[..FIXTURE.len() - 1].to_vec()),
        "append-1" => check([FIXTURE, &[0]].concat()),
        "other-key" => {
            let other = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes();
            Schedule::verify_with_key(FIXTURE, &other).map(|_| ())
        }
        "shorter-than-a-signature" => check(FIXTURE[..63].to_vec()),
        "pinned-key" => Schedule::verify(FIXTURE).map(|_| ()),
        "magic" => {
            let mut body = raw_body();
            body[3] = b'Z';
            check(fixture::resign_body(&body))
        }
        "version-2" => {
            let mut body = raw_body();
            body[4] = 2;
            check(fixture::resign_body(&body))
        }
        "trailing-byte" => check(fixture::resign_body(&[raw_body(), vec![0]].concat())),
        "network-4" => {
            let mut body = raw_body();
            body[13] = 4;
            check(fixture::resign_body(&body))
        }
        "issuer-name-empty" => check(edited(|c| c.issuer_name.clear())),
        "issuer-name-space" => check(edited(|c| c.issuer_name = "ghost issuer".into())),
        "issuer-name-65" => check(edited(|c| c.issuer_name = "a".repeat(65))),
        "issuer-onion-checksum" => {
            check(edited(|c| c.issuer_onion = corrupt_onion(&c.issuer_onion)))
        }
        "issuer-onion-uppercase" => check(edited(|c| {
            c.issuer_onion = c.issuer_onion.to_ascii_uppercase()
        })),
        "constants-access-per-slot-0" => check(edited(|c| c.constants.access_per_slot = 0)),
        "constants-claim-min-above-max" => check(edited(|c| {
            c.constants.min_claim_credits = c.constants.max_claim_credits + 1
        })),
        "key-unknown-kind" => {
            let mut body = raw_body();
            let at = first_key_kind_offset(&body, &c);
            assert_eq!(body[at], c.keys[0].kind.byte());
            body[at] = 4;
            check(fixture::resign_body(&body))
        }
        "key-duplicate-kind-epoch" => check(edited(|c| {
            let dup = c.keys[access0 + 1].clone();
            c.keys.push(KeyContent {
                epoch: FIRST_WEEK,
                ..dup
            });
        })),
        "key-same-spki-twice" => check(edited(|c| {
            let invite = key_index(c, Kind::Invite, invite_epoch(FIRST_WEEK));
            c.keys[invite].spki = c.keys[access0].spki.clone();
            c.keys[invite].proof = c.keys[access0].proof;
        })),
        "key-2047-bit" => check(edited(|c| {
            let mut n = vec![0u8; 256];
            n[0] = 0x40;
            n[255] = 1;
            c.keys[access0] = fake_key(&n, &[1, 0, 1], &c.keys[access0], Kind::Access, FIRST_WEEK);
        })),
        "key-2049-bit" => check(edited(|c| {
            let mut n = vec![0u8; 257];
            n[0] = 1;
            n[256] = 1;
            c.keys[access0] = fake_key(&n, &[1, 0, 1], &c.keys[access0], Kind::Access, FIRST_WEEK);
        })),
        "key-e-3" => check(edited(|c| {
            let pk = PublicKey::from_spki(&c.keys[access0].spki).unwrap();
            c.keys[access0] = fake_key(
                pk.n_bytes(),
                &[3],
                &c.keys[access0],
                Kind::Access,
                FIRST_WEEK,
            );
        })),
        "key-spki-trailing-byte" => check(edited(|c| c.keys[access0].spki.push(0))),
        "key-spki-rsaencryption" => check(edited(|c| {
            // The same (n, e) under rsaEncryption instead of id-RSASSA-PSS with SHA-384 parameters.
            let pss = &c.keys[access0].spki;
            let rsa_alg = [
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                0x00,
            ];
            let bit_string = &pss[4 + 63..];
            let len = (rsa_alg.len() + bit_string.len()) as u16;
            c.keys[access0].spki =
                [&[0x30, 0x82], &len.to_be_bytes()[..], &rsa_alg, bit_string].concat();
        })),
        "key-proof-tampered" => check(edited(|c| c.keys[access0].proof[5][17] ^= 0x01)),
        "key-proof-of-other-key" => check(edited(|c| {
            c.keys[access0].proof = c.keys[access0 + 1].proof
        })),
        "key-small-factor" => check(edited(|c| {
            // n = 65537 * p * q with its own mathematically valid permutation proof
            // (blind-rsa tests/permutation_proof.rs): only the trial division refuses it.
            let v = common::section("perm-proof-negative")
                .into_iter()
                .find(|v| v.id == "small-factor-65537")
                .unwrap();
            let proof = v.hex("proof");
            c.keys[access0] = KeyContent {
                kind: Kind::Access,
                epoch: FIRST_WEEK,
                spki: PublicKey::from_components(&v.hex("n"), &[1, 0, 1])
                    .unwrap()
                    .to_spki(),
                proof: std::array::from_fn(|i| {
                    proof[i * PROOF_BLOCK_LEN..(i + 1) * PROOF_BLOCK_LEN]
                        .try_into()
                        .unwrap()
                }),
            };
        })),
        "key-proof-not-canonical" => check(edited(|c| {
            // The first proof element sigma_i of any key for which sigma_i + n fits 256 bytes:
            // (sigma_i + n)^e == rho_i still holds, only the canonical range sigma_i < n refuses it.
            let (k, i, lifted) = c
                .keys
                .iter()
                .enumerate()
                .find_map(|(k, key)| {
                    let pk = PublicKey::from_spki(&key.spki).unwrap();
                    key.proof.iter().enumerate().find_map(|(i, sigma)| {
                        let lifted = BigUint::from_bytes_be(sigma) + pk.n();
                        i2osp(&lifted, PROOF_BLOCK_LEN).ok().map(|b| (k, i, b))
                    })
                })
                .unwrap();
            c.keys[k].proof[i].copy_from_slice(&lifted);
        })),
        "coverage-access-gap" => check(edited(|c| {
            c.keys.remove(key_index(c, Kind::Access, FIRST_WEEK + 5));
        })),
        "coverage-25-weeks" => check(edited(|c| {
            c.keys
                .remove(key_index(c, Kind::Access, FIRST_WEEK + WEEKS - 1));
        })),
        "coverage-missing-invite" => check(edited(|c| {
            c.keys
                .remove(key_index(c, Kind::Invite, invite_epoch(FIRST_WEEK + 12)));
        })),
        "coverage-missing-credit" => check(edited(|c| {
            c.keys.remove(key_index(
                c,
                Kind::Credit,
                credit_epoch(FIRST_WEEK + WEEKS - 1),
            ));
        })),
        "coverage-missing-price" => check(edited(|c| {
            c.prices
                .retain(|p| p.price_epoch != price_epoch(FIRST_WEEK + 13));
        })),
        "coverage-week-without-slot" => check(edited(|c| {
            for s in c
                .slots
                .iter_mut()
                .filter(|s| s.valid_from_week == FIRST_WEEK)
            {
                s.valid_from_week = FIRST_WEEK + 1;
            }
        })),
        "coverage-epoch-extremes" => check(edited(|c| {
            // Correctly signed keys at access epochs 0 and u64::MAX: the week span must not overflow.
            let last = key_index(c, Kind::Access, FIRST_WEEK + WEEKS - 1);
            c.keys[access0].epoch = 0;
            c.keys[last].epoch = u64::MAX;
        })),
        "slots-empty" => check(edited(|c| c.slots.clear())),
        "slot-32" => check(edited(|c| c.slots[0].slot = 32)),
        "slot-overlap" => check(edited(|c| {
            let onion = c.slots[1].onion.clone();
            c.slots.push(SlotEntry {
                slot: 0,
                onion,
                valid_from_week: FIRST_WEEK + 3,
                valid_until_week: FIRST_WEEK + 4,
            });
        })),
        "slot-until-before-from" => check(edited(|c| {
            c.slots[0].valid_until_week = c.slots[0].valid_from_week;
        })),
        "slot-onion-checksum" => check(edited(|c| {
            c.slots[1].onion = corrupt_onion(&c.slots[1].onion)
        })),
        "slot-onion-under-two-slots" => check(edited(|c| {
            // Slots 0 and 1 at one exact onion:port in every week (Q27).
            c.slots[0].onion = c.slots[1].onion.clone();
        })),
        "slot-onion-two-slots-later-week" => check(edited(|c| {
            // Slot 1 is served from week FIRST_WEEK + 12 at slot 0's address (Q27 in one week only).
            c.slots[1].valid_until_week = FIRST_WEEK + 12;
            let onion = c.slots[0].onion.clone();
            c.slots.push(SlotEntry {
                slot: 1,
                onion,
                valid_from_week: FIRST_WEEK + 12,
                valid_until_week: 0,
            });
        })),
        "slot-onion-other-slot-disjoint-weeks" => check(edited(|c| {
            // The relay that served slot 2 until week FIRST_WEEK + 10 serves slot 1 from then on.
            let slot2 = c
                .slots
                .iter()
                .find(|s| s.slot == 2 && s.valid_from_week == FIRST_WEEK)
                .unwrap();
            assert_eq!(slot2.valid_until_week, FIRST_WEEK + 10);
            let onion = slot2.onion.clone();
            c.slots[1].valid_until_week = FIRST_WEEK + 10;
            c.slots.push(SlotEntry {
                slot: 1,
                onion,
                valid_from_week: FIRST_WEEK + 10,
                valid_until_week: 0,
            });
        })),
        "slot-service-key-two-slots-two-ports" => check(edited(|c| {
            // One onion service under slots 0 and 1 at two ports (§19.22 point 3).
            let (host, port) = c.slots[1].onion.rsplit_once(':').unwrap();
            let other = port.parse::<u16>().unwrap() + 1;
            c.slots[0].onion = format!("{host}:{other}");
        })),
        "price-not-divisible-by-10" => check(edited(|c| c.prices[0].pack_price_atomic += 5)),
        "price-zero" => check(edited(|c| c.prices[0].pack_price_atomic = 0)),
        "price-duplicate" => check(edited(|c| {
            let dup = c.prices[0];
            c.prices.push(dup);
        })),
        "revoked-access-week" => check(edited(|c| c.revoked.push((Kind::Access, FIRST_WEEK + 3)))),
        "revoked-unknown" => check(edited(|c| c.revoked.push((Kind::Access, FIRST_WEEK + 100)))),
        "revoked-duplicate" => check(edited(|c| {
            c.revoked.push((Kind::Credit, credit_epoch(FIRST_WEEK)));
            c.revoked.push((Kind::Credit, credit_epoch(FIRST_WEEK)));
        })),
        "memory-same" => memory_case(FIXTURE, FIXTURE),
        "memory-successor-seq-2" => memory_case(FIXTURE, &edited(|c| c.seq = 2)),
        "memory-onion-moved" => memory_case(
            FIXTURE,
            &edited(|c| {
                // An emergency move of slot 0 to a new onion service (E18).
                c.seq = 2;
                c.slots[0].onion = format!("{}:443", onion::hostname(&fresh_service_key()));
            }),
        ),
        "memory-rollback" => memory_case(&edited(|c| c.seq = 2), FIXTURE),
        "memory-key-changed" => memory_case(
            FIXTURE,
            &edited(|c| {
                // Two covered weeks swap keys: each schedule alone is valid.
                c.seq = 2;
                let (a, b) = (c.keys[access0].clone(), c.keys[access0 + 1].clone());
                c.keys[access0] = KeyContent {
                    epoch: FIRST_WEEK,
                    ..b
                };
                c.keys[access0 + 1] = KeyContent {
                    epoch: FIRST_WEEK + 1,
                    ..a
                };
            }),
        ),
        "memory-slot-set-changed" => memory_case(
            FIXTURE,
            &edited(|c| {
                // Slot 2 is no longer served from week FIRST_WEEK + 10 on.
                c.seq = 2;
                c.slots
                    .retain(|s| !(s.slot == 2 && s.valid_from_week == FIRST_WEEK + 10));
            }),
        ),
        "memory-price-changed" => memory_case(
            FIXTURE,
            &edited(|c| {
                c.seq = 2;
                c.prices[0].pack_price_atomic += 10;
            }),
        ),
        "memory-revocation-added" => memory_case(
            FIXTURE,
            &edited(|c| {
                c.seq = 2;
                c.revoked.push((Kind::Access, FIRST_WEEK + 3));
            }),
        ),
        "memory-revocation-kept" => memory_case(
            &edited(|c| {
                c.seq = 2;
                c.revoked.push((Kind::Access, FIRST_WEEK + 3));
            }),
            &edited(|c| {
                c.seq = 3;
                c.revoked.push((Kind::Credit, credit_epoch(FIRST_WEEK)));
                c.revoked.push((Kind::Access, FIRST_WEEK + 3));
            }),
        ),
        "memory-revocation-dropped" => memory_case(
            &edited(|c| {
                // Runbook I1 revoked a leaked week; a later schedule must not silently restore it.
                c.seq = 2;
                c.revoked.push((Kind::Access, FIRST_WEEK + 3));
            }),
            &edited(|c| c.seq = 3),
        ),
        "client-regtest" => fixture::schedule().refuse_regtest(),
        "client-stagenet" => verify(&edited(|c| c.network = MoneroNetwork::Stagenet))
            .and_then(|s| s.refuse_regtest()),
        other => panic!("unknown case {other}"),
    }
}

#[test]
fn fixture_facts_match_the_vector_file() {
    let line = VECTORS.lines().find(|l| l.starts_with("fixture|")).unwrap();
    let f: Vec<&str> = line.split('|').collect();
    assert_eq!(f[1], "test_schedule.ghes");
    assert_eq!(hex::encode(Sha256::digest(FIXTURE)), f[2], "fixture hash");
    assert_eq!(hex::encode(fixture::schedule_key()), f[3], "schedule key");
    let s = fixture::schedule();
    let facts = format!(
        "seq={}|network=regtest|first_week={}|last_week={}|keys={}|slot_entries={}",
        s.seq(),
        s.first_access_week(),
        s.last_access_week(),
        s.keys().count(),
        s.content().slots.len()
    );
    assert_eq!(f[4..].join("|"), facts);
    assert_eq!(s.network(), MoneroNetwork::Regtest);
    assert_eq!(s.digest().as_slice(), Sha256::digest(FIXTURE).as_slice());
}

#[test]
fn every_case_has_its_verdict() {
    let mut cases = 0;
    for line in VECTORS.lines().filter(|l| l.starts_with("case|")) {
        let f: Vec<&str> = line.split('|').collect();
        assert_eq!(verdict_name(&run(f[1])), f[2], "case {}", f[1]);
        cases += 1;
    }
    assert!(cases >= 55, "{cases} cases");
}

#[test]
fn verified_schedule_answers_layout_questions() {
    let s = fixture::schedule();
    assert_eq!(s.slots_in_week(FIRST_WEEK), vec![0, 1, 2]);
    assert_eq!(s.slots_in_week(FIRST_WEEK + 9), vec![0, 1, 2]);
    assert_ne!(
        s.slot_onion(2, FIRST_WEEK + 9),
        s.slot_onion(2, FIRST_WEEK + 10)
    );
    assert_eq!(s.slot_onion(3, FIRST_WEEK), None);
    assert_eq!(s.pack_price(price_epoch(FIRST_WEEK)), Some(200_000_000_000));
    assert_eq!(
        s.credit_value(credit_epoch(FIRST_WEEK)),
        Some(20_000_000_000)
    );
    for k in s.keys() {
        assert_eq!(s.key_by_id(&k.key_id).unwrap().epoch, k.epoch);
    }
    assert!(s.key_by_id(&[0; 32]).is_none());
    assert!(!s.is_revoked(Kind::Access, FIRST_WEEK));
}
