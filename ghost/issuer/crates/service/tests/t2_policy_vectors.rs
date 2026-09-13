//! Replays `protocol/test-vectors/entitlement_policy.txt` against the Rust T2 reference policy
//! (Phase 8 design §13.4, §13.7): the same file the real Kotlin engine replays in
//! `PolicyVectorsTest.kt`, so the reference policy the T2 world schedules its clients with cannot
//! drift from the engine on anything the file pins. Every line must pass and every operation must
//! occur. Runs in the debug profile (no crypto beyond one HKDF per `attempt` line).

mod common;
mod t2;

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use t2::policy::{self, ClockEstimate, Decision, NeedKind, NeedReason, Onion, SlotRow, WorkKind};

const VECTORS: &str = include_str!("../../../../protocol/test-vectors/entitlement_policy.txt");

fn time(spec: &str) -> i64 {
    let i = spec
        .find(['+', '-'])
        .unwrap_or_else(|| panic!("time {spec}"));
    let start = policy::week_start(spec[..i].parse().unwrap());
    let s: i64 = spec[i + 1..].parse().unwrap();
    if &spec[i..=i] == "+" {
        start + s
    } else {
        start - s
    }
}

fn optional_time(spec: &str) -> Option<i64> {
    (spec != "none").then(|| time(spec))
}

fn onion(spec: &str) -> Onion {
    let (label, port) = spec.rsplit_once(':').unwrap();
    Onion {
        key: Sha256::digest(label.as_bytes()).into(),
        port: port.parse().unwrap(),
    }
}

fn show(slots: &[u8]) -> String {
    if slots.is_empty() {
        "none".to_string()
    } else {
        slots
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Default)]
struct Replay {
    slots: Vec<SlotRow>,
    estimate: ClockEstimate,
}

impl Replay {
    fn run(&mut self, words: &[&str], expect: Option<&[&str]>) -> String {
        let op = words[0].to_string();
        let a: BTreeMap<&str, &str> = words[1..]
            .iter()
            .filter_map(|w| w.split_once('='))
            .collect();
        let e = expect.and_then(|x| x.first().copied());
        match words[0] {
            "slot" => self.slots.push(SlotRow {
                slot: words[1].parse().unwrap(),
                from: a["from"].parse().unwrap(),
                until: if a["until"] == "open" {
                    0
                } else {
                    a["until"].parse().unwrap()
                },
                onion: onion(a["onion"]),
            }),
            "boundary" => assert_eq!(e == Some("yes"), policy::near_boundary(time(a["t"]))),
            "slotsfor" => assert_eq!(
                e.unwrap(),
                show(&policy::slots_for(
                    &self.slots,
                    onion(a["relay"]),
                    a["week"].parse().unwrap()
                ))
            ),
            "plan" => self.plan(&a, expect.unwrap()),
            "estimate" => match words[1] {
                "reset" => self.estimate = ClockEstimate::default(),
                "record" => self.estimate.record(
                    a["relay"].parse().unwrap(),
                    a["relay_minute"].parse().unwrap(),
                    a["period"].parse().unwrap(),
                    time(a["local"]),
                    a["wrong"] == "yes",
                ),
                "now" => assert_eq!(time(e.unwrap()), self.estimate.now(time(a["wall"]))),
                "week" => assert_eq!(
                    e.unwrap().parse::<i64>().unwrap(),
                    self.estimate
                        .week(a["relay"].parse().unwrap(), time(a["wall"]))
                ),
                other => panic!("unknown estimate {other}"),
            },
            "eligible" => {
                let mut queue: Vec<f64> = if a["uniforms"] == "none" {
                    Vec::new()
                } else {
                    a["uniforms"]
                        .split(',')
                        .map(|u| u.parse().unwrap())
                        .collect()
                };
                queue.reverse();
                let mut draw = || queue.pop().expect("a uniform too many");
                let high = a["mode"] == "high";
                let t = time(a["finalized"]);
                let got = if a["batch"] == "pack" {
                    policy::pack_eligible_minute(t, &mut draw, high)
                } else {
                    policy::trial_eligible_minute(t, &mut draw, high)
                };
                assert_eq!(time(e.unwrap()), got);
                assert!(queue.is_empty(), "every listed uniform is consumed");
            }
            "attempt" => {
                let seed: [u8; 32] = hex::decode(a["seed"]).unwrap().try_into().unwrap();
                assert_eq!(
                    time(e.unwrap()),
                    policy::blind_sign_due_minute(
                        &seed,
                        time(a["receipt"]),
                        a["k"].parse().unwrap()
                    )
                );
            }
            "retry" => assert_eq!(
                optional_time(e.unwrap()),
                policy::next_due_after_send(
                    a["attempt"].parse().unwrap(),
                    optional_time(a["current"]),
                    time(a["now"]),
                    a["uniform"].parse().unwrap()
                )
            ),
            "classify" => {
                let got = match policy::classify(words[1]) {
                    policy::Failure::Transient => "transient",
                    policy::Failure::Unauthorized => "unauthorized",
                    policy::Failure::Rejected => "rejected",
                    policy::Failure::Malformed => "malformed",
                };
                assert_eq!(e.unwrap(), got);
            }
            "work" => self.work(&a, e.unwrap()),
            "cover" => self.cover(&a, e.unwrap()),
            other => panic!("unknown operation {other}"),
        }
        op
    }

    fn plan(&self, a: &BTreeMap<&str, &str>, expect: &[&str]) {
        let kind = if a["kind"] == "write" {
            NeedKind::Write
        } else {
            NeedKind::Read
        };
        let reason = match a["reason"] {
            "missing" => NeedReason::Missing,
            "expiring" => NeedReason::Expiring,
            "exhausted" => NeedReason::Exhausted,
            "rejected" => NeedReason::Rejected,
            other => panic!("reason {other}"),
        };
        let d = policy::plan(
            kind,
            reason,
            onion(a["relay"]),
            &self.slots,
            time(a["now"]),
            a["week"].parse().unwrap(),
            a["trusted"] == "yes",
            time(a["first"]),
            optional_time(a["write_expiry"]),
            a["prf"].parse().unwrap(),
        );
        if expect[0] == "redeem" {
            let f: BTreeMap<&str, &str> = expect[1..]
                .iter()
                .map(|w| w.split_once('=').unwrap())
                .collect();
            let Decision::Redeem { week, slots, due } = d else {
                panic!("expected a redemption, got {d:?}");
            };
            assert_eq!(f["week"].parse::<i64>().unwrap(), week, "week");
            assert_eq!(f["slots"], show(&slots), "slots");
            assert_eq!(time(f["due"]), due, "due");
        } else {
            let got = match d {
                Decision::Deferred => "deferred",
                Decision::NoSlot => "no_slot",
                Decision::Skip => "skip",
                Decision::Redeem { .. } => "redeem",
            };
            assert_eq!(expect.join(" "), got);
        }
    }

    fn work(&self, a: &BTreeMap<&str, &str>, expect: &str) {
        let now = time(a["now"]);
        let items: Vec<(WorkKind, i64)> = if a["items"] == "none" {
            Vec::new()
        } else {
            a["items"]
                .split(',')
                .map(|item| {
                    let (kind, due) = item.split_once('@').unwrap();
                    let kind = match kind {
                        "request" => WorkKind::Request,
                        "sign" => WorkKind::Sign,
                        "refresh" => WorkKind::Refresh,
                        "revocation" => WorkKind::Revocation,
                        "claim" => WorkKind::Claim,
                        "renewal" => WorkKind::Renewal,
                        other => panic!("item {other}"),
                    };
                    (kind, time(due))
                })
                .collect()
        };
        let got = policy::pick(&items, now).map_or("none".to_string(), |i| i.to_string());
        assert_eq!(expect, got);
    }

    fn cover(&self, a: &BTreeMap<&str, &str>, expect: &str) {
        let prices: BTreeMap<i64, i64> = a["prices"]
            .split(',')
            .map(|p| {
                let (e, v) = p.split_once(':').unwrap();
                (e.parse().unwrap(), v.parse().unwrap())
            })
            .collect();
        let credits: Vec<i64> = a["credits"]
            .split(',')
            .map(|c| c.parse().unwrap())
            .collect();
        // The vector file's schedule: `credits_per_free_pack = 10` (TestSchedule of the Kotlin
        // replayer and the T2 test ES alike).
        let got = policy::covering_set(
            &prices,
            &credits,
            a["base"].parse().unwrap(),
            a["now"].parse().unwrap(),
            10,
        )
        .map_or("none".to_string(), |c| {
            c.iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        });
        assert_eq!(expect, got);
    }
}

#[test]
fn the_reference_policy_matches_the_shared_policy_vectors() {
    let mut replay = Replay::default();
    let mut seen = std::collections::BTreeSet::new();
    let mut outcomes = 0;
    for (index, raw) in VECTORS.lines().enumerate() {
        let line = raw.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let (op_part, expect_part) = match line.split_once("->") {
            Some((o, e)) => (o, Some(e)),
            None => (line, None),
        };
        let words: Vec<&str> = op_part.split_whitespace().collect();
        let expect: Option<Vec<&str>> = expect_part.map(|e| e.split_whitespace().collect());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            replay.run(&words, expect.as_deref())
        }));
        match result {
            Ok(op) => {
                seen.insert(op);
            }
            Err(e) => {
                let msg = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                panic!("entitlement_policy.txt:{}: `{line}`: {msg}", index + 1);
            }
        }
        if expect.is_some() {
            outcomes += 1;
        }
    }
    let all: std::collections::BTreeSet<String> = [
        "slot", "boundary", "slotsfor", "plan", "estimate", "eligible", "attempt", "retry",
        "classify", "work", "cover",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(seen, all, "every operation of the file occurs");
    assert!(outcomes >= 70, "only {outcomes} outcomes");
}
