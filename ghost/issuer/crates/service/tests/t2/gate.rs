//! The T2 gate (Phase 8 design §1.3, §13.4, §19.16): the worlds of one variant, the twin-world
//! comparisons, the join search and the statistical tests, and the report.
//!
//! **Worlds.** `W_train` (the attacker learns the policy from it: the code is open source) and
//! `W_test` (= NI world A) at the variant's scale; from `W_test`'s record the twins NI-1 (same
//! cell: other issuer randomness, pool minors, latencies up to 30 s, chain timing, one extra
//! `UNAVAILABLE` on a non-final `BlindSign` per purchase, an extra issuer restore), NI-1 across
//! cells (an extra `UNAVAILABLE` on the signing `BlindSign` of a fifth of the purchases, compared
//! per client before the earlier activation-slot cell) and NI-2 (other token-level randomness and
//! namespaces, the declared user actions replayed); at the small scale NI-3 (relays shift a fifth of
//! the clients' clock) and NI-1d (a third of the invitees buy their first pack two days later);
//! and a lying issuer (every invoice answered `AWAITING_CONFIRMATIONS` until the client's last
//! attempt) for the second S4 bound.
//!
//! **Seeds.** Pinned (`SEEDS`); a failure on a correct implementation is investigated, never
//! re-seeded (Phase 7 policy).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;

use ghost_t2_join::checks;
use ghost_t2_join::model::Truth;
use ghost_t2_join::stats::{self, Attackers};
use ghost_t2_join::transforms;
use ghost_t2_join::values;
use sha2::Digest;

use super::config::{Config, Mutant, UserScript};
use super::population::{self, Scale};
use super::rng::Rng;
use super::world::{non_final_attempts, Outcome, World};

/// The pinned seed pairs (train, test): the first is the gate's and the PR variant's; the nightly
/// sweep runs all ten.
pub const SEEDS: [(u64, u64); 10] = [
    (0x7432_0001, 0x7432_0002),
    (0x7432_0011, 0x7432_0012),
    (0x7432_0021, 0x7432_0022),
    (0x7432_0031, 0x7432_0032),
    (0x7432_0041, 0x7432_0042),
    (0x7432_0051, 0x7432_0052),
    (0x7432_0061, 0x7432_0062),
    (0x7432_0071, 0x7432_0072),
    (0x7432_0081, 0x7432_0082),
    (0x7432_0091, 0x7432_0092),
];

pub const ALPHA: f64 = 0.001;
/// Q21: the declared-leak attacker's top-1 accuracy bound.
pub const S4_BOUND: f64 = 0.25;

#[derive(Default)]
pub struct Findings {
    pub lines: Vec<String>,
    pub failed: Vec<String>,
}

impl Findings {
    pub fn check(&mut self, name: &str, ok: bool, detail: impl AsRef<str>) {
        let verdict = if ok { "PASS" } else { "FAIL" };
        self.lines
            .push(format!("{name}: {verdict} {}", detail.as_ref()));
        if !ok {
            self.failed.push(name.to_string());
        }
    }

    pub fn note(&mut self, text: impl AsRef<str>) {
        self.lines.push(text.as_ref().to_string());
    }

    pub fn failed(&self, name: &str) -> bool {
        self.failed
            .iter()
            .any(|f| f == name || f.starts_with(&format!("{name} ")))
    }

    pub fn text(&self) -> String {
        let mut s = String::new();
        for l in &self.lines {
            writeln!(s, "{l}").unwrap();
        }
        s
    }
}

fn hits_line(hits: &[values::Hit]) -> String {
    match hits.first() {
        None => "0 hits".to_string(),
        Some(h) => format!("{} hits, first: {h}", hits.len()),
    }
}

/// The J9 due minute of attempt k (the reference policy).
fn due(seed: &[u8; 32], receipt: u64, k: usize) -> u64 {
    super::policy::blind_sign_due_minute(seed, receipt as i64, k) as u64
}

/// J1–J10, T2b and T2c on a world's views.
pub fn joins(f: &mut Findings, test: &Outcome) {
    let acc = test.rec.acc.as_ref().expect("an analyzed world");
    let truth = &test.truth;
    let t = std::time::Instant::now();
    let j1 = values::j1(&acc.values, &acc.public);
    f.check("J1", j1.is_empty(), hits_line(&j1));
    let j2 = values::j2(&acc.values, &acc.public);
    f.check("J2", j2.is_empty(), hits_line(&j2));
    let j3 = transforms::j3(&acc.values, &acc.public);
    f.check("J3", j3.is_empty(), hits_line(&j3));
    let labels: Vec<Vec<u8>> = transforms::LABELS
        .iter()
        .map(|l| l.as_bytes().to_vec())
        .collect();
    let j4 = values::j4(&acc.values, &acc.public, &labels);
    f.check("J4", j4.is_empty(), hits_line(&j4));
    let j5 = checks::j5c(acc);
    f.check(
        "J5",
        j5.is_empty(),
        format!(
            "(c: every blind signature under its position's ES key) {}",
            hits_line(&j5)
        ),
    );
    let j6 = checks::j6(acc);
    f.check("J6", j6.is_empty(), hits_line(&j6));
    let j7 = checks::j7(acc);
    f.check("J7", j7.is_empty(), hits_line(&j7));
    let j8 = checks::j8(acc);
    f.check(
        "J8",
        j8.is_empty(),
        format!(
            "{} ({} WRONG_PERIOD redemptions of devices more than 24 h off, which the clipped relay-facing clock corrects only to within 24 h, §19.23 point 2; {} identical retries of ambiguous redemptions landing after their week, R8)",
            hits_line(&j8),
            checks::j8_far_skew(acc),
            checks::j8_late_retries(acc)
        ),
    );
    let j9 = checks::j9(acc, truth, due);
    f.check("J9", j9.is_empty(), hits_line(&j9));
    let proofs: Vec<_> = acc
        .schedule
        .content()
        .keys
        .iter()
        .map(|k| {
            let pk = ghost_blind_rsa::PublicKey::from_spki(&k.spki).unwrap();
            (k.kind, k.epoch, pk, k.proof.to_vec())
        })
        .collect();
    let j10 = checks::j10_keys(acc, &proofs);
    f.check("J10", j10.is_empty(), hits_line(&j10));
    let t2b = values::t2b(&acc.values, &acc.public);
    f.check("T2b", t2b.is_empty(), hits_line(&t2b));
    let (t2c, released) = checks::t2c_counted(acc, truth);
    f.check(
        "T2c",
        t2c.is_empty(),
        format!("{} ({released} credits re-presented after an unanswered credits-pack flow, §19.23 point 2)", hits_line(&t2c)),
    );
    // Completeness: every call a handler received is in a view.
    let redeems = test
        .log
        .counts
        .iter()
        .filter(|(k, _)| k.starts_with("redemptions "))
        .map(|(_, v)| *v)
        .sum::<u64>();
    f.check(
        "completeness",
        acc.issuer.len() as u64 == test.rec.digests.issuer_calls
            && acc.relay_calls == test.rec.digests.relay_calls.iter().sum::<u64>()
            && acc.redemptions.len() as u64 >= redeems,
        format!(
            "issuer calls {} in view {}, relay calls {} in views {}, redemptions {} (client-side {redeems})",
            test.rec.digests.issuer_calls,
            acc.issuer.len(),
            test.rec.digests.relay_calls.iter().sum::<u64>(),
            acc.relay_calls,
            acc.redemptions.len()
        ),
    );
    f.note(format!(
        "join search: {} distinct values, {} relay calls, {:.1} s",
        acc.values.map.len(),
        acc.relay_calls,
        t.elapsed().as_secs_f64()
    ));
}

pub fn train(
    o: &Outcome,
    seed: u64,
) -> (
    Attackers,
    Vec<stats::InvoiceFacts>,
    Vec<stats::ClusterFacts>,
) {
    let acc = o.rec.acc.as_ref().expect("an analyzed world");
    let inv = stats::invoice_facts(acc, &o.truth);
    let clu = stats::cluster_facts(acc, o.truth.clients.len());
    (stats::train(&inv, &clu, seed), inv, clu)
}

/// S1–S4 on `W_test` with attackers trained on `W_train`.
pub fn statistics(f: &mut Findings, a: &Attackers, test: &Outcome, seed: u64) -> f64 {
    let acc = test.rec.acc.as_ref().unwrap();
    let inv = stats::invoice_facts(acc, &test.truth);
    let clu = stats::cluster_facts(acc, test.truth.clients.len());
    let s1 = stats::s1(&inv, &clu, a);
    // The two assignments are one family: each is tested at α/2.
    f.check(
        "S1",
        s1.p >= ALPHA / 2.0 && s1.h_p >= ALPHA / 2.0,
        format!(
            "n={} argmax full {:.3} declared {:.3} lift {:+.3} (n10={}, n01={}, p={:.2e}); Hungarian full {:.3} declared {:.3} (p={:.2e}); {:.0} candidates per invoice",
            s1.n,
            s1.acc_full,
            s1.acc_declared,
            s1.acc_full - s1.acc_declared,
            s1.n10,
            s1.n01,
            s1.p,
            s1.h_acc_full,
            s1.h_acc_declared,
            s1.h_p,
            s1.mean_candidates
        ),
    );
    let s2 = stats::s2(&inv, &clu, seed);
    f.check(
        "S2",
        s2.exceeded > 0,
        format!(
            "n={} max-T {:.2} ({}), permuted maxima at or above it {} of {} (p={:.3})",
            s2.n,
            s2.t_max,
            s2.strongest,
            s2.exceeded,
            stats::B,
            s2.p
        ),
    );
    let s3 = stats::s3(acc, &inv, &clu, seed ^ 0x53);
    let ok = |p: &stats::Presence| !(p.observed > p.max_permuted && p.p <= ALPHA);
    f.check(
        "S3a",
        ok(&s3.a),
        format!(
            "co-presence at automatic issuer calls: n={} true {:.4} max permuted {:.4} p={:.3}",
            s3.a.n, s3.a.observed, s3.a.max_permuted, s3.a.p
        ),
    );
    f.check(
        "S3b",
        ok(&s3.b),
        format!(
            "session start/end within [-120 s, +30 s]: n={} true {:.4} max permuted {:.4} p={:.3}",
            s3.b.n, s3.b.observed, s3.b.max_permuted, s3.b.p
        ),
    );
    f.note(format!(
        "S3c (reported, declared L5): quiet-gap rate true {:.3} other {:.3}: {:.2} bits per call, {:.2} bits per invoice",
        s3.gap_true, s3.gap_other, s3.bits_per_call, s3.bits_per_invoice
    ));
    f.check(
        "S3d",
        ok(&s3.d),
        format!(
            "payment co-presence (screen payments): n={} true {:.4} max permuted {:.4} p={:.3}",
            s3.d.n, s3.d.observed, s3.d.max_permuted, s3.d.p
        ),
    );
    let (acc4, n4) = stats::s4(&inv, &clu, a);
    f.check("S4", acc4 <= S4_BOUND, format!("declared-leak top-1 accuracy {acc4:.3} over {n4} XMR packs of non-genesis clients (bound {S4_BOUND})"));
    acc4
}

// -------------------------------------------------------------------------------------------------
// Twin worlds.
// -------------------------------------------------------------------------------------------------

fn first_diff(a: &[(u64, [u8; 8])], b: &[(u64, [u8; 8])], horizon: u64) -> Option<(usize, u64)> {
    let fa: Vec<_> = a.iter().filter(|e| e.0 < horizon).collect();
    let fb: Vec<_> = b.iter().filter(|e| e.0 < horizon).collect();
    for k in 0..fa.len().max(fb.len()) {
        match (fa.get(k), fb.get(k)) {
            (Some(x), Some(y)) if x == y => {}
            (x, y) => return Some((k, x.or(y).map_or(0, |e| e.0))),
        }
    }
    None
}

/// A world's client-internal notes, per client (`GHOST_T2_DEBUG=1`).
type Notes = [Vec<(u64, String)>];

/// The first differing call of any client, with its readable lines when the worlds kept them
/// (`GHOST_T2_DEBUG=1`) and the client's runs and process starts around it in both worlds.
fn per_client_diff_text(
    a: &[Vec<(u64, [u8; 8])>],
    b: &[Vec<(u64, [u8; 8])>],
    horizons: &HashMap<usize, u64>,
    ta: &[Vec<String>],
    tb: &[Vec<String>],
    truths: (&Truth, &Truth),
    notes: (&Notes, &Notes),
) -> Option<String> {
    let n = a.len().max(b.len());
    let empty = Vec::new();
    let empty_t = Vec::new();
    // The earliest difference of any client.
    let mut first: Option<(u64, usize, usize, u64)> = None;
    for c in 0..n {
        let h = horizons.get(&c).copied().unwrap_or(u64::MAX);
        if let Some((k, t)) = first_diff(a.get(c).unwrap_or(&empty), b.get(c).unwrap_or(&empty), h)
        {
            if first.is_none_or(|f| t < f.0) {
                first = Some((t, c, k, h));
            }
        }
    }
    let (t, c, k, h) = first?;
    let line = |v: &[Vec<String>]| -> String {
        let lines = v.get(c).unwrap_or(&empty_t);
        (k.saturating_sub(4)..(k + 4).min(lines.len()))
            .map(|i| format!("\n    {}", &lines[i][..lines[i].len().min(400)]))
            .collect()
    };
    let horizon = if h == u64::MAX {
        String::new()
    } else {
        format!(" (horizon {h})")
    };
    let (lo, hi) = (t.saturating_sub(4 * 3_600), t + 3_600);
    let around = |tr: &Truth, world: &str| -> String {
        let Some(cl) = tr.clients.get(c) else {
            return String::new();
        };
        let runs: Vec<String> = cl
            .runs
            .iter()
            .filter(|r| (lo..=hi).contains(&r.start))
            .map(|r| {
                format!(
                    "{}{}:{}r/{}i",
                    r.start,
                    if r.quiet { "q" } else { "" },
                    r.relay_calls,
                    r.issuer_calls
                )
            })
            .collect();
        let starts: Vec<String> = cl
            .processes
            .iter()
            .filter(|p| (lo..=hi).contains(*p))
            .map(u64::to_string)
            .collect();
        let before: Vec<u64> = cl.processes.iter().copied().filter(|&p| p <= t).collect();
        format!(
            "\n    {world}: runs [{}], process starts [{}], {} processes started before, the last at {:?}",
            runs.join(" "),
            starts.join(" "),
            before.len(),
            before.last()
        )
    };
    // The client's internal events of the three days before (GHOST_T2_DEBUG=1), at most 30.
    let noted = |v: &[Vec<(u64, String)>], world: &str| -> String {
        let Some(n) = v.get(c) else {
            return String::new();
        };
        let lines: Vec<String> = n
            .iter()
            .filter(|(x, _)| *x + 3 * 86_400 >= t && *x <= hi)
            .map(|(x, s)| format!("\n      {world} {x}: {s}"))
            .collect();
        lines[lines.len().saturating_sub(30)..].concat()
    };
    Some(format!(
        "client {c}: call {k} at {t}{horizon}{}{}{}{}{}{}",
        line(ta),
        line(tb),
        around(truths.0, "A"),
        around(truths.1, "B"),
        noted(notes.0, "A"),
        noted(notes.1, "B")
    ))
}

/// The offset of a device clock at true time `t`, from the client's skew intervals.
fn offset_at(skew: &[(u64, u64, i64)], t: u64) -> i64 {
    skew.iter().find(|s| s.0 <= t && t < s.1).map_or(0, |s| s.2)
}

/// The first true time at which the device clock shows `w` or later: a linear piece reaching `w`
/// or a jump of the clock, whichever comes first.
fn true_at_wall(skew: &[(u64, u64, i64)], w: u64) -> u64 {
    let shows = |t: u64| t as i64 + offset_at(skew, t) >= w as i64;
    let mut candidates = vec![w];
    for &(from, until, offset) in skew {
        candidates.extend([from, until, (w as i64 - offset).max(0) as u64]);
    }
    candidates
        .into_iter()
        .filter(|&t| shows(t))
        .min()
        .unwrap_or(w)
}

/// NI-1 (same cell): every relay view and relay database snapshot byte-identical.
pub fn ni1(f: &mut Findings, a: &Outcome, b: &Outcome) {
    let da = &a.rec.digests;
    let db = &b.rec.digests;
    let same_views =
        (0..3).all(|k| da.relay[k].clone().finalize() == db.relay[k].clone().finalize());
    let same_db = da.relay_db_weeks == db.relay_db_weeks;
    let detail = if same_views && same_db {
        format!(
            "3 relay views ({} calls) and {} relay database snapshots identical",
            da.relay_calls.iter().sum::<u64>(),
            da.relay_db_weeks.len()
        )
    } else {
        let where_ = per_client_diff_text(
            &da.relay_by_client,
            &db.relay_by_client,
            &HashMap::new(),
            &da.relay_text_by_client,
            &db.relay_text_by_client,
            (&a.truth, &b.truth),
            (&da.notes_by_client, &db.notes_by_client),
        )
        .unwrap_or_else(|| "databases only".into());
        format!(
            "relay views differ ({where_}); databases {}",
            if same_db { "identical" } else { "differ" }
        )
    };
    f.check("NI-1", same_views && same_db, detail);
}

/// The earlier activation-slot cell of each flow whose finalization differs between the worlds
/// (NI-1 across cells), per client: the moved flows, and the flows whose quiet run a moved flow's
/// extra attempt took (one issuer call per quiet run, §19.14), whose signing the issuer's answer
/// moved just as well. A cell is the first UTC-day boundary at or after `t_f + 4 h` in either world.
/// The pack rule runs on the device clock (§12.3 takes the finalization's device time), so the cell
/// starts when the client's device clock reaches that boundary: earlier than on true time for a
/// clock running ahead. Revocations count too: their spares activate at once (R4). Also returns,
/// per client, its differing flows (for the report).
fn cell_horizons(a: &Outcome, b: &Outcome) -> (HashMap<usize, u64>, HashMap<usize, String>) {
    let fin = |o: &Outcome| -> HashMap<(u32, u64), Option<u64>> {
        o.truth
            .invoices
            .iter()
            .map(|i| ((i.client, i.instance), i.finalized))
            .collect()
    };
    let (fa, fb) = (fin(a), fin(b));
    let keys: std::collections::BTreeSet<(u32, u64)> =
        fa.keys().chain(fb.keys()).copied().collect();
    let mut h: HashMap<usize, u64> = HashMap::new();
    let mut notes: HashMap<usize, String> = HashMap::new();
    for key in keys {
        let (x, y) = (
            fa.get(&key).copied().flatten(),
            fb.get(&key).copied().flatten(),
        );
        if x == y {
            continue;
        }
        let skew = a
            .truth
            .clients
            .get(key.0 as usize)
            .map_or(&[][..], |cl| &cl.skew[..]);
        let cell = |t: Option<u64>| {
            t.map_or(u64::MAX, |t| {
                let w = (t as i64 + offset_at(skew, t)).max(0) as u64;
                true_at_wall(skew, (w + 4 * 3_600).div_ceil(86_400) * 86_400)
            })
        };
        let d = cell(x).min(cell(y));
        let e = h.entry(key.0 as usize).or_insert(u64::MAX);
        *e = (*e).min(d);
        let _ = write!(
            notes.entry(key.0 as usize).or_default(),
            " flow {} finalized A {x:?} B {y:?} (cell {d});",
            key.1
        );
    }
    // A revocation's spare tokens are trial tokens, eligible at once (STANDARD) or at a slot (HIGH,
    // R4): a revocation whose quiet run a moved flow's consequences took (a refresh of a credit the
    // moved pack funded, an extra attempt) moves them, and its eligible moment starts the client's
    // cell as a pack's activation does.
    let rev = |o: &Outcome| -> HashMap<(u32, u64), (u64, i64)> {
        o.log
            .revocations
            .iter()
            .map(|&(c, i, t, e)| ((c, i), (t, e)))
            .collect()
    };
    let (ra, rb) = (rev(a), rev(b));
    let rkeys: std::collections::BTreeSet<(u32, u64)> =
        ra.keys().chain(rb.keys()).copied().collect();
    for key in rkeys {
        let (x, y) = (ra.get(&key).copied(), rb.get(&key).copied());
        if x == y {
            continue;
        }
        let skew = a
            .truth
            .clients
            .get(key.0 as usize)
            .map_or(&[][..], |cl| &cl.skew[..]);
        let at = |r: Option<(u64, i64)>| {
            r.map_or(u64::MAX, |(_, e)| true_at_wall(skew, e.max(0) as u64))
        };
        let d = at(x).min(at(y));
        let e = h.entry(key.0 as usize).or_insert(u64::MAX);
        *e = (*e).min(d);
        let _ = write!(
            notes.entry(key.0 as usize).or_default(),
            " revocation {} answered A {:?} B {:?} (spares from {d});",
            key.1,
            x.map(|r| r.0),
            y.map(|r| r.0)
        );
    }
    // An invite exists only from its pack's activation slot, and an invitee takes one of those
    // available when it onboards: moved slots change which invite an invitee holds and when an
    // inviter starts listening on a drop, for inviters whose own flows did not move. From the
    // first hand-over that differs, the invitee and the inviters involved are compared before it.
    let takes = |o: &Outcome| -> BTreeMap<u32, Vec<(u32, u64, u64)>> {
        let mut m: BTreeMap<u32, Vec<(u32, u64, u64)>> = BTreeMap::new();
        for &(inviter, src, invitee, t) in &o.log.takes {
            m.entry(invitee).or_default().push((inviter, src, t));
        }
        m
    };
    let (ta, tb) = (takes(a), takes(b));
    let invitees: std::collections::BTreeSet<u32> = ta.keys().chain(tb.keys()).copied().collect();
    let none = Vec::new();
    for invitee in invitees {
        let (la, lb) = (
            ta.get(&invitee).unwrap_or(&none),
            tb.get(&invitee).unwrap_or(&none),
        );
        let Some(j) = (0..la.len().max(lb.len())).find(|&j| la.get(j) != lb.get(j)) else {
            continue;
        };
        for &(inviter, src, t) in la.iter().skip(j).chain(lb.iter().skip(j)) {
            for who in [invitee, inviter] {
                let e = h.entry(who as usize).or_insert(u64::MAX);
                *e = (*e).min(t);
            }
            let _ = write!(
                notes.entry(inviter as usize).or_default(),
                " invite of pack {src:x} handed to {invitee} at {t} in one world only;"
            );
        }
    }
    // A drop namespace is shared by an inviter and its invitee: each one's relay answers there
    // reflect the other's calls (the invitee's write, made when its tokens allow, is in the
    // inviter's list), so an invite pair shares the earlier of its horizons, to a fixpoint.
    let pairs: Vec<(usize, usize)> = a
        .log
        .takes
        .iter()
        .chain(b.log.takes.iter())
        .map(|&(i, _, c, _)| (i as usize, c as usize))
        .collect();
    loop {
        let mut changed = false;
        for &(x, y) in &pairs {
            let m = h
                .get(&x)
                .copied()
                .unwrap_or(u64::MAX)
                .min(h.get(&y).copied().unwrap_or(u64::MAX));
            if m == u64::MAX {
                continue;
            }
            for z in [x, y] {
                let e = h.entry(z).or_insert(u64::MAX);
                if m < *e {
                    *e = m;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    (h, notes)
}

pub fn ni1_cells(f: &mut Findings, a: &Outcome, b: &Outcome, moved: &HashSet<(u32, u64)>) {
    let (h, notes) = cell_horizons(a, b);
    let (da, db) = (&a.rec.digests, &b.rec.digests);
    let d = per_client_diff_text(
        &da.relay_by_client,
        &db.relay_by_client,
        &h,
        &da.relay_text_by_client,
        &db.relay_text_by_client,
        (&a.truth, &b.truth),
        (&da.notes_by_client, &db.notes_by_client),
    );
    let differing: usize = notes.values().map(|n| n.matches("finalized").count()).sum();
    f.check(
        "NI-1 across cells",
        d.is_none(),
        match d {
            None => format!(
                "{} flows moved ({differing} finalized differently, the others displaced by their extra attempts); every client's relay calls identical before the earlier activation cell",
                moved.len()
            ),
            Some(w) => {
                let c: Option<usize> = w
                    .strip_prefix("client ")
                    .and_then(|s| s.split(':').next())
                    .and_then(|s| s.parse().ok());
                let flows = c.and_then(|c| notes.get(&c)).map_or("", String::as_str);
                format!("relay calls differ before the activation cell: {w}\n    flows of the client finalized differently:{flows}")
            }
        },
    );
}

pub fn ni2(f: &mut Findings, a: &Outcome, b: &Outcome) {
    let (da, db) = (&a.rec.digests, &b.rec.digests);
    let same = da.issuer_masked.clone().finalize() == db.issuer_masked.clone().finalize()
        && da.wallet.clone().finalize() == db.wallet.clone().finalize();
    let detail = if same {
        format!("issuer view ({} calls) identical modulo blinded and signature bytes; wallet view identical", da.issuer_calls)
    } else {
        per_client_diff_text(
            &da.issuer_masked_by_client,
            &db.issuer_masked_by_client,
            &HashMap::new(),
            &da.issuer_text_by_client,
            &db.issuer_text_by_client,
            (&a.truth, &b.truth),
            (&da.notes_by_client, &db.notes_by_client),
        )
        .map_or("wallet view differs".to_string(), |w| {
            format!("issuer view differs: {w}")
        })
    };
    f.check("NI-2", same, detail);
}

pub fn ni3(f: &mut Findings, a: &Outcome, b: &Outcome) {
    let (da, db) = (&a.rec.digests, &b.rec.digests);
    let same = da.issuer.clone().finalize() == db.issuer.clone().finalize()
        && da.wallet.clone().finalize() == db.wallet.clone().finalize();
    let detail = if same {
        format!(
            "issuer view ({} calls) and wallet view identical",
            da.issuer_calls
        )
    } else {
        per_client_diff_text(
            &da.issuer_by_client,
            &db.issuer_by_client,
            &HashMap::new(),
            &da.issuer_text_by_client,
            &db.issuer_text_by_client,
            (&a.truth, &b.truth),
            (&da.notes_by_client, &db.notes_by_client),
        )
        .map_or("wallet view differs".to_string(), |w| {
            format!("issuer view differs: {w}")
        })
    };
    f.check("NI-3", same, detail);
}

pub fn ni1d(f: &mut Findings, a: &Outcome, b: &Outcome) {
    let (da, db) = (&a.rec.digests.drops, &b.rec.digests.drops);
    f.check(
        "NI-1d",
        da == db,
        if da == db {
            format!("{} drop writes identical (time, relay, length)", da.len())
        } else {
            let k = da
                .iter()
                .zip(db.iter())
                .position(|(x, y)| x != y)
                .unwrap_or(da.len().min(db.len()));
            format!(
                "drop writes differ at write {k} ({} and {} writes)",
                da.len(),
                db.len()
            )
        },
    );
}

// -------------------------------------------------------------------------------------------------
// Variants.
// -------------------------------------------------------------------------------------------------

pub fn script_of(o: &Outcome) -> Arc<UserScript> {
    Arc::new(UserScript {
        need_starts: o.log.need_starts.clone(),
        receipts: o.log.receipts.clone(),
        plan_seeds: o
            .truth
            .invoices
            .iter()
            .map(|i| (i.client, i.instance, i.seed))
            .collect(),
    })
}

pub fn ni1_twin(base: &Config, a: &Outcome) -> Config {
    let mut b = base.clone();
    b.name = format!("{}-ni1", base.name);
    b.analyze = false;
    b.per_client = true;
    b.seeds.issuer ^= 0x4E49_2D31;
    b.seeds.chain ^= 0x4E49_2D31;
    b.pool_target = 7;
    b.latency_jitter = true;
    b.chain_jitter = true;
    // One extra UNAVAILABLE per purchase, on a BlindSign attempt its world answered AWAITING.
    let mut per: BTreeMap<(u32, u64), usize> = BTreeMap::new();
    for (c, i, k) in non_final_attempts(&a.log) {
        let e = per.entry((c, i)).or_insert(k);
        *e = (*e).min(k);
    }
    b.fail_sign = Arc::new(per.into_iter().map(|((c, i), k)| (c, i, k)).collect());
    let d = base.scale.window_days;
    b.restores.push((d / 2, d / 2 + 1));
    b
}

pub fn ni1_cells_twin(base: &Config, a: &Outcome) -> (Config, HashSet<(u32, u64)>) {
    let mut b = base.clone();
    b.name = format!("{}-ni1x", base.name);
    b.analyze = false;
    b.per_client = true;
    let mut r = Rng::new(0x4E49_3158, &[b"moved"]);
    // Packs whose invites were handed out move invitees too (an invite exists only once its pack
    // is finalized); the moved flows are packs none of whose invites was given in world A.
    // Moreover an extra attempt takes a quiet run from the client's other due work and so moves
    // its other packs' signing too, and with it when their invites exist: the moved flows are packs
    // of clients none of whose invites was given in world A, so no invitee's choice can change.
    let givers: HashSet<u32> = a.log.given_invites.iter().map(|g| g.0).collect();
    let signed: Vec<(u32, u64, usize)> = a
        .log
        .sign_outcomes
        .iter()
        .filter(|&&(c, _, _, s)| s == 1 && !givers.contains(&c))
        .map(|&(c, i, k, _)| (c, i, k))
        .collect();
    let chosen: HashSet<(u32, u64, usize)> = signed.into_iter().filter(|_| r.chance(0.2)).collect();
    let moved = chosen.iter().map(|&(c, i, _)| (c, i)).collect();
    b.fail_sign = Arc::new(chosen);
    (b, moved)
}

pub fn ni2_twin(base: &Config, a: &Outcome) -> Config {
    let mut b = base.clone();
    b.name = format!("{}-ni2", base.name);
    b.analyze = false;
    b.seeds.token ^= 0x4E49_2D32;
    b.seeds.ns ^= 0x4E49_2D32;
    b.script = Some(script_of(a));
    b
}

pub fn ni3_twin(base: &Config, a: &Outcome) -> Config {
    let mut b = base.clone();
    b.name = format!("{}-ni3", base.name);
    b.analyze = false;
    b.shift_fraction = 0.2;
    b.script = Some(script_of(a));
    b
}

pub fn ni1d_twin(base: &Config) -> Config {
    let mut b = base.clone();
    b.name = format!("{}-ni1d", base.name);
    b.analyze = false;
    b.first_pack_shift = Some((0.34, 2 * 86_400 + 5 * 3_600));
    b
}

/// Runs closures in parallel threads and collects their results in order.
pub fn parallel<T: Send>(jobs: Vec<Box<dyn FnOnce() -> T + Send + '_>>) -> Vec<T> {
    std::thread::scope(|s| {
        let hs: Vec<_> = jobs.into_iter().map(|j| s.spawn(j)).collect();
        hs.into_iter()
            .map(|h| h.join().expect("a T2 world"))
            .collect()
    })
}

pub struct VariantReport {
    pub findings: Findings,
    pub s4: f64,
    pub s4_liar: f64,
}

/// One variant: `scale` for the statistical worlds, `small` for NI-3, NI-1d and the lying
/// issuer's S4 bound.
pub fn variant(
    name: &str,
    scale: Scale,
    small: Scale,
    seeds: (u64, u64),
    mutant: Mutant,
) -> VariantReport {
    let started = std::time::Instant::now();
    let mut f = Findings::default();
    let cache = super::es::global_cache();
    let (cache_train, cache_test, cache_small) = (&cache, &cache, &cache);
    let mut train_cfg = Config::new(&format!("{name}-train"), scale, seeds.0);
    train_cfg.analyze = true;
    train_cfg.mutant = mutant;
    let mut test_cfg = Config::new(&format!("{name}-test"), scale, seeds.1);
    test_cfg.analyze = true;
    test_cfg.per_client = true;
    test_cfg.mutant = mutant;
    test_cfg.export = std::env::var("GHOST_T2_EXPORT")
        .ok()
        .map(|d| std::path::PathBuf::from(d).join(name));
    let mut small_cfg = Config::new(&format!("{name}-small"), small, seeds.1 ^ 0x5341);
    small_cfg.mutant = mutant;
    small_cfg.per_client = true;
    let mut liar_train = Config::new(&format!("{name}-liar-train"), small, seeds.0 ^ 0x4C49);
    liar_train.liar = 4;
    liar_train.analyze = true;
    liar_train.mutant = mutant;
    let mut liar_test = Config::new(&format!("{name}-liar-test"), small, seeds.1 ^ 0x4C49);
    liar_test.liar = 4;
    liar_test.analyze = true;
    liar_test.mutant = mutant;
    let ni1d_b = ni1d_twin(&small_cfg);
    let (cl, ct, cs) = (&cache_train, &cache_test, &cache_small);
    let first: Vec<Outcome> = parallel(vec![
        Box::new(|| World::new(train_cfg.clone(), cl).run()),
        Box::new(|| World::new(test_cfg.clone(), ct).run()),
        Box::new(|| World::new(small_cfg.clone(), cs).run()),
        Box::new(|| World::new(ni1d_b.clone(), cs).run()),
        Box::new(|| World::new(liar_train.clone(), cs).run()),
        Box::new(|| World::new(liar_test.clone(), cs).run()),
    ]);
    let mut first = first.into_iter();
    let (w_train, w_test, small_a, small_d, lie_train, lie_test) = (
        first.next().unwrap(),
        first.next().unwrap(),
        first.next().unwrap(),
        first.next().unwrap(),
        first.next().unwrap(),
        first.next().unwrap(),
    );
    let ni1_b = ni1_twin(&test_cfg, &w_test);
    let (ni1x_b, moved) = ni1_cells_twin(&test_cfg, &w_test);
    let ni2_b = ni2_twin(&test_cfg, &w_test);
    let ni3_b = ni3_twin(&small_cfg, &small_a);
    let second: Vec<Outcome> = parallel(vec![
        Box::new(|| World::new(ni1_b.clone(), ct).run()),
        Box::new(|| World::new(ni1x_b.clone(), ct).run()),
        Box::new(|| World::new(ni2_b.clone(), ct).run()),
        Box::new(|| World::new(ni3_b.clone(), cs).run()),
    ]);
    let mut second = second.into_iter();
    let (w_ni1, w_ni1x, w_ni2, w_ni3) = (
        second.next().unwrap(),
        second.next().unwrap(),
        second.next().unwrap(),
        second.next().unwrap(),
    );
    f.note(format!(
        "T2 variant {name}: N = {} packs, {} days, seeds {:#x}/{:#x}, mutant {:?}",
        scale.packs, scale.window_days, seeds.0, seeds.1, mutant
    ));
    for o in [&w_train, &w_test] {
        let c = &o.log.counts;
        let g = |k: &str| c.get(k).copied().unwrap_or(0);
        f.note(format!(
            "world {}: {:.0} s; window packs signed {} (invoices {}, renewals started {}, resumes {}, credits packs {}, claims {}), trials {}, warm-up packs {}, need-triggered starts {}, drops {}, credits refreshed {}, issuer calls {}, relay calls {}",
            o.name,
            o.seconds,
            g("window packs signed"),
            g("window invoices"),
            g("window renewals started"),
            g("resumes started"),
            g("credits packs started"),
            g("claims answered"),
            g("trials"),
            g("warm-up packs signed"),
            o.log.need_starts.len(),
            g("drops written"),
            g("credits refreshed"),
            o.rec.digests.issuer_calls,
            o.rec.digests.relay_calls.iter().sum::<u64>()
        ));
    }
    joins(&mut f, &w_test);
    let (attackers, _, _) = train(&w_train, seeds.0);
    let s4 = statistics(&mut f, &attackers, &w_test, seeds.1);
    ni1(&mut f, &w_test, &w_ni1);
    ni1_cells(&mut f, &w_test, &w_ni1x, &moved);
    ni2(&mut f, &w_test, &w_ni2);
    ni3(&mut f, &small_a, &w_ni3);
    ni1d(&mut f, &small_a, &small_d);
    let (liar_attackers, _, _) = train(&lie_train, seeds.0 ^ 0x4C49);
    let acc = lie_test.rec.acc.as_ref().unwrap();
    let inv = stats::invoice_facts(acc, &lie_test.truth);
    let clu = stats::cluster_facts(acc, lie_test.truth.clients.len());
    let (s4_liar, n) = stats::s4(&inv, &clu, &liar_attackers);
    f.check("S4 lying issuer", s4_liar <= S4_BOUND, format!("declared-leak top-1 accuracy {s4_liar:.3} over {n} XMR packs when the issuer lies AWAITING_CONFIRMATIONS until the last attempt (bound {S4_BOUND})"));
    let j9 = checks::j9(acc, &lie_test.truth, due);
    f.check("J9 lying issuer", j9.is_empty(), hits_line(&j9));
    f.note(format!(
        "signature cache: test family {} hits / {} signed",
        cache_test.hits.load(std::sync::atomic::Ordering::Relaxed),
        cache_test.misses.load(std::sync::atomic::Ordering::Relaxed)
    ));
    f.note(format!(
        "variant {name} took {:.0} s",
        started.elapsed().as_secs_f64()
    ));
    VariantReport {
        findings: f,
        s4,
        s4_liar,
    }
}

/// The scales of a variant: `GHOST_T2_SCALE=gate` for the exit gate, the PR variant otherwise.
pub fn scales() -> (&'static str, Scale, Scale) {
    match std::env::var("GHOST_T2_SCALE").as_deref() {
        Ok("gate") => ("gate", population::GATE, population::PR),
        _ => ("pr", population::PR, population::SMALL),
    }
}
