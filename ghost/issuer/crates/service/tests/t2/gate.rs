//! The T2 gate (Phase 8 design §1.3, §13.4, §19.16): the worlds of one variant, the twin-world
//! comparisons, the join search and the statistical tests, and the report.
//!
//! **Worlds.** `W_train` (the attacker learns the policy from it: the code is open source) and
//! `W_test` (= NI world A) at the variant's scale; from `W_test`'s record the twins NI-1 (same
//! cell: other issuer randomness, pool minors, latencies up to 30 s, chain timing, one extra
//! `UNAVAILABLE` on a non-final `BlindSign` per purchase, an extra issuer restore), NI-1 across
//! cells (an extra `UNAVAILABLE` on the signing `BlindSign` of a fifth of the purchases, compared
//! per client before the earlier activation-slot cell) and NI-2 (other token-level randomness and
//! namespaces, the declared user actions replayed, the relays holding every drop blob of a received
//! credit back from its reader by hours to days, across the invite's first refresh time where they
//! can, §19.26); at the small scale NI-3 (relays shift a fifth of the clients' clock and hold the
//! drop blobs back as NI-2's do) and NI-1d (every invitee buys its first pack two days later);
//! and a lying issuer (every invoice answered `AWAITING_CONFIRMATIONS` until the client's last
//! attempt) for the second S4 bound.
//!
//! **Seeds.** Pinned (`SEEDS`); a failure on a correct implementation is investigated, never
//! re-seeded (Phase 7 policy).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;

use ghost_entitlement::grid::week_start;
use ghost_t2_join::checks;
use ghost_t2_join::model::Truth;
use ghost_t2_join::stats::{self, Attackers};
use ghost_t2_join::transforms;
use ghost_t2_join::values;
use sha2::Digest;

use super::config::{Config, Mutant, UserScript};
use super::population::{self, Scale};
use super::rng::Rng;
use super::world::{non_final_attempts, Outcome, Receipt, World};

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

/// The smallest samples a statistical check may pass on (a check with no data tests nothing).
pub const FLOOR_S12: usize = 100;
pub const FLOOR_S3: usize = 100;
pub const FLOOR_S3D: usize = 50;
pub const FLOOR_S4: usize = 50;
/// The fewest moved flows the twins NI-1 (inside the cell) and NI-1 across cells may pass on.
pub const FLOOR_MOVED: usize = 10;
/// The fewest drop writes NI-1d may pass on.
pub const FLOOR_DROPS: usize = 3;
/// The achieved population must be within this share of the design's (§13.4 "World").
pub const POPULATION_TOLERANCE: f64 = 0.3;

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
            "{} ({} WRONG_PERIOD redemptions of devices more than 24 h off, which the clipped relay-facing clock corrects only to within a day, §19.23 point 2: reported; identical retries refused a period, counted: {})",
            hits_line(&j8),
            checks::j8_far_skew(acc),
            checks::j8_late_retries(acc)
        ),
    );
    let j9 = checks::j9(acc, truth, due);
    let q = checks::j9_quiet(acc, truth, due);
    f.check(
        "J9",
        j9.is_empty(),
        format!(
            "{} (quiet runs independent of due work: {} of {} automatic BlindSign calls served by the first job run at or after their due minute, q = 1/8, p = {:.2})",
            hits_line(&j9),
            q.first,
            q.n,
            q.p
        ),
    );
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
    // Completeness (§13.4): every request a handler received is in a view, counted independently
    // of the recorder (the issuer links count at each handler's entry, the relays write one
    // capture event per call), and every ground-truth nullifier is in some relay view.
    let presented = truth.presented.len() as u64;
    let missing = checks::nullifiers_missing(acc, truth);
    f.check(
        "completeness",
        acc.issuer.len() as u64 == test.log.issuer_received
            && acc.relay_calls == test.log.capture_lines
            && acc.redemptions.len() as u64 == presented
            && missing == 0
            && test.log.issuer_received > 0,
        format!(
            "issuer view {} of {} requests received (counted at the handlers' entry), relay views {} of {} capture events, redemptions {} of {} tokens presented, {missing} ground-truth nullifiers in no relay view",
            acc.issuer.len(),
            test.log.issuer_received,
            acc.relay_calls,
            test.log.capture_lines,
            acc.redemptions.len(),
            presented
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
    // α = 0.001 per test (§13.4): each assignment is a test.
    f.check(
        "S1",
        s1.p >= ALPHA && s1.h_p >= ALPHA && s1.n >= FLOOR_S12,
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
        s2.exceeded > 0 && s2.n >= FLOOR_S12,
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
    let ok = |p: &stats::Presence, floor: usize| {
        !(p.observed > p.max_permuted && p.p <= ALPHA) && p.n >= floor
    };
    f.check(
        "S3a",
        ok(&s3.a, FLOOR_S3),
        format!(
            "co-presence at automatic issuer calls: n={} true {:.4} max permuted {:.4} p={:.3}",
            s3.a.n, s3.a.observed, s3.a.max_permuted, s3.a.p
        ),
    );
    f.check(
        "S3b",
        ok(&s3.b, FLOOR_S3),
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
        ok(&s3.d, FLOOR_S3D),
        format!(
            "payment co-presence (screen payments): n={} true {:.4} max permuted {:.4} p={:.3}",
            s3.d.n, s3.d.observed, s3.d.max_permuted, s3.d.p
        ),
    );
    let (acc4, n4) = stats::s4(&inv, &clu, a);
    f.check("S4", acc4 <= S4_BOUND && n4 >= FLOOR_S4, format!("declared-leak top-1 accuracy {acc4:.3} over {n4} XMR packs of non-genesis clients (bound {S4_BOUND})"));
    acc4
}

/// The achieved population of a scored world against the design's (§13.4 "World", §19.16): the
/// window's signed packs within ±30 % of N and the need-triggered extra packs about 5 % of N; the
/// rest is reported.
pub fn population_check(f: &mut Findings, o: &Outcome, scale: Scale) {
    let g = |k: &str| o.log.counts.get(k).copied().unwrap_or(0);
    let n = scale.packs as f64;
    let packs = g("window packs signed") as f64;
    let need = o.log.need_starts.len() as f64;
    let want_need = population::NEED_SHARE * n;
    let ok = (packs - n).abs() <= POPULATION_TOLERANCE * n
        && (need - want_need).abs() <= (0.6 * want_need).max(3.0);
    f.check(
        "population",
        ok,
        format!(
            "window packs signed {packs} (N = {n}, ±{:.0} %), need-triggered starts {need} ({:.0} % of N: {want_need:.0}), renewals started {}, invitee first packs {}, resumes {}, trials {}, credits packs {}, claims {}",
            POPULATION_TOLERANCE * 100.0,
            population::NEED_SHARE * 100.0,
            g("window renewals started"),
            o.log.first_packs.len(),
            g("resumes started"),
            g("trials"),
            g("credits packs started"),
            g("claims answered")
        ),
    );
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

/// NI-1 (same cell): every relay view and relay database snapshot byte-identical. The twin moves
/// packs' finalization times inside their activation-slot cells (signing answers up to 30 s later,
/// across minute boundaries), which a correct client cannot show a relay; a finalization pushed
/// across a cell boundary (within 30 s of one) is an L1 change, so that client is compared before
/// the earlier cell and the database snapshots before the earliest one.
pub fn ni1(f: &mut Findings, a: &Outcome, b: &Outcome) {
    let da = &a.rec.digests;
    let db = &b.rec.digests;
    let (h, _, in_cell) = cell_horizons(a, b, true);
    let same_views =
        (0..3).all(|k| da.relay[k].clone().finalize() == db.relay[k].clone().finalize());
    let first_cross = h.values().min().copied();
    let same_db = match first_cross {
        None => da.relay_db_weeks == db.relay_db_weeks,
        Some(m) => da
            .relay_db_weeks
            .iter()
            .filter(|((w, _), _)| week_start(*w) < m)
            .all(|(k, v)| db.relay_db_weeks.get(k) == Some(v)),
    };
    let diff = if same_views {
        None
    } else {
        Some(
            per_client_diff_text(
                &da.relay_by_client,
                &db.relay_by_client,
                &h,
                &da.relay_text_by_client,
                &db.relay_text_by_client,
                (&a.truth, &b.truth),
                (&da.notes_by_client, &db.notes_by_client),
            )
            .unwrap_or_default(),
        )
    };
    let views_ok = diff.as_ref().is_none_or(|d| d.is_empty());
    let ok = views_ok && same_db && in_cell >= FLOOR_MOVED;
    let detail = if views_ok && same_db {
        format!(
            "3 relay views ({} calls) and {} relay database snapshots identical; {in_cell} finalizations moved inside their activation-slot cell, {} clients with one pushed across a cell boundary compared before it",
            da.relay_calls.iter().sum::<u64>(),
            da.relay_db_weeks.len(),
            h.len()
        )
    } else {
        format!(
            "relay views differ ({}); databases {}; {in_cell} finalizations moved inside their cell",
            diff.filter(|d| !d.is_empty())
                .unwrap_or_else(|| "none before a cell boundary".into()),
            if same_db { "identical" } else { "differ" }
        )
    };
    f.check("NI-1", ok, detail);
}

/// The earlier activation-slot cell of each flow whose finalization differs between the worlds
/// (NI-1 across cells), per client: the moved flows, and the flows whose quiet run a moved flow's
/// extra attempt took (one issuer call per quiet run, §19.14), whose signing the issuer's answer
/// moved just as well. A cell is the first UTC-day boundary at or after `t_f + 4 h` in either world.
/// The pack rule runs on the device clock (§12.3 takes the finalization's device time), so the cell
/// starts when the client's device clock reaches that boundary: earlier than on true time for a
/// clock running ahead. Revocations count too: their spares activate at their slot (R4). A client whose
/// process started at other times in the two worlds (a crash after an extra `BlindSign` attempt
/// that only one world made, the 5 % fault: the new process draws a fresh quiet pattern) is
/// compared before the first differing start. Also returns, per client, its differing flows (for
/// the report), and the number of flows finalized at other times inside the same cell.
///
/// `exact` (NI-1, same cell): a flow finalized at another time inside its cell sets no horizon (a
/// correct client shows the relays nothing of it), and only the consequences of flows pushed across
/// a cell boundary do (the invites of such a pack, the revocations of such a client); process
/// starts must not differ at all.
fn cell_horizons(
    a: &Outcome,
    b: &Outcome,
    exact: bool,
) -> (HashMap<usize, u64>, HashMap<usize, String>, usize) {
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
    let mut in_cell = 0usize;
    let mut crossed: HashSet<(u32, u64)> = HashSet::new();
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
        if exact && cell(x) == cell(y) {
            in_cell += 1;
            continue;
        }
        crossed.insert(key);
        let d = cell(x).min(cell(y));
        let e = h.entry(key.0 as usize).or_insert(u64::MAX);
        *e = (*e).min(d);
        let _ = write!(
            notes.entry(key.0 as usize).or_default(),
            " flow {} finalized A {x:?} B {y:?} (cell {d});",
            key.1
        );
    }
    // A revocation's spare tokens become eligible at an activation slot by the pack rule (R4,
    // §19.24 point 13, §19.26): a revocation whose quiet run a moved flow's consequences took (a
    // refresh of a credit the moved pack funded, an extra attempt) moves them, and its eligible
    // moment starts the client's cell as a pack's activation does.
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
    let crossed_clients: HashSet<u32> = crossed.iter().map(|k| k.0).collect();
    for key in rkeys {
        let (x, y) = (ra.get(&key).copied(), rb.get(&key).copied());
        if x == y || (exact && !crossed_clients.contains(&key.0)) {
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
            if exact && !crossed.contains(&(inviter, src)) {
                continue;
            }
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
    // Process starts: a crash after an extra attempt of one world restarts the process there.
    if !exact {
        for (c, (pa, pb)) in a
            .truth
            .clients
            .iter()
            .zip(b.truth.clients.iter())
            .map(|(x, y)| (&x.processes, &y.processes))
            .enumerate()
        {
            if let Some(j) = (0..pa.len().max(pb.len())).find(|&j| pa.get(j) != pb.get(j)) {
                let t = pa
                    .get(j)
                    .copied()
                    .unwrap_or(u64::MAX)
                    .min(pb.get(j).copied().unwrap_or(u64::MAX));
                let e = h.entry(c).or_insert(u64::MAX);
                *e = (*e).min(t);
                let _ = write!(
                    notes.entry(c).or_default(),
                    " a process started at {t} in one world only;"
                );
            }
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
    (h, notes, in_cell)
}

pub fn ni1_cells(f: &mut Findings, a: &Outcome, b: &Outcome, moved: &HashSet<(u32, u64)>) {
    let (h, notes, _) = cell_horizons(a, b, false);
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
        d.is_none() && moved.len() >= FLOOR_MOVED,
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

/// What two worlds' drop reads of received credits show (§19.26, Q31; review T2GAPS-1, T2GAPS-2).
#[derive(Default)]
struct Reads {
    /// Per inviter with a credit refreshed at the other pre-drawn time (the declared bit of E17:
    /// read at or before the invite's first refresh time in one world, after it in the other), the
    /// true time of the earlier due time: that inviter's issuer calls are compared before it.
    horizons: HashMap<usize, u64>,
    /// Credits read in both worlds, those read at another time, those moved by an hour or more,
    /// and those whose read crossed the first refresh time and so took the other time.
    both: usize,
    moved: usize,
    far: usize,
    crossed: usize,
    /// Credits whose due times differ other than by the declared bit (a refresh time the read
    /// set, other pre-drawn times, a read across the cut): the first, readable.
    unexplained: Vec<String>,
}

/// The fewest drop reads a twin (NI-2, NI-3) must move by an hour or more: a twin whose reads
/// stay put tests nothing of Q31 (review T2GAPS-2).
pub const FLOOR_READS_MOVED: usize = 1;

/// Whether two reads of one credit differ only by the declared bit: the same invite's two refresh
/// times and cut in both worlds, one read at or before the first time and due then (or at the cut),
/// the other after it and due at the second time (or at the cut).
fn declared_bit(x: &Receipt, y: &Receipt) -> bool {
    if (x.first, x.second, x.cut) != (y.first, y.second, y.cut) {
        return false;
    }
    let (early, late) = match (x.w <= x.first, y.w <= y.first) {
        (true, false) => (x, y),
        (false, true) => (y, x),
        _ => return false,
    };
    early.due == Some(early.first.min(early.cut)) && late.due == Some(late.second.min(late.cut))
}

/// The drop reads of received credits in two worlds (§19.26, Q31): every twin reads each credit at
/// its own times (relay activity; the NI-2 and NI-3 twins hold drop blobs back by hours to days),
/// and a credit's refresh is due at one of two times its invite drew, the read picking only which
/// (the first if read at or before it, else the second; both cut, and a credit whose due time would
/// precede its read dropped). Due times that differ in any other way are a refresh time the read
/// set, and fail the twin whether or not the refresh falls inside the world. A credit read in one
/// world only gets no exemption: the views decide.
fn refresh_crossings(a: &Outcome, b: &Outcome) -> Reads {
    let by_key = |o: &Outcome| -> BTreeMap<(u32, u32), Receipt> {
        o.log
            .receipts
            .iter()
            .map(|r| ((r.inviter, r.invitee), *r))
            .collect()
    };
    let (ra, rb) = (by_key(a), by_key(b));
    let mut out = Reads::default();
    for (key, x) in &ra {
        let Some(y) = rb.get(key) else { continue };
        out.both += 1;
        if x.t != y.t {
            out.moved += 1;
        }
        if x.t.abs_diff(y.t) >= 3_600 {
            out.far += 1;
        }
        if x.due == y.due {
            continue;
        }
        if !declared_bit(x, y) {
            out.unexplained.push(format!(
                "inviter {} credit of invitee {}: read A {} (due {:?}), B {} (due {:?}), refresh times {} and {}, cut {}",
                key.0, key.1, x.w, x.due, y.w, y.due, x.first, x.second, x.cut
            ));
            continue;
        }
        out.crossed += 1;
        let due = x.due.min(y.due).unwrap_or(0);
        let skew = a
            .truth
            .clients
            .get(key.0 as usize)
            .map_or(&[][..], |cl| &cl.skew[..]);
        let at = true_at_wall(skew, due.max(0) as u64);
        let e = out.horizons.entry(key.0 as usize).or_insert(u64::MAX);
        *e = (*e).min(at);
    }
    out
}

/// NI-2 and NI-3: the issuer view (masked or in full) and the wallet view identical, the drop reads
/// of received credits at each world's own times (moved by the twin's relays, at least
/// [`FLOOR_READS_MOVED`] by an hour or more); an inviter whose credit's refresh came from the other
/// pre-drawn time (a read on the other side of the first) is compared before that refresh, and a
/// due time that differs otherwise fails the twin.
fn issuer_twin(f: &mut Findings, name: &str, a: &Outcome, b: &Outcome, masked: bool) {
    let (da, db) = (&a.rec.digests, &b.rec.digests);
    let (digest_a, digest_b, by_a, by_b) = if masked {
        (
            &da.issuer_masked,
            &db.issuer_masked,
            &da.issuer_masked_by_client,
            &db.issuer_masked_by_client,
        )
    } else {
        (
            &da.issuer,
            &db.issuer,
            &da.issuer_by_client,
            &db.issuer_by_client,
        )
    };
    let r = refresh_crossings(a, b);
    let wallet = da.wallet.clone().finalize() == db.wallet.clone().finalize();
    let exact = digest_a.clone().finalize() == digest_b.clone().finalize();
    let diff = if exact {
        None
    } else {
        per_client_diff_text(
            by_a,
            by_b,
            &r.horizons,
            &da.issuer_text_by_client,
            &db.issuer_text_by_client,
            (&a.truth, &b.truth),
            (&da.notes_by_client, &db.notes_by_client),
        )
    };
    let enough = r.far >= FLOOR_READS_MOVED;
    // Without a crossing the views must be identical as a whole; with one, every client's calls
    // before its horizon (the crossing inviters') and all of the others'.
    let views = exact || (!r.horizons.is_empty() && diff.is_none());
    let ok = wallet && r.unexplained.is_empty() && enough && views;
    let reads = format!(
        "{} received credits read in both worlds, {} of them at another time ({} by an hour or more, {} across their first refresh time)",
        r.both, r.moved, r.far, r.crossed
    );
    let detail = if ok {
        let what = if masked {
            "identical modulo blinded and signature bytes"
        } else {
            "identical"
        };
        format!(
            "issuer view ({} calls) {what}{}; wallet view identical; {reads}, each refreshed at a time its invite drew; {} inviters with a credit read on the other side of its first refresh time, compared before its refresh",
            da.issuer_calls,
            if exact { "" } else { " before the refreshes the reads moved" },
            r.horizons.len()
        )
    } else if let Some(u) = r.unexplained.first() {
        format!(
            "refresh due time follows the read ({} credits): {u}; {reads}",
            r.unexplained.len()
        )
    } else if !wallet {
        format!("wallet view differs; {reads}")
    } else if !views {
        format!(
            "issuer view differs: {}; {reads}",
            diff.unwrap_or_else(|| "in the order of calls".to_string())
        )
    } else {
        format!(
            "{reads}: fewer than {FLOOR_READS_MOVED} reads moved by an hour or more, so the twin tested nothing of Q31"
        )
    };
    f.check(name, ok, detail);
}

pub fn ni2(f: &mut Findings, a: &Outcome, b: &Outcome) {
    issuer_twin(f, "NI-2", a, b, true);
}

pub fn ni3(f: &mut Findings, a: &Outcome, b: &Outcome) {
    issuer_twin(f, "NI-3", a, b, false);
}

/// E30, the redeem-hold length (Q29, design §12.6, §19.26), reported: the background sessions of
/// a world, those the pending write needs at their start armed, those the hold kept open past their
/// lanes with the extra time (what the Tor guard, the local network and a relay with an open
/// circuit see), and the unarmed sessions whose lanes ended before the redeem lane's first step.
pub fn e30(f: &mut Findings, o: &Outcome) {
    let g = |k: &str| o.log.counts.get(k).copied().unwrap_or(0);
    let mut holds: Vec<u64> = o.log.holds.iter().map(|h| h.2 - h.1).collect();
    holds.sort_unstable();
    let q = |p: f64| {
        holds
            .get(((holds.len().max(1) - 1) as f64 * p).round() as usize)
            .copied()
            .unwrap_or(0)
    };
    let empty = o.log.holds.iter().filter(|h| h.3 == 0).count();
    let redeemed: u64 = o.log.holds.iter().map(|h| u64::from(h.3)).sum();
    f.note(format!(
        "E30 (reported, declared residue, Q29 redeem hold): {} background sessions, {} armed by a pending write need, {} held past their lanes (hold median {} s, p90 {} s, max {} s; {empty} held steps redeemed nothing, {redeemed} redemptions in held steps); {} unarmed sessions ended before their lane step; {} stepped while their lane events ran ({} redeem steps in all)",
        g("background sessions"),
        g("background sessions armed"),
        holds.len(),
        q(0.5),
        q(0.9),
        holds.last().copied().unwrap_or(0),
        g("background lane steps missed"),
        g("background sessions stepped while their lanes ran"),
        g("background redeem steps")
    ));
}

pub fn ni1d(f: &mut Findings, a: &Outcome, b: &Outcome) {
    let (da, db) = (&a.rec.digests.drops, &b.rec.digests.drops);
    f.check(
        "NI-1d",
        da == db && da.len() >= FLOOR_DROPS,
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
    b.sign_jitter = true;
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

/// The drop holds of a twin (NI-2, NI-3; review T2GAPS-2): from world A's reads of received
/// credits, the true time until which the twin's relays hold each drop blob back from its reader.
/// Relays may hold a blob as long as they like (the adversary's power §19.26 point 1 names); the
/// twin moves every read it can. A read at or before the invite's first refresh time is held until
/// 1–12 h after it where that changes the due time (the declared bit, so NI-2 and NI-3 exercise the
/// comparison before the refresh), every other read by 2 h to 3 days. A hold always ends six hours
/// before the listening ends, the blob expires (30 days after its write), the credit's refresh cut
/// or the world ends, so the held read still happens and still refreshes: withholding a blob past
/// those moments suppresses the credit, which is no question of the refresh's timing.
pub fn drop_holds(a: &Outcome, te: u64) -> BTreeMap<(u32, u32), u64> {
    const HOUR: u64 = 3_600;
    const DAY: u64 = 86_400;
    let mut out = BTreeMap::new();
    for r in a.log.receipts.iter().filter(|r| r.due.is_some()) {
        let skew = a
            .truth
            .clients
            .get(r.inviter as usize)
            .map_or(&[][..], |cl| &cl.skew[..]);
        let wall = |w: i64| true_at_wall(skew, w.max(0) as u64);
        let limit = r
            .until
            .min(r.written + 30 * DAY)
            .min(wall(r.cut))
            .min(te)
            .saturating_sub(6 * HOUR);
        let mut rng = Rng::new(
            0x484f_4c44,
            &[
                b"drop-hold",
                &r.inviter.to_be_bytes(),
                &r.invitee.to_be_bytes(),
            ],
        );
        let cross = (r.w <= r.first && r.first < r.cut)
            .then(|| wall(r.first) + rng.range(HOUR, 12 * HOUR))
            .filter(|&at| at > r.t && at < limit);
        let at = cross.unwrap_or_else(|| (r.t + rng.range(2 * HOUR, 3 * DAY)).min(limit));
        if cross.is_some() || at >= r.t + 2 * HOUR {
            out.insert((r.inviter, r.invitee), at);
        }
    }
    out
}

pub fn ni2_twin(base: &Config, a: &Outcome) -> Config {
    let mut b = base.clone();
    b.name = format!("{}-ni2", base.name);
    b.analyze = false;
    b.seeds.token ^= 0x4E49_2D32;
    b.seeds.ns ^= 0x4E49_2D32;
    b.script = Some(script_of(a));
    b.drop_holds = Arc::new(drop_holds(a, population::Timeline::of(base.scale).te));
    b
}

pub fn ni3_twin(base: &Config, a: &Outcome) -> Config {
    let mut b = base.clone();
    b.name = format!("{}-ni3", base.name);
    b.analyze = false;
    b.shift_fraction = 0.2;
    b.script = Some(script_of(a));
    b.drop_holds = Arc::new(drop_holds(a, population::Timeline::of(base.scale).te));
    b
}

/// NI-1d: every invitee buys its first pack two days and five hours later (across activation-slot
/// cells), so every drop write comes from a moved invitee.
pub fn ni1d_twin(base: &Config) -> Config {
    let mut b = base.clone();
    b.name = format!("{}-ni1d", base.name);
    b.analyze = false;
    b.first_pack_shift = Some((1.0, 2 * 86_400 + 5 * 3_600));
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
    test_cfg.export_truth = std::env::var("GHOST_T2_TRUTH")
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
            "world {}: {:.0} s; window packs signed {} (invoices {}, renewals started {}, resumes {}, credits packs {}, claims {}), trials {}, warm-up packs {}, need-triggered starts {}, drops {}, credits received {} (refreshes due at the first time {}, at the second {}, at their cut {}; dropped after their cut {}), credits refreshed {}, issuer calls {}, relay calls {}",
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
            g("credits received"),
            g("refreshes due at the first time"),
            g("refreshes due at the second time"),
            g("refreshes due at their cut"),
            g("received credits dropped after their refresh cut"),
            g("credits refreshed"),
            o.rec.digests.issuer_calls,
            o.rec.digests.relay_calls.iter().sum::<u64>()
        ));
    }
    population_check(&mut f, &w_test, scale);
    e30(&mut f, &w_test);
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

/// The twin checks on hand-made outcomes (no world runs, so they run in the debug profile too).
#[cfg(test)]
mod tests {
    use ghost_t2_join::model::{ClientKind, ClientTruth, Truth};

    use super::super::views::Recorder;
    use super::super::world::{Log, Outcome, Receipt};
    use super::{ni2, ni3, Findings};

    const DAY: u64 = 86_400;
    const HOUR: u64 = 3_600;
    const FIRST: i64 = 60 * DAY as i64;
    const SECOND: i64 = 80 * DAY as i64;
    const CUT: i64 = 200 * DAY as i64;

    fn client() -> ClientTruth {
        ClientTruth {
            kind: ClientKind::Existing,
            namespaces: 1,
            user_calls: Vec::new(),
            scripted: Vec::new(),
            runs: Vec::new(),
            skew: Vec::new(),
            processes: Vec::new(),
        }
    }

    /// A read of the credit invitee 1 sent inviter 0, at true (= device) time `t`.
    fn read(t: u64, first: i64, due: Option<i64>) -> Receipt {
        Receipt {
            inviter: 0,
            invitee: 1,
            t,
            w: t as i64,
            written: t - HOUR,
            until: 70 * DAY,
            first,
            second: SECOND,
            cut: CUT,
            due,
        }
    }

    /// A world whose only difference from its twin is its receipts: every view identical.
    fn world(receipts: Vec<Receipt>) -> Outcome {
        Outcome {
            name: "hand-made".into(),
            rec: Recorder::new(None, None, true),
            truth: Truth {
                clients: vec![client(), client()],
                ..Truth::default()
            },
            log: Log {
                receipts,
                ..Log::default()
            },
            seconds: 0.0,
        }
    }

    fn verdicts(a: &Outcome, b: &Outcome) -> Findings {
        let mut f = Findings::default();
        ni2(&mut f, a, b);
        ni3(&mut f, a, b);
        f
    }

    /// The review's probe (T2GAPS-1): a refresh 1 day after the read, the read 5 h later in the
    /// twin. The views are identical (the refresh lies after the world), but the due times follow
    /// the read, which no declared bit explains.
    #[test]
    fn a_refresh_timed_by_the_read_fails_the_twins() {
        let t = 10 * DAY;
        let a = world(vec![read(t, FIRST, Some((t + DAY) as i64))]);
        let b = world(vec![read(
            t + 5 * HOUR,
            FIRST,
            Some((t + 5 * HOUR + DAY) as i64),
        )]);
        let f = verdicts(&a, &b);
        for name in ["NI-2", "NI-3"] {
            assert!(
                f.failed(name),
                "{name} passed a read-timed refresh:\n{}",
                f.text()
            );
            let line = f.lines.iter().find(|l| l.starts_with(name)).unwrap();
            assert!(
                line.contains("refresh due time follows the read"),
                "{name} failed for another reason: {line}"
            );
        }
    }

    /// The declared bit (E17): read before the first time in one world, after it in the other.
    #[test]
    fn a_read_across_the_first_time_is_the_declared_bit() {
        let a = world(vec![read(
            (FIRST - 2 * HOUR as i64) as u64,
            FIRST,
            Some(FIRST),
        )]);
        let b = world(vec![read(
            (FIRST + 3 * HOUR as i64) as u64,
            FIRST,
            Some(SECOND),
        )]);
        let f = verdicts(&a, &b);
        assert!(!f.failed("NI-2") && !f.failed("NI-3"), "{}", f.text());
        assert!(
            f.lines[0].contains("1 across their first refresh time")
                && f.lines[0].contains("1 inviters with a credit read on the other side"),
            "{}",
            f.text()
        );
    }

    /// Two reads hours apart before the first time give the same due time.
    #[test]
    fn reads_hours_apart_before_the_first_time_pass() {
        let t = 10 * DAY;
        let a = world(vec![read(t, FIRST, Some(FIRST))]);
        let b = world(vec![read(t + 5 * HOUR, FIRST, Some(FIRST))]);
        let f = verdicts(&a, &b);
        assert!(!f.failed("NI-2") && !f.failed("NI-3"), "{}", f.text());
        assert!(f.lines[0].contains("(1 by an hour or more"), "{}", f.text());
    }

    /// T2GAPS-2: a twin that moves no read by an hour tests nothing of Q31.
    #[test]
    fn a_twin_that_moves_no_read_fails() {
        let t = 10 * DAY;
        let a = world(vec![read(t, FIRST, Some(FIRST))]);
        let b = world(vec![read(t + 20, FIRST, Some(FIRST))]);
        let f = verdicts(&a, &b);
        for name in ["NI-2", "NI-3"] {
            assert!(
                f.failed(name),
                "{name} passed without a moved read:\n{}",
                f.text()
            );
            let line = f.lines.iter().find(|l| l.starts_with(name)).unwrap();
            assert!(line.contains("fewer than"), "{line}");
        }
    }

    /// Other pre-drawn times (another invite) are no declared bit.
    #[test]
    fn due_times_from_other_refresh_times_fail() {
        let t = 10 * DAY;
        let other = FIRST + DAY as i64;
        let a = world(vec![read(t, FIRST, Some(FIRST))]);
        let b = world(vec![read(t + 5 * HOUR, other, Some(other))]);
        let f = verdicts(&a, &b);
        assert!(f.failed("NI-2") && f.failed("NI-3"), "{}", f.text());
        assert!(
            f.lines[0].contains("refresh due time follows the read"),
            "{}",
            f.text()
        );
    }

    /// T2GAPS-2: the twin's relays move every read they can by hours to days, and a read before
    /// the first refresh time across it where that changes the due time, always releasing the blob
    /// before the listening ends, the blob expires, the cut or the world ends.
    #[test]
    fn the_twin_holds_drop_blobs_back_by_hours_to_days() {
        let te = 100 * DAY;
        let t = 10 * DAY;
        // Crossable: read before the first time, which precedes the cut and the listening's end.
        let mut cross = read(t, 20 * DAY as i64, Some(20 * DAY as i64));
        cross.invitee = 1;
        // The first time lies after the listening: held by hours to days only.
        let mut far = read(t, 60 * DAY as i64, Some(60 * DAY as i64));
        far.invitee = 2;
        far.until = 55 * DAY;
        // Read too close to the world's end, and a credit dropped after its cut: not held.
        let mut late = read(te - HOUR, FIRST, Some(FIRST));
        late.invitee = 3;
        let mut dropped = read(t, FIRST, None);
        dropped.invitee = 4;
        let a = world(vec![cross, far, late, dropped]);
        let holds = super::drop_holds(&a, te);
        let at = |invitee: u32| holds.get(&(0, invitee)).copied();
        let c = at(1).expect("a crossing hold");
        assert!((20 * DAY + HOUR..20 * DAY + 12 * HOUR).contains(&c), "{c}");
        let f = at(2).expect("a hold of hours to days");
        assert!((t + 2 * HOUR..t + 3 * DAY).contains(&f), "{f}");
        assert_eq!((at(3), at(4)), (None, None));
    }

    /// A credit refreshed in one world and dropped after its cut in the other: the read decided
    /// whether an issuer call happens, which is no declared bit.
    #[test]
    fn a_read_across_the_cut_fails() {
        let cut_first = CUT - 10 * DAY as i64;
        let mut x = read((CUT - HOUR as i64) as u64, cut_first, Some(CUT));
        let mut y = read((CUT + 5 * HOUR as i64) as u64, cut_first, None);
        x.second = CUT + 20 * DAY as i64;
        y.second = x.second;
        let f = verdicts(&world(vec![x]), &world(vec![y]));
        assert!(f.failed("NI-2") && f.failed("NI-3"), "{}", f.text());
        assert!(
            f.lines[0].contains("refresh due time follows the read"),
            "{}",
            f.text()
        );
    }
}
