//! The privacy mutants of T2 (Phase 8 design §13.5, §19.16 point 4, §19.24 point 4): each mutant
//! runs in the T2 world (or, for M14, on the public context) and must fail the check the design
//! names, for the reason the mutant causes (the failing line's text), while the same check passes
//! on the control: the unmutated world at the same scale, seeds and issuer, with the same twins
//! (`MutantDetectionTest` pattern: mutants live only in tests). The controls are computed once per
//! process and shared by the tests that need them.
//!
//! Detectors that differ from §13.5 (§19.24 point 4): M3 and M13 are asserted by NI-1 across
//! activation-slot cells and M3 also by S1 at the PR scale; M13's S1 is reported (it needs the
//! gate's onboardings, and the gate world runs no mutant). M20 is asserted by J9's quiet-run
//! independence, read from the job runs' times and the issuer view (the design's NI-K runs on the
//! real Kotlin engine, `EntitlementMutantDetectionTest`; NI-2 cannot see a forced quiet run in this
//! world: its job times do not follow relay activity). M1 runs twice: with the generic info word
//! "nonce" and, as M1b, with a GHOST label and the position as the HKDF info (J3's label-counter
//! family), so J3's detection does not rest on the mutant's own string. M22 (a received credit's
//! refresh timed by its drop read, the rule Q31 replaced) is asserted by NI-2, whose relays hold
//! the drop blobs back by hours to days (§19.26 point 7).
//!
//! M4 (`SharedIssuerScope`) is also caught by the `client-core` unit test of the `IssuerFlow` map
//! (`isolation.rs`, §19.17 point 6); here the reference client's shared scope is caught by J6 a and
//! T2c. Release profile only; `t2-exit-gate.yml` runs them.

mod common;
mod t2;

use std::sync::OnceLock;

use ghost_entitlement::schedule::KeyContent;
use ghost_entitlement::Kind;
use ghost_t2_join::checks;
use t2::config::{Config, Mutant};
use t2::gate::{self, Findings};
use t2::population::{self, Scale};
use t2::world::{Outcome, World};

const SEEDS: (u64, u64) = gate::SEEDS[0];

fn world(
    name: &str,
    scale: Scale,
    seed: u64,
    mutant: Mutant,
    analyze: bool,
    liar: u32,
) -> (Config, Outcome) {
    let mut cfg = Config::new(name, scale, seed);
    cfg.mutant = mutant;
    cfg.analyze = analyze;
    cfg.per_client = true;
    cfg.liar = liar;
    let out = World::new(cfg.clone(), &t2::es::global_cache()).run();
    (cfg, out)
}

fn run(cfg: Config) -> Outcome {
    World::new(cfg, &t2::es::global_cache()).run()
}

/// The failing line of `check`, if the check failed.
fn failing<'a>(f: &'a Findings, check: &str) -> Option<&'a String> {
    let prefix = format!("{check}: FAIL");
    f.lines.iter().find(|l| l.starts_with(&prefix))
}

/// The mutant fails `check` with every one of `reasons` in the failing line, and the control
/// passes it.
fn detected(f: &Findings, control: &Findings, check: &str, reasons: &[&str], mutant: Mutant) {
    println!("{mutant:?}:\n{}", f.text());
    let line = failing(f, check).unwrap_or_else(|| {
        panic!(
            "mutant {mutant:?} was not detected by {check}:\n{}",
            f.text()
        )
    });
    for r in reasons {
        assert!(
            line.contains(r),
            "mutant {mutant:?} failed {check}, but not for its reason ({r}): {line}"
        );
    }
    assert!(
        !control.failed(check),
        "the control of {mutant:?} fails {check} too, so the mutant's failure is no detection:\n{}",
        control.text()
    );
}

/// As [`detected`], with any one of `reasons` in the failing line.
fn detected_any(f: &Findings, control: &Findings, check: &str, reasons: &[&str], mutant: Mutant) {
    println!("{mutant:?}:\n{}", f.text());
    let line = failing(f, check).unwrap_or_else(|| {
        panic!(
            "mutant {mutant:?} was not detected by {check}:\n{}",
            f.text()
        )
    });
    assert!(
        reasons.iter().any(|r| line.contains(r)),
        "mutant {mutant:?} failed {check}, but for none of its reasons {reasons:?}: {line}"
    );
    assert!(
        !control.failed(check),
        "the control of {mutant:?} fails {check} too, so the mutant's failure is no detection:\n{}",
        control.text()
    );
}

// -------------------------------------------------------------------------------------------------
// Controls: the unmutated worlds of every configuration a mutant runs in.
// -------------------------------------------------------------------------------------------------

struct Control {
    joins: Findings,
    ni1: Findings,
    ni1x: Findings,
    ni2: Findings,
    ni3: Findings,
    ni1d: Findings,
    stats: Findings,
}

/// The small-scale control: world A (seed 1), its twins, and the statistics against a trained
/// world (seed 0).
fn small() -> &'static Control {
    static C: OnceLock<Control> = OnceLock::new();
    C.get_or_init(|| {
        let (cfg, a) = world(
            "control-small-a",
            population::SMALL,
            SEEDS.1,
            Mutant::None,
            true,
            0,
        );
        let b1 = gate::ni1_twin(&cfg, &a);
        let (bx, moved) = gate::ni1_cells_twin(&cfg, &a);
        let b2 = gate::ni2_twin(&cfg, &a);
        let b3 = gate::ni3_twin(&cfg, &a);
        let bd = gate::ni1d_twin(&cfg);
        let mut tr = Config::new("control-small-train", population::SMALL, SEEDS.0);
        tr.analyze = true;
        tr.per_client = true;
        let outs = gate::parallel(vec![
            Box::new(|| run(b1)),
            Box::new(|| run(bx)),
            Box::new(|| run(b2)),
            Box::new(|| run(b3)),
            Box::new(|| run(bd)),
            Box::new(|| run(tr)),
        ]);
        let mut c = Control {
            joins: Findings::default(),
            ni1: Findings::default(),
            ni1x: Findings::default(),
            ni2: Findings::default(),
            ni3: Findings::default(),
            ni1d: Findings::default(),
            stats: Findings::default(),
        };
        gate::joins(&mut c.joins, &a);
        gate::ni1(&mut c.ni1, &a, &outs[0]);
        gate::ni1_cells(&mut c.ni1x, &a, &outs[1], &moved);
        gate::ni2(&mut c.ni2, &a, &outs[2]);
        gate::ni3(&mut c.ni3, &a, &outs[3]);
        gate::ni1d(&mut c.ni1d, &a, &outs[4]);
        let (attackers, _, _) = gate::train(&outs[5], SEEDS.0);
        gate::statistics(&mut c.stats, &attackers, &a, SEEDS.1);
        println!(
            "control (small):\n{}{}{}{}{}{}{}",
            c.joins.text(),
            c.ni1.text(),
            c.ni1x.text(),
            c.ni2.text(),
            c.ni3.text(),
            c.ni1d.text(),
            c.stats.text()
        );
        c
    })
}

/// The PR-scale control: world A (seed 1) with its NI-1 twin, and the statistics against a trained
/// world (seed 0).
fn pr() -> &'static Control {
    static C: OnceLock<Control> = OnceLock::new();
    C.get_or_init(|| {
        let (cfg, a) = world(
            "control-pr-a",
            population::PR,
            SEEDS.1,
            Mutant::None,
            true,
            0,
        );
        let b1 = gate::ni1_twin(&cfg, &a);
        let mut tr = Config::new("control-pr-train", population::PR, SEEDS.0);
        tr.analyze = true;
        tr.per_client = true;
        let outs = gate::parallel(vec![Box::new(|| run(b1)), Box::new(|| run(tr))]);
        let mut c = Control {
            joins: Findings::default(),
            ni1: Findings::default(),
            ni1x: Findings::default(),
            ni2: Findings::default(),
            ni3: Findings::default(),
            ni1d: Findings::default(),
            stats: Findings::default(),
        };
        gate::joins(&mut c.joins, &a);
        gate::ni1(&mut c.ni1, &a, &outs[0]);
        let (attackers, _, _) = gate::train(&outs[1], SEEDS.0);
        gate::statistics(&mut c.stats, &attackers, &a, SEEDS.1);
        println!(
            "control (PR):\n{}{}{}",
            c.joins.text(),
            c.ni1.text(),
            c.stats.text()
        );
        c
    })
}

/// The join search on the small world of an issuer that lies `AWAITING_CONFIRMATIONS` to the
/// first eight `BlindSign` calls of every invoice (M16's world).
fn liar_joins() -> &'static Findings {
    static C: OnceLock<Findings> = OnceLock::new();
    C.get_or_init(|| {
        let (_, out) = world(
            "control-liar",
            population::SMALL,
            SEEDS.1,
            Mutant::None,
            true,
            8,
        );
        let mut f = Findings::default();
        gate::joins(&mut f, &out);
        println!("control (liar):\n{}", f.text());
        f
    })
}

// -------------------------------------------------------------------------------------------------
// Mutant worlds.
// -------------------------------------------------------------------------------------------------

/// The join search on one mutant world at the small scale.
fn joins(mutant: Mutant) -> Findings {
    let (_, out) = world(
        &format!("{mutant:?}"),
        population::SMALL,
        SEEDS.1,
        mutant,
        true,
        0,
    );
    let mut f = Findings::default();
    gate::joins(&mut f, &out);
    f
}

/// NI-1 (same cell) on a mutant world and its twin.
fn ni1(mutant: Mutant, scale: Scale) -> Findings {
    let (cfg, a) = world(&format!("{mutant:?}-a"), scale, SEEDS.1, mutant, false, 0);
    let b = run(gate::ni1_twin(&cfg, &a));
    let mut f = Findings::default();
    gate::ni1(&mut f, &a, &b);
    f
}

/// NI-1 across activation-slot cells on a mutant world and its twin.
fn ni1_cells(mutant: Mutant, scale: Scale) -> Findings {
    let (cfg, a) = world(&format!("{mutant:?}-a"), scale, SEEDS.1, mutant, false, 0);
    let (b_cfg, moved) = gate::ni1_cells_twin(&cfg, &a);
    let b = run(b_cfg);
    let mut f = Findings::default();
    gate::ni1_cells(&mut f, &a, &b, &moved);
    f
}

/// S1–S4 on a mutant world pair (train, test).
fn statistics(mutant: Mutant, scale: Scale) -> Findings {
    let (_, tr) = world(
        &format!("{mutant:?}-train"),
        scale,
        SEEDS.0,
        mutant,
        true,
        0,
    );
    let (_, te) = world(&format!("{mutant:?}-test"), scale, SEEDS.1, mutant, true, 0);
    let (attackers, _, _) = gate::train(&tr, SEEDS.0);
    let mut f = Findings::default();
    gate::statistics(&mut f, &attackers, &te, SEEDS.1);
    f
}

macro_rules! mutant_test {
    ($name:ident, $body:block) => {
        #[test]
        #[ignore = "T2 mutants: t2-exit-gate.yml, release profile"]
        fn $name() $body
    };
}

const NI1_DIFFER: &[&str] = &["relay views differ"];

mutant_test!(m1_nonce_from_invoice, {
    let m = Mutant::M1NonceFromInvoice;
    detected(
        &joins(m),
        &small().joins,
        "J3",
        &["[hkdf(info=word||u8)]"],
        m,
    );
    let b = Mutant::M1bNonceFromInvoiceLabel;
    detected(
        &joins(b),
        &small().joins,
        "J3",
        &["[hkdf(info=label||u8)]"],
        b,
    );
    detected(
        &ni1(m, population::SMALL),
        &small().ni1,
        "NI-1",
        NI1_DIFFER,
        m,
    );
});

mutant_test!(m2_per_invoice_key, {
    let m = Mutant::M2PerInvoiceKey;
    detected_any(
        &joins(m),
        &small().joins,
        "J7",
        &["not an ES", "not in the ES"],
        m,
    );
    detected(
        &ni1(m, population::SMALL),
        &small().ni1,
        "NI-1",
        NI1_DIFFER,
        m,
    );
});

mutant_test!(m2b_server_key_id, {
    let m = Mutant::M2bServerKeyId;
    detected(&joins(m), &small().joins, "J1", &["server_key_id"], m);
    detected(
        &ni1(m, population::SMALL),
        &small().ni1,
        "NI-1",
        NI1_DIFFER,
        m,
    );
});

mutant_test!(m3_immediate_eligible, {
    let m = Mutant::M3ImmediateEligible;
    detected(
        &ni1_cells(m, population::SMALL),
        &small().ni1x,
        "NI-1 across cells",
        &["relay calls differ before the activation cell"],
        m,
    );
    // S1 at the PR scale is asserted again (§19.26 point 7, restoring §19.24 point 4): with the
    // background lanes lasting until their pairs' events, as the engine runs them, a session whose
    // capabilities are usable steps its redeem lane, so an immediately eligible pack's first use
    // follows its finalization again (p = 5.6e-5 argmax, 1.3e-5 Hungarian on seed pair 0).
    // §19.26 point 6 had reported it only, because the world ended the lanes too early.
    detected(
        &statistics(m, population::PR),
        &pr().stats,
        "S1",
        &["lift"],
        m,
    );
});

mutant_test!(m4_shared_issuer_scope, {
    let m = Mutant::M4SharedIssuerScope;
    let f = joins(m);
    detected(&f, &small().joins, "J6", &["flow instances"], m);
    detected(&f, &small().joins, "T2c", &["circuit"], m);
});

mutant_test!(m5a_no_blinding, {
    // Unblinded, the issuer sees each token's `em` as a block and returns its authenticator as a
    // signature; the first hit is whichever of the two joins sorts first.
    let m = Mutant::M5aNoBlinding;
    detected_any(
        &joins(m),
        &small().joins,
        "J1",
        &["relay.redeem.em", "relay.redeem.req.token.authenticator"],
        m,
    );
});

mutant_test!(m5b_square_blinding, {
    // With margin: no permuted maximum reaches the observed one, and the strongest pair is the
    // Jacobi symbols of the blocks and of the tokens at the relays.
    let m = Mutant::M5bSquareBlinding;
    detected(
        &statistics(m, population::PR),
        &pr().stats,
        "S2",
        &["jacobi(B) x jacobi(em)", "at or above it 0 of"],
        m,
    );
});

mutant_test!(m6_cross_relay_retry, {
    let m = Mutant::M6CrossRelayRetry;
    detected(&joins(m), &small().joins, "T2b", &["relay"], m);
});

mutant_test!(m7_issuer_base_week, {
    let m = Mutant::M7IssuerBaseWeek;
    detected(&ni1(m, population::PR), &pr().ni1, "NI-1", NI1_DIFFER, m);
});

mutant_test!(m8_variable_counts, {
    let m = Mutant::M8VariableCounts;
    let (cfg, a) = world("m8-a", population::SMALL, SEEDS.1, m, false, 0);
    let b = run(gate::ni2_twin(&cfg, &a));
    let mut f = Findings::default();
    gate::ni2(&mut f, &a, &b);
    detected_any(
        &f,
        &small().ni2,
        "NI-2",
        &["issuer view differs", "wallet view differs"],
        m,
    );
});

mutant_test!(m9_session_issuer_calls, {
    let m = Mutant::M9SessionIssuerCalls;
    detected(
        &joins(m),
        &small().joins,
        "J9",
        &["automatic call in a run that is not quiet"],
        m,
    );
    let (_, te) = world("m9-test", population::SMALL, SEEDS.1, m, true, 0);
    let (_, tr) = world("m9-train", population::SMALL, SEEDS.0, m, true, 0);
    let (attackers, _, _) = gate::train(&tr, SEEDS.0);
    let mut f = Findings::default();
    gate::statistics(&mut f, &attackers, &te, SEEDS.1);
    detected(&f, &small().stats, "S3a", &["co-presence"], m);
});

mutant_test!(m10_referral_id_at_issuer, {
    let m = Mutant::M10ReferralIdAtIssuer;
    let f = joins(m);
    detected(&f, &small().joins, "T2c", &["referral_id"], m);
    detected(&f, &small().joins, "J1", &["referral_id"], m);
});

mutant_test!(m11_device_clock_period, {
    // The mutant decides on the raw device clock although two relays answered it: a corrected
    // client redeeming near a true week boundary, or refused a period (§12.5, J8). At the PR scale
    // (§19.26 point 6, re-checked by point 7 with the engine's lane timing): the small world holds
    // no corrected skewed client's redemption near a week boundary, so its mutant world passes J8.
    let m = Mutant::M11DeviceClockPeriod;
    let (_, out) = world(
        "M11DeviceClockPeriod-pr",
        population::PR,
        SEEDS.1,
        m,
        true,
        0,
    );
    let mut f = Findings::default();
    gate::joins(&mut f, &out);
    detected_any(
        &f,
        &pr().joins,
        "J8",
        &[
            "WRONG_PERIOD after the relay-facing clock was corrected",
            "within 1 h of a week boundary",
        ],
        m,
    );
});

mutant_test!(m12_claim_in_purchase_run, {
    let m = Mutant::M12ClaimInPurchaseRun;
    let f = joins(m);
    detected(&f, &small().joins, "J9", &["issuer calls"], m);
    detected(&f, &small().joins, "J6", &["flow instances"], m);
});

mutant_test!(m13_paid_onboarding, {
    let m = Mutant::M13PaidOnboarding;
    detected(
        &ni1_cells(m, population::SMALL),
        &small().ni1x,
        "NI-1 across cells",
        &["relay calls differ before the activation cell"],
        m,
    );
    // S1, the design's other detector, lacks the power at the PR scale for the few invitee first
    // packs of a world: reported, not asserted (§19.24 point 4).
    println!(
        "{m:?} S1 (reported):\n{}control:\n{}",
        statistics(m, population::PR).text(),
        pr().stats.text()
    );
});

mutant_test!(m14_non_permutation_key, {
    // The mutant: a key whose x ↦ x^e is not a permutation (65537 | p − 1) with the proof check
    // skipped. J10 checks every key's proof on the public context; the ES parser refuses it. The
    // control: every key of the T2 schedule passes J10.
    let schedule = t2::es::schedule();
    let (pk, proof, spki) = non_permutation_key();
    let mut proofs: Vec<_> = schedule
        .content()
        .keys
        .iter()
        .map(|k| {
            let pk = ghost_blind_rsa::PublicKey::from_spki(&k.spki).unwrap();
            (k.kind, k.epoch, pk, k.proof.to_vec())
        })
        .collect();
    let acc = ghost_t2_join::accumulate::Accumulator::new(
        schedule.clone(),
        ghost_t2_join::public::public_context(schedule, &[]),
    );
    assert!(
        checks::j10_keys(&acc, &proofs).is_empty(),
        "control: J10 on the T2 schedule"
    );
    let target = proofs.iter().position(|p| p.0 == Kind::Access).unwrap();
    proofs[target] = (Kind::Access, proofs[target].1, pk, proof.to_vec());
    let hits = checks::j10_keys(&acc, &proofs);
    assert!(
        hits.iter()
            .any(|h| h.b.contains("permutation proof does not verify")),
        "M14 not detected by J10: {hits:?}"
    );
    // The ES negative test: a schedule listing it is refused.
    let mut content = schedule.content().clone();
    content.keys[target] = KeyContent {
        kind: Kind::Access,
        epoch: content.keys[target].epoch,
        spki,
        proof,
    };
    let bytes = common::fixture::sign_content(&content);
    assert!(ghost_entitlement::Schedule::verify_with_key(
        &bytes,
        &common::fixture::schedule_public_key()
    )
    .is_err());
});

mutant_test!(m15_seed_reuse_across_flows, {
    let m = Mutant::M15SeedReuseAcrossFlows;
    detected(&joins(m), &small().joins, "T2c", &["blinded"], m);
});

mutant_test!(m16_issuer_forces_retries, {
    let m = Mutant::M16IssuerForcesRetries;
    let (_, out) = world("m16", population::SMALL, SEEDS.1, m, true, 8);
    let mut f = Findings::default();
    gate::joins(&mut f, &out);
    detected(&f, liar_joins(), "J9", &["BlindSign calls (cap 5)"], m);
});

mutant_test!(m17_relay_clock_drives_base_week, {
    let m = Mutant::M17RelayClockDrivesBaseWeek;
    let (cfg, a) = world("m17-a", population::SMALL, SEEDS.1, m, false, 0);
    let b = run(gate::ni3_twin(&cfg, &a));
    let mut f = Findings::default();
    gate::ni3(&mut f, &a, &b);
    detected_any(
        &f,
        &small().ni3,
        "NI-3",
        &["issuer view differs", "wallet view differs"],
        m,
    );
});

mutant_test!(m18_drop_at_eligible_minute, {
    let m = Mutant::M18DropAtEligibleMinute;
    let (cfg, a) = world("m18-a", population::SMALL, SEEDS.1, m, false, 0);
    let b = run(gate::ni1d_twin(&cfg));
    let mut f = Findings::default();
    gate::ni1d(&mut f, &a, &b);
    detected(&f, &small().ni1d, "NI-1d", &["drop writes differ"], m);
});

mutant_test!(m19_pay_inside_session, {
    let m = Mutant::M19PayInsideSession;
    let (_, tr) = world("m19-train", population::SMALL, SEEDS.0, m, true, 0);
    let (_, te) = world("m19-test", population::SMALL, SEEDS.1, m, true, 0);
    let (attackers, _, _) = gate::train(&tr, SEEDS.0);
    let mut f = Findings::default();
    gate::statistics(&mut f, &attackers, &te, SEEDS.1);
    detected(&f, &small().stats, "S3d", &["payment co-presence"], m);
});

mutant_test!(m20_quiet_when_work_due, {
    // The mutant forces a quiet run when a BlindSign is overdue, so quiet runs follow issuer state
    // (P-7): J9 sees nearly every automatic BlindSign served by the first job run after its due
    // minute (q = 1/8 bounds that share for independent draws). The design's NI-K asserts it on the
    // real Kotlin engine (`EntitlementMutantDetectionTest`).
    let m = Mutant::M20QuietWhenWorkDue;
    detected(
        &joins(m),
        &small().joins,
        "J9",
        &["quiet runs follow due work"],
        m,
    );
});

mutant_test!(m21_spend_received_credit, {
    // The Sybil-invitee world: the attacker's invitees send their credits to claimants, whose
    // claims then present them unrefreshed.
    let m = Mutant::M21SpendReceivedCredit;
    let (_, out) = world("m21", population::PR, SEEDS.1, m, true, 0);
    let mut f = Findings::default();
    gate::joins(&mut f, &out);
    detected(
        &f,
        &pr().joins,
        "T2c",
        &["presents a credit the attacker's Sybil client finalized"],
        m,
    );
});

mutant_test!(m22_refresh_at_read, {
    // The rule Q31 replaced (§19.26, review T2GAPS-1): a received credit's refresh due 1–14 days
    // after its drop read. NI-2's relays hold every drop blob back by hours to days, so the
    // mutant's due times follow the reads, which no declared bit explains; the control's due times
    // differ only where a read crossed the invite's first refresh time.
    let m = Mutant::M22RefreshAtRead;
    let (cfg, a) = world("m22-a", population::SMALL, SEEDS.1, m, false, 0);
    let b = run(gate::ni2_twin(&cfg, &a));
    let mut f = Findings::default();
    gate::ni2(&mut f, &a, &b);
    detected(
        &f,
        &small().ni2,
        "NI-2",
        &["refresh due time follows the read"],
        m,
    );
});

// -------------------------------------------------------------------------------------------------
// M14: a 2048-bit modulus n = p q with 65537 | p − 1, and its owner's best proof.
// -------------------------------------------------------------------------------------------------

use ghost_blind_rsa::BigUint;
use sha2::{Digest, Sha256};

struct Stream(u64);

impl Stream {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < len {
            self.0 += 1;
            out.extend_from_slice(&Sha256::digest(
                [b"ghost/t2/m14".as_slice(), &self.0.to_be_bytes()].concat(),
            ));
        }
        out.truncate(len);
        out
    }
}

fn probable_prime(n: &BigUint, s: &mut Stream) -> bool {
    let one = BigUint::from(1u32);
    let two = BigUint::from(2u32);
    for p in [3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if (n % BigUint::from(p)) == BigUint::from(0u32) {
            return n == &BigUint::from(p);
        }
    }
    let n1 = n - &one;
    let mut d = n1.clone();
    let mut r = 0;
    while (&d % &two) == BigUint::from(0u32) {
        d >>= 1;
        r += 1;
    }
    'rounds: for _ in 0..24 {
        let a = BigUint::from_bytes_be(&s.bytes(128)) % (n - BigUint::from(4u32)) + &two;
        let mut x = a.modpow(&d, n);
        if x == one || x == n1 {
            continue;
        }
        for _ in 1..r {
            x = x.modpow(&two, n);
            if x == n1 {
                continue 'rounds;
            }
        }
        return false;
    }
    true
}

fn non_permutation_key() -> (ghost_blind_rsa::PublicKey, [[u8; 256]; 8], Vec<u8>) {
    let e = BigUint::from(65_537u32);
    let mut s = Stream(0);
    // p = 2 e k + 1 of 1024 bits.
    let p = loop {
        let mut k = BigUint::from_bytes_be(&s.bytes(126));
        k |= BigUint::from(1u32) << 1000usize;
        let cand = BigUint::from(2u32) * &e * k + BigUint::from(1u32);
        if cand.bits() == 1024 && probable_prime(&cand, &mut s) {
            break cand;
        }
    };
    let q = loop {
        let mut b = s.bytes(128);
        b[0] |= 0xC0;
        b[127] |= 1;
        let cand = BigUint::from_bytes_be(&b);
        if (&cand - BigUint::from(1u32)) % &e != BigUint::from(0u32)
            && probable_prime(&cand, &mut s)
        {
            break cand;
        }
    };
    let n = &p * &q;
    assert_eq!(n.bits(), 2048);
    let pk =
        ghost_blind_rsa::PublicKey::from_components(&n.to_bytes_be(), &e.to_bytes_be()).unwrap();
    // The owner's best effort: d' = e^-1 mod ((p - 1) / e)(q - 1), exact on the e-th residues mod p.
    let lambda = ((&p - BigUint::from(1u32)) / &e) * (&q - BigUint::from(1u32));
    let d = ghost_blind_rsa::mod_inv(&e, &lambda).expect("e invertible modulo (p-1)/e (q-1)");
    let challenges = ghost_blind_rsa::permutation_proof_challenges(&pk).unwrap();
    let proof = challenges.map(|c| {
        let x = BigUint::from_bytes_be(&c).modpow(&d, &n);
        let v = ghost_blind_rsa::i2osp(&x, 256).unwrap();
        let mut out = [0u8; 256];
        out.copy_from_slice(&v);
        out
    });
    let spki = pk.to_spki();
    (pk, proof, spki)
}
