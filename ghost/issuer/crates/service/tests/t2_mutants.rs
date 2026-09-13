//! The privacy mutants of T2 (Phase 8 design §13.5, §19.16 point 4): each mutant is run in the T2
//! world (or, for M14, on the public context) and must be detected by the check the design names,
//! for the reason it names (`MutantDetectionTest` pattern: mutants live only in tests). The control
//! runs are the variants of `t2_unlinkability.rs`, where every check passes on the same seeds.
//!
//! M4 (`SharedIssuerScope`) is also caught by the `client-core` unit test of the `IssuerFlow` map
//! (`isolation.rs`, §19.17 point 6); here the reference client's shared scope is caught by J6 a and
//! T2c. Release profile only; `t2-exit-gate.yml` runs them.

mod common;
mod t2;

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

fn detected(f: &Findings, check: &str, mutant: Mutant) {
    println!("{:?}:\n{}", mutant, f.text());
    assert!(
        f.failed(check),
        "mutant {mutant:?} was not detected by {check}:\n{}",
        f.text()
    );
}

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
    let b_cfg = gate::ni1_twin(&cfg, &a);
    let b = World::new(b_cfg, &t2::es::global_cache()).run();
    let mut f = Findings::default();
    gate::ni1(&mut f, &a, &b);
    f
}

/// NI-1 across activation-slot cells on a mutant world and its twin.
fn ni1_cells(mutant: Mutant, scale: Scale) -> Findings {
    let (cfg, a) = world(&format!("{mutant:?}-a"), scale, SEEDS.1, mutant, false, 0);
    let (b_cfg, moved) = gate::ni1_cells_twin(&cfg, &a);
    let b = World::new(b_cfg, &t2::es::global_cache()).run();
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

mutant_test!(m1_nonce_from_invoice, {
    let m = Mutant::M1NonceFromInvoice;
    detected(&joins(m), "J3", m);
    detected(&ni1(m, population::SMALL), "NI-1", m);
});

mutant_test!(m2_per_invoice_key, {
    let m = Mutant::M2PerInvoiceKey;
    detected(&joins(m), "J7", m);
    detected(&ni1(m, population::SMALL), "NI-1", m);
});

mutant_test!(m2b_server_key_id, {
    let m = Mutant::M2bServerKeyId;
    detected(&joins(m), "J1", m);
    detected(&ni1(m, population::SMALL), "NI-1", m);
});

mutant_test!(m3_immediate_eligible, {
    let m = Mutant::M3ImmediateEligible;
    detected(&ni1_cells(m, population::SMALL), "NI-1 across cells", m);
    detected(&statistics(m, population::PR), "S1", m);
});

mutant_test!(m4_shared_issuer_scope, {
    let m = Mutant::M4SharedIssuerScope;
    let f = joins(m);
    detected(&f, "J6", m);
    detected(&f, "T2c", m);
});

mutant_test!(m5a_no_blinding, {
    let m = Mutant::M5aNoBlinding;
    detected(&joins(m), "J1", m);
});

mutant_test!(m5b_square_blinding, {
    let m = Mutant::M5bSquareBlinding;
    detected(&statistics(m, population::PR), "S2", m);
});

mutant_test!(m6_cross_relay_retry, {
    let m = Mutant::M6CrossRelayRetry;
    detected(&joins(m), "T2b", m);
});

mutant_test!(m7_issuer_base_week, {
    let m = Mutant::M7IssuerBaseWeek;
    detected(&ni1(m, population::PR), "NI-1", m);
});

mutant_test!(m8_variable_counts, {
    let m = Mutant::M8VariableCounts;
    let (cfg, a) = world("m8-a", population::SMALL, SEEDS.1, m, false, 0);
    let b = World::new(gate::ni2_twin(&cfg, &a), &t2::es::global_cache()).run();
    let mut f = Findings::default();
    gate::ni2(&mut f, &a, &b);
    detected(&f, "NI-2", m);
});

mutant_test!(m9_session_issuer_calls, {
    let m = Mutant::M9SessionIssuerCalls;
    detected(&joins(m), "J9", m);
    let (_, te) = world("m9-test", population::SMALL, SEEDS.1, m, true, 0);
    let (tr_cfg_a, tr) = world("m9-train", population::SMALL, SEEDS.0, m, true, 0);
    let _ = tr_cfg_a;
    let (attackers, _, _) = gate::train(&tr, SEEDS.0);
    let mut f = Findings::default();
    gate::statistics(&mut f, &attackers, &te, SEEDS.1);
    detected(&f, "S3a", m);
});

mutant_test!(m10_referral_id_at_issuer, {
    let m = Mutant::M10ReferralIdAtIssuer;
    let f = joins(m);
    detected(&f, "T2c", m);
    detected(&f, "J1", m);
});

mutant_test!(m11_device_clock_period, {
    let m = Mutant::M11DeviceClockPeriod;
    detected(&joins(m), "J8", m);
});

mutant_test!(m12_claim_in_purchase_run, {
    let m = Mutant::M12ClaimInPurchaseRun;
    let f = joins(m);
    detected(&f, "J9", m);
    detected(&f, "J6", m);
});

mutant_test!(m13_paid_onboarding, {
    let m = Mutant::M13PaidOnboarding;
    detected(&ni1_cells(m, population::SMALL), "NI-1 across cells", m);
    // S1, the design's other detector, lacks the power at the PR scale for the few invitee first
    // packs of a world: reported, not asserted (the gate scale has about 600 onboardings).
    println!(
        "{m:?} S1 (reported):\n{}",
        statistics(m, population::PR).text()
    );
});

mutant_test!(m14_non_permutation_key, {
    // The mutant: a key whose x ↦ x^e is not a permutation (65537 | p − 1) with the proof check
    // skipped. J10 checks every key's proof on the public context; the ES parser refuses it.
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
    let target = proofs.iter().position(|p| p.0 == Kind::Access).unwrap();
    proofs[target] = (Kind::Access, proofs[target].1, pk, proof.to_vec());
    let acc = ghost_t2_join::accumulate::Accumulator::new(
        schedule.clone(),
        ghost_t2_join::public::public_context(schedule, &[]),
    );
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
    detected(&joins(m), "T2c", m);
});

mutant_test!(m16_issuer_forces_retries, {
    let m = Mutant::M16IssuerForcesRetries;
    let (_, out) = world("m16", population::SMALL, SEEDS.1, m, true, 8);
    let mut f = Findings::default();
    gate::joins(&mut f, &out);
    detected(&f, "J9", m);
});

mutant_test!(m17_relay_clock_drives_base_week, {
    let m = Mutant::M17RelayClockDrivesBaseWeek;
    let (cfg, a) = world("m17-a", population::SMALL, SEEDS.1, m, false, 0);
    let b = World::new(gate::ni3_twin(&cfg, &a), &t2::es::global_cache()).run();
    let mut f = Findings::default();
    gate::ni3(&mut f, &a, &b);
    detected(&f, "NI-3", m);
});

mutant_test!(m18_drop_at_eligible_minute, {
    let m = Mutant::M18DropAtEligibleMinute;
    let (cfg, a) = world("m18-a", population::SMALL, SEEDS.1, m, false, 0);
    let b = World::new(gate::ni1d_twin(&cfg), &t2::es::global_cache()).run();
    let mut f = Findings::default();
    gate::ni1d(&mut f, &a, &b);
    detected(&f, "NI-1d", m);
});

mutant_test!(m19_pay_inside_session, {
    let m = Mutant::M19PayInsideSession;
    let (_, tr) = world("m19-train", population::SMALL, SEEDS.0, m, true, 0);
    let (_, te) = world("m19-test", population::SMALL, SEEDS.1, m, true, 0);
    let (attackers, _, _) = gate::train(&tr, SEEDS.0);
    let mut f = Findings::default();
    gate::statistics(&mut f, &attackers, &te, SEEDS.1);
    detected(&f, "S3d", m);
});

mutant_test!(m20_quiet_when_work_due, {
    // The mutant forces a quiet run when a BlindSign is overdue, so quiet runs follow issuer state
    // (P-7). J9 checks every quiet run against the process's draw. The design's detectors are NI-K
    // (the Kotlin lane) and NI-2, which cannot see it in this world: its job times do not follow
    // relay activity, and the forced run falls after the moved flow's activation cell.
    let m = Mutant::M20QuietWhenWorkDue;
    detected(&joins(m), "J9", m);
});

mutant_test!(m21_spend_received_credit, {
    // The Sybil-invitee world: the attacker's invitees send their credits to claimants, whose
    // claims then present them unrefreshed.
    let m = Mutant::M21SpendReceivedCredit;
    let (_, out) = world("m21", population::PR, SEEDS.1, m, true, 0);
    let mut f = Findings::default();
    gate::joins(&mut f, &out);
    detected(&f, "T2c", m);
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
