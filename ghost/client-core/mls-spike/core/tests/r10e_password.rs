//! Round 10e, the adversarial review of the channel password (design §19.29, the password
//! findings): the committer's `pw_version` check as round 10d wrote it refuses every open invite
//! after the password is removed, and the corrected check (only while flag bit 2 is set) does not;
//! neither check can tell whether a sponsor knew the password (a member that never knew it mints a
//! working invite with a password it makes up, or an open one); the Argon2id floors as round 10d
//! wrote them (`m ≥ 19 MiB, t ≥ 1`) admit a profile below OWASP's pairs, while floors as parameter
//! pairs do not, and the RFC 9106 vector cannot run through a floor-enforcing path; and the offline
//! guessing rate a leaked link allows on one host.
//!
//! Run: `cargo test --release -p ghost-mls-spike --test r10e_password -- --nocapture --test-threads=1`

#[path = "support/invite_v2.rs"]
mod invite_v2;

use std::time::Instant;

use argon2::Params;
use invite_v2::*;
use rayon::prelude::*;

/// The fields of `GhostChannelContext` the password touches (§5.3, §19.28.3).
#[derive(Clone, Copy)]
struct Ctx {
    /// `flags` bit 0: members may invite.
    members_may_invite: bool,
    /// `flags` bit 2: joining requires a password.
    password: bool,
    pw_version: u16,
}

/// Round 10d's (B) check: `INVITE_ISSUED.pw_version == context.pw_version`, TLV 0x0015 absent = 0.
fn check_r10d(ctx: Ctx, tlv: Option<u16>) -> bool {
    tlv.unwrap_or(0) == ctx.pw_version
}

/// The corrected (B) check (§19.29 R10D-P5): only while flag bit 2 is set, and then the TLV must be
/// present and equal; the TLV is canonical only with a value ≥ 1 (absent is the one encoding of
/// "issued in an open channel").
fn check_r10e(ctx: Ctx, tlv: Option<u16>) -> bool {
    if tlv == Some(0) {
        return false; // non-canonical, refused at decode
    }
    !ctx.password || tlv == Some(ctx.pw_version)
}

/// §5.3 validity with Q46 (b): flag bit 2 set forces bit 0 clear.
fn context_valid_q46b(ctx: Ctx) -> bool {
    !(ctx.password && ctx.members_may_invite)
}

/// CO-2 (A)'s sponsor rule: a committer, or any member when `members_may_invite`.
fn may_sponsor(ctx: Ctx, sponsor_is_committer: bool) -> bool {
    sponsor_is_committer || ctx.members_may_invite
}

#[test]
fn r10e_pw_admission_rules() {
    let open_ch = Ctx {
        members_may_invite: true,
        password: false,
        pw_version: 0,
    };
    let pw_ch = |v| Ctx {
        members_may_invite: true,
        password: true,
        pw_version: v,
    };
    let removed = Ctx {
        members_may_invite: true,
        password: false,
        pw_version: 3,
    };
    // (case, context, INVITE_ISSUED TLV 0x0015, round 10d's verdict, the corrected verdict)
    let cases: [(&str, Ctx, Option<u16>, bool, bool); 7] = [
        ("open channel, open invite", open_ch, None, true, true),
        (
            "password channel v1, invite of v1",
            pw_ch(1),
            Some(1),
            true,
            true,
        ),
        (
            "password channel v2, stale invite of v1",
            pw_ch(2),
            Some(1),
            false,
            false,
        ),
        (
            "password channel v1, open invite",
            pw_ch(1),
            None,
            false,
            false,
        ),
        (
            "password removed (v3), open invite",
            removed,
            None,
            false,
            true,
        ),
        (
            "password removed (v3), invite sealed at v3",
            removed,
            Some(3),
            true,
            true,
        ),
        (
            "open channel, TLV 0 (two encodings of open)",
            open_ch,
            Some(0),
            true,
            false,
        ),
    ];
    for (name, ctx, tlv, r10d, r10e) in cases {
        let (a, b) = (check_r10d(ctx, tlv), check_r10e(ctx, tlv));
        println!("R10e PW (B) check: {name}: round 10d admits {a}, corrected admits {b}");
        assert_eq!((a, b), (r10d, r10e), "{name}");
    }

    // Q46 as round 10d claimed it ("a member without the password cannot mint invites") does not
    // hold: a member allowed to invite that never knew the password seals a real V2 link under a
    // password it makes up and posts INVITE_ISSUED with the context's pw_version; every check
    // passes and the invitee joins with the made-up password (or with no password at all, from an
    // open link carrying the same TLV).
    let ctx = pw_ch(3);
    let made_up = b"hello";
    let link = build(&v1_fields(0), 1, Some(made_up), [0x55; 16]);
    let opened = open(&link, Some(made_up));
    let open_link = build(&v1_fields(0), 0, None, [0x66; 16]);
    let admits = check_r10d(ctx, Some(3)) && check_r10e(ctx, Some(3));
    let sponsor_ok = may_sponsor(ctx, false);
    println!(
        "R10e PW Q46: a non-committer that never knew the password: made-up-password link opens {}, open link opens {}, (B) admits {admits}, CO-2 (A) sponsor rule {sponsor_ok}",
        matches!(opened, Opened::Fields(_)),
        matches!(open(&open_link, None), Opened::Fields(_))
    );
    assert!(matches!(opened, Opened::Fields(_)) && admits && sponsor_ok);
    // Q46 (b): flag bit 2 forces bit 0 clear, so only committers may sponsor in a password channel.
    let q46b = Ctx {
        members_may_invite: false,
        ..ctx
    };
    assert!(!context_valid_q46b(ctx) && context_valid_q46b(q46b));
    assert!(!may_sponsor(q46b, false) && may_sponsor(q46b, true));
    println!("R10e PW Q46 (b): a context with bits 0 and 2 both set is invalid; a non-committer's INVITE_ISSUED can then not be admitted (CO-2 (A)); a committer's can");
}

/// Argon2id floors. Round 10d: `m ≥ 19 456 KiB, t ≥ 1, p ≥ 1`, one bound per parameter. Corrected
/// (§19.29 R10D-P10): OWASP's equal-strength pairs for Argon2id (Password Storage Cheat Sheet,
/// accessed 2026-09-28), p ≥ 1.
const FLOOR_PAIRS: [(u32, u32); 5] = [
    (47_104, 1),
    (19_456, 2),
    (12_288, 3),
    (9_216, 4),
    (7_168, 5),
];

fn floor_r10d(m: u32, t: u32, p: u32) -> bool {
    m >= 19_456 && t >= 1 && p >= 1
}

fn floor_pairs(m: u32, t: u32, p: u32) -> bool {
    p >= 1 && FLOOR_PAIRS.iter().any(|&(fm, ft)| m >= fm && t >= ft)
}

/// MM-PW3's killer as §19.29 restates it: every `kdf_code` of the codec's profile table passes the
/// floor pairs (the table is asserted, not the RFC vector); a profile below every pair fails.
#[test]
fn r10e_pw_floor_pairs_and_the_profile_table() {
    let table: [(u8, (u32, u32, u32)); 1] = [(1, profile(1).unwrap())];
    for (code, (m, t, p)) in table {
        assert!(
            floor_pairs(m, t, p),
            "kdf_code {code} is below the floor pairs"
        );
    }
    // Round 10d's floor admits 19 MiB with one pass, which OWASP pairs with t = 2.
    assert!(floor_r10d(19_456, 1, 1) && !floor_pairs(19_456, 1, 1));
    // The RFC 9106 §5.3 vector (m = 32 KiB) is below every floor: it tests the primitive, run on the
    // primitive directly, and cannot pass through a floor-enforcing codec path.
    assert!(!floor_r10d(32, 3, 4) && !floor_pairs(32, 3, 4));
    // t = 0 is refused by the primitive itself (argon2 0.6.0; BouncyCastle likewise), so it is no
    // meaningful mutant of the codec.
    assert!(Params::new(65_536, 0, 4, Some(32)).is_err());
    println!("R10e PW floors: kdf_code 1 (64 MiB, t=1, p=4) passes the pairs; (19 MiB, t=1) passes round 10d's floor and fails the pairs; the RFC vector's 32 KiB fails both; t = 0 is refused by argon2 0.6.0");
}

/// The offline guessing a leaked password link allows: one Argon2id at kdf_code 1, one HKDF, one
/// AEAD open per guess (the tag is an exact oracle), on every core of this host (other agents share
/// it, so a lower bound on an attacker with this one machine).
#[test]
fn r10e_pw_offline_guess_rate() {
    let secret = b"913507"; // a six-digit PIN
    let link = build(&v1_fields(0), 1, Some(secret), [0x5c; 16]);
    let threads = rayon::current_num_threads();
    let n = threads * 8;
    let t = Instant::now();
    let hits: Vec<usize> = (0..n)
        .into_par_iter()
        .filter_map(|i| {
            let g = format!("{:06}", 913_507 - n / 2 + i);
            matches!(open(&link, Some(g.as_bytes())), Opened::Fields(_)).then_some(i)
        })
        .collect();
    let s = t.elapsed().as_secs_f64();
    let rate = n as f64 / s;
    assert_eq!(hits.len(), 1, "the tag is an exact oracle");
    println!(
        "R10e PW guessing: {n} guesses on {threads} threads in {s:.2} s -> {rate:.0} guesses/s on this host (m=64 MiB, t=1, p=4)"
    );
    for (what, bits) in [
        ("6-digit PIN", (1e6_f64).log2()),
        ("8 lowercase letters", 8.0 * 26f64.log2()),
        ("3 words of 2 048", 33.0),
        ("5 words of 2 048", 55.0),
        ("6 words of 2 048", 66.0),
    ] {
        let secs = 2f64.powf(bits) / 2.0 / rate;
        println!(
            "R10e PW guessing: {what} ({bits:.1} bits): expected {:.3e} s on this host ({:.3e} years)",
            secs,
            secs / 31_557_600.0
        );
    }
}
