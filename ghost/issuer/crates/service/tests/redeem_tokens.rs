//! The pinned entitlement tokens of `protocol/test-vectors/redeem.txt` (Phase 8 design §10.8). The
//! relay replays that file without any private key, so its tokens are fixed bytes; this test proves
//! they are what the file says they are:
//!
//! - every `token ... signer=<kind>:<epoch> hex=...` line is re-derived here from the committed test
//!   schedule and its private keys and must match byte for byte;
//! - the one line signed by a key outside the schedule (`signer=spki:<hex>`) verifies under that
//!   SPKI, carries its key id, names no schedule key and has the stated challenge.
//!
//! Regenerate the token block (in release mode) with
//!
//!   GHOST_VECTOR_OUT=<file> cargo test --release -p ghost-issuer --test redeem_tokens -- --ignored generate_redeem_tokens
//!
//! and paste it into the vector file. The `spki` line changes on every run (a fresh key).

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;

use common::fixture;
use ghost_blind_rsa::PublicKey;
use ghost_entitlement::challenge::challenge_digest;
use ghost_entitlement::grid::Kind;
use ghost_entitlement::token::{self, Token, AUTHENTICATOR_LEN, MODULUS_BITS};
use ghost_issuer::signer::{CheckedSigner, ReferenceSigner, Signer};
use sha2::{Digest, Sha256, Sha384};

const VECTORS: &str = include_str!("../../../../protocol/test-vectors/redeem.txt");

/// (name, challenge kind, challenge epoch, slot, signing key kind, signing key epoch).
type Spec = (&'static str, Kind, u64, Option<u8>, Kind, u64);

/// The tokens signed by keys of the test schedule.
const ES_TOKENS: &[Spec] = &[
    ("a1", Kind::Access, 2959, Some(1), Kind::Access, 2959),
    ("a2", Kind::Access, 2959, Some(1), Kind::Access, 2959),
    ("a3", Kind::Access, 2959, Some(1), Kind::Access, 2959),
    ("b0", Kind::Access, 2958, Some(1), Kind::Access, 2958),
    ("b1", Kind::Access, 2960, Some(1), Kind::Access, 2960),
    ("c2", Kind::Access, 2957, Some(1), Kind::Access, 2957),
    ("c4", Kind::Access, 2961, Some(1), Kind::Access, 2961),
    ("s0", Kind::Access, 2959, Some(0), Kind::Access, 2959),
    ("m1", Kind::Access, 2966, Some(2), Kind::Access, 2966),
    ("m2", Kind::Access, 2967, Some(2), Kind::Access, 2967),
    ("i1", Kind::Invite, 739, None, Kind::Invite, 739),
    ("k1", Kind::Credit, 227, None, Kind::Credit, 227),
    // An ACCESS challenge signed by the INVITE key of the same week (a correct signature under
    // a key of another kind).
    ("x1", Kind::Access, 2959, Some(1), Kind::Invite, 739),
    // A challenge of week 2959 signed by the ACCESS key of week 2960.
    ("y1", Kind::Access, 2959, Some(1), Kind::Access, 2960),
];

/// The token signed by a fresh key outside the schedule, with a self-consistent key id.
const NON_ES_TOKEN: (&str, Kind, u64, Option<u8>) = ("n1", Kind::Access, 2959, Some(1));

fn nonce(name: &str) -> [u8; 32] {
    Sha256::digest(format!("ghost/test/redeem-nonce/{name}").as_bytes()).into()
}

fn salt(name: &str) -> [u8; 48] {
    Sha384::digest(format!("ghost/test/redeem-salt/{name}").as_bytes()).into()
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Access => "access",
        Kind::Invite => "invite",
        Kind::Credit => "credit",
    }
}

fn kind_of(name: &str) -> Kind {
    match name {
        "access" => Kind::Access,
        "invite" => Kind::Invite,
        "credit" => Kind::Credit,
        other => panic!("unknown kind {other}"),
    }
}

/// Signs the token `name` without blinding: the blinded message is the EMSA-PSS encoding itself
/// (r = 1), so the blind signature is the RSASSA-PSS signature.
fn sign<S: Signer>(
    signer: &S,
    public_key: &PublicKey,
    issuer_name: &str,
    name: &str,
    kind: Kind,
    epoch: u64,
    slot: Option<u8>,
) -> Token {
    let digest = challenge_digest(issuer_name, kind, epoch, slot).unwrap();
    let input = token::token_input(&nonce(name), &digest, &token::key_id(&public_key.to_spki()));
    let em =
        ghost_blind_rsa::emsa_pss_encode_sha384(&input, &salt(name), MODULUS_BITS - 1).unwrap();
    let em: [u8; AUTHENTICATOR_LEN] = em.try_into().unwrap();
    let sig = signer.blind_sign(&em).unwrap();
    let token = Token::from_parts(&input, &sig);
    token.verify_signature(public_key).unwrap();
    token
}

fn line(
    name: &str,
    kind: Kind,
    epoch: u64,
    slot: Option<u8>,
    signer: &str,
    token: &Token,
) -> String {
    let slot = slot.map_or(String::new(), |s| format!(" slot={s}"));
    format!(
        "token {name} kind={} epoch={epoch}{slot} signer={signer} hex={}",
        kind_name(kind),
        hex::encode(token.as_bytes())
    )
}

#[test]
#[ignore = "writes the token block of protocol/test-vectors/redeem.txt"]
fn generate_redeem_tokens() {
    let schedule = fixture::schedule();
    let signers = fixture::signers(&schedule);
    let issuer = schedule.issuer_name();
    let mut out = String::new();
    for &(name, kind, epoch, slot, key_kind, key_epoch) in ES_TOKENS {
        let signer = &signers[&(key_kind, key_epoch)];
        let token = sign(signer, signer.public_key(), issuer, name, kind, epoch, slot);
        let by = format!("{}:{key_epoch}", kind_name(key_kind));
        writeln!(out, "{}", line(name, kind, epoch, slot, &by, &token)).unwrap();
    }
    let (name, kind, epoch, slot) = NON_ES_TOKEN;
    let fresh = ReferenceSigner::generate(Kind::Access, epoch).unwrap();
    let pk = fresh.public_key().clone();
    let checked = CheckedSigner::new(fresh, pk.clone()).unwrap();
    assert!(schedule.key_by_id(&token::key_id(&pk.to_spki())).is_none());
    let token = sign(&checked, &pk, issuer, name, kind, epoch, slot);
    let by = format!("spki:{}", hex::encode(pk.to_spki()));
    writeln!(out, "{}", line(name, kind, epoch, slot, &by, &token)).unwrap();
    let path = std::env::var("GHOST_VECTOR_OUT").expect("set GHOST_VECTOR_OUT=<file>");
    std::fs::write(path, out).unwrap();
}

#[test]
fn pinned_redeem_tokens_match_the_test_schedule() {
    let schedule = fixture::schedule();
    let signers = fixture::signers(&schedule);
    let issuer = schedule.issuer_name();
    let mut seen = BTreeSet::new();
    for raw in VECTORS.lines() {
        let text = raw.split('#').next().unwrap_or_default().trim();
        let Some(rest) = text.strip_prefix("token ") else {
            continue;
        };
        if !rest.contains(" hex=") {
            continue; // a derived token (from=...)
        }
        let mut words = rest.split_whitespace();
        let name = words.next().unwrap();
        let fields: std::collections::BTreeMap<&str, &str> =
            words.filter_map(|w| w.split_once('=')).collect();
        let kind = kind_of(fields["kind"]);
        let epoch: u64 = fields["epoch"].parse().unwrap();
        let slot: Option<u8> = fields.get("slot").map(|s| s.parse().unwrap());
        let pinned = hex::decode(fields["hex"]).unwrap();
        let (by_kind, by_rest) = fields["signer"].split_once(':').unwrap();
        if by_kind == "spki" {
            let spki = hex::decode(by_rest).unwrap();
            let pk = PublicKey::from_spki(&spki).unwrap();
            let t = Token::parse(&pinned).unwrap();
            assert_eq!(t.key_id(), token::key_id(&spki), "{name}: key id");
            assert!(
                schedule.key_by_id(t.key_id()).is_none(),
                "{name}: an ES key"
            );
            assert_eq!(t.nonce(), nonce(name), "{name}: nonce");
            let digest = challenge_digest(issuer, kind, epoch, slot).unwrap();
            assert_eq!(t.challenge_digest(), digest, "{name}: challenge");
            t.verify_signature(&pk).unwrap();
            assert_eq!(
                (name, kind, epoch, slot),
                NON_ES_TOKEN,
                "{name}: the spki token"
            );
        } else {
            let key = (kind_of(by_kind), by_rest.parse::<u64>().unwrap());
            let signer = &signers[&key];
            let token = sign(signer, signer.public_key(), issuer, name, kind, epoch, slot);
            assert_eq!(
                hex::encode(token.as_bytes()),
                hex::encode(&pinned),
                "{name}: pinned bytes"
            );
            assert!(
                ES_TOKENS.contains(&(name, kind, epoch, slot, key.0, key.1)),
                "{name}: not in the generator's list"
            );
        }
        assert!(seen.insert(name.to_string()), "token {name} pinned twice");
    }
    let expected: BTreeSet<String> = ES_TOKENS
        .iter()
        .map(|s| s.0)
        .chain([NON_ES_TOKEN.0])
        .map(str::to_string)
        .collect();
    assert_eq!(
        seen, expected,
        "the vector file pins exactly the generated tokens"
    );
}
