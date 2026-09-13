//! `keygen` (runbook K1, design §3.3): the custody secret, the Ed25519 schedule key, the Ed25519
//! ops key that signs payout batch files (runbook P1, §9.5), or RSA-2048 token keys for
//! consecutive epochs of one kind, each with its permutation proof, its public entry and its
//! sealed private key.

use std::path::Path;

use ghost_blind_rsa::{PROOF_BLOCK_LEN, PROOF_ROUNDS};
use ghost_entitlement::schedule::KeyContent;
use ghost_entitlement::token;
use ghost_entitlement::Kind;
use ghost_issuer::custody::{self, CustodySecret};
use ghost_issuer::signer::{CheckedSigner, PrimeCheck, ReferenceSigner, Signer};
use ring::rand::{SecureRandom, SystemRandom};

use crate::args::Flags;
use crate::input::{input_refused, io_error, read_secret};
use crate::report::{Code, Field, Line, Sink};
use crate::{output, public_entry, Failure};

/// At most this many token keys per run (two years of access weeks).
pub const MAX_COUNT: u64 = 104;

const FLAGS: [&str; 9] = [
    "new-custody-secret",
    "new-schedule-key",
    "new-ops-key",
    "kind",
    "from-epoch",
    "count",
    "custody-secret",
    "public-dir",
    "sealed-dir",
];

pub fn run(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse(argv, &FLAGS)?;
    let rng = SystemRandom::new();
    if flags.has("new-custody-secret") {
        flags.only(&["new-custody-secret"])?;
        let secret = CustodySecret::generate(&rng)
            .map_err(|_| Failure::refused(input_refused("new-custody-secret", "random")))?;
        output::write_custody_secret(
            &flags.path("new-custody-secret")?,
            &secret,
            "new-custody-secret",
        )?;
        sink.emit(Line::new(Code::CustodySecretCreated));
        return Ok(());
    }
    if flags.has("new-schedule-key") {
        flags.only(&["new-schedule-key"])?;
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)
            .map_err(|_| Failure::refused(input_refused("new-schedule-key", "random")))?;
        let public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let written =
            output::write_schedule_key(&flags.path("new-schedule-key")?, &seed, "new-schedule-key");
        seed.fill(0);
        written?;
        sink.emit(Line::new(Code::ScheduleKeyCreated).hex(Field::Public, &public));
        return Ok(());
    }
    if flags.has("new-ops-key") {
        flags.only(&["new-ops-key"])?;
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)
            .map_err(|_| Failure::refused(input_refused("new-ops-key", "random")))?;
        let public = ghost_issuer::payout::OpsKey::from_seed(&seed).public();
        let written = output::write_ops_key(&flags.path("new-ops-key")?, &seed, "new-ops-key");
        seed.fill(0);
        written?;
        sink.emit(Line::new(Code::OpsKeyCreated).hex(Field::Public, &public));
        return Ok(());
    }
    token_keys(&flags, &rng, sink)
}

fn token_keys(flags: &Flags, rng: &dyn SecureRandom, sink: &mut dyn Sink) -> Result<(), Failure> {
    let kind = flags.kind("kind")?;
    let from = flags.u64("from-epoch")?;
    let count = flags.u64("count")?;
    if count == 0 || count > MAX_COUNT {
        return Err(Failure::usage("bad-value", Some("count")));
    }
    let last = from
        .checked_add(count - 1)
        .ok_or(Failure::usage("bad-value", Some("from-epoch")))?;
    let secret = CustodySecret::from_bytes(read_secret(
        &flags.path("custody-secret")?,
        "custody-secret",
    )?);
    let public_dir = flags.path("public-dir")?;
    let sealed_dir = flags.path("sealed-dir")?;
    output::create_dir(&public_dir, "public-dir")?;
    output::create_dir(&sealed_dir, "sealed-dir")?;
    // Refuse before generating anything if any output exists: a key is never replaced.
    for epoch in from..=last {
        exists_refused(
            &public_dir.join(public_entry::file_name(kind, epoch)),
            "public-dir",
            kind,
            epoch,
        )?;
        exists_refused(
            &sealed_dir.join(custody::sealed_file_name(kind, epoch)),
            "sealed-dir",
            kind,
            epoch,
        )?;
    }
    for epoch in from..=last {
        let (entry, sealed) = ceremony_key(&secret, kind, epoch, rng)?;
        let key_id = token::key_id(&entry.spki);
        output::write_sealed_key(&sealed_dir, kind, epoch, &sealed, "sealed-dir")?;
        output::write_public_entry(&public_dir, &entry, "public-dir")?;
        sink.emit(
            Line::new(Code::KeyCreated)
                .kind_epoch(kind, epoch)
                .hex(Field::KeyId, &key_id),
        );
    }
    Ok(())
}

fn exists_refused(path: &Path, flag: &'static str, kind: Kind, epoch: u64) -> Result<(), Failure> {
    if path.exists() {
        let mut failure = io_error(flag, "exists");
        failure.line = failure.line.kind_epoch(kind, epoch);
        return Err(failure);
    }
    Ok(())
}

fn key_refused(kind: Kind, epoch: u64, reason: &'static str) -> Failure {
    Failure::refused(
        Line::new(Code::KeyRefused)
            .kind_epoch(kind, epoch)
            .word(Field::Reason, reason),
    )
}

fn prime_reason(check: PrimeCheck) -> &'static str {
    match check {
        PrimeCheck::PrimeCount => "prime-count",
        PrimeCheck::Product => "prime-product",
        PrimeCheck::Equal => "primes-equal",
        PrimeCheck::TooClose => "primes-too-close",
        PrimeCheck::ExponentNotCoprime => "exponent-not-coprime",
    }
}

/// One key of the ceremony: generation, prime checks, permutation proof through the checked
/// signer, and the sealed private key (proven to open into the same key).
fn ceremony_key(
    secret: &CustodySecret,
    kind: Kind,
    epoch: u64,
    rng: &dyn SecureRandom,
) -> Result<(KeyContent, Vec<u8>), Failure> {
    let signer =
        ReferenceSigner::generate(kind, epoch).map_err(|_| key_refused(kind, epoch, "generate"))?;
    signer
        .check_prime_conditions()
        .map_err(|c| key_refused(kind, epoch, prime_reason(c)))?;
    let public_key = signer.public_key().clone();
    let mut der = signer
        .to_pkcs8_der()
        .map_err(|_| key_refused(kind, epoch, "encode"))?;
    let checked = CheckedSigner::new(signer, public_key.clone())
        .map_err(|_| key_refused(kind, epoch, "sign-check"))?;
    let challenges = ghost_blind_rsa::permutation_proof_challenges(&public_key)
        .map_err(|_| key_refused(kind, epoch, "proof"))?;
    let mut proof = [[0u8; PROOF_BLOCK_LEN]; PROOF_ROUNDS];
    for (block, challenge) in proof.iter_mut().zip(&challenges) {
        *block = checked
            .blind_sign(challenge)
            .map_err(|_| key_refused(kind, epoch, "proof"))?;
    }
    ghost_blind_rsa::verify_permutation_proof(&public_key, &proof)
        .map_err(|_| key_refused(kind, epoch, "proof"))?;

    let seal_key = secret.seal_key(kind, epoch);
    let sealed = custody::seal(&seal_key, kind, epoch, &der, rng);
    der.fill(0);
    let sealed = sealed.map_err(|_| key_refused(kind, epoch, "seal"))?;
    let reopened = custody::unseal(&seal_key, kind, epoch, &sealed)
        .map_err(|_| key_refused(kind, epoch, "seal"))?;
    if reopened.public_key() != &public_key {
        return Err(key_refused(kind, epoch, "seal"));
    }
    Ok((
        KeyContent {
            kind,
            epoch,
            spki: public_key.to_spki(),
            proof,
        },
        sealed,
    ))
}
