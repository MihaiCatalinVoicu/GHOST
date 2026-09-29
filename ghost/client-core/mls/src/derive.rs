//! The channel derivations of design §5.2 (labels are part of the compatibility contract; vectors
//! in `protocol/test-vectors/ch_derive.txt`) and the typed key inputs of rule (1).
//!
//! **Rule (1), T36.** Every derivation takes a secret key input — an exporter output, a generation
//! secret, a key derived from one, a random seed, the password or its Argon2id output — never a
//! `channel_id`, a pseudonym key or a KeyPackage. Each key input is a newtype of this module; the
//! one declared **public** input is [`OpenInviteSalt`], accepted only by the open invite's seal
//! ([`derive_open_invite_seal_key`], §19.29.3: that seal gives open and password invites one format,
//! not confidentiality; the link itself is the bearer secret). Gate G-M3's Rust half is
//! [`tests::every_derive_function_is_enumerated_and_keyed_by_a_typed_secret`]; its script half is
//! `scripts/gates/ch-derivation-inputs.sh`.
//!
//! `HKDF(ikm, salt, info, L)` is HKDF-SHA256; an absent salt is the empty one.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::result::{Code, MlsError, MlsResult};

/// Length of every derived channel secret.
pub const SECRET_BYTES: usize = 32;

// Labels (§5.2, §5.6, §19.28.3). Each is used by exactly one function below.
pub const LABEL_EPOCH: &str = "ghost/v1/ch/epoch";
pub const LABEL_GENERATION: &str = "ghost/v1/ch/generation";
pub const LABEL_RECOGNITION: &[u8] = b"ghost/v1/ch-recognition";
pub const LABEL_NAMESPACE: &[u8] = b"ghost/v1/ch/ns";
pub const LABEL_READ_BASE: &[u8] = b"ghost/v1/ch/read-base";
pub const LABEL_DEPOSIT_BASE: &[u8] = b"ghost/v1/ch/deposit-base";
pub const LABEL_READ: &[u8] = b"ghost/v1/ch/read";
pub const LABEL_DEPOSIT: &[u8] = b"ghost/v1/ch/deposit";
pub const LABEL_JOIN_KEY: &[u8] = b"ghost/v1/ch/join-key";
pub const LABEL_COMMITTERS: &[u8] = b"ghost/v1/ch/committers";
pub const LABEL_SEAL: &[u8] = b"ghost/v1/ch-seal";
pub const LABEL_INVITE_SEAL: &[u8] = b"ghost/v1/ch/invite-seal";
/// Bearer credential v3 verifier labels (F9 §4.3, unchanged).
pub const LABEL_READ_VERIFIER: &[u8] = b"ghost/v1/read-verifier";
pub const LABEL_DEPOSIT_VERIFIER: &[u8] = b"ghost/v1/deposit-verifier";

macro_rules! secret_newtype {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Wraps raw bytes as this key kind.
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The raw bytes, for the one primitive that consumes this key kind.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Secrets never render: a Debug of a key would put it in a panic payload.
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

secret_newtype!(
    /// `K_ep(e) = Exporter_e("ghost/v1/ch/epoch", channel_id, 32)` (§5.2): the epoch key.
    EpochExport,
    SECRET_BYTES
);
secret_newtype!(
    /// `G_g = Exporter_{E_g}("ghost/v1/ch/generation", channel_id, 32)` (§5.2).
    GenerationSecret,
    SECRET_BYTES
);
secret_newtype!(
    /// `RB_g`, the read base of a generation (§5.2); an invite carries it (rule (3)).
    ReadBase,
    SECRET_BYTES
);
secret_newtype!(
    /// `DB_g`, the deposit base of a generation (§5.2); an invite carries it (rule (3)).
    DepositBase,
    SECRET_BYTES
);
secret_newtype!(
    /// `JK_g`, the join key of a generation (§5.2): the seal key input of modes 0x12 and 0x13.
    JoinKey,
    SECRET_BYTES
);
secret_newtype!(
    /// A recognition key `R_ep(e)` or `R_join(g)` (§5.2): what Kotlin holds and matches hints with
    /// (CS-S6). An output, never an HKDF key input.
    RecognitionKey,
    SECRET_BYTES
);
secret_newtype!(
    /// The per-blob seal key `k` (§5.6) or the invite's seal key (§19.28.3). An output only.
    SealKey,
    SECRET_BYTES
);
secret_newtype!(
    /// The 32-byte pseudonym seed `ps` (§5.1), derived in `:identity`; the Ed25519 seed of the
    /// pseudonym signer (§3.3).
    PseudonymSeed,
    SECRET_BYTES
);
secret_newtype!(
    /// `invite_seed`, 32 random bytes of an invite (§5.1, §5.9): the invite key's Ed25519 seed.
    InviteSeed,
    SECRET_BYTES
);
secret_newtype!(
    /// `ikm = Argon2id(password, salt, profile(kdf_code), T = 32)` of a password invite
    /// (§19.28.3).
    InvitePasswordKey,
    SECRET_BYTES
);
secret_newtype!(
    /// The channel state key `mls_state_key` (§10.4, F9 §2.5 pattern): 32 random bytes Kotlin holds
    /// wrapped by the Keystore; every row and key envelope of the channel API is sealed under it.
    StateKey,
    SECRET_BYTES
);

/// The password of a password invite as it crosses JNI: the NFKD UTF-8 bytes of what the user
/// typed (§10.2 fn 14, §19.28.3). Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InvitePassword(Vec<u8>);

impl InvitePassword {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for InvitePassword {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InvitePassword(..)")
    }
}

/// The salt printed in an **open** invite's header (§19.28.3): a public value, the one declared
/// exemption of §5.2 rule (1). Accepted only by [`derive_open_invite_seal_key`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenInviteSalt([u8; 16]);

impl OpenInviteSalt {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The Argon2id profile of a `kdf_code` (§19.28.5, Q44): `(m KiB, t, p)`. Code 1 is the P0
/// profile (m = 64 MiB, t = 1, p = 4); 0 is the open invite (no KDF); anything else is refused.
pub fn argon2id_profile(kdf_code: u8) -> Option<(u32, u32, u32)> {
    match kdf_code {
        1 => Some((65_536, 1, 4)),
        _ => None,
    }
}

/// OWASP's equal-strength Argon2id pairs `(m KiB, t)`, with p ≥ 1 (§19.28.5 floors, corrected
/// §19.29.3; MM-PW3's killer asserts every profile of the table against them).
pub const ARGON2ID_FLOOR_PAIRS: [(u32, u32); 5] = [
    (47_104, 1),
    (19_456, 2),
    (12_288, 3),
    (9_216, 4),
    (7_168, 5),
];

/// Whether `(m, t, p)` meets one of the floor pairs.
pub fn argon2id_meets_floor(m_kib: u32, t: u32, p: u32) -> bool {
    p >= 1
        && ARGON2ID_FLOOR_PAIRS
            .iter()
            .any(|&(fm, ft)| m_kib >= fm && t >= ft)
}

fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[&[u8]]) -> [u8; SECRET_BYTES] {
    let mut out = [0u8; SECRET_BYTES];
    let info: Vec<u8> = info.concat();
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(&info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// `R_ep(e) = HKDF(K_ep(e), ∅, "ghost/v1/ch-recognition", 32)`.
pub fn derive_epoch_recognition(k_ep: &EpochExport) -> RecognitionKey {
    RecognitionKey(hkdf32(k_ep.as_bytes(), None, &[LABEL_RECOGNITION]))
}

/// `ns_g = HKDF(G_g, ∅, "ghost/v1/ch/ns", 32)`.
pub fn derive_namespace(g: &GenerationSecret) -> [u8; SECRET_BYTES] {
    hkdf32(g.as_bytes(), None, &[LABEL_NAMESPACE])
}

/// `RB_g = HKDF(G_g, ∅, "ghost/v1/ch/read-base", 32)`.
pub fn derive_read_base(g: &GenerationSecret) -> ReadBase {
    ReadBase(hkdf32(g.as_bytes(), None, &[LABEL_READ_BASE]))
}

/// `DB_g = HKDF(G_g, ∅, "ghost/v1/ch/deposit-base", 32)`.
pub fn derive_deposit_base(g: &GenerationSecret) -> DepositBase {
    DepositBase(hkdf32(g.as_bytes(), None, &[LABEL_DEPOSIT_BASE]))
}

/// `RS_{g,s} = HKDF(RB_g, ∅, "ghost/v1/ch/read" ‖ u8(s), 32)`.
pub fn derive_read_secret(rb: &ReadBase, slot: u8) -> [u8; SECRET_BYTES] {
    hkdf32(rb.as_bytes(), None, &[LABEL_READ, &[slot]])
}

/// `DS_{g,s} = HKDF(DB_g, ∅, "ghost/v1/ch/deposit" ‖ u8(s), 32)`.
pub fn derive_deposit_secret(db: &DepositBase, slot: u8) -> [u8; SECRET_BYTES] {
    hkdf32(db.as_bytes(), None, &[LABEL_DEPOSIT, &[slot]])
}

/// `JK_g = HKDF(G_g, ∅, "ghost/v1/ch/join-key", 32)`.
pub fn derive_join_key(g: &GenerationSecret) -> JoinKey {
    JoinKey(hkdf32(g.as_bytes(), None, &[LABEL_JOIN_KEY]))
}

/// `R_join(g) = HKDF(JK_g, ∅, "ghost/v1/ch-recognition", 32)`.
pub fn derive_join_recognition(jk: &JoinKey) -> RecognitionKey {
    RecognitionKey(hkdf32(jk.as_bytes(), None, &[LABEL_RECOGNITION]))
}

/// The seal key of mode 0x11 (§5.6): `k = HKDF(ikm = K_ep(e), salt, "ghost/v1/ch-seal" ‖ ns, 32)`.
pub fn derive_epoch_seal_key(k_ep: &EpochExport, salt: &[u8; 16], ns: &[u8; 32]) -> SealKey {
    SealKey(hkdf32(k_ep.as_bytes(), Some(salt), &[LABEL_SEAL, ns]))
}

/// The seal key of modes 0x12 and 0x13 (§5.6): `k = HKDF(ikm = JK_g, salt, "ghost/v1/ch-seal" ‖ ns, 32)`.
pub fn derive_join_seal_key(jk: &JoinKey, salt: &[u8; 16], ns: &[u8; 32]) -> SealKey {
    SealKey(hkdf32(jk.as_bytes(), Some(salt), &[LABEL_SEAL, ns]))
}

/// The invite key (§5.2): Ed25519 (RFC 8032) from the 32-byte `invite_seed`.
pub fn derive_invite_signing_key(seed: &InviteSeed) -> SigningKey {
    SigningKey::from_bytes(seed.as_bytes())
}

/// `ikm = Argon2id(password, salt, profile(kdf_code), T = 32)` (§19.28.3) with the RustCrypto
/// `argon2` 0.6.0 (Q47 (a)); its matrix lives in native memory and is zeroized by the crate.
/// `NON_CANONICAL` for a `kdf_code` without a profile (0 included: an open invite has no KDF).
pub fn derive_invite_password_key(
    password: &InvitePassword,
    salt: &[u8; 16],
    kdf_code: u8,
) -> MlsResult<InvitePasswordKey> {
    let (m, t, p) = argon2id_profile(kdf_code).ok_or(MlsError::new(Code::NonCanonical))?;
    let params = argon2::Params::new(m, t, p, Some(SECRET_BYTES))
        .map_err(|_| MlsError::new(Code::Internal))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; SECRET_BYTES]);
    a.hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|_| MlsError::new(Code::Internal))?;
    Ok(InvitePasswordKey(*out))
}

/// A password invite's seal key (§19.28.3):
/// `k = HKDF(ikm, salt = salt, "ghost/v1/ch/invite-seal" ‖ kdf_code, 32)`, `kdf_code ≥ 1`.
pub fn derive_invite_seal_key(ikm: &InvitePasswordKey, salt: &[u8; 16], kdf_code: u8) -> SealKey {
    SealKey(hkdf32(
        ikm.as_bytes(),
        Some(salt),
        &[LABEL_INVITE_SEAL, &[kdf_code]],
    ))
}

/// An open invite's seal key (§19.28.3, `kdf_code = 0`): `ikm = salt`, the declared exemption of
/// §5.2 rule (1) (§19.29.3). This seal gives every invite one format; it is not confidentiality.
pub fn derive_open_invite_seal_key(salt: &OpenInviteSalt) -> SealKey {
    SealKey(hkdf32(
        salt.as_bytes(),
        Some(salt.as_bytes()),
        &[LABEL_INVITE_SEAL, &[0u8]],
    ))
}

/// The committers digest (S0-15, corrected by §19.27 TR-6): `SHA-256("ghost/v1/ch/committers" ‖
/// channel_id ‖ u8(k) ‖ c_0 ‖ … ‖ c_{k−1})` over the committers **sorted bytewise ascending**, so a
/// reorder (a transfer of rank 0) leaves it unchanged and an add or removal changes it. A public
/// commitment, not a key (rule (1) does not apply). `None` above 255 committers (the context
/// allows 8).
pub fn committers_digest(channel_id: &[u8; 32], committers: &[[u8; 32]]) -> Option<[u8; 32]> {
    let k = u8::try_from(committers.len()).ok()?;
    let mut sorted = committers.to_vec();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    h.update(LABEL_COMMITTERS);
    h.update(channel_id);
    h.update([k]);
    for c in &sorted {
        h.update(c);
    }
    Some(h.finalize().into())
}

/// Bearer credential kinds of F9 §4.3 used by channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialKind {
    Read = 0x01,
    Deposit = 0x03,
}

/// Credential v3 (F9 §4.3, unchanged): `3 ‖ kind ‖ u8(slot) ‖ ns ‖ secret` (67 bytes).
pub fn credential_v3(kind: CredentialKind, slot: u8, ns: &[u8; 32], secret: &[u8; 32]) -> Vec<u8> {
    let mut c = Vec::with_capacity(67);
    c.push(3);
    c.push(kind as u8);
    c.push(slot);
    c.extend_from_slice(ns);
    c.extend_from_slice(secret);
    c
}

/// Its verifier: `SHA-256(label(kind) ‖ u8(slot) ‖ ns ‖ secret)`.
pub fn credential_verifier(
    kind: CredentialKind,
    slot: u8,
    ns: &[u8; 32],
    secret: &[u8; 32],
) -> [u8; 32] {
    let label = match kind {
        CredentialKind::Read => LABEL_READ_VERIFIER,
        CredentialKind::Deposit => LABEL_DEPOSIT_VERIFIER,
    };
    let mut h = Sha256::new();
    h.update(label);
    h.update([slot]);
    h.update(ns);
    h.update(secret);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Rust half of gate G-M3 (T36): every `derive_*` function takes a typed key input, so a
    /// `channel_id`, a pseudonym key or a KeyPackage cannot be passed as HKDF key material. The
    /// build fails if a signature changes.
    #[test]
    fn derivation_key_inputs_are_typed() {
        let _: fn(&EpochExport) -> RecognitionKey = derive_epoch_recognition;
        let _: fn(&GenerationSecret) -> [u8; 32] = derive_namespace;
        let _: fn(&GenerationSecret) -> ReadBase = derive_read_base;
        let _: fn(&GenerationSecret) -> DepositBase = derive_deposit_base;
        let _: fn(&ReadBase, u8) -> [u8; 32] = derive_read_secret;
        let _: fn(&DepositBase, u8) -> [u8; 32] = derive_deposit_secret;
        let _: fn(&GenerationSecret) -> JoinKey = derive_join_key;
        let _: fn(&JoinKey) -> RecognitionKey = derive_join_recognition;
        let _: fn(&EpochExport, &[u8; 16], &[u8; 32]) -> SealKey = derive_epoch_seal_key;
        let _: fn(&JoinKey, &[u8; 16], &[u8; 32]) -> SealKey = derive_join_seal_key;
        let _: fn(&InviteSeed) -> SigningKey = derive_invite_signing_key;
        let _: fn(&InvitePassword, &[u8; 16], u8) -> MlsResult<InvitePasswordKey> =
            derive_invite_password_key;
        let _: fn(&InvitePasswordKey, &[u8; 16], u8) -> SealKey = derive_invite_seal_key;
        let _: fn(&OpenInviteSalt) -> SealKey = derive_open_invite_seal_key;
    }

    /// The names [`derivation_key_inputs_are_typed`] pins, in one list the enumeration below
    /// compares with the sources.
    const PINNED_DERIVATIONS: [&str; 14] = [
        "derive_deposit_base",
        "derive_deposit_secret",
        "derive_epoch_recognition",
        "derive_epoch_seal_key",
        "derive_invite_password_key",
        "derive_invite_seal_key",
        "derive_invite_signing_key",
        "derive_join_key",
        "derive_join_recognition",
        "derive_join_seal_key",
        "derive_namespace",
        "derive_open_invite_seal_key",
        "derive_read_base",
        "derive_read_secret",
    ];

    /// The key-input types T36 allows (§5.2 rule (1), the G-M3 list of §13.1 with the secrets
    /// derived from them and the password the Argon2id step consumes), and the one public input.
    const TYPED_KEY_INPUTS: [&str; 9] = [
        "&EpochExport",
        "&GenerationSecret",
        "&ReadBase",
        "&DepositBase",
        "&JoinKey",
        "&InviteSeed",
        "&InvitePassword",
        "&InvitePasswordKey",
        "&OpenInviteSalt",
    ];

    /// Every `fn derive_…` declared in `text`, with the type of its first parameter as written
    /// (whitespace removed): `(name, type)`. Prose is skipped only as whole `//` lines, so a
    /// declaration is never missed and a mention elsewhere can only add a name (which then fails).
    /// (The reader of `ghost-client-dm`'s G-DM3 half, the same method.)
    fn derivations_in(text: &str) -> Vec<(String, String)> {
        let code: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let bytes = code.as_bytes();
        let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        // Built at run time, so this file's own source does not hold the text it looks for.
        let marker = ["derive", "_"].concat();
        let mut found = Vec::new();
        let mut from = 0;
        while let Some(at) = code[from..].find(&marker).map(|i| from + i) {
            from = at + marker.len();
            let before = code[..at].trim_end_matches([' ', '\t', '\n', '\r']);
            if before.len() == at
                || !before.ends_with("fn")
                || (before.len() > 2 && ident(bytes[before.len() - 3]))
                || (at > 0 && ident(bytes[at - 1]))
            {
                continue;
            }
            let name: String = code[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let mut rest = code[at + name.len()..].trim_start();
            if let Some(generics) = rest.strip_prefix('<') {
                let mut depth = 1usize;
                let mut end = generics.len();
                for (i, c) in generics.char_indices() {
                    match c {
                        '<' => depth += 1,
                        '>' => {
                            depth -= 1;
                            if depth == 0 {
                                end = i + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                rest = generics[end..].trim_start();
            }
            let first = rest.strip_prefix('(').map(|params| {
                let mut depth = 0i32;
                let mut end = params.len();
                for (i, c) in params.char_indices() {
                    match c {
                        '(' | '[' | '<' => depth += 1,
                        ']' | '>' => depth -= 1,
                        ')' if depth == 0 => {
                            end = i;
                            break;
                        }
                        ')' => depth -= 1,
                        ',' if depth == 0 => {
                            end = i;
                            break;
                        }
                        _ => {}
                    }
                }
                params[..end]
                    .split_once(':')
                    .map(|(_, ty)| ty.split_whitespace().collect::<String>())
                    .unwrap_or_default()
            });
            found.push((name, first.unwrap_or_default()));
        }
        found
    }

    fn derivations_in_sources() -> std::collections::BTreeMap<String, (String, String)> {
        fn walk(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("src is readable") {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    walk(&path, files);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
        let mut files = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        let mut found = std::collections::BTreeMap::new();
        for file in files {
            let text = std::fs::read_to_string(&file).expect("a source file is readable");
            let short = file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            for (name, first) in derivations_in(&text) {
                let previous = found.insert(name.clone(), (first, short.clone()));
                assert!(previous.is_none(), "{name} is declared twice in src/");
            }
        }
        found
    }

    /// The Rust half of gate G-M3, **enumerated**: every `fn derive_…` of the crate's sources is
    /// pinned above and keyed by a typed secret, and the one public input, `OpenInviteSalt`, keys
    /// only the open invite's seal. A `derive_*` function added anywhere in `src/` — one keyed by
    /// `&[u8]`, a `channel_id` or a pseudonym key included — fails here.
    #[test]
    fn every_derive_function_is_enumerated_and_keyed_by_a_typed_secret() {
        let found = derivations_in_sources();
        let names: Vec<&str> = found.keys().map(String::as_str).collect();
        assert_eq!(names, PINNED_DERIVATIONS.to_vec());
        for (name, (first, file)) in &found {
            assert_eq!(file, "derive.rs", "{name} is declared outside derive.rs");
            assert!(
                TYPED_KEY_INPUTS.contains(&first.as_str()),
                "{name} takes `{first}` as its key input; T36 allows only {TYPED_KEY_INPUTS:?}"
            );
            if first == "&OpenInviteSalt" {
                assert_eq!(
                    name, "derive_open_invite_seal_key",
                    "OpenInviteSalt is accepted only by the open invite's seal (§19.29.3)"
                );
            }
        }
    }

    /// The reader is not vacuous and not evadable by layout.
    #[test]
    fn the_derive_enumeration_reads_what_it_claims() {
        let found = derivations_in_sources();
        assert_eq!(
            found.get("derive_epoch_seal_key").map(|v| v.0.as_str()),
            Some("&EpochExport")
        );
        let d = ["derive", "_"].concat();
        let samples = [
            format!("pub fn  {d}a(key: &[u8]) {{}}"),
            format!("fn\t{d}b<K: AsRef<[u8]>>(key: K) {{}}"),
            format!("pub(crate) fn\n{d}c(\n    g: &GenerationSecret,\n) {{}}"),
            format!("fn {d}d {{}}"),
            format!("// fn {d}e(x: &[u8]) is prose\nfn {d}f(r: &JoinKey) {{}}"),
            format!("fn every_{d}g(x: &[u8]) {{}} fn x{d}h() {{}}"),
        ];
        let read: Vec<(String, String)> = samples.iter().flat_map(|s| derivations_in(s)).collect();
        let expect = |n: &str, t: &str| (format!("{d}{n}"), t.to_owned());
        assert_eq!(
            read,
            vec![
                expect("a", "&[u8]"),
                expect("b", "K"),
                expect("c", "&GenerationSecret"),
                expect("d", ""),
                expect("f", "&JoinKey"),
            ]
        );
    }

    #[test]
    fn the_committers_digest_binds_the_set_not_the_order() {
        let ch = [7u8; 32];
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let ab = committers_digest(&ch, &[a, b]).unwrap();
        // A transfer of rank 0 (a reorder) keeps the digest (TR-6, MM-45's killer) ...
        assert_eq!(ab, committers_digest(&ch, &[b, a]).unwrap());
        // ... an add or a removal changes it, and so does another channel.
        assert_ne!(ab, committers_digest(&ch, &[a, b, c]).unwrap());
        assert_ne!(ab, committers_digest(&ch, &[a]).unwrap());
        assert_ne!(ab, committers_digest(&[8u8; 32], &[a, b]).unwrap());
    }

    /// MM-PW3's killer (§19.29.3): every profile of the table meets OWASP's floor pairs; a profile
    /// below every pair (and round 10d's 19 MiB with one pass) does not.
    #[test]
    fn every_kdf_profile_meets_the_floor_pairs() {
        let mut codes = 0;
        for code in 0..=u8::MAX {
            if let Some((m, t, p)) = argon2id_profile(code) {
                codes += 1;
                assert!(argon2id_meets_floor(m, t, p), "kdf_code {code} below floor");
            }
        }
        assert_eq!(codes, 1, "one profile in P0 (kdf_code 1)");
        assert!(!argon2id_meets_floor(19_456, 1, 1));
        assert!(
            !argon2id_meets_floor(32, 3, 4),
            "the RFC 9106 vector is below every floor"
        );
        assert!(argon2id_meets_floor(19_456, 2, 1));
    }

    /// RFC 9106 §5.3 (the Argon2id test vector, E-65): P = 32 × 0x01, S = 16 × 0x02, K = 8 × 0x03,
    /// X = 12 × 0x04, m = 32 KiB, t = 3, p = 4, T = 32. Run on the primitive directly: its 32 KiB is
    /// below every floor, so it cannot pass through the codec's profile table (MM-PW3).
    #[test]
    fn rfc9106_argon2id_vector() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[4u8; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let a = argon2::Argon2::new_with_secret(
            &[3u8; 8],
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        )
        .unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
            .unwrap();
        assert_eq!(
            hex::encode(out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
        // t = 0 is refused by the primitive itself, so it is no meaningful mutant of the codec.
        assert!(argon2::Params::new(65_536, 0, 4, Some(32)).is_err());
    }

    #[test]
    fn secrets_never_render() {
        let k = EpochExport::from_bytes([0xab; 32]);
        assert_eq!(format!("{k:?}"), "EpochExport(..)");
        assert_eq!(
            format!("{:?}", InvitePassword::from_bytes(b"pw".to_vec())),
            "InvitePassword(..)"
        );
    }
}
