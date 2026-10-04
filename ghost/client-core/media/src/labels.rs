//! Every string of the media format (design §3.2 "Labels", corrected by S0-6): the three HKDF
//! `info` labels, the two associated-data prefixes, the `op_id` label and the wrap label. No string
//! of the set is a prefix of another (the `DerivationLabelsTest` rule; tested below and pinned by
//! `protocol/test-vectors/media_object.txt`).

/// The prefix of every media label.
pub const MEDIA_PREFIX: &str = "ghost/v1/media/";
/// `K_p = HKDF-SHA256(ikm = K_f, salt = object_id, info = PAYLOAD)` (§3.2).
pub const PAYLOAD: &str = "ghost/v1/media/payload";
/// `K_m = HKDF-SHA256(ikm = K_f, salt = object_id, info = MANIFEST)` (§3.2).
pub const MANIFEST: &str = "ghost/v1/media/manifest";
/// `commit = HKDF-SHA256(ikm = K_f, salt = object_id, info = COMMIT)` (§3.2).
pub const COMMIT: &str = "ghost/v1/media/commit";
/// The prefix of `AD_c` (§3.3; S0-6).
pub const AD_CHUNK: &str = "ghost/v1/media/ad/chunk";
/// The prefix of `AD_m` (§3.5; S0-6).
pub const AD_MANIFEST: &str = "ghost/v1/media/ad/manifest";
/// The `op_id` label (§6.4).
pub const OP_ID: &str = "ghost/v1/media/op";
/// The wrap label of `key_env` (§4.2): F9 §2.5's `"ghost/v1/wrap/" || name` with the name
/// `media-file-key`. The wrap itself is the S2 native surface's (`WrapName::MediaFileKey` in
/// `ghost-client-dm`); the string is here so the prefix rule ranges over the whole format.
pub const WRAP_MEDIA_FILE_KEY: &str = "ghost/v1/wrap/media-file-key";
/// The version byte that follows each associated-data prefix (§3.3, §3.5).
pub const AD_VERSION: u8 = 0x01;

/// The seven strings of the format.
pub const ALL: [&str; 7] = [
    PAYLOAD,
    MANIFEST,
    COMMIT,
    AD_CHUNK,
    AD_MANIFEST,
    OP_ID,
    WRAP_MEDIA_FILE_KEY,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_label_is_a_prefix_of_another() {
        for (i, a) in ALL.iter().enumerate() {
            for (j, b) in ALL.iter().enumerate() {
                if i != j {
                    assert!(!b.starts_with(a), "{a} is a prefix of {b}");
                }
            }
        }
    }

    #[test]
    fn the_media_labels_share_the_media_prefix() {
        for l in ALL {
            assert!(l.is_ascii());
            assert!(
                l.starts_with(MEDIA_PREFIX) || l == WRAP_MEDIA_FILE_KEY,
                "{l}"
            );
        }
    }
}
