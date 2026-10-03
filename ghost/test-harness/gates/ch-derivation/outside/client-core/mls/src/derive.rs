// Fixture (ch-derivation-inputs.sh, G-M3): the rules hold. A declaration in a comment is not code:
/* fn derive_commented(key: &[u8]) -> [u8; 32] */
use hkdf::Hkdf;
pub fn derive_namespace(g: &GenerationSecret) -> [u8; 32] {
    let _ = Hkdf::<Sha256>::new(None, g.as_bytes());
    [0; 32]
}
pub fn derive_join_seal_key<'a>(
    jk: &JoinKey,
    salt: &[u8; 16],
) -> SealKey {
    todo_fixture(jk, salt)
}
pub fn derive_open_invite_seal_key(salt: &OpenInviteSalt) -> SealKey {
    let s = "fn derive_in_a_string(x: &[u8])";
    todo_fixture(salt, s)
}
