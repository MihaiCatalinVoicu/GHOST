// Fixture (G-M3 rule 2): a derivation a macro generates, keyed by untyped bytes.
use hkdf::Hkdf;
fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(salt, ikm).expand(&info.concat(), &mut out).unwrap();
    out
}
pub fn derive_namespace(g: &GenerationSecret) -> [u8; 32] {
    hkdf32(g.as_bytes(), None, &[b"ns"])
}
macro_rules! untyped {
    ($name:ident) => {
        pub fn $name(ikm: &[u8]) -> [u8; 32] {
            hkdf32(ikm, None, &[b"x"])
        }
    };
}
untyped!(derive_generated);
