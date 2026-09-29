// Fixture (G-M3 rule 2): the typed module is correct; HKDF is reached elsewhere by other names.
use hkdf::Hkdf;
fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(salt, ikm).expand(&info.concat(), &mut out).unwrap();
    out
}
pub fn derive_namespace(g: &GenerationSecret) -> [u8; 32] {
    hkdf32(g.as_bytes(), None, &[b"ns"])
}
