// Fixture (G-M3 rule 2): HKDF by another name outside derive.rs.
pub fn key(ns: &[u8; 32]) -> [u8; 32] {
    let k = hkdf::SimpleHkdf::<Sha256>::new(None, ns);
    todo_fixture(k)
}
