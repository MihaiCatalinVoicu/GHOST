//! Negative fixture: the other issuer crates write nothing (line 3 is reported).
pub fn dump(bytes: &[u8]) {
    std::fs::write("dump.bin", bytes).unwrap();
}
