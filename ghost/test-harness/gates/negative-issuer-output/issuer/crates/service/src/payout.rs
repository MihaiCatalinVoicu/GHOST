//! Negative fixture: payout.rs writes batch files (line 3 is allowed) but never the console (line 4).
pub fn export(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    println!("exported");
}
