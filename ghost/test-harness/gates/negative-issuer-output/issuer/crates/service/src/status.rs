//! Negative fixture: status.rs writes files (line 3 is allowed) but never the console (line 4).
pub fn write(path: &std::path::Path) {
    std::fs::rename(path, path).unwrap();
    println!("status");
}
