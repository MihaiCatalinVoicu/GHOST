//! Negative fixture: a service module outside status.rs, store.rs and journal.rs writes no file,
//! and no service module writes to the console. Lines 4, 5 and 6 are reported.
pub fn leak(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).unwrap();
    let _ = std::fs::OpenOptions::new().append(true).open(path);
    eprintln!("{text}");
}
