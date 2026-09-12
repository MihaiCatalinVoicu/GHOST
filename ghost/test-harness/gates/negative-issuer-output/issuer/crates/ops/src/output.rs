//! Negative fixture: output.rs writes files (line 3 is allowed) but never the console (line 4).
pub fn write(path: &std::path::Path) {
    std::fs::File::create(path).unwrap();
    eprintln!("written");
}
